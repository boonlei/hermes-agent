"""Worker protocol validation and deterministic hashing."""
from __future__ import annotations
import hashlib, json, re
from datetime import datetime, timezone
from uuid import UUID

WORKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
EXPECTED_HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
INSTRUCTION_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SAFE_FAILURE_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

KNOWN_CAPABILITIES = ("system.echo", "codex.execute")
CODEX_EXECUTE_WORKER_ID = "server-a-worker"
CODEX_EXECUTE_HOST = "DESKTOP-87SSHTU"
CODEX_EXECUTE_REPOSITORY = "boonlei/HermesServerWorker"
CODEX_EXECUTE_PATH_ID = "hermes-server-worker"
CODEX_EXECUTE_BRANCH = "main"
CODEX_EXECUTE_MODE = "read_only"
CODEX_EXECUTE_MAX_INSTRUCTION_BYTES = 16 * 1024
CODEX_EXECUTE_MAX_RESULT_BYTES = 32 * 1024
CODEX_EXECUTE_RESULT_GRACE_SECONDS = 5

def canonical_json_hash(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()

def validate_system_echo_payload(payload: object, max_bytes: int = 4096) -> dict[str, str]:
    if not isinstance(payload, dict) or set(payload) != {"message"}:
        raise ValueError("invalid_task_payload")
    message = payload["message"]
    if not isinstance(message, str) or not message or len(message.encode("utf-8")) > max_bytes:
        raise ValueError("invalid_task_payload")
    return {"message": message}

def validate_capabilities(value: object) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError("unsupported_capability")
    if any(not isinstance(item, str) for item in value):
        raise ValueError("unsupported_capability")
    requested = set(value)
    canonical = [name for name in KNOWN_CAPABILITIES if name in requested]
    if len(requested) != len(value) or value != canonical:
        raise ValueError("unsupported_capability")
    return canonical

def validate_codex_execute_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != {
        "task_type", "target", "instruction", "limits"
    }:
        raise ValueError("invalid_task_payload")
    target = payload["target"]
    instruction = payload["instruction"]
    limits = payload["limits"]
    if payload["task_type"] != "codex.execute":
        raise ValueError("invalid_task_payload")
    if not isinstance(target, dict) or set(target) != {
        "host", "repository", "path_id", "branch", "expected_head"
    }:
        raise ValueError("invalid_task_payload")
    if (
        target["host"] != CODEX_EXECUTE_HOST
        or target["repository"] != CODEX_EXECUTE_REPOSITORY
        or target["path_id"] != CODEX_EXECUTE_PATH_ID
        or target["branch"] != CODEX_EXECUTE_BRANCH
        or not isinstance(target["expected_head"], str)
        or not EXPECTED_HEAD_RE.fullmatch(target["expected_head"])
    ):
        raise ValueError("invalid_task_payload")
    if not isinstance(instruction, dict) or set(instruction) != {
        "task_id", "text", "mode"
    }:
        raise ValueError("invalid_task_payload")
    if (
        not isinstance(instruction["task_id"], str)
        or not INSTRUCTION_TASK_ID_RE.fullmatch(instruction["task_id"])
        or not isinstance(instruction["text"], str)
        or not instruction["text"]
        or len(instruction["text"].encode("utf-8"))
        > CODEX_EXECUTE_MAX_INSTRUCTION_BYTES
        or instruction["mode"] != CODEX_EXECUTE_MODE
    ):
        raise ValueError("invalid_task_payload")
    if not isinstance(limits, dict) or set(limits) != {
        "timeout_seconds", "max_result_bytes"
    }:
        raise ValueError("invalid_task_payload")
    if (
        type(limits["timeout_seconds"]) is not int
        or not 60 <= limits["timeout_seconds"] <= 900
        or type(limits["max_result_bytes"]) is not int
        or not 1 <= limits["max_result_bytes"] <= CODEX_EXECUTE_MAX_RESULT_BYTES
    ):
        raise ValueError("invalid_task_payload")
    return {
        "task_type": "codex.execute",
        "target": dict(target),
        "instruction": dict(instruction),
        "limits": dict(limits),
    }

def validate_safe_failure_code(value: object) -> str:
    if not isinstance(value, str) or not SAFE_FAILURE_CODE_RE.fullmatch(value):
        raise ValueError("invalid_result")
    return value

def require_uuid(value: object, name: str) -> str:
    if not isinstance(value, str): raise ValueError(f"invalid_{name}")
    try: UUID(value)
    except (ValueError, TypeError): raise ValueError(f"invalid_{name}") from None
    return value

def require_worker_id(value: object) -> str:
    if not isinstance(value, str) or not WORKER_ID_RE.fullmatch(value): raise ValueError("invalid_worker_id")
    return value

def require_timestamp(value: object, name: str) -> str:
    if not isinstance(value, str): raise ValueError(f"invalid_{name}")
    try: datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: raise ValueError(f"invalid_{name}") from None
    return value

def closed(data: object, fields: set[str]) -> dict:
    if not isinstance(data, dict) or set(data) - fields: raise ValueError("malformed_request")
    return data
