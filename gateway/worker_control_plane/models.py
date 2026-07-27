"""Worker protocol validation and deterministic hashing."""
from __future__ import annotations
import hashlib, json, re
from datetime import datetime, timezone
from uuid import UUID

WORKER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
SAFE_RESULT_IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")

KNOWN_CAPABILITIES = ("system.echo", "codex.execute")
CODEX_EXECUTE_WORKER_ID = "server-a-worker"
CODEX_EXECUTE_PATH_ID = "hermes-server-worker"
CODEX_EXECUTE_MODE = "read_only"
CODEX_EXECUTE_MAX_INSTRUCTION_BYTES = 8 * 1024
CODEX_EXECUTE_MAX_RESULT_BYTES = 32 * 1024
CODEX_EXECUTE_RESULT_GRACE_SECONDS = 5
CODEX_EXECUTE_FAILURE_CODES_BY_STATUS = {
    "failed": {
        "post_guard_failed",
        "process_adapter_failed",
        "execution_failed",
        "invalid_result",
        "codex_failed",
        "worker_error",
    },
    "rejected": {"guard_rejected", "repository_mismatch"},
    "timed_out": {"execution_timed_out", "timeout"},
}
CODEX_EXECUTE_RESULT_STATUSES = {
    "completed",
    "failed",
    "rejected",
    "timed_out",
}

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
    if "codex.execute" in requested and value != list(KNOWN_CAPABILITIES):
        raise ValueError("unsupported_capability")
    return canonical

def validate_codex_execute_payload(payload: object) -> dict:
    if not isinstance(payload, dict) or set(payload) != {
        "path_id", "mode", "instruction", "timeout_seconds"
    }:
        raise ValueError("invalid_task_payload")
    if (
        payload["path_id"] != CODEX_EXECUTE_PATH_ID
        or payload["mode"] != CODEX_EXECUTE_MODE
        or not isinstance(payload["instruction"], str)
        or not payload["instruction"]
        or len(payload["instruction"].encode("utf-8"))
        > CODEX_EXECUTE_MAX_INSTRUCTION_BYTES
        or type(payload["timeout_seconds"]) is not int
        or not 60 <= payload["timeout_seconds"] <= 900
    ):
        raise ValueError("invalid_task_payload")
    return {
        "path_id": CODEX_EXECUTE_PATH_ID,
        "mode": CODEX_EXECUTE_MODE,
        "instruction": payload["instruction"],
        "timeout_seconds": payload["timeout_seconds"],
    }

def validate_codex_execute_result(value: object) -> dict:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid_result")
    try:
        result = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("invalid_result") from None
    if not isinstance(result, dict):
        raise ValueError("invalid_result")
    required = {
        "status",
        "classification",
        "failure_code",
        "summary",
        "exit_code",
        "duration_ms",
        "guards",
    }
    if not required <= set(result) or set(result) - required - {"truncated"}:
        raise ValueError("invalid_result")
    if json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) != value:
        raise ValueError("invalid_result")
    if result["status"] not in CODEX_EXECUTE_RESULT_STATUSES:
        raise ValueError("invalid_result")
    if (
        not isinstance(result["classification"], str)
        or not SAFE_RESULT_IDENTIFIER_RE.fullmatch(result["classification"])
        or not isinstance(result["summary"], str)
        or not result["summary"]
        or len(result["summary"].encode("utf-8"))
        > CODEX_EXECUTE_MAX_RESULT_BYTES
        or type(result["exit_code"]) is not int
        or type(result["duration_ms"]) is not int
        or result["duration_ms"] < 0
        or not isinstance(result["guards"], dict)
        or len(result["guards"]) > 32
        or any(
            not isinstance(name, str)
            or not SAFE_RESULT_IDENTIFIER_RE.fullmatch(name)
            or type(passed) is not bool
            for name, passed in result["guards"].items()
        )
        or ("truncated" in result and type(result["truncated"]) is not bool)
    ):
        raise ValueError("invalid_result")
    if result["status"] == "completed":
        if result["failure_code"] is not None or result["exit_code"] != 0:
            raise ValueError("invalid_result")
    elif (
        result["failure_code"]
        not in CODEX_EXECUTE_FAILURE_CODES_BY_STATUS[result["status"]]
        or result["exit_code"] == 0
    ):
        raise ValueError("invalid_result")
    return result

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
