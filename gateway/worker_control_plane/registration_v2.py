"""Closed Registration v2 contract and token-wrapping primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .models import require_uuid, require_worker_id


PROTOCOL_VERSION = 2
WORKER_ID = "server-a-worker"
HOST = "DESKTOP-87SSHTU"
PATH_ID = "hermes-server-worker"
REMOTE = "https://github.com/boonlei/HermesServerWorker.git"
BRANCH = "main"
APPROVED_HEAD = "4092825b22184ad9820b4899b49fb1f833ac0b19"
PATH_DIGEST = "e8f0e3d56567d83c62ce7c3cc72e84188ee217660680b153e41f25e97c546a95"
CAPABILITIES = ["system.echo", "codex.execute"]
PENDING_STATE = "issued_pending_confirmation"
TERMINAL_STATES = {"confirmed", "superseded", "revoked", "expired"}
ALL_STATES = {PENDING_STATE, *TERMINAL_STATES}
MAX_RECOVERIES = 5
WRAP_INFO = b"hermes-wcp-registration-v2-token-wrap"

REGISTER_FIELDS = {
    "protocol_version",
    "worker_id",
    "instance_id",
    "worker_name",
    "worker_version",
    "capabilities",
    "host",
    "path_id",
    "target_identity",
    "registration_transaction_id",
}
RECOVERY_FIELDS = {
    "protocol_version",
    "worker_id",
    "instance_id",
    "registration_transaction_id",
    "host",
    "path_id",
    "target_identity",
}
CONFIRM_FIELDS = {
    *RECOVERY_FIELDS,
    "registration_id",
    "credential_id",
    "installation_proof",
}
TARGET_FIELDS = {"path_digest", "remote", "branch", "approved_head"}
STATUS_FIELDS = {"instance_id", "registration_id"}
LOWER_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class WrappedToken:
    salt: bytes
    nonce: bytes
    ciphertext: bytes


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def request_hash(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _bounded_text(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > 256
        or not value.isprintable()
    ):
        raise ValueError(field)
    return value


def _canonical_uuid(value: object, field: str) -> str:
    require_uuid(value, field)
    if value != value.lower() or str(UUID(value)) != value:
        raise ValueError(field)
    return value


def validate_target_identity(value: object) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != TARGET_FIELDS:
        raise ValueError("invalid_target_identity")
    if (
        not isinstance(value["path_digest"], str)
        or not LOWER_HEX_64.fullmatch(value["path_digest"])
        or value["path_digest"] != PATH_DIGEST
        or value["remote"] != REMOTE
        or value["branch"] != BRANCH
        or value["approved_head"] != APPROVED_HEAD
    ):
        raise ValueError("invalid_target_identity")
    return {
        "path_digest": value["path_digest"],
        "remote": REMOTE,
        "branch": BRANCH,
        "approved_head": APPROVED_HEAD,
    }


def _validate_common(data: object, fields: set[str]) -> dict:
    if not isinstance(data, dict) or set(data) != fields:
        raise ValueError("malformed_request")
    require_worker_id(data["worker_id"])
    if data["worker_id"] != WORKER_ID:
        raise ValueError("invalid_credential")
    _canonical_uuid(data["instance_id"], "instance_id")
    _canonical_uuid(
        data["registration_transaction_id"],
        "registration_transaction_id",
    )
    if (
        type(data["protocol_version"]) is not int
        or data["protocol_version"] != PROTOCOL_VERSION
    ):
        raise ValueError("unsupported_protocol")
    if data["host"] != HOST or data["path_id"] != PATH_ID:
        raise ValueError("invalid_target_identity")
    validate_target_identity(data["target_identity"])
    return data


def validate_register_request(data: object) -> dict:
    value = _validate_common(data, REGISTER_FIELDS)
    _bounded_text(value["worker_name"], "malformed_request")
    _bounded_text(value["worker_version"], "malformed_request")
    if value["capabilities"] != CAPABILITIES:
        raise ValueError("unsupported_capability")
    return value


def validate_recovery_request(data: object) -> dict:
    return _validate_common(data, RECOVERY_FIELDS)


def validate_confirmation_request(data: object) -> dict:
    value = _validate_common(data, CONFIRM_FIELDS)
    _canonical_uuid(value["credential_id"], "credential_id")
    _canonical_uuid(value["registration_id"], "registration_id")
    proof = value["installation_proof"]
    if not isinstance(proof, str) or not LOWER_HEX_64.fullmatch(proof):
        raise ValueError("invalid_credential")
    return value


def validate_status_request(data: object) -> dict[str, str]:
    if not isinstance(data, dict) or set(data) != STATUS_FIELDS:
        raise ValueError("malformed_request")
    return {
        "instance_id": _canonical_uuid(data["instance_id"], "instance_id"),
        "registration_id": _canonical_uuid(
            data["registration_id"],
            "registration_id",
        ),
    }


def identity_aad(
    *,
    transaction_id: str,
    registration_id: str,
    credential_id: str,
    worker_id: str,
    instance_id: str,
    host: str,
    path_id: str,
    target_identity: dict,
    capabilities: list[str],
    issued_at: str,
    expires_at: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "registration_transaction_id": transaction_id,
            "registration_id": registration_id,
            "credential_id": credential_id,
            "worker_id": worker_id,
            "instance_id": instance_id,
            "host": host,
            "path_id": path_id,
            "target_identity": target_identity,
            "capabilities": capabilities,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
    )


def _wrapping_key(secret: str, salt: bytes) -> bytes:
    if not isinstance(secret, str) or not secret:
        raise ValueError("invalid_credential")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=WRAP_INFO,
    ).derive(secret.encode("utf-8"))


def wrap_token(
    secret: str,
    token: str,
    aad: bytes,
    *,
    random_bytes,
) -> WrappedToken:
    salt = random_bytes(32)
    nonce = random_bytes(12)
    ciphertext = AESGCM(_wrapping_key(secret, salt)).encrypt(
        nonce,
        token.encode("utf-8"),
        aad,
    )
    return WrappedToken(salt, nonce, ciphertext)


def unwrap_token(
    secret: str,
    wrapped: WrappedToken,
    aad: bytes,
) -> str:
    plaintext = AESGCM(_wrapping_key(secret, wrapped.salt)).decrypt(
        wrapped.nonce,
        wrapped.ciphertext,
        aad,
    )
    return plaintext.decode("utf-8")


def confirmation_message(body: dict) -> bytes:
    return canonical_json_bytes(
        {key: value for key, value in body.items() if key != "installation_proof"}
    )


def verify_installation_proof(token: str, body: dict) -> bool:
    expected = hmac.new(
        token.encode("utf-8"),
        confirmation_message(body),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, body["installation_proof"])
