"""Exact operator lifecycle for expired Registration-v2 handoffs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone

from .registration_v2 import (
    APPROVED_HEAD,
    BRANCH,
    CAPABILITIES,
    HOST,
    PATH_DIGEST,
    PATH_ID,
    REMOTE,
)
from .storage import CURRENT_LIFECYCLE_VERSION, WorkerControlPlaneStore


ArtifactPreparation = Callable[
    [str, bool, bool, int | None, int | None],
    tuple[
        Callable[[], None] | None,
        Callable[[], dict[str, object]],
        Callable[[], dict[str, object]],
        dict[str, object],
    ],
]
LifecycleHook = Callable[[str], None]


def _utc_now(clock: Callable[[], datetime] | None = None) -> datetime:
    value = (clock or (lambda: datetime.now(timezone.utc)))()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RuntimeError("clock must return timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _expiry(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"{field} is invalid") from None
    if parsed.tzinfo is None:
        raise ValueError(f"{field} is invalid")
    return parsed.astimezone(timezone.utc)


def _audit(
    connection: sqlite3.Connection,
    *,
    occurred_at: str,
    event_type: str,
    worker_id: str,
    instance_id: str,
    outcome: str,
    reason_code: str,
    details: dict[str, object],
) -> int:
    cursor = connection.execute(
        "INSERT INTO worker_audit_log("
        "occurred_at,event_type,worker_id,instance_id,registration_id,"
        "task_id,delivery_id,trace_id,outcome,reason_code,details_json"
        ") VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (
            occurred_at,
            event_type,
            worker_id,
            instance_id,
            None,
            None,
            None,
            None,
            outcome,
            reason_code,
            json.dumps(details, sort_keys=True, separators=(",", ":")),
        ),
    )
    return int(cursor.lastrowid)


def _verified_lifecycle_audit_ids(
    connection: sqlite3.Connection,
    *,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
    revoked_at: str,
) -> list[int]:
    rows = connection.execute(
        "SELECT audit_id,occurred_at,event_type,worker_id,instance_id,outcome,"
        "reason_code,details_json FROM worker_audit_log "
        "WHERE (event_type='registration_v2_handoff_operator_expired' "
        "AND reason_code=?) OR "
        "(event_type='bootstrap_credential_operator_revoked' "
        "AND reason_code=?) ORDER BY audit_id",
        (registration_transaction_id, bootstrap_credential_id),
    ).fetchall()
    expected = {
        "registration_v2_handoff_operator_expired": {
            "outcome": "expired",
            "reason_code": registration_transaction_id,
            "details": {
                "bootstrap_credential_id": bootstrap_credential_id,
                "state": "expired",
            },
        },
        "bootstrap_credential_operator_revoked": {
            "outcome": "revoked",
            "reason_code": bootstrap_credential_id,
            "details": {
                "registration_transaction_id": (
                    registration_transaction_id
                ),
                "state": "revoked",
            },
        },
    }
    if len(rows) != len(expected):
        raise ValueError(
            "terminal handoff lacks exact operator lifecycle audit"
        )
    seen: set[str] = set()
    for row in rows:
        event_type = row["event_type"]
        contract = expected.get(event_type)
        try:
            details = json.loads(row["details_json"])
        except (TypeError, json.JSONDecodeError):
            details = None
        if (
            contract is None
            or event_type in seen
            or row["worker_id"] != worker_id
            or row["instance_id"] != instance_id
            or row["occurred_at"] != revoked_at
            or row["outcome"] != contract["outcome"]
            or row["reason_code"] != contract["reason_code"]
            or details != contract["details"]
        ):
            raise ValueError(
                "terminal handoff operator lifecycle audit is ambiguous"
            )
        seen.add(event_type)
    return [int(row["audit_id"]) for row in rows]


def _verified_artifact_audit_state(
    connection: sqlite3.Connection,
    *,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
) -> dict[str, object]:
    rows = connection.execute(
        "SELECT audit_id,event_type,worker_id,instance_id,outcome,"
        "reason_code,details_json FROM worker_audit_log "
        "WHERE event_type IN "
        "('registration_v2_handoff_artifact_cleanup_required',"
        "'registration_v2_handoff_artifact_sanitized',"
        "'registration_v2_handoff_artifact_deleted') "
        "AND reason_code=? ORDER BY audit_id",
        (registration_transaction_id,),
    ).fetchall()
    state: dict[str, object] = {
        "cleanup_required_audit_id": None,
        "sanitized_audit_id": None,
        "deleted_audit_id": None,
        "sanitized_device": None,
        "sanitized_inode": None,
    }
    contracts = {
        "registration_v2_handoff_artifact_cleanup_required": (
            "cleanup_required",
            "cleanup_required_audit_id",
        ),
        "registration_v2_handoff_artifact_sanitized": (
            "sanitized",
            "sanitized_audit_id",
        ),
        "registration_v2_handoff_artifact_deleted": (
            "deleted",
            "deleted_audit_id",
        ),
    }
    for row in rows:
        contract = contracts[row["event_type"]]
        try:
            details = json.loads(row["details_json"])
        except (TypeError, json.JSONDecodeError):
            details = None
        if (
            state[contract[1]] is not None
            or row["worker_id"] != worker_id
            or row["instance_id"] != instance_id
            or row["outcome"] != contract[0]
            or row["reason_code"] != registration_transaction_id
            or not isinstance(details, dict)
            or details.get("bootstrap_credential_id")
            != bootstrap_credential_id
        ):
            raise ValueError("handoff artifact audit history is ambiguous")
        if row["event_type"].endswith("_cleanup_required"):
            if set(details) != {
                "bootstrap_credential_id",
                "safe_reason",
            } or not isinstance(details["safe_reason"], str):
                raise ValueError(
                    "handoff artifact audit history is ambiguous"
                )
        elif row["event_type"].endswith("_sanitized"):
            if (
                set(details)
                != {
                    "bootstrap_credential_id",
                    "device",
                    "inode",
                    "state",
                }
                or details["state"] != "sanitized"
                or not isinstance(details["device"], int)
                or not isinstance(details["inode"], int)
            ):
                raise ValueError(
                    "handoff artifact audit history is ambiguous"
                )
            state["sanitized_device"] = details["device"]
            state["sanitized_inode"] = details["inode"]
        elif details != {
            "bootstrap_credential_id": bootstrap_credential_id,
            "artifact": "removed",
        }:
            raise ValueError("handoff artifact audit history is ambiguous")
        state[contract[1]] = int(row["audit_id"])
    return state


def inspect_expired_orphan_handoff(
    connection: sqlite3.Connection,
    *,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Validate the exact expired orphan without mutating database state."""
    checked_at = _utc_now(lambda: now) if now is not None else _utc_now()
    expected_capabilities = json.dumps(CAPABILITIES, separators=(",", ":"))
    row = connection.execute(
        "SELECT h.*,b.kind AS bootstrap_kind,"
        "b.expires_at AS bootstrap_expires_at,"
        "b.revoked_at AS bootstrap_revoked_at,"
        "b.consumed_at AS bootstrap_consumed_at,"
        "b.single_use AS bootstrap_single_use,"
        "b.lifecycle_version AS bootstrap_lifecycle_version,"
        "b.capabilities_json AS bootstrap_capabilities "
        "FROM worker_registration_handoffs_v2 h "
        "JOIN worker_credentials b ON b.credential_id="
        "h.bootstrap_credential_id "
        "WHERE h.registration_transaction_id=?",
        (registration_transaction_id,),
    ).fetchone()
    if row is None:
        raise ValueError("handoff target not found")
    if row["worker_id"] != worker_id:
        raise ValueError("worker_id does not match handoff")
    if row["instance_id"] != instance_id:
        raise ValueError("instance_id does not match handoff")
    if row["bootstrap_credential_id"] != bootstrap_credential_id:
        raise ValueError("bootstrap credential does not match handoff")
    if (
        row["host"] != HOST
        or row["path_id"] != PATH_ID
        or row["path_digest"] != PATH_DIGEST
        or row["remote"] != REMOTE
        or row["branch"] != BRANCH
        or row["approved_head"] != APPROVED_HEAD
        or row["capabilities_json"] != expected_capabilities
        or row["bootstrap_capabilities"] != expected_capabilities
    ):
        raise ValueError("handoff target binding is invalid")
    if row["bootstrap_kind"] != "bootstrap":
        raise ValueError("bound credential is not a bootstrap credential")
    if row["bootstrap_lifecycle_version"] != CURRENT_LIFECYCLE_VERSION:
        raise ValueError("bootstrap credential lifecycle is ineligible")
    if row["bootstrap_single_use"] != 1:
        raise ValueError("bootstrap credential is not single-use")

    transaction_count = connection.execute(
        "SELECT count(*) FROM worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=? OR bootstrap_credential_id=?",
        (registration_transaction_id, bootstrap_credential_id),
    ).fetchone()[0]
    if transaction_count:
        raise ValueError("handoff is referenced by a Registration-v2 transaction")
    registration_count = connection.execute(
        "SELECT count(*) FROM worker_instances "
        "WHERE access_credential_id=?",
        (bootstrap_credential_id,),
    ).fetchone()[0]
    if registration_count:
        raise ValueError("bootstrap credential is linked to a registration")
    pending_tasks = connection.execute(
        "SELECT count(*) FROM worker_tasks WHERE worker_id=? "
        "AND state IN ('queued','leased','running')",
        (worker_id,),
    ).fetchone()[0]
    open_deliveries = connection.execute(
        "SELECT count(*) FROM worker_deliveries "
        "WHERE worker_id=? AND state IN ('leased','acknowledged')",
        (worker_id,),
    ).fetchone()[0]
    if pending_tasks or open_deliveries:
        raise ValueError("pending task or delivery depends on worker lifecycle")

    handoff_expiry = _expiry(row["expires_at"], "handoff expiry")
    bootstrap_expiry = _expiry(
        row["bootstrap_expires_at"], "bootstrap expiry"
    )
    expected_file = (
        f".registration-v2-handoff-{registration_transaction_id}.secret"
    )
    if row["secret_file_name"] != expected_file:
        raise ValueError("handoff artifact association is invalid")
    artifact_audits = _verified_artifact_audit_state(
        connection,
        worker_id=worker_id,
        instance_id=instance_id,
        registration_transaction_id=registration_transaction_id,
        bootstrap_credential_id=bootstrap_credential_id,
    )
    idempotent = (
        row["state"] == "expired"
        and row["consumed_at"] is None
        and row["bootstrap_consumed_at"] is None
        and row["bootstrap_revoked_at"] is not None
    )
    if idempotent:
        if row["retrieved_at"] is not None:
            raise ValueError("terminal handoff was previously retrieved")
        if handoff_expiry > checked_at or bootstrap_expiry > checked_at:
            raise ValueError("terminal handoff expiry is inconsistent")
        _verified_lifecycle_audit_ids(
            connection,
            worker_id=worker_id,
            instance_id=instance_id,
            registration_transaction_id=registration_transaction_id,
            bootstrap_credential_id=bootstrap_credential_id,
            revoked_at=row["bootstrap_revoked_at"],
        )
        return {
            "eligible": True,
            "idempotent": True,
            "checked_at": _utc_text(checked_at),
            "registration_transaction_id": registration_transaction_id,
            "worker_id": worker_id,
            "instance_id": instance_id,
            "bootstrap_credential_id": bootstrap_credential_id,
            "handoff_state": row["state"],
            "handoff_expires_at": row["expires_at"],
            "bootstrap_state": "revoked",
            "bootstrap_expires_at": row["bootstrap_expires_at"],
            "secret_file_name": row["secret_file_name"],
            "artifact_cleanup_required_audited": (
                artifact_audits["cleanup_required_audit_id"] is not None
            ),
            "artifact_sanitized_audited": (
                artifact_audits["sanitized_audit_id"] is not None
            ),
            "artifact_deleted_audited": (
                artifact_audits["deleted_audit_id"] is not None
            ),
            "sanitized_device": artifact_audits["sanitized_device"],
            "sanitized_inode": artifact_audits["sanitized_inode"],
        }
    if row["state"] != "pending":
        raise ValueError("handoff is not pending")
    if row["consumed_at"] is not None:
        raise ValueError("handoff is already consumed")
    if row["retrieved_at"] is not None:
        raise ValueError("handoff was already retrieved")
    if handoff_expiry > checked_at:
        raise ValueError("handoff is not expired")
    if row["bootstrap_consumed_at"] is not None:
        raise ValueError("bootstrap credential is already consumed")
    if row["bootstrap_revoked_at"] is not None:
        raise ValueError("bootstrap credential is already revoked")
    if bootstrap_expiry > checked_at:
        raise ValueError("bootstrap credential is not expired")
    existing_lifecycle_audits = connection.execute(
        "SELECT count(*) FROM worker_audit_log "
        "WHERE event_type IN "
        "('registration_v2_handoff_operator_expired',"
        "'bootstrap_credential_operator_revoked') "
        "AND (reason_code=? OR reason_code=?)",
        (registration_transaction_id, bootstrap_credential_id),
    ).fetchone()[0]
    if existing_lifecycle_audits:
        raise ValueError("pending handoff has operator lifecycle audit")
    if any(value is not None for value in artifact_audits.values()):
        raise ValueError("pending handoff has artifact lifecycle audit")
    return {
        "eligible": True,
        "idempotent": False,
        "checked_at": _utc_text(checked_at),
        "registration_transaction_id": registration_transaction_id,
        "worker_id": worker_id,
        "instance_id": instance_id,
        "bootstrap_credential_id": bootstrap_credential_id,
        "handoff_state": row["state"],
        "handoff_expires_at": row["expires_at"],
        "bootstrap_state": "expired",
        "bootstrap_expires_at": row["bootstrap_expires_at"],
        "secret_file_name": row["secret_file_name"],
        "artifact_cleanup_required_audited": False,
        "artifact_sanitized_audited": False,
        "artifact_deleted_audited": False,
        "sanitized_device": None,
        "sanitized_inode": None,
    }


def _existing_audit_ids(
    connection: sqlite3.Connection,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
) -> list[int]:
    row = connection.execute(
        "SELECT h.worker_id,h.instance_id,b.revoked_at "
        "FROM worker_registration_handoffs_v2 h "
        "JOIN worker_credentials b ON b.credential_id="
        "h.bootstrap_credential_id "
        "WHERE h.registration_transaction_id=? "
        "AND h.bootstrap_credential_id=?",
        (registration_transaction_id, bootstrap_credential_id),
    ).fetchone()
    if row is None:
        raise ValueError("terminal handoff target changed")
    return _verified_lifecycle_audit_ids(
        connection,
        worker_id=row["worker_id"],
        instance_id=row["instance_id"],
        registration_transaction_id=registration_transaction_id,
        bootstrap_credential_id=bootstrap_credential_id,
        revoked_at=row["revoked_at"],
    )


def _record_artifact_deleted(
    store: WorkerControlPlaneStore,
    *,
    occurred_at: str,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
    test_hook: LifecycleHook | None,
) -> int:
    with store.transaction() as connection:
        row = connection.execute(
            "SELECT h.state,b.revoked_at FROM "
            "worker_registration_handoffs_v2 h "
            "JOIN worker_credentials b ON b.credential_id="
            "h.bootstrap_credential_id "
            "WHERE h.registration_transaction_id=? "
            "AND h.worker_id=? AND h.instance_id=? "
            "AND h.bootstrap_credential_id=?",
            (
                registration_transaction_id,
                worker_id,
                instance_id,
                bootstrap_credential_id,
            ),
        ).fetchone()
        if row is None or row["state"] != "expired" or row["revoked_at"] is None:
            raise ValueError("terminal handoff state changed before artifact audit")
        artifact_audits = _verified_artifact_audit_state(
            connection,
            worker_id=worker_id,
            instance_id=instance_id,
            registration_transaction_id=registration_transaction_id,
            bootstrap_credential_id=bootstrap_credential_id,
        )
        if artifact_audits["deleted_audit_id"] is not None:
            return int(artifact_audits["deleted_audit_id"])
        if test_hook is not None:
            test_hook("before_artifact_audit")
        return _audit(
            connection,
            occurred_at=occurred_at,
            event_type="registration_v2_handoff_artifact_deleted",
            worker_id=worker_id,
            instance_id=instance_id,
            outcome="deleted",
            reason_code=registration_transaction_id,
            details={
                "bootstrap_credential_id": bootstrap_credential_id,
                "artifact": "removed",
            },
        )


def _record_artifact_sanitized(
    store: WorkerControlPlaneStore,
    *,
    occurred_at: str,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
    device: int,
    inode: int,
) -> int:
    with store.transaction() as connection:
        artifact_audits = _verified_artifact_audit_state(
            connection,
            worker_id=worker_id,
            instance_id=instance_id,
            registration_transaction_id=registration_transaction_id,
            bootstrap_credential_id=bootstrap_credential_id,
        )
        if artifact_audits["sanitized_audit_id"] is not None:
            if (
                artifact_audits["sanitized_device"] != device
                or artifact_audits["sanitized_inode"] != inode
            ):
                raise ValueError(
                    "sanitized artifact identity is ambiguous"
                )
            return int(artifact_audits["sanitized_audit_id"])
        return _audit(
            connection,
            occurred_at=occurred_at,
            event_type="registration_v2_handoff_artifact_sanitized",
            worker_id=worker_id,
            instance_id=instance_id,
            outcome="sanitized",
            reason_code=registration_transaction_id,
            details={
                "bootstrap_credential_id": bootstrap_credential_id,
                "device": device,
                "inode": inode,
                "state": "sanitized",
            },
        )


def _record_artifact_cleanup_required(
    store: WorkerControlPlaneStore,
    *,
    occurred_at: str,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
    safe_reason: str,
) -> int:
    with store.transaction() as connection:
        row = connection.execute(
            "SELECT h.state,b.revoked_at FROM "
            "worker_registration_handoffs_v2 h "
            "JOIN worker_credentials b ON b.credential_id="
            "h.bootstrap_credential_id "
            "WHERE h.registration_transaction_id=? "
            "AND h.worker_id=? AND h.instance_id=? "
            "AND h.bootstrap_credential_id=?",
            (
                registration_transaction_id,
                worker_id,
                instance_id,
                bootstrap_credential_id,
            ),
        ).fetchone()
        if row is None or row["state"] != "expired" or row["revoked_at"] is None:
            raise ValueError(
                "terminal handoff state changed before cleanup audit"
            )
        artifact_audits = _verified_artifact_audit_state(
            connection,
            worker_id=worker_id,
            instance_id=instance_id,
            registration_transaction_id=registration_transaction_id,
            bootstrap_credential_id=bootstrap_credential_id,
        )
        if artifact_audits["cleanup_required_audit_id"] is not None:
            return int(artifact_audits["cleanup_required_audit_id"])
        return _audit(
            connection,
            occurred_at=occurred_at,
            event_type=(
                "registration_v2_handoff_artifact_cleanup_required"
            ),
            worker_id=worker_id,
            instance_id=instance_id,
            outcome="cleanup_required",
            reason_code=registration_transaction_id,
            details={
                "bootstrap_credential_id": bootstrap_credential_id,
                "safe_reason": safe_reason,
            },
        )


def expire_expired_orphan_handoff(
    settings,
    *,
    worker_id: str,
    instance_id: str,
    registration_transaction_id: str,
    bootstrap_credential_id: str,
    prepare_artifact: ArtifactPreparation,
    clock: Callable[[], datetime] | None = None,
    test_hook: LifecycleHook | None = None,
) -> dict[str, object]:
    """Atomically terminalize an exact orphan, then delete its artifact."""
    checked_at = _utc_now(clock)
    occurred_at = _utc_text(checked_at)
    store = WorkerControlPlaneStore(settings)
    rollback_artifact: Callable[[], None] | None = None
    sanitize_artifact: Callable[[], dict[str, object]] | None = None
    finalize_artifact: Callable[[], dict[str, object]] | None = None
    artifact_evidence: dict[str, object] = {}
    audit_ids: list[int] = []
    idempotent = False
    try:
        try:
            with store.transaction() as connection:
                evidence = inspect_expired_orphan_handoff(
                    connection,
                    worker_id=worker_id,
                    instance_id=instance_id,
                    registration_transaction_id=registration_transaction_id,
                    bootstrap_credential_id=bootstrap_credential_id,
                    now=checked_at,
                )
                idempotent = bool(evidence["idempotent"])
                (
                    rollback_artifact,
                    sanitize_artifact,
                    finalize_artifact,
                    artifact_evidence,
                ) = prepare_artifact(
                    str(evidence["secret_file_name"]),
                    idempotent,
                    bool(evidence["artifact_sanitized_audited"]),
                    evidence["sanitized_device"],
                    evidence["sanitized_inode"],
                )
                if not idempotent:
                    if test_hook is not None:
                        test_hook("before_handoff_update")
                    changed = connection.execute(
                        "UPDATE worker_registration_handoffs_v2 "
                        "SET state='expired' "
                        "WHERE registration_transaction_id=? "
                        "AND worker_id=? AND instance_id=? "
                        "AND bootstrap_credential_id=? "
                        "AND state='pending' AND consumed_at IS NULL",
                        (
                            registration_transaction_id,
                            worker_id,
                            instance_id,
                            bootstrap_credential_id,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise ValueError("handoff changed during expiration")
                    if test_hook is not None:
                        test_hook("after_handoff_update")
                    changed = connection.execute(
                        "UPDATE worker_credentials SET revoked_at=? "
                        "WHERE credential_id=? AND worker_id=? "
                        "AND kind='bootstrap' AND revoked_at IS NULL "
                        "AND consumed_at IS NULL",
                        (
                            occurred_at,
                            bootstrap_credential_id,
                            worker_id,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise ValueError(
                            "bootstrap credential changed during revocation"
                        )
                    if test_hook is not None:
                        test_hook("after_bootstrap_update")
                        test_hook("before_lifecycle_audit")
                    audit_ids.append(
                        _audit(
                            connection,
                            occurred_at=occurred_at,
                            event_type=(
                                "registration_v2_handoff_operator_expired"
                            ),
                            worker_id=worker_id,
                            instance_id=instance_id,
                            outcome="expired",
                            reason_code=registration_transaction_id,
                            details={
                                "bootstrap_credential_id": (
                                    bootstrap_credential_id
                                ),
                                "state": "expired",
                            },
                        )
                    )
                    audit_ids.append(
                        _audit(
                            connection,
                            occurred_at=occurred_at,
                            event_type=(
                                "bootstrap_credential_operator_revoked"
                            ),
                            worker_id=worker_id,
                            instance_id=instance_id,
                            outcome="revoked",
                            reason_code=bootstrap_credential_id,
                            details={
                                "registration_transaction_id": (
                                    registration_transaction_id
                                ),
                                "state": "revoked",
                            },
                        )
                    )
                else:
                    audit_ids = _existing_audit_ids(
                        connection,
                        registration_transaction_id,
                        bootstrap_credential_id,
                    )
        except Exception:
            if rollback_artifact is not None:
                rollback_artifact()
            raise

        if sanitize_artifact is None or finalize_artifact is None:
            raise RuntimeError("artifact cleanup callbacks were not prepared")
        try:
            sanitized_result = sanitize_artifact()
            sanitized_audit_id = _record_artifact_sanitized(
                store,
                occurred_at=occurred_at,
                worker_id=worker_id,
                instance_id=instance_id,
                registration_transaction_id=registration_transaction_id,
                bootstrap_credential_id=bootstrap_credential_id,
                device=int(sanitized_result["device"]),
                inode=int(sanitized_result["inode"]),
            )
            if sanitized_audit_id not in audit_ids:
                audit_ids.append(sanitized_audit_id)
        except Exception as exc:
            cleanup_audit_id = None
            try:
                cleanup_audit_id = _record_artifact_cleanup_required(
                    store,
                    occurred_at=occurred_at,
                    worker_id=worker_id,
                    instance_id=instance_id,
                    registration_transaction_id=(
                        registration_transaction_id
                    ),
                    bootstrap_credential_id=bootstrap_credential_id,
                    safe_reason=type(exc).__name__,
                )
            except Exception:
                pass
            return {
                "status": "cleanup_required",
                "eligible": True,
                "idempotent": idempotent,
                "registration_transaction_id": (
                    registration_transaction_id
                ),
                "worker_id": worker_id,
                "instance_id": instance_id,
                "bootstrap_credential_id": bootstrap_credential_id,
                "handoff_state": "expired",
                "bootstrap_state": "revoked",
                "artifact_cleanup": False,
                "artifact_sanitized": False,
                "artifact_cleanup_audit_complete": (
                    cleanup_audit_id is not None
                ),
                "artifact": artifact_evidence,
                "audit_ids": (
                    audit_ids
                    if cleanup_audit_id is None
                    else [*audit_ids, cleanup_audit_id]
                ),
                "safe_reason": type(exc).__name__,
            }
        try:
            artifact_result = finalize_artifact()
        except Exception as exc:
            cleanup_audit_id = None
            try:
                cleanup_audit_id = _record_artifact_cleanup_required(
                    store,
                    occurred_at=occurred_at,
                    worker_id=worker_id,
                    instance_id=instance_id,
                    registration_transaction_id=(
                        registration_transaction_id
                    ),
                    bootstrap_credential_id=bootstrap_credential_id,
                    safe_reason=type(exc).__name__,
                )
            except Exception:
                pass
            return {
                "status": "cleanup_required",
                "eligible": True,
                "idempotent": idempotent,
                "registration_transaction_id": registration_transaction_id,
                "worker_id": worker_id,
                "instance_id": instance_id,
                "bootstrap_credential_id": bootstrap_credential_id,
                "handoff_state": "expired",
                "bootstrap_state": "revoked",
                "artifact_cleanup": False,
                "artifact_sanitized": True,
                "artifact_cleanup_audit_complete": (
                    cleanup_audit_id is not None
                ),
                "artifact": artifact_evidence,
                "audit_ids": (
                    audit_ids
                    if cleanup_audit_id is None
                    else [*audit_ids, cleanup_audit_id]
                ),
                "safe_reason": type(exc).__name__,
            }
        try:
            artifact_audit_id = _record_artifact_deleted(
                store,
                occurred_at=occurred_at,
                worker_id=worker_id,
                instance_id=instance_id,
                registration_transaction_id=registration_transaction_id,
                bootstrap_credential_id=bootstrap_credential_id,
                test_hook=test_hook,
            )
        except Exception as exc:
            return {
                "status": "cleanup_required",
                "eligible": True,
                "idempotent": idempotent,
                "registration_transaction_id": (
                    registration_transaction_id
                ),
                "worker_id": worker_id,
                "instance_id": instance_id,
                "bootstrap_credential_id": bootstrap_credential_id,
                "handoff_state": "expired",
                "bootstrap_state": "revoked",
                "artifact_cleanup": True,
                "artifact_audit_complete": False,
                "artifact": artifact_evidence,
                "audit_ids": audit_ids,
                "safe_reason": type(exc).__name__,
            }
        return {
            "status": "completed",
            "eligible": True,
            "idempotent": idempotent,
            "registration_transaction_id": registration_transaction_id,
            "worker_id": worker_id,
            "instance_id": instance_id,
            "bootstrap_credential_id": bootstrap_credential_id,
            "handoff_state": "expired",
            "bootstrap_state": "revoked",
            "artifact_cleanup": bool(artifact_result.get("deleted", True)),
            "artifact_sanitized": True,
            "artifact_audit_complete": True,
            "artifact": artifact_evidence,
            "audit_ids": [*audit_ids, artifact_audit_id],
        }
    finally:
        store.close()
