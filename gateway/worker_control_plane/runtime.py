"""Loopback-only local pilot runtime and local administration commands."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import os
import secrets
import signal
import sqlite3
import stat
import sys
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Final

from aiohttp import web

from .app import create_worker_control_plane_app
from .auth import verify_bootstrap
from .config import PILOT_DATA_DIRECTORY, WorkerControlPlaneSettings
from .models import (
    CODEX_EXECUTE_MODE,
    CODEX_EXECUTE_PATH_ID,
    CODEX_EXECUTE_WORKER_ID,
    KNOWN_CAPABILITIES,
)
from .service import WorkerControlPlaneService
from .registration_v2 import (
    APPROVED_HEAD,
    BRANCH,
    CAPABILITIES as REGISTRATION_V2_CAPABILITIES,
    HOST,
    PATH_DIGEST,
    PATH_ID,
    REMOTE,
    WORKER_ID,
)


_LOOPBACK_ADDRESS: Final = "127.0.0.1"
DEFAULT_PORT = 8765
CREDENTIAL_FILE_NAME = "bootstrap-secret"
LEGACY_CREDENTIAL_FILE_NAMES = frozenset(
    {"bootstrap.secret", "bootstrap-secret"}
)
HANDOFF_ROUTE = "/worker-control-plane/v2/registration/bootstrap"


def _validate_secure_directory_chain(path: Path, *, owner_from: Path) -> None:
    """Validate existing path components without following symbolic links."""
    candidate = Path(path)
    owner_boundary = Path(owner_from)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("pilot directory traversal is not allowed")
    current = Path(candidate.anchor)
    owner_required = False
    for part in candidate.parts[1:]:
        current /= part
        if current == owner_boundary:
            owner_required = True
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if current == candidate:
                return
            raise ValueError("pilot directory ancestor is missing") from None
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("pilot directory symbolic link is forbidden")
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("pilot directory ancestor must be a directory")
        if owner_required:
            if info.st_uid != os.getuid():
                raise ValueError("pilot directory has the wrong owner")
            if stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError("pilot directory has unsafe permissions")


def _create_verified_directory(path: Path, *, owner_from: Path) -> Path:
    _validate_secure_directory_chain(path, owner_from=owner_from)
    if not path.exists():
        parent_flags = os.O_RDONLY | os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            parent_flags |= os.O_NOFOLLOW
        parent_fd = os.open(path.parent, parent_flags)
        try:
            os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    _validate_secure_directory_chain(path, owner_from=owner_from)
    info = os.lstat(path)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("pilot directory must be owner-only")
    return path


def ensure_pilot_directory() -> Path:
    return _create_verified_directory(
        PILOT_DATA_DIRECTORY, owner_from=Path("/home/boonl")
    )


def pilot_settings(**overrides) -> WorkerControlPlaneSettings:
    ensure_pilot_directory()
    return WorkerControlPlaneSettings.for_pilot(**overrides)


def pilot_test_settings(
    data_dir: Path, **overrides
) -> WorkerControlPlaneSettings:
    """Dedicated temporary pilot factory used only by automated tests."""
    raw = Path(data_dir)
    if not raw.is_absolute() or ".." in raw.parts or ".hermes" in raw.parts:
        raise ValueError("temporary pilot path is not isolated")
    root = _create_verified_directory(raw, owner_from=raw.parent)
    return WorkerControlPlaneSettings.for_test_pilot(root, **overrides)


def _open_verified_root(settings: WorkerControlPlaneSettings) -> int:
    root = settings.approved_test_root
    owner_from = root.parent if settings.test_pilot_mode else Path("/home/boonl")
    _validate_secure_directory_chain(root, owner_from=owner_from)
    flags = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(root, flags)
    opened = os.fstat(descriptor)
    current = os.lstat(root)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or opened.st_uid != os.getuid()
        or stat.S_IMODE(opened.st_mode) != 0o700
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        os.close(descriptor)
        raise ValueError("pilot root changed after validation")
    return descriptor


def _verify_root_identity(root_fd: int, root: Path) -> None:
    opened = os.fstat(root_fd)
    try:
        current = os.lstat(root)
    except FileNotFoundError:
        raise ValueError("pilot root changed during provisioning") from None
    if (
        stat.S_ISLNK(current.st_mode)
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        raise ValueError("pilot root changed during provisioning")


def _credential_destination_exists(
    root_fd: int, name: str = CREDENTIAL_FILE_NAME
) -> bool:
    try:
        info = os.stat(
            name, dir_fd=root_fd, follow_symlinks=False
        )
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise ValueError("credential destination is unsafe")
    return True


def _stage_owner_only_secret(root_fd: int, name: str, secret: str) -> str:
    temporary = f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ValueError("temporary credential file is unsafe")
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(secret)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return temporary


def _install_staged_secret(
    root_fd: int, root: Path, name: str, temporary: str
):
    _verify_root_identity(root_fd, root)
    if _credential_destination_exists(root_fd, name):
        raise ValueError("credential destination changed during provisioning")
    try:
        os.replace(
            temporary,
            name,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        final_fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        try:
            info = os.fstat(final_fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise ValueError("installed credential file is unsafe")
        finally:
            os.close(final_fd)
        os.fsync(root_fd)
    except Exception:
        try:
            os.unlink(name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        raise

    def rollback() -> None:
        try:
            os.unlink(name, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.fsync(root_fd)

    def finalize() -> None:
        return None

    return rollback, finalize


def _credential_output_name(
    settings: WorkerControlPlaneSettings, output_path: Path
) -> str:
    raw = Path(output_path)
    if not raw.is_absolute() or ".." in raw.parts:
        raise ValueError("credential output must be an absolute confined path")
    try:
        parent = raw.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError("credential output parent is unavailable") from None
    if (
        parent != settings.approved_test_root
        or raw != parent / raw.name
        or not raw.name
        or raw.name == settings.db_path.name
    ):
        raise ValueError("credential output must be a direct pilot-root file")
    return raw.name


def provision_local_worker(
    settings: WorkerControlPlaneSettings,
    output_path: Path,
    *,
    ttl_seconds: int = 900,
    capabilities: list[str] | None = None,
) -> dict:
    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
        raise ValueError("bootstrap TTL must be between 1 and 900 seconds")
    name = _credential_output_name(settings, Path(output_path))
    root_fd = _open_verified_root(settings)
    temporary = None
    try:
        if _credential_destination_exists(root_fd, name):
            raise ValueError("credential destination already exists")
        secret = secrets.token_urlsafe(32)
        secret_bytes = secret.encode("utf-8")
        temporary = _stage_owner_only_secret(root_fd, name, secret)
        service = WorkerControlPlaneService(settings)
        try:
            provisioned = service.provision_worker(
                secret=secret,
                ttl_seconds=ttl_seconds,
                single_use=True,
                capabilities=capabilities,
                install_credential=lambda: _install_staged_secret(
                    root_fd, settings.approved_test_root, name, temporary
                ),
            )
            temporary = None
        finally:
            service.close()
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        os.close(root_fd)
    return {
        "credential_id": provisioned["credential_id"],
        "expires_at": provisioned["expires_at"],
        "single_use": provisioned["single_use"],
        "capabilities": provisioned["capabilities"],
        "transfer_file_sha256": hashlib.sha256(secret_bytes).hexdigest(),
    }


def _canonical_uuid(value: str, field: str) -> str:
    try:
        canonical = str(uuid.UUID(value))
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be a canonical UUID") from None
    if value != canonical:
        raise ValueError(f"{field} must be a canonical UUID")
    return canonical


def _tailnet_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("expected source must be a Tailnet IPv4 address") from None
    if (
        address.version != 4
        or address not in ipaddress.ip_network("100.64.0.0/10")
    ):
        raise ValueError("expected source must be a Tailnet IPv4 address")
    return address.compressed


def provision_registration_v2_handoff(
    settings: WorkerControlPlaneSettings,
    *,
    instance_id: str,
    registration_transaction_id: str,
    expected_source_ip: str,
    ttl_seconds: int = 900,
) -> dict:
    instance_id = _canonical_uuid(instance_id, "instance_id")
    registration_transaction_id = _canonical_uuid(
        registration_transaction_id, "registration_transaction_id"
    )
    expected_source_ip = _tailnet_ipv4(expected_source_ip)
    file_name = (
        f".registration-v2-handoff-{registration_transaction_id}.secret"
    )
    root_fd = _open_verified_root(settings)
    temporary = None
    try:
        if _credential_destination_exists(root_fd, file_name):
            raise ValueError("handoff destination already exists")
        secret = secrets.token_urlsafe(32)
        temporary = _stage_owner_only_secret(root_fd, file_name, secret)
        service = WorkerControlPlaneService(settings)
        try:
            provisioned = service.provision_worker(
                secret=secret,
                ttl_seconds=ttl_seconds,
                single_use=True,
                capabilities=list(REGISTRATION_V2_CAPABILITIES),
                handoff={
                    "registration_transaction_id": (
                        registration_transaction_id
                    ),
                    "instance_id": instance_id,
                    "secret_file_name": file_name,
                    "expected_source_ip": expected_source_ip,
                },
                install_credential=lambda: _install_staged_secret(
                    root_fd,
                    settings.approved_test_root,
                    file_name,
                    temporary,
                ),
            )
            temporary = None
        finally:
            service.close()
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        os.close(root_fd)
    return {
        "registration_transaction_id": registration_transaction_id,
        "worker_id": WORKER_ID,
        "instance_id": instance_id,
        "credential_id": provisioned["credential_id"],
        "issued_at": provisioned["issued_at"],
        "expires_at": provisioned["expires_at"],
        "capabilities": list(REGISTRATION_V2_CAPABILITIES),
        "target_identity": {
            "host": HOST,
            "path_id": PATH_ID,
            "path_digest": PATH_DIGEST,
            "remote": REMOTE,
            "branch": BRANCH,
            "approved_head": APPROVED_HEAD,
        },
        "expected_source_ip": expected_source_ip,
        "handoff_route": HANDOFF_ROUTE,
        "single_use": True,
    }


def _read_only_connection(settings: WorkerControlPlaneSettings):
    connection = sqlite3.connect(
        f"file:{settings.db_path}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def commissioning_postcheck(
    settings: WorkerControlPlaneSettings,
    *,
    registration_transaction_id: str,
    task_id: str | None = None,
) -> dict:
    registration_transaction_id = _canonical_uuid(
        registration_transaction_id, "registration_transaction_id"
    )
    if task_id is not None:
        task_id = _canonical_uuid(task_id, "task_id")
    connection = _read_only_connection(settings)
    try:
        before = connection.total_changes
        transaction = connection.execute(
            "SELECT t.registration_transaction_id,t.state,t.worker_id,"
            "t.instance_id,t.registration_id,t.credential_id,t.host,"
            "t.path_id,t.path_digest,t.remote,t.branch,t.approved_head,"
            "t.capabilities_json,t.expires_at,t.confirmed_at,"
            "t.bootstrap_credential_id,h.state AS handoff_state,"
            "h.retrieved_at,b.consumed_at AS bootstrap_consumed_at,"
            "b.revoked_at AS bootstrap_revoked_at,i.status AS instance_state "
            "FROM worker_registration_transactions_v2 t "
            "LEFT JOIN worker_registration_handoffs_v2 h USING("
            "registration_transaction_id) "
            "JOIN worker_credentials b ON b.credential_id="
            "t.bootstrap_credential_id "
            "JOIN worker_instances i ON i.registration_id=t.registration_id "
            "WHERE t.registration_transaction_id=?",
            (registration_transaction_id,),
        ).fetchone()
        handoff = connection.execute(
            "SELECT registration_transaction_id,state,worker_id,instance_id,"
            "bootstrap_credential_id,expected_source_ip,host,path_id,"
            "path_digest,remote,branch,approved_head,capabilities_json,"
            "issued_at,expires_at,retrieved_at "
            "FROM worker_registration_handoffs_v2 "
            "WHERE registration_transaction_id=?",
            (registration_transaction_id,),
        ).fetchone()
        task = None
        if task_id is not None:
            task_row = connection.execute(
                "SELECT task_id,task_type,state,attempt,max_attempts,worker_id "
                "FROM worker_tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if task_row is not None:
                delivery_count = connection.execute(
                    "SELECT count(*) FROM worker_deliveries WHERE task_id=?",
                    (task_id,),
                ).fetchone()[0]
                ack_count = connection.execute(
                    "SELECT count(*) FROM worker_deliveries WHERE task_id=? "
                    "AND acknowledged_at IS NOT NULL",
                    (task_id,),
                ).fetchone()[0]
                result_count = connection.execute(
                    "SELECT count(*) FROM worker_results WHERE task_id=?",
                    (task_id,),
                ).fetchone()[0]
                task_events = [
                    row[0]
                    for row in connection.execute(
                        "SELECT event_type FROM worker_audit_log "
                        "WHERE task_id=? ORDER BY audit_id",
                        (task_id,),
                    )
                ]
                task = {
                    "task_id": task_row["task_id"],
                    "type": task_row["task_type"],
                    "state": task_row["state"],
                    "poll_deliveries": delivery_count,
                    "ack_count": ack_count,
                    "result_count": result_count,
                    "retry_count": max(0, delivery_count - 1),
                    "duplicate_count": max(0, result_count - 1),
                    "audit_events": task_events,
                }
        pending_tasks = connection.execute(
            "SELECT count(*) FROM worker_tasks WHERE state IN "
            "('queued','leased','running')"
        ).fetchone()[0]
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        foreign_key_errors = len(
            connection.execute("PRAGMA foreign_key_check").fetchall()
        )
        audit_rows = connection.execute(
            "SELECT event_type,details_json FROM worker_audit_log "
            "WHERE details_json IS NOT NULL"
        ).fetchall()
        forbidden = ("bootstrap_secret", "access_token", "authorization")
        redaction_ok = all(
            not any(
                marker in (row["details_json"] or "").lower()
                for marker in forbidden
            )
            for row in audit_rows
        )
        if connection.total_changes != before:
            raise RuntimeError("read-only postcheck attempted a database write")
        return {
            "registration": (
                None
                if transaction is None
                else {
                    key: (
                        json.loads(transaction[key])
                        if key == "capabilities_json"
                        else transaction[key]
                    )
                    for key in transaction.keys()
                }
            ),
            "handoff": (
                None
                if handoff is None
                else {
                    key: (
                        json.loads(handoff[key])
                        if key == "capabilities_json"
                        else handoff[key]
                    )
                    for key in handoff.keys()
                }
            ),
            "task": task,
            "integrity": {
                "quick_check": quick_check,
                "foreign_key_errors": foreign_key_errors,
                "pending_tasks": pending_tasks,
                "audit_secret_redaction": redaction_ok,
            },
            "db_writes": 0,
        }
    finally:
        connection.close()


def _process_has_open_inode(device: int, inode: int) -> bool:
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        if process.name == str(os.getpid()):
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
        except FileNotFoundError:
            continue
        directory = process / "fd"
        try:
            descriptors = list(directory.iterdir())
        except FileNotFoundError:
            continue
        except PermissionError:
            continue
        for descriptor in descriptors:
            try:
                info = descriptor.stat()
            except (FileNotFoundError, PermissionError):
                continue
            if (info.st_dev, info.st_ino) == (device, inode):
                return True
    return False


def inspect_legacy_bootstrap_artifact(
    settings: WorkerControlPlaneSettings, file_name: str
) -> dict:
    if file_name not in LEGACY_CREDENTIAL_FILE_NAMES:
        raise ValueError("legacy artifact name is not allowlisted")
    root_fd = _open_verified_root(settings)
    descriptor = -1
    try:
        descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        opened = os.fstat(descriptor)
        current = os.stat(file_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (current.st_dev, current.st_ino)
            or opened.st_size > 128
        ):
            raise ValueError("legacy artifact identity is unsafe")
        secret = os.read(descriptor, 129).decode("ascii")
        if not secret or len(secret.encode("ascii")) > 128:
            raise ValueError("legacy artifact is malformed")
        connection = _read_only_connection(settings)
        try:
            matches = []
            for row in connection.execute(
                "SELECT credential_id,salt,token_hash,expires_at,revoked_at,"
                "consumed_at,lifecycle_version FROM worker_credentials "
                "WHERE kind='bootstrap'"
            ):
                try:
                    if verify_bootstrap(
                        secret, row["salt"], row["token_hash"]
                    ):
                        matches.append(row)
                except (TypeError, ValueError):
                    continue
            if not matches:
                raise ValueError("legacy artifact origin is ambiguous")
            active = []
            now = datetime.now().astimezone()
            for row in matches:
                try:
                    expiry = datetime.fromisoformat(
                        row["expires_at"].replace("Z", "+00:00")
                    )
                except (AttributeError, ValueError):
                    expiry = None
                if (
                    row["lifecycle_version"] == 3
                    and row["revoked_at"] is None
                    and row["consumed_at"] is None
                    and expiry is not None
                    and expiry.tzinfo is not None
                    and expiry > now
                ):
                    active.append(row["credential_id"])
            referenced = connection.execute(
                "SELECT count(*) FROM worker_registration_transactions_v2 "
                "WHERE bootstrap_credential_id IN (%s) AND state IN "
                "('issued_pending_confirmation','confirmed')"
                % ",".join("?" for _ in matches),
                tuple(row["credential_id"] for row in matches),
            ).fetchone()[0]
        finally:
            connection.close()
        if active or referenced or _process_has_open_inode(
            opened.st_dev, opened.st_ino
        ):
            raise ValueError("legacy artifact is active or referenced")
        return {
            "file_name": file_name,
            "owner_uid": opened.st_uid,
            "mode": f"{stat.S_IMODE(opened.st_mode):04o}",
            "link_count": opened.st_nlink,
            "device": opened.st_dev,
            "inode": opened.st_ino,
            "matched_credential_ids": [
                row["credential_id"] for row in matches
            ],
            "orphan_verified": True,
        }
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(root_fd)


def delete_verified_legacy_bootstrap_artifact(
    settings: WorkerControlPlaneSettings, file_name: str
) -> dict:
    evidence = inspect_legacy_bootstrap_artifact(settings, file_name)
    root_fd = _open_verified_root(settings)
    connection = sqlite3.connect(settings.db_path)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN IMMEDIATE")
        current = os.stat(file_name, dir_fd=root_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (
            evidence["device"],
            evidence["inode"],
        ):
            raise ValueError("legacy artifact identity changed")
        connection.execute(
            "INSERT INTO worker_audit_log("
            "occurred_at,event_type,worker_id,instance_id,registration_id,"
            "task_id,delivery_id,trace_id,outcome,reason_code,details_json"
            ") VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                datetime.now().astimezone().isoformat(),
                "legacy_bootstrap_artifact_deleted",
                WORKER_ID,
                None,
                None,
                None,
                None,
                None,
                "deleted",
                "verified_orphan",
                json.dumps(
                    {"file_name": file_name},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            ),
        )
        os.unlink(file_name, dir_fd=root_fd)
        os.fsync(root_fd)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
        os.close(root_fd)
    return {
        "file_name": file_name,
        "orphan_verified": True,
        "deleted": True,
        "audit_event": "legacy_bootstrap_artifact_deleted",
    }


def list_bootstrap_credentials(
    settings: WorkerControlPlaneSettings, worker_id: str
) -> list[dict]:
    service = WorkerControlPlaneService(settings)
    try:
        return service.list_bootstrap_credentials(worker_id)
    finally:
        service.close()


def revoke_bootstrap_credential(
    settings: WorkerControlPlaneSettings, worker_id: str, credential_id: str
) -> dict:
    service = WorkerControlPlaneService(settings)
    try:
        return service.revoke_bootstrap_credential(worker_id, credential_id)
    finally:
        service.close()


def list_registrations(
    settings: WorkerControlPlaneSettings, worker_id: str
) -> list[dict]:
    service = WorkerControlPlaneService(settings)
    try:
        return service.list_registrations(worker_id)
    finally:
        service.close()


def revoke_registration(
    settings: WorkerControlPlaneSettings,
    worker_id: str,
    instance_id: str,
    registration_id: str,
) -> dict:
    service = WorkerControlPlaneService(settings)
    try:
        return service.revoke_registration(
            worker_id, instance_id, registration_id
        )
    finally:
        service.close()


def enqueue_local_echo(settings: WorkerControlPlaneSettings, message: str) -> str:
    service = WorkerControlPlaneService(settings)
    try:
        return service.enqueue_system_echo(
            {"message": message}, f"pilot-enqueue-{uuid.uuid4()}"
        )
    finally:
        service.close()


def enqueue_local_codex_execute(
    settings: WorkerControlPlaneSettings,
    *,
    instruction: str,
    timeout_seconds: int,
    idempotency_key: str,
) -> str:
    payload = {
        "path_id": CODEX_EXECUTE_PATH_ID,
        "mode": CODEX_EXECUTE_MODE,
        "instruction": instruction,
        "timeout_seconds": timeout_seconds,
    }
    service = WorkerControlPlaneService(settings)
    try:
        return service.enqueue_codex_execute(
            payload, idempotency_key, CODEX_EXECUTE_WORKER_ID
        )
    finally:
        service.close()


class LocalPilotRuntime:
    """Owns one aiohttp runner bound only to the IPv4 loopback address."""

    def __init__(
        self,
        settings: WorkerControlPlaneSettings,
        port: int = DEFAULT_PORT,
        *,
        clock: Callable[[], datetime] | None = None,
    ):
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if not settings.pilot_mode or settings.test_mode:
            raise ValueError("pilot runtime requires pilot mode")
        self.settings = settings
        self.port = port
        self._clock = clock
        self.service: WorkerControlPlaneService | None = None
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    async def start(self) -> None:
        if self._runner is not None:
            raise RuntimeError("pilot runtime is already started")
        service = WorkerControlPlaneService(self.settings, clock=self._clock)
        runner = web.AppRunner(
            create_worker_control_plane_app(self.settings, service),
            access_log=None,
        )
        site = None
        try:
            await runner.setup()
            site = web.TCPSite(
                runner, host=_LOOPBACK_ADDRESS, port=self.port
            )
            await site.start()
        except BaseException:
            try:
                await self._cleanup_resources(site, runner, service)
            except BaseException:
                pass
            raise
        self.service = service
        self._runner = runner
        self._site = site

    async def stop(self) -> None:
        site, runner, service = self._site, self._runner, self.service
        self._site = None
        self._runner = None
        self.service = None
        await self._cleanup_resources(site, runner, service)

    @staticmethod
    async def _cleanup_resources(site, runner, service) -> None:
        errors = []
        if site is not None:
            try:
                await site.stop()
            except BaseException as exc:
                errors.append(exc)
        if runner is not None:
            try:
                await runner.cleanup()
            except BaseException as exc:
                errors.append(exc)
        if service is not None:
            try:
                service.close()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise errors[0]

    @property
    def running(self) -> bool:
        return self._runner is not None

    @property
    def host(self) -> str:
        return _LOOPBACK_ADDRESS


async def _serve(settings: WorkerControlPlaneSettings, port: int) -> None:
    runtime = LocalPilotRuntime(settings, port)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    handled_signals = (signal.SIGINT, signal.SIGTERM)
    registered_signals = []
    cleanup_errors = []
    try:
        await runtime.start()
        for handled_signal in handled_signals:
            loop.add_signal_handler(handled_signal, stop.set)
            registered_signals.append(handled_signal)
        await stop.wait()
    finally:
        for handled_signal in reversed(registered_signals):
            try:
                loop.remove_signal_handler(handled_signal)
            except BaseException as exc:
                cleanup_errors.append(exc)
        try:
            await runtime.stop()
        except BaseException as exc:
            cleanup_errors.append(exc)
        if cleanup_errors and sys.exc_info()[0] is None:
            raise cleanup_errors[0]


def _port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def _bootstrap_ttl(value: str) -> int:
    try:
        ttl = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            "bootstrap TTL must be an integer"
        ) from None
    if not 1 <= ttl <= 900:
        raise argparse.ArgumentTypeError(
            "bootstrap TTL must be between 1 and 900 seconds"
        )
    return ttl


def _uuid(value: str) -> str:
    try:
        uuid.UUID(value)
    except ValueError:
        raise argparse.ArgumentTypeError("identifier must be a UUID") from None
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes local Worker Control Plane pilot")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="start the loopback-only pilot runtime")
    serve.add_argument("--port", type=_port, default=DEFAULT_PORT)
    provision = commands.add_parser(
        "provision", help="create one short-lived commissioning credential"
    )
    provision.add_argument("--output", type=Path, required=True)
    provision.add_argument("--ttl-seconds", type=_bootstrap_ttl, default=900)
    provision.add_argument(
        "--capability",
        action="append",
        choices=KNOWN_CAPABILITIES,
        dest="capabilities",
    )
    bootstrap = commands.add_parser(
        "bootstrap", help="inspect or revoke one bootstrap credential"
    )
    bootstrap_commands = bootstrap.add_subparsers(
        dest="bootstrap_command", required=True
    )
    bootstrap_list = bootstrap_commands.add_parser("list")
    bootstrap_list.add_argument(
        "--worker-id", choices=("server-a-worker",), required=True
    )
    bootstrap_revoke = bootstrap_commands.add_parser("revoke")
    bootstrap_revoke.add_argument(
        "--worker-id", choices=("server-a-worker",), required=True
    )
    bootstrap_revoke.add_argument(
        "--credential-id", type=_uuid, required=True
    )
    registration = commands.add_parser(
        "registration", help="inspect or revoke one registration"
    )
    registration_commands = registration.add_subparsers(
        dest="registration_command", required=True
    )
    registration_list = registration_commands.add_parser("list")
    registration_list.add_argument(
        "--worker-id", choices=("server-a-worker",), required=True
    )
    registration_revoke = registration_commands.add_parser("revoke")
    registration_revoke.add_argument(
        "--worker-id", choices=("server-a-worker",), required=True
    )
    registration_revoke.add_argument(
        "--instance-id", type=_uuid, required=True
    )
    registration_revoke.add_argument(
        "--registration-id", type=_uuid, required=True
    )
    commission = commands.add_parser(
        "commission", help="operate Registration v2 commissioning safely"
    )
    commission_commands = commission.add_subparsers(
        dest="commission_command", required=True
    )
    commission_provision = commission_commands.add_parser(
        "provision", help="authorize one protected Registration v2 handoff"
    )
    commission_provision.add_argument(
        "--instance-id", type=_uuid, required=True
    )
    commission_provision.add_argument(
        "--transaction-id", type=_uuid, required=True
    )
    commission_provision.add_argument(
        "--expected-source-ip", required=True
    )
    commission_provision.add_argument(
        "--ttl-seconds", type=_bootstrap_ttl, default=900
    )
    commission_status = commission_commands.add_parser(
        "status", help="read-only Registration v2 commissioning postcheck"
    )
    commission_status.add_argument(
        "--transaction-id", type=_uuid, required=True
    )
    commission_status.add_argument("--task-id", type=_uuid)
    artifact = commission_commands.add_parser(
        "legacy-artifact", help="inspect or delete one verified orphan"
    )
    artifact.add_argument(
        "action", choices=("inspect", "delete")
    )
    artifact.add_argument(
        "--name", choices=sorted(LEGACY_CREDENTIAL_FILE_NAMES), required=True
    )
    enqueue = commands.add_parser("enqueue", help="enqueue one local pilot task")
    enqueue.add_argument("task_type", choices=KNOWN_CAPABILITIES)
    enqueue.add_argument("message")
    enqueue.add_argument("--idempotency-key")
    enqueue.add_argument("--timeout-seconds", type=int, default=60)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["serve"]
    parsed = build_parser().parse_args(arguments)
    settings = pilot_settings()
    if parsed.command == "provision":
        report = provision_local_worker(
            settings,
            parsed.output,
            ttl_seconds=parsed.ttl_seconds,
            capabilities=parsed.capabilities,
        )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if parsed.command == "bootstrap":
        if parsed.bootstrap_command == "list":
            report = list_bootstrap_credentials(settings, parsed.worker_id)
        else:
            report = revoke_bootstrap_credential(
                settings, parsed.worker_id, parsed.credential_id
            )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if parsed.command == "registration":
        if parsed.registration_command == "list":
            report = list_registrations(settings, parsed.worker_id)
        else:
            report = revoke_registration(
                settings,
                parsed.worker_id,
                parsed.instance_id,
                parsed.registration_id,
            )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if parsed.command == "commission":
        if parsed.commission_command == "provision":
            report = provision_registration_v2_handoff(
                settings,
                instance_id=parsed.instance_id,
                registration_transaction_id=parsed.transaction_id,
                expected_source_ip=parsed.expected_source_ip,
                ttl_seconds=parsed.ttl_seconds,
            )
        elif parsed.commission_command == "status":
            report = commissioning_postcheck(
                settings,
                registration_transaction_id=parsed.transaction_id,
                task_id=parsed.task_id,
            )
        elif parsed.action == "inspect":
            report = inspect_legacy_bootstrap_artifact(
                settings, parsed.name
            )
        else:
            report = delete_verified_legacy_bootstrap_artifact(
                settings, parsed.name
            )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    if parsed.command == "enqueue":
        if parsed.task_type == "system.echo":
            if any(
                value is not None
                for value in (
                    parsed.idempotency_key,
                )
            ):
                build_parser().error(
                    "codex.execute options are not valid for system.echo"
                )
            task_id = enqueue_local_echo(settings, parsed.message)
        else:
            if (
                not isinstance(parsed.idempotency_key, str)
                or not parsed.idempotency_key
                or len(parsed.idempotency_key) > 128
            ):
                build_parser().error(
                    "codex.execute requires a valid idempotency key"
                )
            task_id = enqueue_local_codex_execute(
                settings,
                instruction=parsed.message,
                timeout_seconds=parsed.timeout_seconds,
                idempotency_key=parsed.idempotency_key,
            )
        print(f"Enqueued {parsed.task_type} task {task_id}")
        return 0
    try:
        asyncio.run(_serve(settings, parsed.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
