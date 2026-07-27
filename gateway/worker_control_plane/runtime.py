"""Loopback-only local pilot runtime and local administration commands."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import signal
import stat
import sys
import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Final

from aiohttp import web

from .app import create_worker_control_plane_app
from .config import PILOT_DATA_DIRECTORY, WorkerControlPlaneSettings
from .models import (
    CODEX_EXECUTE_MODE,
    CODEX_EXECUTE_PATH_ID,
    CODEX_EXECUTE_WORKER_ID,
    KNOWN_CAPABILITIES,
)
from .service import WorkerControlPlaneService


_LOOPBACK_ADDRESS: Final = "127.0.0.1"
DEFAULT_PORT = 8765
CREDENTIAL_FILE_NAME = "bootstrap-secret"


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
