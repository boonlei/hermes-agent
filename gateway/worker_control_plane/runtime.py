"""Loopback-only local pilot runtime and local administration commands."""

from __future__ import annotations

import argparse
import asyncio
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


def _credential_destination_exists(root_fd: int) -> bool:
    try:
        info = os.stat(
            CREDENTIAL_FILE_NAME, dir_fd=root_fd, follow_symlinks=False
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


def _stage_owner_only_secret(root_fd: int, secret: str) -> str:
    temporary = f".{CREDENTIAL_FILE_NAME}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
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
            stream.write("\n")
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
    root_fd: int, root: Path, temporary: str, existed: bool
):
    _verify_root_identity(root_fd, root)
    if _credential_destination_exists(root_fd) != existed:
        raise ValueError("credential destination changed during provisioning")
    backup = f".{CREDENTIAL_FILE_NAME}.{uuid.uuid4().hex}.backup" if existed else None
    if backup is not None:
        os.replace(
            CREDENTIAL_FILE_NAME,
            backup,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
    try:
        os.replace(
            temporary,
            CREDENTIAL_FILE_NAME,
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        final_fd = os.open(
            CREDENTIAL_FILE_NAME,
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
        if backup is not None:
            os.replace(
                backup,
                CREDENTIAL_FILE_NAME,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
        else:
            try:
                os.unlink(CREDENTIAL_FILE_NAME, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        raise

    def rollback() -> None:
        if backup is not None:
            os.replace(
                backup,
                CREDENTIAL_FILE_NAME,
                src_dir_fd=root_fd,
                dst_dir_fd=root_fd,
            )
        else:
            try:
                os.unlink(CREDENTIAL_FILE_NAME, dir_fd=root_fd)
            except FileNotFoundError:
                pass
        os.fsync(root_fd)

    def finalize() -> None:
        if backup is not None:
            os.unlink(backup, dir_fd=root_fd)
            os.fsync(root_fd)

    return rollback, finalize


def provision_local_worker(
    settings: WorkerControlPlaneSettings,
) -> Path:
    root_fd = _open_verified_root(settings)
    temporary = None
    try:
        existed = _credential_destination_exists(root_fd)
        secret = secrets.token_urlsafe(32)
        temporary = _stage_owner_only_secret(root_fd, secret)
        service = WorkerControlPlaneService(settings)
        try:
            service.provision_worker(
                secret=secret,
                install_credential=lambda: _install_staged_secret(
                    root_fd, settings.approved_test_root, temporary, existed
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
    target = settings.approved_test_root / CREDENTIAL_FILE_NAME
    return target


def enqueue_local_echo(settings: WorkerControlPlaneSettings, message: str) -> str:
    service = WorkerControlPlaneService(settings)
    try:
        return service.enqueue_system_echo(
            {"message": message}, f"pilot-enqueue-{uuid.uuid4()}"
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes local Worker Control Plane pilot")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="start the loopback-only pilot runtime")
    serve.add_argument("--port", type=_port, default=DEFAULT_PORT)
    commands.add_parser("provision", help="rotate the local bootstrap credential")
    enqueue = commands.add_parser("enqueue", help="enqueue one local pilot task")
    enqueue.add_argument("task_type", choices=("system.echo",))
    enqueue.add_argument("message")
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["serve"]
    parsed = build_parser().parse_args(arguments)
    settings = pilot_settings()
    if parsed.command == "provision":
        credential = provision_local_worker(settings)
        print(f"Worker provisioned; credential stored at {credential}")
        return 0
    if parsed.command == "enqueue":
        task_id = enqueue_local_echo(settings, parsed.message)
        print(f"Enqueued {parsed.task_type} task {task_id}")
        return 0
    try:
        asyncio.run(_serve(settings, parsed.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
