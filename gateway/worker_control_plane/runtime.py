"""Loopback-only local pilot runtime and local administration commands."""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import uuid
from pathlib import Path

from aiohttp import web

from .app import create_worker_control_plane_app
from .config import WorkerControlPlaneSettings
from .service import WorkerControlPlaneService


LISTEN_ADDRESS = "127.0.0.1"
DEFAULT_PORT = 8765
PILOT_DATA_DIRECTORY = Path.home() / ".hermes" / "worker-control-plane-pilot"
CREDENTIAL_FILE_NAME = "bootstrap-secret"


def ensure_pilot_directory(data_dir: Path = PILOT_DATA_DIRECTORY) -> Path:
    path = Path(data_dir).expanduser()
    if path.is_symlink():
        raise ValueError("pilot data directory must not be a symbolic link")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise ValueError("pilot data directory must be a directory")
    os.chmod(path, 0o700)
    return path


def pilot_settings(
    data_dir: Path = PILOT_DATA_DIRECTORY, **overrides
) -> WorkerControlPlaneSettings:
    root = ensure_pilot_directory(data_dir)
    return WorkerControlPlaneSettings.for_pilot(root, **overrides)


def _write_owner_only_secret(path: Path, secret: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(secret)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def provision_local_worker(
    settings: WorkerControlPlaneSettings,
) -> Path:
    service = WorkerControlPlaneService(settings)
    try:
        secret = service.provision_worker()
    finally:
        service.close()
    target = settings.approved_test_root / CREDENTIAL_FILE_NAME
    _write_owner_only_secret(target, secret)
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

    def __init__(self, settings: WorkerControlPlaneSettings, port: int = DEFAULT_PORT):
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if not settings.pilot_mode or settings.test_mode:
            raise ValueError("pilot runtime requires pilot mode")
        self.settings = settings
        self.host = LISTEN_ADDRESS
        self.port = port
        self.service: WorkerControlPlaneService | None = None
        self._runner: web.AppRunner | None = None

    async def start(self) -> None:
        if self._runner is not None:
            raise RuntimeError("pilot runtime is already started")
        service = WorkerControlPlaneService(self.settings)
        runner = web.AppRunner(
            create_worker_control_plane_app(self.settings, service),
            access_log=None,
        )
        try:
            await runner.setup()
            await web.TCPSite(runner, host=self.host, port=self.port).start()
        except Exception:
            await runner.cleanup()
            service.close()
            raise
        self.service = service
        self._runner = runner

    async def stop(self) -> None:
        runner, service = self._runner, self.service
        self._runner = None
        self.service = None
        if runner is not None:
            await runner.cleanup()
        if service is not None:
            service.close()

    @property
    def running(self) -> bool:
        return self._runner is not None


async def _serve(settings: WorkerControlPlaneSettings, port: int) -> None:
    runtime = LocalPilotRuntime(settings, port)
    await runtime.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    handled_signals = (signal.SIGINT, signal.SIGTERM)
    for handled_signal in handled_signals:
        loop.add_signal_handler(handled_signal, stop.set)
    try:
        await stop.wait()
    finally:
        for handled_signal in handled_signals:
            loop.remove_signal_handler(handled_signal)
        await runtime.stop()


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
