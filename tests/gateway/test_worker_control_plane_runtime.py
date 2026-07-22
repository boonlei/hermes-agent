"""Real-loopback tests for the standalone local Worker Control Plane pilot."""

from __future__ import annotations

import inspect
import os
import stat
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import ClientSession
from aiohttp.test_utils import unused_port

from gateway.worker_control_plane import runtime as pilot
from gateway.worker_control_plane.config import WorkerControlPlaneSettings
from gateway.worker_control_plane.errors import WorkerControlPlaneError


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class MutableClock:
    def __init__(self):
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


def test_pilot_provisioning_uses_owner_only_files_and_safe_storage(tmp_path):
    data_dir = tmp_path / "pilot"
    settings = pilot.pilot_test_settings(data_dir)
    credential = pilot.provision_local_worker(settings)

    assert settings.pilot_mode is True
    assert settings.test_mode is False
    assert settings.db_path == data_dir.resolve() / "worker-control-plane.db"
    assert credential == data_dir.resolve() / "bootstrap-secret"
    assert _mode(data_dir) == 0o700
    assert _mode(settings.db_path) == 0o600
    assert _mode(credential) == 0o600

    secret = credential.read_text(encoding="utf-8").strip()
    assert len(secret) >= 32
    service = pilot.WorkerControlPlaneService(settings)
    try:
        assert secret not in service.audit_text()
        stored = service.store.conn.execute(
            "SELECT token_hash FROM worker_credentials WHERE kind='bootstrap' "
            "AND revoked_at IS NULL"
        ).fetchone()[0]
        assert secret != stored
    finally:
        service.close()


def test_pilot_directory_rejects_symbolic_link(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = tmp_path / "pilot"
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError):
        pilot.pilot_test_settings(linked)


def test_runtime_cli_has_configurable_port_but_no_host_option():
    parser = pilot.build_parser()
    parsed = parser.parse_args(["serve", "--port", "9876"])
    assert parsed.port == 9876
    assert pilot._LOOPBACK_ADDRESS == "127.0.0.1"
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--host", "0.0.0.0"])


@pytest.mark.asyncio
async def test_real_loopback_http_system_echo_lifecycle(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    credential = pilot.provision_local_worker(settings)
    secret = credential.read_text(encoding="utf-8").strip()
    port = unused_port()
    runtime = pilot.LocalPilotRuntime(settings, port)
    await runtime.start()
    assert runtime.running is True
    assert runtime.host == "127.0.0.1"

    worker_id = "server-a-worker"
    instance_id = str(uuid.uuid4())
    base_url = f"http://127.0.0.1:{port}"
    try:
        async with ClientSession() as client:
            response = await client.post(
                f"{base_url}/worker/v1/register",
                headers={"Authorization": f"Worker-Bootstrap {secret}"},
                json={
                    "protocol_version": "1.0",
                    "worker_id": worker_id,
                    "instance_id": instance_id,
                    "worker_name": "local pilot test",
                    "worker_version": "0.1.0",
                    "capabilities": ["system.echo"],
                },
            )
            assert response.status == 201
            registration = await response.json()
            registration_id = registration["registration_id"]
            access_token = registration["access_token"]
            headers = {"Authorization": f"Bearer {access_token}"}
            identity = {
                "worker_id": worker_id,
                "instance_id": instance_id,
                "registration_id": registration_id,
            }

            response = await client.post(
                f"{base_url}/worker/v1/heartbeat",
                headers=headers,
                json=identity
                | {
                    "status": "idle",
                    "current_task_id": None,
                    "worker_time": "2026-01-01T00:00:00Z",
                },
            )
            assert response.status == 200

            task_id = pilot.enqueue_local_echo(settings, "hello")
            response = await client.post(
                f"{base_url}/worker/v1/tasks/poll",
                headers=headers | {"Idempotency-Key": "runtime-poll"},
                json=identity
                | {
                    "capabilities": ["system.echo"],
                    "max_tasks": 1,
                    "wait_seconds": 0,
                },
            )
            assert response.status == 200
            task = (await response.json())["task"]
            assert task["task_id"] == task_id
            assert task["payload"] == {"message": "hello"}

            response = await client.post(
                f"{base_url}/worker/v1/tasks/{task_id}/ack",
                headers=headers | {"Idempotency-Key": "runtime-ack"},
                json=identity
                | {
                    "delivery_id": task["delivery_id"],
                    "accepted": True,
                    "reason": None,
                    "worker_time": "2026-01-01T00:00:00Z",
                },
            )
            assert response.status == 200

            echoed = task["payload"]["message"]
            response = await client.post(
                f"{base_url}/worker/v1/tasks/{task_id}/result",
                headers=headers | {"Idempotency-Key": "runtime-result"},
                json=identity
                | {
                    "delivery_id": task["delivery_id"],
                    "task_id": task_id,
                    "task_type": "system.echo",
                    "status": "completed",
                    "stdout": echoed,
                    "stderr": "",
                    "exit_code": 0,
                    "started_at": "2026-01-01T00:00:00Z",
                    "finished_at": "2026-01-01T00:00:00Z",
                    "duration_ms": 0,
                    "result_idempotency_key": "runtime-result-body",
                    "payload_hash": task["payload_hash"],
                    "trace_id": task["trace_id"],
                },
            )
            assert response.status == 200
            result = await response.json()
            assert result["task_state"] == "completed"
            assert runtime.service is not None
            assert runtime.service.task_state(task_id) == "completed"
            audit = runtime.service.audit_text()
            assert secret not in audit
            assert access_token not in audit
            assert "hello" not in audit
    finally:
        await runtime.stop()

    assert runtime.running is False
    assert runtime.service is None
    replacement = pilot.LocalPilotRuntime(settings, port)
    await replacement.start()
    await replacement.stop()


def test_runtime_has_no_task_executor_or_production_integration():
    source = inspect.getsource(pilot)
    for forbidden in (
        "subprocess",
        "os.system",
        "0.0.0.0",
        "gateway.run",
        "api_server",
        "SessionDB",
        "kanban.db",
        "state.db",
        "INPRO",
        "Codex",
        "LLM",
    ):
        assert forbidden not in source


def _registered_service(tmp_path, **overrides):
    clock = MutableClock()
    settings = pilot.pilot_test_settings(tmp_path / "pilot", **overrides)
    service = pilot.WorkerControlPlaneService(settings, clock=clock)
    secret = service.provision_worker()
    instance_id = str(uuid.uuid4())
    _, registration = service.register_worker(
        {
            "protocol_version": "1.0",
            "worker_id": "server-a-worker",
            "instance_id": instance_id,
            "worker_name": "security test",
            "worker_version": "0.1.0",
            "capabilities": ["system.echo"],
        },
        secret,
    )
    identity = {
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
        "registration_id": registration["registration_id"],
    }
    return service, clock, registration["access_token"], identity


def test_access_token_expires_with_injected_clock(tmp_path):
    service, clock, token, identity = _registered_service(
        tmp_path, token_ttl_seconds=2
    )
    try:
        clock.advance(2)
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.heartbeat(
                identity
                | {
                    "status": "idle",
                    "current_task_id": None,
                    "worker_time": "2026-01-01T00:00:02Z",
                },
                token,
            )
        assert exc.value.code == "invalid_credential"
    finally:
        service.close()


def test_default_service_clock_reads_current_utc_each_time(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(settings)
    try:
        before = datetime.now(timezone.utc)
        first = datetime.fromisoformat(service.now().replace("Z", "+00:00"))
        second = datetime.fromisoformat(service.now().replace("Z", "+00:00"))
        after = datetime.now(timezone.utc)
        assert before <= first <= second <= after
    finally:
        service.close()


def test_ack_deadline_expires_with_injected_clock(tmp_path):
    service, clock, token, identity = _registered_service(
        tmp_path, ack_deadline_seconds=2
    )
    try:
        service.enqueue_system_echo({"message": "late ack"}, "clock-ack-task")
        task = service.poll_one_task(
            identity
            | {"capabilities": ["system.echo"], "max_tasks": 1, "wait_seconds": 0},
            token,
            "clock-poll-ack",
        )["task"]
        clock.advance(2)
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.ack_delivery(
                task["task_id"],
                identity
                | {
                    "delivery_id": task["delivery_id"],
                    "accepted": True,
                    "reason": None,
                    "worker_time": "2026-01-01T00:00:02Z",
                },
                token,
                "clock-ack",
            )
        assert exc.value.code == "lease_expired"
    finally:
        service.close()


def test_result_rejected_after_lease_expiry_with_injected_clock(tmp_path):
    service, clock, token, identity = _registered_service(
        tmp_path, ack_deadline_seconds=2, lease_seconds=3
    )
    try:
        service.enqueue_system_echo({"message": "late result"}, "clock-result-task")
        task = service.poll_one_task(
            identity
            | {"capabilities": ["system.echo"], "max_tasks": 1, "wait_seconds": 0},
            token,
            "clock-poll-result",
        )["task"]
        service.ack_delivery(
            task["task_id"],
            identity
            | {
                "delivery_id": task["delivery_id"],
                "accepted": True,
                "reason": None,
                "worker_time": "2026-01-01T00:00:00Z",
            },
            token,
            "clock-ack-result",
        )
        clock.advance(3)
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.submit_result(
                task["task_id"],
                identity
                | {
                    "delivery_id": task["delivery_id"],
                    "task_id": task["task_id"],
                    "task_type": "system.echo",
                    "status": "completed",
                    "stdout": "late result",
                    "stderr": "",
                    "exit_code": 0,
                    "started_at": "2026-01-01T00:00:00Z",
                    "finished_at": "2026-01-01T00:00:03Z",
                    "duration_ms": 3000,
                    "result_idempotency_key": "clock-result-body",
                    "payload_hash": task["payload_hash"],
                    "trace_id": task["trace_id"],
                },
                token,
                "clock-result",
            )
        assert exc.value.code == "lease_expired"
    finally:
        service.close()


def test_real_pilot_factory_has_no_data_directory_override():
    signature = inspect.signature(WorkerControlPlaneSettings.for_pilot)
    assert "data_dir" not in signature.parameters
    with pytest.raises(TypeError):
        pilot.pilot_settings("/tmp/not-the-real-pilot")


def test_test_mode_rejects_pilot_shaped_hermes_path(tmp_path):
    root = tmp_path / ".hermes" / "worker-control-plane-pilot"
    root.mkdir(parents=True)
    with pytest.raises(ValueError, match="production-like"):
        WorkerControlPlaneSettings.for_test(
            root / "worker-control-plane.db", approved_test_root=root
        )


def test_production_pilot_settings_reject_alternate_root(tmp_path):
    root = tmp_path / "pilot"
    root.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="fixed pilot"):
        WorkerControlPlaneSettings(
            enabled=True,
            test_mode=False,
            pilot_mode=True,
            db_path=root / "worker-control-plane.db",
            approved_test_root=root,
        )


def test_existing_unsafe_database_is_rejected_without_chmod(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    settings.db_path.touch(mode=0o644)
    settings.db_path.chmod(0o644)
    with pytest.raises(ValueError, match="database file is unsafe"):
        pilot.WorkerControlPlaneService(settings)
    assert _mode(settings.db_path) == 0o644


def test_secure_directory_chain_rejects_symlink_ancestor(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    linked = tmp_path / "linked"
    try:
        os.symlink(outside, linked, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="symbolic link"):
        pilot._validate_secure_directory_chain(linked / "pilot", owner_from=tmp_path)


def test_secure_directory_chain_rejects_unsafe_permissions(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    with pytest.raises(ValueError, match="unsafe permissions"):
        pilot._validate_secure_directory_chain(unsafe / "pilot", owner_from=unsafe)


def test_secure_directory_chain_rejects_wrong_owner(tmp_path, monkeypatch):
    actual_uid = os.getuid()
    monkeypatch.setattr(pilot.os, "getuid", lambda: actual_uid + 1)
    with pytest.raises(ValueError, match="wrong owner"):
        pilot._validate_secure_directory_chain(
            tmp_path / "pilot", owner_from=tmp_path
        )


def test_secure_directory_chain_rejects_non_directory_ancestor(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValueError, match="must be a directory"):
        pilot._validate_secure_directory_chain(
            blocked / "pilot", owner_from=tmp_path
        )


def test_loopback_host_is_read_only_and_sink_is_fixed(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    runtime = pilot.LocalPilotRuntime(settings, unused_port())
    assert runtime.host == "127.0.0.1"
    with pytest.raises(AttributeError):
        runtime.host = "0.0.0.0"
    source = inspect.getsource(pilot.LocalPilotRuntime.start)
    assert "host=_LOOPBACK_ADDRESS" in source


def _active_bootstrap_hash(settings):
    service = pilot.WorkerControlPlaneService(settings)
    try:
        return service.store.conn.execute(
            "SELECT token_hash FROM worker_credentials "
            "WHERE kind='bootstrap' AND revoked_at IS NULL"
        ).fetchone()[0]
    finally:
        service.close()


def test_unsafe_credential_destination_rejected_before_db_rotation(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    credential = pilot.provision_local_worker(settings)
    original_hash = _active_bootstrap_hash(settings)
    credential.unlink()
    credential.mkdir()
    with pytest.raises(ValueError, match="credential destination"):
        pilot.provision_local_worker(settings)
    assert _active_bootstrap_hash(settings) == original_hash


def test_credential_symlink_rejected_before_db_rotation(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    credential = pilot.provision_local_worker(settings)
    original_hash = _active_bootstrap_hash(settings)
    outside = tmp_path / "outside-secret"
    outside.write_text("unchanged", encoding="utf-8")
    credential.unlink()
    try:
        os.symlink(outside, credential)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="credential destination"):
        pilot.provision_local_worker(settings)
    assert outside.read_text(encoding="utf-8") == "unchanged"
    assert _active_bootstrap_hash(settings) == original_hash


def test_parent_replacement_is_rejected_without_secret_escape_or_db_rotation(
    tmp_path, monkeypatch
):
    root = tmp_path / "pilot"
    settings = pilot.pilot_test_settings(root)
    pilot.provision_local_worker(settings)
    original_hash = _active_bootstrap_hash(settings)
    moved = tmp_path / "pilot-original"
    outside = tmp_path / "outside"
    original_provision = pilot.WorkerControlPlaneService.provision_worker

    def racing_provision(service, **kwargs):
        root.rename(moved)
        outside.mkdir(mode=0o700)
        os.symlink(outside, root, target_is_directory=True)
        return original_provision(service, **kwargs)

    monkeypatch.setattr(
        pilot.WorkerControlPlaneService, "provision_worker", racing_provision
    )
    with pytest.raises(ValueError, match="pilot root changed"):
        pilot.provision_local_worker(settings)
    assert not (outside / pilot.CREDENTIAL_FILE_NAME).exists()
    moved_settings = pilot.pilot_test_settings(moved)
    assert _active_bootstrap_hash(moved_settings) == original_hash


@pytest.mark.asyncio
async def test_shutdown_closes_service_even_when_runner_cleanup_fails(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    runtime = pilot.LocalPilotRuntime(settings, unused_port())
    closed = []

    class BrokenRunner:
        async def cleanup(self):
            raise RuntimeError("runner cleanup failed")

    class Service:
        def close(self):
            closed.append(True)

    runtime._runner = BrokenRunner()
    runtime.service = Service()
    with pytest.raises(RuntimeError, match="runner cleanup failed"):
        await runtime.stop()
    assert closed == [True]
    assert runtime.running is False


@pytest.mark.asyncio
async def test_shutdown_continues_after_site_stop_failure(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    runtime = pilot.LocalPilotRuntime(settings, unused_port())
    events = []

    class BrokenSite:
        async def stop(self):
            events.append("site")
            raise RuntimeError("site stop failed")

    class Runner:
        async def cleanup(self):
            events.append("runner")

    class Service:
        def close(self):
            events.append("service")

    runtime._site = BrokenSite()
    runtime._runner = Runner()
    runtime.service = Service()
    with pytest.raises(RuntimeError, match="site stop failed"):
        await runtime.stop()
    assert events == ["site", "runner", "service"]


@pytest.mark.asyncio
async def test_startup_failure_closes_service_when_runner_cleanup_fails(
    tmp_path, monkeypatch
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    closed = []

    class Service:
        def __init__(self, settings, **kwargs):
            pass

        def close(self):
            closed.append(True)

    class BrokenRunner:
        def __init__(self, app, **kwargs):
            pass

        async def setup(self):
            raise LookupError("setup failed")

        async def cleanup(self):
            raise RuntimeError("cleanup failed")

    monkeypatch.setattr(pilot, "WorkerControlPlaneService", Service)
    monkeypatch.setattr(pilot.web, "AppRunner", BrokenRunner)
    monkeypatch.setattr(
        pilot, "create_worker_control_plane_app", lambda settings, service: object()
    )
    runtime = pilot.LocalPilotRuntime(settings, unused_port())
    with pytest.raises(LookupError, match="setup failed"):
        await runtime.start()
    assert closed == [True]
    assert runtime.running is False
