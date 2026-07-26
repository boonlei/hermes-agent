"""Real-loopback tests for the standalone local Worker Control Plane pilot."""

from __future__ import annotations

import inspect
import hashlib
import json
import os
import sqlite3
import stat
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Event, Lock

import pytest
from aiohttp import ClientSession
from aiohttp.test_utils import unused_port

from gateway.worker_control_plane import runtime as pilot
from gateway.worker_control_plane import storage as wcp_storage
from gateway.worker_control_plane.auth import bootstrap_record
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
    credential = data_dir.resolve() / pilot.CREDENTIAL_FILE_NAME
    report = pilot.provision_local_worker(settings, credential)

    assert settings.pilot_mode is True
    assert settings.test_mode is False
    assert settings.db_path == data_dir.resolve() / "worker-control-plane.db"
    assert credential == data_dir.resolve() / "bootstrap-secret"
    assert _mode(data_dir) == 0o700
    assert _mode(settings.db_path) == 0o600
    assert _mode(credential) == 0o600
    assert report["single_use"] is True

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
    credential = settings.approved_test_root / pilot.CREDENTIAL_FILE_NAME
    pilot.provision_local_worker(settings, credential)
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
            assert runtime.service is not None
            assert runtime.service.store.conn.execute(
                "SELECT c.lifecycle_version FROM worker_credentials c "
                "JOIN worker_instances i "
                "ON i.access_credential_id=c.credential_id "
                "WHERE i.registration_id=?",
                (registration_id,),
            ).fetchone()[0] == wcp_storage.CURRENT_LIFECYCLE_VERSION
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
    secret = service.provision_worker()["secret"]
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


def _bootstrap_hash_by_id(settings, credential_id):
    service = pilot.WorkerControlPlaneService(settings)
    try:
        return service.store.conn.execute(
            "SELECT token_hash FROM worker_credentials WHERE credential_id=?",
            (credential_id,),
        ).fetchone()[0]
    finally:
        service.close()


def test_unsafe_credential_destination_rejected_before_db_rotation(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    credential = settings.approved_test_root / pilot.CREDENTIAL_FILE_NAME
    pilot.provision_local_worker(settings, credential)
    original_hash = _active_bootstrap_hash(settings)
    credential.unlink()
    credential.mkdir()
    with pytest.raises(ValueError, match="credential destination"):
        pilot.provision_local_worker(settings, credential)
    assert _active_bootstrap_hash(settings) == original_hash


def test_credential_symlink_rejected_before_db_rotation(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    credential = settings.approved_test_root / pilot.CREDENTIAL_FILE_NAME
    pilot.provision_local_worker(settings, credential)
    original_hash = _active_bootstrap_hash(settings)
    outside = tmp_path / "outside-secret"
    outside.write_text("unchanged", encoding="utf-8")
    credential.unlink()
    try:
        os.symlink(outside, credential)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    with pytest.raises(ValueError, match="credential destination"):
        pilot.provision_local_worker(settings, credential)
    assert outside.read_text(encoding="utf-8") == "unchanged"
    assert _active_bootstrap_hash(settings) == original_hash


def test_parent_replacement_is_rejected_without_secret_escape_or_db_rotation(
    tmp_path, monkeypatch
):
    root = tmp_path / "pilot"
    settings = pilot.pilot_test_settings(root)
    credential = settings.approved_test_root / pilot.CREDENTIAL_FILE_NAME
    first = pilot.provision_local_worker(settings, credential)
    original_hash = _active_bootstrap_hash(settings)
    service = pilot.WorkerControlPlaneService(settings)
    try:
        service.revoke_bootstrap_credential(
            "server-a-worker", first["credential_id"]
        )
    finally:
        service.close()
    credential.unlink()
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
        pilot.provision_local_worker(settings, credential)
    assert not (outside / pilot.CREDENTIAL_FILE_NAME).exists()
    moved_settings = pilot.pilot_test_settings(moved)
    assert (
        _bootstrap_hash_by_id(moved_settings, first["credential_id"])
        == original_hash
    )


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


def _registration_body(instance_id: str) -> dict:
    return {
        "protocol_version": "1.0",
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
        "worker_name": "commissioning security test",
        "worker_version": "0.1.0",
        "capabilities": ["system.echo"],
    }


@pytest.mark.parametrize("advance_seconds", (900, 901))
def test_bootstrap_expired_at_or_after_boundary_is_rejected(
    tmp_path, advance_seconds
):
    clock = MutableClock()
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(settings, clock=clock)
    try:
        provisioned = service.provision_worker(
            ttl_seconds=900, single_use=True
        )
        clock.advance(advance_seconds)
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(str(uuid.uuid4())),
                provisioned["secret"],
            )
        assert exc.value.code == "invalid_credential"
        row = service.store.conn.execute(
            "SELECT consumed_at FROM worker_credentials "
            "WHERE credential_id=?",
            (provisioned["credential_id"],),
        ).fetchone()
        assert row["consumed_at"] is None
        assert service.store.conn.execute(
            "SELECT count(*) FROM worker_instances"
        ).fetchone()[0] == 0
    finally:
        service.close()


def test_valid_bootstrap_is_consumed_once_after_successful_register(tmp_path):
    clock = MutableClock()
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(settings, clock=clock)
    instance_id = str(uuid.uuid4())
    try:
        provisioned = service.provision_worker(
            ttl_seconds=900, single_use=True
        )
        status, _ = service.register_worker(
            _registration_body(instance_id), provisioned["secret"]
        )
        assert status == 201
        row = service.store.conn.execute(
            "SELECT expires_at,single_use,consumed_at,revoked_at,"
            "lifecycle_version "
            "FROM worker_credentials WHERE credential_id=?",
            (provisioned["credential_id"],),
        ).fetchone()
        issued = datetime.fromisoformat(
            provisioned["issued_at"].replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            row["expires_at"].replace("Z", "+00:00")
        )
        assert expires - issued == timedelta(minutes=15)
        assert row["single_use"] == 1
        assert (
            row["lifecycle_version"]
            == wcp_storage.CURRENT_LIFECYCLE_VERSION
        )
        assert row["consumed_at"] is not None
        assert row["revoked_at"] == row["consumed_at"]

        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(instance_id), provisioned["secret"]
            )
        assert exc.value.code == "invalid_credential"
    finally:
        service.close()


def test_failed_register_does_not_consume_single_use_bootstrap(tmp_path):
    clock = MutableClock()
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(settings, clock=clock)
    first_instance = str(uuid.uuid4())
    try:
        first = service.provision_worker(ttl_seconds=900, single_use=True)
        assert service.register_worker(
            _registration_body(first_instance), first["secret"]
        )[0] == 201

        second = service.provision_worker(ttl_seconds=900, single_use=True)
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(str(uuid.uuid4())), second["secret"]
            )
        assert exc.value.code == "duplicate_active_instance"
        row = service.store.conn.execute(
            "SELECT consumed_at,revoked_at FROM worker_credentials "
            "WHERE credential_id=?",
            (second["credential_id"],),
        ).fetchone()
        assert row["consumed_at"] is None
        assert row["revoked_at"] is None

        assert service.register_worker(
            _registration_body(first_instance), second["secret"]
        )[0] == 200
    finally:
        service.close()


def test_concurrent_single_use_register_allows_exactly_one_success(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    setup = pilot.WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    try:
        provisioned = setup.provision_worker(
            ttl_seconds=900, single_use=True
        )
    finally:
        setup.close()

    services = [
        pilot.WorkerControlPlaneService(settings, clock=MutableClock())
        for _ in range(2)
    ]

    def attempt(index):
        try:
            return services[index].register_worker(
                _registration_body(str(uuid.uuid4())),
                provisioned["secret"],
            )[0]
        except WorkerControlPlaneError as exc:
            return exc.code

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, range(2)))
        assert sorted(map(str, results)) == ["201", "invalid_credential"]
        assert services[0].store.conn.execute(
            "SELECT count(*) FROM worker_instances"
        ).fetchone()[0] == 1
    finally:
        for service in services:
            service.close()


def test_revoked_bootstrap_is_rejected_and_metadata_is_redacted(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    try:
        provisioned = service.provision_worker(
            ttl_seconds=900, single_use=True
        )
        metadata = service.list_bootstrap_credentials("server-a-worker")
        rendered = json.dumps(metadata)
        assert provisioned["secret"] not in rendered
        assert "token_hash" not in rendered
        assert "salt" not in rendered
        assert metadata[0]["credential_id"] == provisioned["credential_id"]

        with pytest.raises(ValueError, match="credential target"):
            service.revoke_bootstrap_credential(
                "server-a-worker", str(uuid.uuid4())
            )
        assert service.store.conn.execute(
            "SELECT revoked_at FROM worker_credentials "
            "WHERE credential_id=?",
            (provisioned["credential_id"],),
        ).fetchone()["revoked_at"] is None

        revoked = service.revoke_bootstrap_credential(
            "server-a-worker", provisioned["credential_id"]
        )
        assert revoked["state"] == "revoked"
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(str(uuid.uuid4())),
                provisioned["secret"],
            )
        assert exc.value.code == "invalid_credential"
        assert "bootstrap_credential_revoked" in service.audit_text()
    finally:
        service.close()


def test_registration_inspection_and_exact_selected_revocation(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    instance_id = str(uuid.uuid4())
    try:
        provisioned = service.provision_worker(
            ttl_seconds=900, single_use=True
        )
        _, response = service.register_worker(
            _registration_body(instance_id), provisioned["secret"]
        )
        registrations = service.list_registrations("server-a-worker")
        rendered = json.dumps(registrations)
        assert response["access_token"] not in rendered
        assert "token_hash" not in rendered
        assert registrations[0]["registration_id"] == response["registration_id"]

        with pytest.raises(ValueError, match="registration target"):
            service.revoke_registration(
                "server-a-worker",
                str(uuid.uuid4()),
                response["registration_id"],
            )
        assert service.store.conn.execute(
            "SELECT status FROM worker_instances WHERE registration_id=?",
            (response["registration_id"],),
        ).fetchone()["status"] == "active"

        revoked = service.revoke_registration(
            "server-a-worker", instance_id, response["registration_id"]
        )
        assert revoked["status"] == "revoked"
        assert "registration_revoked" in service.audit_text()
    finally:
        service.close()


def test_provisioning_writes_exact_secret_only_artifact_and_safe_report(
    tmp_path
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    destination = settings.approved_test_root / "commissioning.secret"
    report = pilot.provision_local_worker(
        settings, destination, ttl_seconds=900
    )
    raw = destination.read_bytes()
    secret = raw.decode("utf-8")
    assert raw == secret.encode("utf-8")
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert not raw.endswith(b"\n")
    assert _mode(destination) == 0o600
    assert report["single_use"] is True
    assert set(report) == {
        "credential_id",
        "expires_at",
        "single_use",
        "transfer_file_sha256",
    }
    assert report["transfer_file_sha256"] == pilot.hashlib.sha256(raw).hexdigest()
    assert secret not in json.dumps(report)

    service = pilot.WorkerControlPlaneService(settings)
    try:
        row = service.store.conn.execute(
            "SELECT token_hash,salt,issued_at,expires_at,single_use "
            "FROM worker_credentials WHERE credential_id=?",
            (report["credential_id"],),
        ).fetchone()
        issued = datetime.fromisoformat(row["issued_at"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        assert expires - issued == timedelta(minutes=15)
        assert row["single_use"] == 1
        assert secret not in {row["token_hash"], row["salt"]}
        assert secret not in service.audit_text()
    finally:
        service.close()


@pytest.mark.parametrize("ttl", (True, 0, 901))
def test_bootstrap_ttl_is_bounded_before_file_or_db_creation(tmp_path, ttl):
    settings = pilot.pilot_test_settings(tmp_path / f"pilot-{ttl}")
    destination = settings.approved_test_root / "commissioning.secret"
    with pytest.raises(ValueError, match="TTL"):
        pilot.provision_local_worker(settings, destination, ttl_seconds=ttl)
    assert not destination.exists()
    service = pilot.WorkerControlPlaneService(settings)
    try:
        assert service.store.conn.execute(
            "SELECT count(*) FROM worker_credentials WHERE kind='bootstrap'"
        ).fetchone()[0] == 0
    finally:
        service.close()


def _create_legacy_database(
    path,
    *,
    expires_at="2099-01-01T00:00:00Z",
    revoked_at=None,
):
    secret = "legacy-secret"
    bootstrap_id = str(uuid.uuid4())
    access_id = str(uuid.uuid4())
    registration_id = str(uuid.uuid4())
    instance_id = str(uuid.uuid4())
    salt, digest = bootstrap_record(secret)
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE schema_migrations(
            version TEXT PRIMARY KEY, applied_at TEXT NOT NULL
        );
        CREATE TABLE workers(
            worker_id TEXT PRIMARY KEY, worker_name TEXT NOT NULL,
            allowed_capabilities TEXT NOT NULL, enabled INTEGER NOT NULL,
            revoked_at TEXT
        );
        CREATE TABLE worker_credentials(
            credential_id TEXT PRIMARY KEY,
            worker_id TEXT NOT NULL REFERENCES workers(worker_id),
            kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, salt TEXT,
            issued_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT
        );
        CREATE TABLE worker_instances(
            registration_id TEXT PRIMARY KEY,
            worker_id TEXT NOT NULL REFERENCES workers(worker_id),
            instance_id TEXT NOT NULL, status TEXT NOT NULL,
            worker_version TEXT NOT NULL, protocol_version TEXT NOT NULL,
            registered_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
            access_credential_id TEXT NOT NULL
                REFERENCES worker_credentials(credential_id),
            current_task_id TEXT, UNIQUE(worker_id, instance_id)
        );
        """
    )
    connection.execute(
        "INSERT INTO workers VALUES(?,?,?,1,NULL)",
        ("server-a-worker", "legacy", '["system.echo"]'),
    )
    connection.execute(
        "INSERT INTO worker_credentials VALUES(?,?,?,?,?,?,?,?)",
        (
            bootstrap_id,
            "server-a-worker",
            "bootstrap",
            digest,
            salt,
            "2025-12-31T23:59:00Z",
            expires_at,
            revoked_at,
        ),
    )
    connection.execute(
        "INSERT INTO worker_credentials VALUES(?,?,?,?,?,?,?,?)",
        (
            access_id,
            "server-a-worker",
            "access",
            hashlib.sha256(b"legacy-access-token").hexdigest(),
            None,
            "2025-12-31T23:59:30Z",
            "2099-01-01T00:00:00Z",
            None,
        ),
    )
    connection.execute(
        "INSERT INTO worker_instances VALUES(?,?,?,?,?,?,?,?,?,NULL)",
        (
            registration_id,
            "server-a-worker",
            instance_id,
            "active",
            "0.1.0",
            "1.0",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            access_id,
        ),
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)
    return {
        "secret": secret,
        "bootstrap_id": bootstrap_id,
        "access_id": access_id,
        "registration_id": registration_id,
    }


def _create_v2_database(path):
    secret = "v2-legacy-secret"
    bootstrap_id = "00000000-0000-4000-8000-000000000201"
    access_id = "00000000-0000-4000-8000-000000000202"
    registration_id = "00000000-0000-4000-8000-000000000203"
    instance_id = "00000000-0000-4000-8000-000000000204"
    salt, digest = bootstrap_record(secret)
    migrations = (
        ("worker_control_plane_schema_v1", "2026-07-22 11:57:47"),
        (
            "worker_control_plane_bootstrap_lifecycle_v2",
            "2026-07-26 09:55:01",
        ),
    )
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.executescript(
        """
        CREATE TABLE schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL);
        CREATE TABLE workers(worker_id TEXT PRIMARY KEY, worker_name TEXT NOT NULL, allowed_capabilities TEXT NOT NULL, enabled INTEGER NOT NULL, revoked_at TEXT);
        CREATE TABLE worker_credentials(credential_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL REFERENCES workers(worker_id), kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, salt TEXT, issued_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, single_use INTEGER NOT NULL DEFAULT 0 CHECK(single_use IN (0,1)), consumed_at TEXT);
        CREATE TABLE worker_instances(registration_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL REFERENCES workers(worker_id), instance_id TEXT NOT NULL, status TEXT NOT NULL, worker_version TEXT NOT NULL, protocol_version TEXT NOT NULL, registered_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, access_credential_id TEXT NOT NULL REFERENCES worker_credentials(credential_id), current_task_id TEXT, UNIQUE(worker_id, instance_id));
        CREATE TABLE worker_tasks(task_id TEXT PRIMARY KEY, task_type TEXT NOT NULL CHECK(task_type='system.echo'), payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, available_at TEXT NOT NULL, leased_until TEXT, attempt INTEGER NOT NULL, max_attempts INTEGER NOT NULL, creation_idempotency_key TEXT NOT NULL UNIQUE, trace_id TEXT NOT NULL);
        CREATE TABLE worker_deliveries(delivery_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES worker_tasks(task_id), worker_id TEXT NOT NULL, registration_id TEXT NOT NULL REFERENCES worker_instances(registration_id), attempt INTEGER NOT NULL, state TEXT NOT NULL, leased_at TEXT NOT NULL, ack_deadline_at TEXT NOT NULL, lease_expires_at TEXT NOT NULL, acknowledged_at TEXT, finished_at TEXT, UNIQUE(task_id, attempt));
        CREATE TABLE worker_results(result_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES worker_tasks(task_id), delivery_id TEXT NOT NULL UNIQUE REFERENCES worker_deliveries(delivery_id), result_idempotency_key TEXT NOT NULL, result_hash TEXT NOT NULL, status TEXT NOT NULL, stdout TEXT NOT NULL, stderr TEXT NOT NULL, exit_code INTEGER, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, duration_ms INTEGER NOT NULL, accepted_at TEXT NOT NULL, UNIQUE(task_id, result_idempotency_key));
        CREATE TABLE worker_request_dedup(worker_id TEXT NOT NULL, registration_id TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, task_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_body_hash TEXT NOT NULL, response_status INTEGER NOT NULL, response_json TEXT NOT NULL, PRIMARY KEY(worker_id, idempotency_key));
        CREATE TABLE worker_audit_log(audit_id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, event_type TEXT NOT NULL, worker_id TEXT, instance_id TEXT, registration_id TEXT, task_id TEXT, delivery_id TEXT, trace_id TEXT, outcome TEXT NOT NULL, reason_code TEXT, details_json TEXT);
        CREATE INDEX idx_tasks_queue ON worker_tasks(state,available_at,created_at);
        CREATE INDEX idx_deliveries_lease ON worker_deliveries(state,lease_expires_at);
        """
    )
    connection.executemany(
        "INSERT INTO schema_migrations VALUES(?,?)", migrations
    )
    connection.execute(
        "INSERT INTO workers VALUES(?,?,?,1,NULL)",
        ("server-a-worker", "v2 worker", '["system.echo"]'),
    )
    connection.execute(
        "INSERT INTO worker_credentials VALUES(?,?,?,?,?,?,?,?,?,NULL)",
        (
            bootstrap_id,
            "server-a-worker",
            "bootstrap",
            digest,
            salt,
            "2026-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            None,
            1,
        ),
    )
    connection.execute(
        "INSERT INTO worker_credentials VALUES(?,?,?,?,?,?,?,?,0,NULL)",
        (
            access_id,
            "server-a-worker",
            "access",
            hashlib.sha256(b"v2-access-token").hexdigest(),
            None,
            "2026-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            None,
        ),
    )
    connection.execute(
        "INSERT INTO worker_instances VALUES(?,?,?,?,?,?,?,?,?,NULL)",
        (
            registration_id,
            "server-a-worker",
            instance_id,
            "active",
            "0.2.0",
            "1.0",
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            access_id,
        ),
    )
    connection.execute(
        "INSERT INTO worker_audit_log("
        "audit_id,occurred_at,event_type,worker_id,instance_id,"
        "registration_id,outcome,reason_code"
        ") VALUES(1,?,?,?,?,?,?,?)",
        (
            "2026-01-01T00:00:00Z",
            "worker_registered",
            "server-a-worker",
            instance_id,
            registration_id,
            "ok",
            "v2-fixture",
        ),
    )
    connection.commit()
    connection.close()
    path.chmod(0o600)
    return {
        "secret": secret,
        "bootstrap_id": bootstrap_id,
        "access_id": access_id,
        "registration_id": registration_id,
        "instance_id": instance_id,
        "migrations": migrations,
    }


def _v2_business_snapshot(path, connect=sqlite3.connect):
    connection = connect(path)
    credentials = connection.execute(
        "SELECT credential_id,worker_id,kind,token_hash,salt,issued_at,"
        "expires_at,revoked_at,single_use,consumed_at "
        "FROM worker_credentials ORDER BY credential_id"
    ).fetchall()
    registrations = connection.execute(
        "SELECT * FROM worker_instances ORDER BY registration_id"
    ).fetchall()
    audit = connection.execute(
        "SELECT * FROM worker_audit_log ORDER BY audit_id"
    ).fetchall()
    secret_material = hashlib.sha256(
        json.dumps(
            [(row[0], row[3], row[4]) for row in credentials],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    connection.close()
    return credentials, registrations, audit, secret_material


def _migrated_v2_snapshot(connection, *, include_audit=True):
    credentials = connection.execute(
        "SELECT credential_id,worker_id,kind,issued_at,expires_at,revoked_at,"
        "single_use,consumed_at,lifecycle_version "
        "FROM worker_credentials ORDER BY credential_id"
    ).fetchall()
    secret_material = connection.execute(
        "SELECT credential_id,token_hash,salt FROM worker_credentials "
        "ORDER BY credential_id"
    ).fetchall()
    snapshot = {
        "workers": tuple(
            tuple(row)
            for row in connection.execute("SELECT * FROM workers ORDER BY worker_id")
        ),
        "credentials": tuple(tuple(row) for row in credentials),
        "credential_ids": tuple(row["credential_id"] for row in credentials),
        "credential_count": len(credentials),
        "secret_material_sha256": hashlib.sha256(
            json.dumps(
                [tuple(row) for row in secret_material],
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
        "access_credential_ids": tuple(
            row["credential_id"] for row in credentials if row["kind"] == "access"
        ),
        "registrations": tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM worker_instances ORDER BY registration_id"
            )
        ),
        "tasks": tuple(
            tuple(row)
            for row in connection.execute("SELECT * FROM worker_tasks ORDER BY task_id")
        ),
        "deliveries": tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM worker_deliveries ORDER BY delivery_id"
            )
        ),
        "results": tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM worker_results ORDER BY result_id"
            )
        ),
        "dedup": tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT * FROM worker_request_dedup "
                "ORDER BY worker_id,idempotency_key"
            )
        ),
    }
    if include_audit:
        snapshot["audit"] = tuple(
            tuple(row)
            for row in connection.execute(
                "SELECT audit_id,occurred_at,event_type,worker_id,instance_id,"
                "registration_id,task_id,delivery_id,trace_id,outcome,"
                "reason_code,details_json FROM worker_audit_log ORDER BY audit_id"
            )
        )
    return snapshot


def _legacy_business_snapshot(path, connect=sqlite3.connect):
    connection = connect(path)
    credentials = connection.execute(
        "SELECT credential_id,worker_id,kind,token_hash,salt,issued_at,"
        "expires_at,revoked_at FROM worker_credentials "
        "ORDER BY credential_id"
    ).fetchall()
    registrations = connection.execute(
        "SELECT registration_id,worker_id,instance_id,status,worker_version,"
        "protocol_version,registered_at,last_seen_at,access_credential_id,"
        "current_task_id FROM worker_instances ORDER BY registration_id"
    ).fetchall()
    secret_material = hashlib.sha256(
        json.dumps(
            [(row[0], row[3], row[4]) for row in credentials],
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    connection.close()
    return credentials, registrations, secret_material


class _FailingMigrationConnection:
    def __init__(self, connection, should_fail):
        self._connection = connection
        self._should_fail = should_fail

    @property
    def row_factory(self):
        return self._connection.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self._connection.row_factory = value

    def execute(self, statement, parameters=()):
        if self._should_fail(" ".join(statement.split()), parameters):
            raise sqlite3.OperationalError("injected migration failure")
        return self._connection.execute(statement, parameters)

    def __getattr__(self, name):
        return getattr(self._connection, name)


class _ContendedMigrationConnection:
    def __init__(
        self,
        connection,
        begin_locked,
        alter_statements,
        statements_lock,
    ):
        self._connection = connection
        self._begin_locked = begin_locked
        self._alter_statements = alter_statements
        self._statements_lock = statements_lock

    @property
    def row_factory(self):
        return self._connection.row_factory

    @row_factory.setter
    def row_factory(self, value):
        self._connection.row_factory = value

    def execute(self, statement, parameters=()):
        normalized = " ".join(statement.split())
        if normalized.startswith("ALTER TABLE"):
            with self._statements_lock:
                self._alter_statements.append(normalized)
        try:
            return self._connection.execute(statement, parameters)
        except sqlite3.OperationalError as exc:
            if normalized == "BEGIN IMMEDIATE" and "locked" in str(exc).lower():
                self._begin_locked.set()
            raise

    def __getattr__(self, name):
        return getattr(self._connection, name)


def test_fresh_database_has_complete_atomic_lifecycle_schema(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(settings)
    try:
        columns = {
            row["name"]: row
            for row in service.store.conn.execute(
                "PRAGMA table_info(worker_credentials)"
            )
        }
        assert {
            "single_use",
            "consumed_at",
            "lifecycle_version",
        } <= columns.keys()
        migrations = service.store.conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert [row[0] for row in migrations] == sorted(
            {
                "worker_control_plane_schema_v1",
                "worker_control_plane_bootstrap_lifecycle_v2",
                wcp_storage.LIFECYCLE_MIGRATION_V3,
            }
        )
    finally:
        service.close()


def test_real_legacy_rows_are_preserved_and_future_expiry_fails_closed(
    tmp_path, capsys
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    legacy = _create_legacy_database(settings.db_path)
    before = _legacy_business_snapshot(settings.db_path)

    service = pilot.WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    try:
        after = _legacy_business_snapshot(settings.db_path)
        assert after == before
        versions = service.store.conn.execute(
            "SELECT DISTINCT lifecycle_version FROM worker_credentials"
        ).fetchall()
        assert [row[0] for row in versions] == [0]
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(str(uuid.uuid4())), legacy["secret"]
            )
        assert (exc.value.code, exc.value.status, exc.value.message) == (
            "invalid_credential",
            401,
            "Authentication failed",
        )
        assert service.store.conn.execute(
            "SELECT count(*) FROM worker_credentials"
        ).fetchone()[0] == 2
        assert service.store.conn.execute(
            "SELECT count(*) FROM worker_instances"
        ).fetchone()[0] == 1
        metadata = service.list_bootstrap_credentials("server-a-worker")
        assert metadata[0]["state"] == "legacy_ineligible"
        assert metadata[0]["lifecycle_version"] == 0
        rendered = json.dumps(metadata)
        assert legacy["secret"] not in rendered
        assert "token_hash" not in rendered
        assert "salt" not in rendered
        output = capsys.readouterr()
        assert legacy["secret"] not in output.out + output.err
        migration_metadata = json.dumps(
            [
                tuple(row)
                for row in service.store.conn.execute(
                    "SELECT * FROM schema_migrations"
                )
            ]
        )
        assert legacy["secret"] not in migration_metadata
    finally:
        service.close()


def test_real_v2_to_v3_migration_preserves_and_enforces_lifecycle(tmp_path):
    clock = MutableClock()
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    legacy = _create_v2_database(settings.db_path)
    before = _v2_business_snapshot(settings.db_path)
    connection = sqlite3.connect(settings.db_path)
    v2_columns = [
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(worker_credentials)"
        )
    ]
    connection.close()

    service = pilot.WorkerControlPlaneService(settings, clock=clock)
    try:
        columns = [
            row["name"]
            for row in service.store.conn.execute(
                "PRAGMA table_info(worker_credentials)"
            )
        ]
        assert columns == [*v2_columns, "lifecycle_version"]
        migrations = {
            row["version"]: row["applied_at"]
            for row in service.store.conn.execute(
                "SELECT version,applied_at FROM schema_migrations"
            )
        }
        assert len(migrations) == 3
        assert tuple(
            (name, migrations[name]) for name, _ in legacy["migrations"]
        ) == legacy["migrations"]
        assert wcp_storage.LIFECYCLE_MIGRATION_V3 in migrations
        assert _v2_business_snapshot(settings.db_path) == before

        credentials = service.store.conn.execute(
            "SELECT credential_id,lifecycle_version FROM worker_credentials "
            "ORDER BY credential_id"
        ).fetchall()
        assert {row["credential_id"] for row in credentials} == {
            legacy["bootstrap_id"],
            legacy["access_id"],
        }
        assert {row["lifecycle_version"] for row in credentials} == {0}
        registration = service.store.conn.execute(
            "SELECT * FROM worker_instances WHERE registration_id=?",
            (legacy["registration_id"],),
        ).fetchone()
        assert registration["instance_id"] == legacy["instance_id"]

        authentication_before = _migrated_v2_snapshot(service.store.conn)
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(legacy["instance_id"]), legacy["secret"]
            )
        assert (
            exc.value.code,
            exc.value.status,
            exc.value.message,
        ) == ("invalid_credential", 401, "Authentication failed")
        rendered_error = json.dumps(
            {
                "code": exc.value.code,
                "status": exc.value.status,
                "message": exc.value.message,
            }
        ).lower()
        assert all(
            forbidden not in rendered_error
            for forbidden in (
                "legacy",
                "lifecycle_version",
                "migration",
                "eligibility",
                legacy["bootstrap_id"].lower(),
            )
        )
        assert _migrated_v2_snapshot(service.store.conn) == authentication_before

        service.revoke_bootstrap_credential(
            "server-a-worker", legacy["bootstrap_id"]
        )
        legacy_before_provision = tuple(
            service.store.conn.execute(
                "SELECT * FROM worker_credentials WHERE credential_id=?",
                (legacy["bootstrap_id"],),
            ).fetchone()
        )
        provisioned = service.provision_worker(
            ttl_seconds=900, single_use=True
        )
        legacy_after_provision = tuple(
            service.store.conn.execute(
                "SELECT * FROM worker_credentials WHERE credential_id=?",
                (legacy["bootstrap_id"],),
            ).fetchone()
        )
        assert legacy_after_provision == legacy_before_provision
        new_row = service.store.conn.execute(
            "SELECT * FROM worker_credentials WHERE credential_id=?",
            (provisioned["credential_id"],),
        ).fetchone()
        assert new_row["lifecycle_version"] == 3
        assert new_row["single_use"] == 1
        issued = datetime.fromisoformat(
            new_row["issued_at"].replace("Z", "+00:00")
        )
        expires = datetime.fromisoformat(
            new_row["expires_at"].replace("Z", "+00:00")
        )
        assert expires - issued == timedelta(seconds=900)

        assert service.register_worker(
            _registration_body(legacy["instance_id"]),
            provisioned["secret"],
        )[0] == 200
        consumed = service.store.conn.execute(
            "SELECT consumed_at,revoked_at FROM worker_credentials "
            "WHERE credential_id=?",
            (provisioned["credential_id"],),
        ).fetchone()
        assert consumed["consumed_at"] is not None
        assert consumed["revoked_at"] == consumed["consumed_at"]
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(legacy["instance_id"]),
                provisioned["secret"],
            )
        assert (exc.value.code, exc.value.status) == (
            "invalid_credential",
            401,
        )
        service.check_health()
        before_reopen = tuple(
            tuple(row)
            for table in (
                "schema_migrations",
                "worker_credentials",
                "worker_instances",
                "worker_audit_log",
            )
            for row in service.store.conn.execute(
                f"SELECT * FROM {table} ORDER BY rowid"
            )
        )
        applied_at = migrations
    finally:
        service.close()

    reopened = pilot.WorkerControlPlaneService(settings, clock=clock)
    try:
        after_reopen = tuple(
            tuple(row)
            for table in (
                "schema_migrations",
                "worker_credentials",
                "worker_instances",
                "worker_audit_log",
            )
            for row in reopened.store.conn.execute(
                f"SELECT * FROM {table} ORDER BY rowid"
            )
        )
        assert after_reopen == before_reopen
        second_applied_at = {
            row["version"]: row["applied_at"]
            for row in reopened.store.conn.execute(
                "SELECT version,applied_at FROM schema_migrations"
            )
        }
        assert second_applied_at == applied_at
        assert len(second_applied_at) == 3
        reopened.check_health()
    finally:
        reopened.close()


@pytest.mark.asyncio
async def test_migrated_v2_access_is_rejected_by_all_worker_endpoints(
    tmp_path,
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    legacy = _create_v2_database(settings.db_path)
    port = unused_port()
    runtime = pilot.LocalPilotRuntime(settings, port)
    await runtime.start()
    assert runtime.service is not None
    service = runtime.service
    before = _migrated_v2_snapshot(service.store.conn, include_audit=False)
    audit_before = service.store.conn.execute(
        "SELECT coalesce(max(audit_id),0) FROM worker_audit_log"
    ).fetchone()[0]
    task_id = "00000000-0000-4000-8000-000000000205"
    delivery_id = "00000000-0000-4000-8000-000000000206"
    identity = {
        "worker_id": "server-a-worker",
        "instance_id": legacy["instance_id"],
        "registration_id": legacy["registration_id"],
    }
    requests = (
        (
            "/worker/v1/heartbeat",
            {},
            identity
            | {
                "status": "idle",
                "current_task_id": None,
                "worker_time": "2026-01-01T00:00:00Z",
            },
            "heartbeat_rejected",
        ),
        (
            "/worker/v1/tasks/poll",
            {"Idempotency-Key": "legacy-poll"},
            identity
            | {
                "capabilities": ["system.echo"],
                "max_tasks": 1,
                "wait_seconds": 0,
            },
            "poll_rejected",
        ),
        (
            f"/worker/v1/tasks/{task_id}/ack",
            {"Idempotency-Key": "legacy-ack"},
            identity
            | {
                "delivery_id": delivery_id,
                "accepted": True,
                "reason": None,
                "worker_time": "2026-01-01T00:00:00Z",
            },
            "ack_rejected",
        ),
        (
            f"/worker/v1/tasks/{task_id}/result",
            {"Idempotency-Key": "legacy-result"},
            identity
            | {
                "delivery_id": delivery_id,
                "task_id": task_id,
                "task_type": "system.echo",
                "status": "completed",
                "stdout": "legacy-result-must-not-run",
                "stderr": "",
                "exit_code": 0,
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": "2026-01-01T00:00:00Z",
                "duration_ms": 0,
                "result_idempotency_key": "legacy-result-body",
                "payload_hash": "0" * 64,
                "trace_id": "00000000-0000-4000-8000-000000000207",
            },
            "result_rejected",
        ),
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        async with ClientSession() as client:
            for path, extra_headers, body, _ in requests:
                response = await client.post(
                    base_url + path,
                    headers={
                        "Authorization": "Bearer v2-access-token",
                        **extra_headers,
                    },
                    json=body,
                )
                payload = await response.json()
                assert response.status == 401
                assert payload["error"]["code"] == "invalid_credential"
                assert payload["error"]["message"] == "Authentication failed"
                rendered = json.dumps(payload).lower()
                assert all(
                    forbidden not in rendered
                    for forbidden in (
                        "legacy",
                        "lifecycle_version",
                        "migration",
                        "eligibility",
                        legacy["access_id"].lower(),
                        "v2-access-token",
                    )
                )
                assert (
                    _migrated_v2_snapshot(
                        service.store.conn, include_audit=False
                    )
                    == before
                )

        rejection_audit = service.store.conn.execute(
            "SELECT event_type,outcome,reason_code,details_json "
            "FROM worker_audit_log WHERE audit_id>? ORDER BY audit_id",
            (audit_before,),
        ).fetchall()
        assert [tuple(row) for row in rejection_audit] == [
            event
            for _, _, _, rejected_event in requests
            for event in (
                (rejected_event, "rejected", "invalid_credential", None),
                ("credential_failed", "rejected", "invalid_credential", None),
            )
        ]
        rendered_audit = json.dumps(
            [tuple(row) for row in rejection_audit]
        ).lower()
        assert all(
            forbidden not in rendered_audit
            for forbidden in (
                "legacy",
                "lifecycle_version",
                "migration",
                "eligibility",
                legacy["access_id"].lower(),
                "v2-access-token",
            )
        )
    finally:
        await runtime.stop()


def test_second_migration_run_does_not_rewrite_schema_data_or_applied_at(
    tmp_path
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    _create_legacy_database(settings.db_path)
    first = pilot.WorkerControlPlaneService(settings)
    first.close()
    connection = sqlite3.connect(settings.db_path)
    before_schema = connection.execute(
        "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
    ).fetchall()
    before_metadata = connection.execute(
        "SELECT version,applied_at FROM schema_migrations ORDER BY version"
    ).fetchall()
    before_business = _legacy_business_snapshot(settings.db_path)
    connection.close()

    second = pilot.WorkerControlPlaneService(settings)
    second.close()
    connection = sqlite3.connect(settings.db_path)
    assert connection.execute(
        "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY name"
    ).fetchall() == before_schema
    assert connection.execute(
        "SELECT version,applied_at FROM schema_migrations ORDER BY version"
    ).fetchall() == before_metadata
    connection.close()
    assert _legacy_business_snapshot(settings.db_path) == before_business


@pytest.mark.parametrize(
    "failure_point",
    ("after_first_ddl", "before_metadata", "metadata_v3"),
)
def test_migration_failure_rolls_back_schema_metadata_and_business_rows(
    tmp_path, monkeypatch, failure_point
):
    settings = pilot.pilot_test_settings(tmp_path / failure_point)
    legacy = _create_legacy_database(settings.db_path)
    before = _legacy_business_snapshot(settings.db_path)
    real_connect = sqlite3.connect
    altered = 0

    def should_fail(statement, parameters):
        nonlocal altered
        if statement.startswith("ALTER TABLE"):
            altered += 1
            if failure_point == "after_first_ddl" and altered == 2:
                return True
        if statement.startswith("INSERT OR IGNORE INTO schema_migrations"):
            if failure_point == "before_metadata":
                return True
            if (
                failure_point == "metadata_v3"
                and parameters == (wcp_storage.LIFECYCLE_MIGRATION_V3,)
            ):
                return True
        return False

    def connect(*args, **kwargs):
        return _FailingMigrationConnection(
            real_connect(*args, **kwargs), should_fail
        )

    monkeypatch.setattr(wcp_storage.sqlite3, "connect", connect)
    with pytest.raises(sqlite3.OperationalError) as exc:
        pilot.WorkerControlPlaneService(settings)
    assert legacy["secret"] not in str(exc.value)

    connection = real_connect(settings.db_path)
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(worker_credentials)"
        )
    }
    assert not {
        "single_use",
        "consumed_at",
        "lifecycle_version",
    } & columns
    assert connection.execute(
        "SELECT count(*) FROM schema_migrations"
    ).fetchone()[0] == 0
    connection.close()
    assert _legacy_business_snapshot(
        settings.db_path, connect=real_connect
    ) == before


def test_concurrent_v2_migration_deterministically_contends_for_lock(
    tmp_path, monkeypatch
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    _create_v2_database(settings.db_path)
    before = _v2_business_snapshot(settings.db_path)
    real_connect = sqlite3.connect
    lock_held = Event()
    begin_locked = Event()
    release_lock = Event()
    statements_lock = Lock()
    alter_statements = []

    def hold_write_lock():
        connection = real_connect(settings.db_path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            lock_held.set()
            if not release_lock.wait(timeout=5):
                raise AssertionError("migration lock release timed out")
            connection.rollback()
        finally:
            connection.close()

    def connect(*args, **kwargs):
        kwargs["timeout"] = 0
        return _ContendedMigrationConnection(
            real_connect(*args, **kwargs),
            begin_locked,
            alter_statements,
            statements_lock,
        )

    def initialize():
        service = pilot.WorkerControlPlaneService(settings)
        service.close()
        return True

    monkeypatch.setattr(wcp_storage.sqlite3, "connect", connect)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(hold_write_lock)
        assert lock_held.wait(timeout=5)
        second = executor.submit(initialize)
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            second.result(timeout=5)
        assert begin_locked.is_set()
        assert not first.done()
        release_lock.set()
        assert first.result(timeout=5) is None

    connection = real_connect(settings.db_path)
    assert "lifecycle_version" not in {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(worker_credentials)"
        )
    }
    assert connection.execute(
        "SELECT count(*) FROM schema_migrations WHERE version=?",
        (wcp_storage.LIFECYCLE_MIGRATION_V3,),
    ).fetchone()[0] == 0
    connection.close()

    assert initialize() is True

    connection = real_connect(settings.db_path)
    columns = {
        row[1]
        for row in connection.execute(
            "PRAGMA table_info(worker_credentials)"
        )
    }
    assert {
        "single_use",
        "consumed_at",
        "lifecycle_version",
    } <= columns
    assert alter_statements == [
        "ALTER TABLE worker_credentials ADD COLUMN lifecycle_version "
        "INTEGER NOT NULL DEFAULT 0 CHECK(lifecycle_version IN (0,3))"
    ]
    assert connection.execute(
        "SELECT count(*) FROM schema_migrations WHERE version=?",
        (wcp_storage.LIFECYCLE_MIGRATION_V3,),
    ).fetchone()[0] == 1
    connection.close()
    assert _v2_business_snapshot(
        settings.db_path, connect=real_connect
    ) == before


@pytest.mark.parametrize(
    ("expires_at", "revoked_at"),
    (
        (None, None),
        ("2099-01-01T00:00:00Z", None),
        ("not-a-timestamp", None),
        ("2099-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
    ),
)
def test_all_legacy_bootstrap_variants_fail_closed(
    tmp_path, expires_at, revoked_at
):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    legacy = _create_legacy_database(
        settings.db_path,
        expires_at=expires_at,
        revoked_at=revoked_at,
    )
    service = pilot.WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    try:
        with pytest.raises(WorkerControlPlaneError) as exc:
            service.register_worker(
                _registration_body(str(uuid.uuid4())), legacy["secret"]
            )
        assert (exc.value.code, exc.value.status) == (
            "invalid_credential",
            401,
        )
        assert legacy["secret"] not in str(exc.value)
        assert service.store.conn.execute(
            "SELECT count(*) FROM worker_instances"
        ).fetchone()[0] == 1
    finally:
        service.close()


def test_provisioning_refuses_unrevoked_credential_without_rotation(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    service = pilot.WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    try:
        first = service.provision_worker(ttl_seconds=900, single_use=True)
        with pytest.raises(ValueError, match="unrevoked bootstrap"):
            service.provision_worker(ttl_seconds=900, single_use=True)
        rows = service.list_bootstrap_credentials("server-a-worker")
        assert len(rows) == 1
        assert rows[0]["credential_id"] == first["credential_id"]
        assert rows[0]["state"] == "active"
    finally:
        service.close()


def test_provisioning_output_is_explicit_and_confined(tmp_path):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    outside = tmp_path / "outside.secret"
    with pytest.raises(ValueError, match="direct pilot-root"):
        pilot.provision_local_worker(settings, outside)
    assert not outside.exists()
    with pytest.raises(ValueError, match="destination already exists"):
        destination = settings.approved_test_root / "existing.secret"
        destination.write_text("do-not-overwrite", encoding="utf-8")
        destination.chmod(0o600)
        pilot.provision_local_worker(settings, destination)
    assert destination.read_text(encoding="utf-8") == "do-not-overwrite"


def test_commissioning_admin_cli_requires_exact_safe_arguments(tmp_path):
    parser = pilot.build_parser()
    output = tmp_path / "commissioning.secret"
    provision = parser.parse_args(
        [
            "provision",
            "--output",
            str(output),
            "--ttl-seconds",
            "900",
        ]
    )
    assert provision.output == output
    assert provision.ttl_seconds == 900
    with pytest.raises(SystemExit):
        parser.parse_args(["provision", "--ttl-seconds", "900"])
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["provision", "--output", str(output), "--ttl-seconds", "901"]
        )

    credential_id = str(uuid.uuid4())
    credential = parser.parse_args(
        [
            "bootstrap",
            "revoke",
            "--worker-id",
            "server-a-worker",
            "--credential-id",
            credential_id,
        ]
    )
    assert credential.credential_id == credential_id

    instance_id = str(uuid.uuid4())
    registration_id = str(uuid.uuid4())
    registration = parser.parse_args(
        [
            "registration",
            "revoke",
            "--worker-id",
            "server-a-worker",
            "--instance-id",
            instance_id,
            "--registration-id",
            registration_id,
        ]
    )
    assert registration.instance_id == instance_id
    assert registration.registration_id == registration_id


def test_provision_cli_prints_only_safe_metadata(monkeypatch, tmp_path, capsys):
    settings = pilot.pilot_test_settings(tmp_path / "pilot")
    destination = settings.approved_test_root / "commissioning.secret"
    monkeypatch.setattr(pilot, "pilot_settings", lambda: settings)

    assert pilot.main(
        [
            "provision",
            "--output",
            str(destination),
            "--ttl-seconds",
            "900",
        ]
    ) == 0

    report = json.loads(capsys.readouterr().out)
    secret = destination.read_text(encoding="utf-8")
    assert set(report) == {
        "credential_id",
        "expires_at",
        "single_use",
        "transfer_file_sha256",
    }
    assert secret not in json.dumps(report)
    assert report["transfer_file_sha256"] == pilot.hashlib.sha256(
        destination.read_bytes()
    ).hexdigest()
