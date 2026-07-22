"""Real-loopback tests for the standalone local Worker Control Plane pilot."""

from __future__ import annotations

import inspect
import os
import stat
import uuid

import pytest
from aiohttp import ClientSession
from aiohttp.test_utils import unused_port

from gateway.worker_control_plane import runtime as pilot


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_pilot_provisioning_uses_owner_only_files_and_safe_storage(tmp_path):
    data_dir = tmp_path / "pilot"
    settings = pilot.pilot_settings(data_dir)
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
        pilot.ensure_pilot_directory(linked)


def test_runtime_cli_has_configurable_port_but_no_host_option():
    parser = pilot.build_parser()
    parsed = parser.parse_args(["serve", "--port", "9876"])
    assert parsed.port == 9876
    assert pilot.LISTEN_ADDRESS == "127.0.0.1"
    with pytest.raises(SystemExit):
        parser.parse_args(["serve", "--host", "0.0.0.0"])


@pytest.mark.asyncio
async def test_real_loopback_http_system_echo_lifecycle(tmp_path):
    settings = pilot.pilot_settings(tmp_path / "pilot")
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
