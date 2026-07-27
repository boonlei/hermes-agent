"""Behavioral tests for the isolated, test-only Worker Control Plane."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.worker_control_plane.app import (
    _http_failure,
    create_worker_control_plane_app,
)
from gateway.worker_control_plane.config import WorkerControlPlaneSettings
from gateway.worker_control_plane.errors import WorkerControlPlaneError
from gateway.worker_control_plane.models import (
    CODEX_EXECUTE_MAX_INSTRUCTION_BYTES,
    CODEX_EXECUTE_MAX_RESULT_BYTES,
    validate_capabilities,
    validate_codex_execute_payload,
    validate_codex_execute_result,
)
from gateway.worker_control_plane.service import WorkerControlPlaneService
from tests.gateway.worker_control_plane_helpers import MockWorkerClient


class MutableTestClock:
    def __init__(self):
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += timedelta(seconds=seconds)


@pytest_asyncio.fixture
async def control_plane(tmp_path):
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db", approved_test_root=tmp_path
    )
    service = WorkerControlPlaneService(settings, clock=MutableTestClock())
    secret = service.seed_test_worker()
    app = create_worker_control_plane_app(settings, service)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        yield service, client, secret
    finally:
        await client.close()
        service.close()


def _codex_payload(**overrides):
    payload = {
        "path_id": "hermes-server-worker",
        "mode": "read_only",
        "instruction": "Inspect the repository and report findings without changes.",
        "timeout_seconds": 60,
    }
    payload.update(overrides)
    return payload


def _codex_inner(
    *,
    status="completed",
    classification="success",
    failure_code=None,
    summary="bounded test result",
    exit_code=0,
    duration_ms=0,
    guards=None,
    truncated=None,
):
    result = {
        "status": status,
        "classification": classification,
        "failure_code": failure_code,
        "summary": summary,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "guards": {"read_only": True} if guards is None else guards,
    }
    if truncated is not None:
        result["truncated"] = truncated
    return json.dumps(
        result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


GOLDEN_VECTOR_DIRECTORY = (
    Path(__file__).parent
    / "fixtures"
    / "worker_control_plane"
    / "codex_execute_v1"
)
GOLDEN_FIXTURE_NAMES = {
    "capability_registration.json",
    "duplicate_result.json",
    "poll_request_invalid_extra_field.json",
    "poll_request_valid.json",
    "result_completed.json",
    "result_failed.json",
    "result_rejected.json",
    "result_timed_out.json",
}


def _canonical_json_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _load_golden_fixture(name):
    return json.loads(
        (GOLDEN_VECTOR_DIRECTORY / name).read_text(encoding="utf-8")
    )


@pytest_asyncio.fixture
async def codex_control_plane(tmp_path):
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db", approved_test_root=tmp_path
    )
    service = WorkerControlPlaneService(settings, clock=MutableTestClock())
    provisioned = service.provision_worker(
        capabilities=["system.echo", "codex.execute"]
    )
    app = create_worker_control_plane_app(settings, service)
    server = TestServer(app)
    client = TestClient(server)
    await client.start_server()
    try:
        yield service, client, provisioned
    finally:
        await client.close()
        service.close()


@pytest.mark.asyncio
async def test_health_is_public_safe_and_read_only(control_plane):
    service, client, _ = control_plane
    changes_before = service.store.conn.total_changes
    audit_before = service.store.conn.execute(
        "SELECT count(*) FROM worker_audit_log"
    ).fetchone()[0]

    response = await client.get("/health")

    assert response.status == 200
    assert response.content_type == "application/json"
    assert await response.json() == {"status": "ok"}
    assert service.store.conn.total_changes == changes_before
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_audit_log"
    ).fetchone()[0] == audit_before


@pytest.mark.asyncio
async def test_health_rejects_head_without_mutation(control_plane):
    service, client, _ = control_plane
    changes_before = service.store.conn.total_changes
    audit_before = service.store.conn.execute(
        "SELECT count(*) FROM worker_audit_log"
    ).fetchone()[0]

    response = await client.head("/health")

    assert response.status == 405
    assert response.content_type == "application/json"
    assert response.headers["Allow"] == "GET"
    assert service.store.conn.total_changes == changes_before
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_audit_log"
    ).fetchone()[0] == audit_before


def test_health_head_error_representation_is_safe_json():
    response = _http_failure(web.HTTPMethodNotAllowed("HEAD", {"GET"}))

    body = json.loads(response.body)
    assert response.status == 405
    assert response.content_type == "application/json"
    assert response.headers["Allow"] == "GET"
    assert set(body) == {"error"}
    assert set(body["error"]) == {
        "code",
        "message",
        "retryable",
        "trace_id",
    }
    assert body["error"]["code"] == "method_not_allowed"
    assert body["error"]["retryable"] is False


@pytest.mark.asyncio
async def test_http_routing_errors_preserve_status_and_safe_json(control_plane):
    _, client, _ = control_plane

    response = await client.post("/health")
    assert response.status == 405
    assert (await response.json())["error"]["code"] == "method_not_allowed"

    response = await client.get("/missing")
    assert response.status == 404
    assert (await response.json())["error"]["code"] == "not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    (
        "/worker/v1/register",
        "/worker/v1/heartbeat",
        "/worker/v1/tasks/poll",
        f"/worker/v1/tasks/{uuid.uuid4()}/ack",
        f"/worker/v1/tasks/{uuid.uuid4()}/result",
    ),
)
async def test_worker_protocol_routes_remain_post_only(control_plane, path):
    _, client, _ = control_plane

    response = await client.get(path)

    assert response.status == 405
    assert (await response.json())["error"]["code"] == "method_not_allowed"


@pytest.mark.asyncio
async def test_real_internal_exception_is_redacted_and_returns_503(tmp_path):
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db", approved_test_root=tmp_path
    )
    service = WorkerControlPlaneService(settings, clock=MutableTestClock())
    app = create_worker_control_plane_app(settings, service)

    async def fail(_request):
        raise RuntimeError("sensitive internal detail")

    app.router.add_get("/fail", fail)
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        response = await client.get("/fail")
        body = await response.json()
        assert response.status == 503
        assert body["error"]["code"] == "internal_error"
        assert body["error"]["retryable"] is True
        assert "sensitive internal detail" not in str(body)
    finally:
        await client.close()
        service.close()


@pytest.mark.asyncio
async def test_health_storage_failure_fails_closed(control_plane, monkeypatch):
    service, client, _ = control_plane

    def fail():
        raise RuntimeError("sensitive database detail")

    monkeypatch.setattr(service.store, "check_health", fail)
    response = await client.get("/health")
    body = await response.json()
    assert response.status == 503
    assert body["error"]["code"] == "internal_error"
    assert body["error"]["retryable"] is True
    assert "sensitive database detail" not in str(body)


def _register_direct_test_worker(service):
    secret = service.seed_test_worker()
    instance_id = str(uuid.uuid4())
    status, response = service.register_worker(
        {
            "protocol_version": "1.0",
            "worker_id": "server-a-worker",
            "instance_id": instance_id,
            "worker_name": "test worker",
            "worker_version": "0.1.0",
            "capabilities": ["system.echo"],
        },
        secret,
    )
    assert status == 201
    identity = {
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
        "registration_id": response["registration_id"],
    }
    return identity, response["access_token"]


def _direct_poll(service, identity, token, key):
    return service.poll_one_task(
        identity
        | {
            "capabilities": ["system.echo"],
            "max_tasks": 1,
            "wait_seconds": 0,
        },
        token,
        key,
    )


def _direct_temporary_nack(service, identity, token, task, key):
    return service.ack_delivery(
        task["task_id"],
        identity
        | {
            "delivery_id": task["delivery_id"],
            "accepted": False,
            "reason": "temporary",
            "worker_time": "2026-01-01T00:00:00Z",
        },
        token,
        key,
    )


@pytest.mark.asyncio
async def test_full_echo_lifecycle_and_idempotent_result(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    task_id = service.create_test_echo_task({"message": "你好 🌍"}, "create-1")
    assert (await worker.heartbeat())[0] == 200
    status, envelope = await worker.poll()
    assert status == 200
    task = envelope["task"]
    assert task["task_id"] == task_id
    assert (await worker.ack(task))[0] == 200
    status, body = await worker.result(task)
    assert status == 200 and body["task_state"] == "completed"
    status, replay = await worker.result(task)
    assert status == 200 and replay == body
    assert service.task_state(task_id) == "completed"
    assert service.result_count(task_id) == 1


@pytest.mark.asyncio
async def test_registration_auth_capability_and_instance_guards(control_plane):
    service, client, secret = control_plane
    bad = MockWorkerClient(client, "not-the-secret")
    assert (await bad.register())[0] == 401
    unknown = MockWorkerClient(client, secret, worker_id="unknown-worker")
    assert (await unknown.register())[0] == 401
    worker = MockWorkerClient(client, secret)
    assert (await worker.register(capabilities=["codex.task"]))[0] == 422
    assert (await worker.register(protocol_version="2.0"))[0] == 422
    assert (await worker.register())[0] == 201
    worker.bootstrap_secret = service.provision_worker()["secret"]
    assert (await worker.register())[0] == 200
    second = MockWorkerClient(
        client, service.provision_worker()["secret"]
    )
    assert (await second.register())[0] == 409


@pytest.mark.asyncio
async def test_register_failure_has_correlated_safe_audit_evidence(
    control_plane
):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    registration_id = worker.registration_id
    service.revoke_registration(
        "server-a-worker", worker.instance_id, registration_id
    )
    service.store.conn.execute(
        "UPDATE worker_instances SET protocol_version='2.0' "
        "WHERE registration_id=?",
        (registration_id,),
    )
    service.store.conn.commit()
    provisioned = service.provision_worker()

    response = await client.post(
        "/worker/v1/register",
        headers={
            "Authorization": f"Worker-Bootstrap {provisioned['secret']}"
        },
        json={
            "protocol_version": "1.0",
            "worker_id": "server-a-worker",
            "instance_id": worker.instance_id,
            "worker_name": "test worker",
            "worker_version": "0.1.0",
            "capabilities": ["system.echo"],
        },
    )
    body = await response.json()

    assert response.status == 409
    assert body["error"]["code"] == "instance_conflict"
    assert body["error"]["trace_id"] == response.headers["X-Request-ID"]
    audit_id = int(response.headers["X-Audit-Event-ID"])
    audit = service.store.conn.execute(
        "SELECT * FROM worker_audit_log WHERE audit_id=?", (audit_id,)
    ).fetchone()
    details = json.loads(audit["details_json"])
    assert audit["event_type"] == "registration_rejected"
    assert audit["outcome"] == "rejected"
    assert audit["reason_code"] == "instance_conflict"
    assert details == {
        "credential_id": provisioned["credential_id"],
        "error_code": "instance_conflict",
        "http_status": 409,
        "instance_id": worker.instance_id,
        "registration_lifecycle_outcome": "immutable_metadata_conflict",
        "request_id": response.headers["X-Request-ID"],
        "worker_id": "server-a-worker",
    }
    bootstrap = service.store.conn.execute(
        "SELECT consumed_at,revoked_at FROM worker_credentials "
        "WHERE credential_id=?",
        (provisioned["credential_id"],),
    ).fetchone()
    assert bootstrap["consumed_at"] is None
    assert bootstrap["revoked_at"] is None
    registration = service.store.conn.execute(
        "SELECT status FROM worker_instances WHERE registration_id=?",
        (registration_id,),
    ).fetchone()
    assert registration["status"] == "revoked"
    audit_text = service.audit_text()
    credential_rows = service.store.conn.execute(
        "SELECT token_hash,salt FROM worker_credentials"
    ).fetchall()
    forbidden = [
        provisioned["secret"],
        worker.access_token,
        f"Worker-Bootstrap {provisioned['secret']}",
    ]
    forbidden.extend(value for row in credential_rows for value in row if value)
    assert all(value not in audit_text for value in forbidden)
    assert "worker_name" not in audit_text
    assert "capabilities" not in audit_text


@pytest.mark.asyncio
@pytest.mark.parametrize("delivery_state", ("leased", "acknowledged"))
async def test_reactivation_invalidates_prior_lifecycle_delivery(
    control_plane, delivery_state
):
    service, _, secret = control_plane
    worker = MockWorkerClient(control_plane[1], secret)
    assert (await worker.register())[0] == 201
    task_id = service.create_test_echo_task(
        {"message": "lifecycle boundary"}, f"create-{delivery_state}"
    )
    status, envelope = await worker.poll(f"poll-{delivery_state}")
    assert status == 200
    task = envelope["task"]
    if delivery_state == "acknowledged":
        assert (await worker.ack(task, key="old-lifecycle-ack"))[0] == 200

    service.revoke_registration(
        "server-a-worker", worker.instance_id, worker.registration_id
    )
    worker.bootstrap_secret = service.provision_worker()["secret"]
    assert (await worker.register())[0] == 200

    delivery = service.store.conn.execute(
        "SELECT state FROM worker_deliveries WHERE delivery_id=?",
        (task["delivery_id"],),
    ).fetchone()
    assert delivery["state"] == "expired"
    assert service.task_state(task_id) == "queued"
    assert service.result_count(task_id) == 0
    status, new_envelope = await worker.poll(f"poll-{delivery_state}")
    assert status == 200
    assert new_envelope["task"]["task_id"] == task_id
    assert new_envelope["task"]["delivery_id"] != task["delivery_id"]
    if delivery_state == "leased":
        status, body = await worker.ack(task, key="new-lifecycle-old-ack")
    else:
        status, body = await worker.ack(task, key="old-lifecycle-ack")
        assert status == 410
        assert body["error"]["code"] == "lease_expired"
        status, body = await worker.result(
            task,
            result_key="new-lifecycle-old-result",
            request_key="new-lifecycle-old-result-request",
        )
    assert status == 410
    assert body["error"]["code"] == "lease_expired"
    assert "registration_delivery_invalidated" in service.audit_text()


@pytest.mark.asyncio
async def test_poll_ack_result_validation_and_fifo(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    await worker.register()
    assert (await worker.poll())[0] == 204
    first = service.create_test_echo_task({"message": "first"}, "fifo-1")
    service.create_test_echo_task({"message": "second"}, "fifo-2")
    status, envelope = await worker.poll("same-poll")
    assert status == 200 and envelope["task"]["task_id"] == first
    status2, replay = await worker.poll("same-poll")
    assert status2 == 200 and replay["task"]["delivery_id"] == envelope["task"]["delivery_id"]
    task = envelope["task"]
    assert (await worker.ack(task))[0] == 200
    wrong_hash = dict(task)
    wrong_hash["payload_hash"] = "0" * 64
    assert (await worker.result(wrong_hash))[0] == 422
    assert (await worker.result(task, stdout="not echo", result_key="bad-result", request_key="bad-request"))[0] == 422
    assert (await worker.result(task))[0] == 200


@pytest.mark.asyncio
async def test_negative_ack_expiry_redelivery_and_dead_letter(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    await worker.register()
    task_id = service.create_test_echo_task({"message": "retry"}, "retry-1")
    _, env = await worker.poll("p1")
    task = env["task"]
    assert (await worker.ack(task, accepted=False, reason="temporary", key="a1"))[0] == 200
    _, env = await worker.poll("p2")
    task = env["task"]
    service.advance_for_test(120)
    service.reap_expired_deliveries()
    assert service.task_state(task_id) == "queued"
    for index in range(3):
        _, env = await worker.poll(f"expire-{index}")
        if env is None:
            break
        service.advance_for_test(120)
        service.reap_expired_deliveries()
    assert service.task_state(task_id) == "dead_letter"


@pytest.mark.asyncio
async def test_wrong_registration_revocation_and_size_limits_are_safe(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    await worker.register()
    task_id = service.create_test_echo_task({"message": "x"}, "size-1")
    _, env = await worker.poll()
    task = env["task"]
    original = worker.registration_id
    worker.registration_id = str(uuid.uuid4())
    assert (await worker.heartbeat())[0] == 409
    worker.registration_id = original
    assert (await worker.ack(task))[0] == 200
    assert (await worker.result(task, stdout="x" * 5000))[0] == 413
    service.revoke_test_worker()
    assert (await worker.heartbeat())[0] == 403
    audit = service.audit_text()
    assert secret not in audit and (worker.access_token or "") not in audit
    assert service.task_state(task_id) == "running"


def test_closed_echo_schema_and_no_production_dependencies(tmp_path):
    from gateway.worker_control_plane.models import validate_system_echo_payload
    from gateway.worker_control_plane import app, auth, service, storage

    assert validate_system_echo_payload({"message": "x"}) == {"message": "x"}
    for invalid in ({}, {"message": ""}, {"message": ["x"]}, {"message": "x", "command": "id"}):
        with pytest.raises(ValueError):
            validate_system_echo_payload(invalid)
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "x.db", approved_test_root=tmp_path
    )
    with pytest.raises(ValueError):
        create_worker_control_plane_app(
            WorkerControlPlaneSettings(
                False, True, tmp_path / "x2.db", approved_test_root=tmp_path
            )
        )
    source = "\n".join(inspect.getsource(module) for module in (app, auth, service, storage))
    for forbidden in ("subprocess", "os.system", "kanban.db", "SessionDB", "state.db", "C:\\\\HermesServerWorker", "/v1/runs"):
        assert forbidden not in source


@pytest.mark.asyncio
async def test_closed_schema_ack_deadline_and_idempotency_conflicts(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    body = worker.base() | {"capabilities": ["system.echo"], "max_tasks": 1, "wait_seconds": 0, "extra": True}
    response = await client.post("/worker/v1/tasks/poll", headers=worker.headers("closed"), json=body)
    assert response.status == 400
    task_id = service.create_test_echo_task({"message": "deadline"}, "deadline-create")
    _, envelope = await worker.poll("deadline-poll")
    task = envelope["task"]
    service.advance_for_test(11)
    assert (await worker.ack(task, key="deadline-ack"))[0] == 410
    assert service.task_state(task_id) == "queued"
    _, envelope = await worker.poll("redelivery-poll")
    task = envelope["task"]
    assert (await worker.ack(task, key="same-key"))[0] == 200
    conflicting = worker.base() | {"delivery_id": task["delivery_id"], "accepted": False, "reason": "temporary", "worker_time": "2026-01-01T00:00:00Z"}
    response = await client.post(f"/worker/v1/tasks/{task_id}/ack", headers=worker.headers("same-key"), json=conflicting)
    assert response.status == 409
    wrong_body = worker.base() | {"task_id": str(uuid.uuid4()), "delivery_id": task["delivery_id"], "task_type": "system.echo", "status": "completed", "stdout": "deadline", "stderr": "", "exit_code": 0, "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:00Z", "duration_ms": 0, "result_idempotency_key": "wrong-task", "payload_hash": task["payload_hash"], "trace_id": task["trace_id"]}
    response = await client.post(f"/worker/v1/tasks/{task_id}/result", headers=worker.headers("wrong-task-request"), json=wrong_body)
    assert response.status == 422


def test_test_settings_reject_non_temporary_database_path():
    with pytest.raises(ValueError):
        WorkerControlPlaneSettings.for_test(
            __import__("pathlib").Path("/home/boonl/not-test-worker.db"),
            approved_test_root=__import__("pathlib").Path("/tmp"),
        )


def test_sqlite_path_is_confined_to_explicit_approved_root(tmp_path):
    approved = tmp_path / "approved"
    approved.mkdir()
    valid = approved / "worker-control-plane.db"
    settings = WorkerControlPlaneSettings.for_test(valid, approved_test_root=approved)
    assert settings.db_path == valid.resolve()
    assert settings.approved_test_root == approved.resolve()

    outside = tmp_path / "outside.db"
    with pytest.raises(ValueError):
        WorkerControlPlaneSettings.for_test(outside, approved_test_root=approved)
    assert not outside.exists()

    traversal = approved / "nested" / ".." / "escape.db"
    with pytest.raises(ValueError):
        WorkerControlPlaneSettings.for_test(traversal, approved_test_root=approved)
    assert not traversal.resolve().exists()


def test_sqlite_path_rejects_symlink_escape_and_production_like_names(tmp_path):
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = approved / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    escaped = link / "worker-control-plane.db"
    with pytest.raises(ValueError):
        WorkerControlPlaneSettings.for_test(escaped, approved_test_root=approved)
    assert not (outside / "worker-control-plane.db").exists()

    production = approved / ".hermes" / "state.db"
    with pytest.raises(ValueError):
        WorkerControlPlaneSettings.for_test(production, approved_test_root=approved)
    assert not production.exists()
    assert not production.parent.exists()


def test_store_revalidates_path_after_delayed_symlink_escape(tmp_path):
    from gateway.worker_control_plane.storage import WorkerControlPlaneStore

    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    child = approved / "child"
    outside_db = outside / "worker-control-plane.db"
    settings = WorkerControlPlaneSettings.for_test(
        child / "worker-control-plane.db", approved_test_root=approved
    )

    try:
        os.symlink(outside, child, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")

    with pytest.raises(ValueError):
        WorkerControlPlaneStore(settings)
    assert not outside_db.exists()


def test_store_connect_time_revalidation_accepts_unchanged_path(tmp_path):
    from gateway.worker_control_plane.storage import WorkerControlPlaneStore

    approved = tmp_path / "approved"
    approved.mkdir()
    child = approved / "child"
    db_path = child / "worker-control-plane.db"
    settings = WorkerControlPlaneSettings.for_test(
        db_path, approved_test_root=approved
    )
    child.mkdir()

    store = WorkerControlPlaneStore(settings)
    try:
        assert db_path.exists()
    finally:
        store.close()


def test_store_and_service_require_test_mode(tmp_path):
    from gateway.worker_control_plane.storage import WorkerControlPlaneStore

    with pytest.raises(ValueError):
        settings = WorkerControlPlaneSettings(
            enabled=True,
            test_mode=False,
            db_path=tmp_path / "disabled.db",
            approved_test_root=tmp_path,
        )
        WorkerControlPlaneService(settings)
    assert not (tmp_path / "disabled.db").exists()

    with pytest.raises((TypeError, ValueError)):
        WorkerControlPlaneStore(tmp_path / "direct.db")
    assert not (tmp_path / "direct.db").exists()


@pytest.mark.asyncio
async def test_idempotency_key_binds_endpoint_and_empty_poll(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201

    assert (await worker.poll("empty-replay"))[0] == 204
    service.create_test_echo_task({"message": "later"}, "empty-later")
    assert (await worker.poll("empty-replay"))[0] == 204

    _, envelope = await worker.poll("lease-later")
    task = envelope["task"]
    status, body = await worker.ack(task, key="empty-replay")
    assert status == 409
    assert body["error"]["code"] == "idempotency_conflict"


@pytest.mark.asyncio
async def test_idempotency_key_binds_body_registration_and_task(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    assert (await worker.poll("identity-key"))[0] == 204

    changed_registration = worker.base() | {
        "registration_id": str(uuid.uuid4()),
        "capabilities": ["system.echo"],
        "max_tasks": 1,
        "wait_seconds": 0,
    }
    response = await client.post(
        "/worker/v1/tasks/poll",
        headers=worker.headers("identity-key"),
        json=changed_registration,
    )
    body = await response.json()
    assert response.status == 409
    assert body["error"]["code"] == "idempotency_conflict"

    first = service.create_test_echo_task({"message": "first"}, "task-key-first")
    _, first_envelope = await worker.poll("first-lease")
    assert first_envelope["task"]["task_id"] == first
    assert (await worker.ack(first_envelope["task"], accepted=False, reason="permanent", key="task-bound"))[0] == 200

    second = service.create_test_echo_task({"message": "second"}, "task-key-second")
    _, second_envelope = await worker.poll("second-lease")
    assert second_envelope["task"]["task_id"] == second
    status, body = await worker.ack(second_envelope["task"], accepted=False, reason="permanent", key="task-bound")
    assert status == 409
    assert body["error"]["code"] == "idempotency_conflict"


@pytest.mark.asyncio
async def test_result_http_idempotency_replays_and_conflicts_before_mutation(control_plane):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    service.create_test_echo_task({"message": "one"}, "result-one")
    _, envelope = await worker.poll("result-poll-one")
    task = envelope["task"]
    assert (await worker.ack(task, key="result-ack-one"))[0] == 200

    status, accepted = await worker.result(task, result_key="body-result-one", request_key="http-result-key")
    assert status == 200 and accepted["duplicate"] is False
    status, replay = await worker.result(task, result_key="body-result-one", request_key="http-result-key")
    assert status == 200 and replay == accepted

    changed = worker.base() | {
        "task_id": task["task_id"],
        "delivery_id": task["delivery_id"],
        "task_type": "system.echo",
        "status": "failed",
        "stdout": "changed",
        "stderr": "",
        "exit_code": 1,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:00Z",
        "duration_ms": 1,
        "result_idempotency_key": "body-result-changed",
        "payload_hash": task["payload_hash"],
        "trace_id": task["trace_id"],
    }
    response = await client.post(
        f'/worker/v1/tasks/{task["task_id"]}/result',
        headers=worker.headers("http-result-key"),
        json=changed,
    )
    body = await response.json()
    assert response.status == 409
    assert body["error"]["code"] == "idempotency_conflict"

    service.create_test_echo_task({"message": "two"}, "result-two")
    _, envelope = await worker.poll("result-poll-two")
    second = envelope["task"]
    assert (await worker.ack(second, key="result-ack-two"))[0] == 200
    status, body = await worker.result(second, result_key="body-result-two", request_key="http-result-key")
    assert status == 409
    assert body["error"]["code"] == "idempotency_conflict"
    assert service.task_state(second["task_id"]) == "running"


@pytest.mark.asyncio
@pytest.mark.parametrize(("field", "value"), (("max_tasks", True), ("wait_seconds", False)))
async def test_poll_rejects_boolean_integer_fields(control_plane, field, value):
    _, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    body = worker.base() | {"capabilities": ["system.echo"], "max_tasks": 1, "wait_seconds": 0}
    body[field] = value
    response = await client.post("/worker/v1/tasks/poll", headers=worker.headers(f"bool-{field}"), json=body)
    assert response.status == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("current_task_id", ("not-a-uuid", {"task_id": str(uuid.uuid4()), "extra": True}))
async def test_heartbeat_rejects_invalid_or_nested_current_task_id(control_plane, current_task_id):
    _, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    status, _ = await worker.heartbeat(current_task_id=current_task_id)
    assert status == 400


@pytest.mark.asyncio
@pytest.mark.parametrize(("field", "value"), (("exit_code", True), ("duration_ms", False)))
async def test_result_rejects_boolean_integer_fields(control_plane, field, value):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    service.create_test_echo_task({"message": "types"}, f"types-{field}")
    _, envelope = await worker.poll(f"types-poll-{field}")
    task = envelope["task"]
    assert (await worker.ack(task, key=f"types-ack-{field}"))[0] == 200
    body = worker.base() | {
        "task_id": task["task_id"],
        "delivery_id": task["delivery_id"],
        "task_type": "system.echo",
        "status": "failed",
        "stdout": "",
        "stderr": "",
        "exit_code": 1,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:00Z",
        "duration_ms": 1,
        "result_idempotency_key": f"types-result-{field}",
        "payload_hash": task["payload_hash"],
        "trace_id": task["trace_id"],
    }
    body[field] = value
    response = await client.post(
        f'/worker/v1/tasks/{task["task_id"]}/result',
        headers=worker.headers(f"types-http-{field}"),
        json=body,
    )
    assert response.status == 422


@pytest.mark.asyncio
async def test_missing_null_and_unknown_fields_are_deterministic(control_plane):
    _, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    base = worker.base() | {"status": "idle", "current_task_id": None, "worker_time": "2026-01-01T00:00:00Z"}
    missing = dict(base)
    missing.pop("status")
    extra = base | {"extra": {"nested": True}}
    wrong_null = base | {"status": None}
    for body in (missing, extra, wrong_null):
        response = await client.post("/worker/v1/heartbeat", headers=worker.headers(), json=body)
        assert response.status == 400


@pytest.mark.asyncio
async def test_temporary_nack_cannot_exceed_retry_limit(control_plane):
    service, _, secret = control_plane
    worker = MockWorkerClient(control_plane[1], secret)
    assert (await worker.register())[0] == 201
    task_id = service.create_test_echo_task({"message": "bounded"}, "bounded-retry")
    for attempt in range(1, service.settings.max_attempts + 1):
        status, envelope = await worker.poll(f"bounded-poll-{attempt}")
        assert status == 200
        status, body = await worker.ack(
            envelope["task"],
            accepted=False,
            reason="temporary",
            key=f"bounded-ack-{attempt}",
        )
        assert status == 200
        expected = "queued" if attempt < service.settings.max_attempts else "dead_letter"
        assert body["task_state"] == expected
        assert service.task_state(task_id) == expected
    assert (await worker.poll("bounded-after"))[0] == 204
    assert service.store.conn.execute(
        "SELECT max(attempt) FROM worker_deliveries WHERE task_id=?", (task_id,)
    ).fetchone()[0] == service.settings.max_attempts
    assert "task_dead_lettered" in service.audit_text()


def test_temporary_nack_uses_persisted_limit_after_config_increase(tmp_path):
    db_path = tmp_path / "persisted-increase.db"
    initial_settings = WorkerControlPlaneSettings(
        enabled=True,
        test_mode=True,
        db_path=db_path,
        approved_test_root=tmp_path,
        max_attempts=2,
    )
    service = WorkerControlPlaneService(initial_settings)
    try:
        identity, token = _register_direct_test_worker(service)
        task_id = service.create_test_echo_task(
            {"message": "persisted increase"}, "persisted-increase-task"
        )
        first = _direct_poll(service, identity, token, "persisted-increase-poll-1")["task"]
        assert _direct_temporary_nack(
            service, identity, token, first, "persisted-increase-ack-1"
        )["task_state"] == "queued"
        second = _direct_poll(service, identity, token, "persisted-increase-poll-2")["task"]
        assert second["attempt"] == 2
    finally:
        service.close()

    reopened_settings = WorkerControlPlaneSettings(
        enabled=True,
        test_mode=True,
        db_path=db_path,
        approved_test_root=tmp_path,
        max_attempts=5,
    )
    reopened = WorkerControlPlaneService(reopened_settings)
    try:
        response = _direct_temporary_nack(
            reopened, identity, token, second, "persisted-increase-ack-2"
        )
        assert response["task_state"] == "dead_letter"
        assert reopened.task_state(task_id) == "dead_letter"
        assert "task_dead_lettered" in reopened.audit_text()
        assert _direct_poll(
            reopened, identity, token, "persisted-increase-after"
        ) is None
    finally:
        reopened.close()


def test_temporary_nack_uses_persisted_limit_after_config_decrease(tmp_path):
    db_path = tmp_path / "persisted-decrease.db"
    initial_settings = WorkerControlPlaneSettings(
        enabled=True,
        test_mode=True,
        db_path=db_path,
        approved_test_root=tmp_path,
        max_attempts=5,
    )
    service = WorkerControlPlaneService(initial_settings)
    try:
        identity, token = _register_direct_test_worker(service)
        task_id = service.create_test_echo_task(
            {"message": "persisted decrease"}, "persisted-decrease-task"
        )
        first = _direct_poll(service, identity, token, "persisted-decrease-poll-1")["task"]
        assert _direct_temporary_nack(
            service, identity, token, first, "persisted-decrease-ack-1"
        )["task_state"] == "queued"
        second = _direct_poll(service, identity, token, "persisted-decrease-poll-2")["task"]
        assert second["attempt"] == 2
    finally:
        service.close()

    reopened_settings = WorkerControlPlaneSettings(
        enabled=True,
        test_mode=True,
        db_path=db_path,
        approved_test_root=tmp_path,
        max_attempts=2,
    )
    reopened = WorkerControlPlaneService(reopened_settings)
    try:
        response = _direct_temporary_nack(
            reopened, identity, token, second, "persisted-decrease-ack-2"
        )
        assert response["task_state"] == "queued"
        assert reopened.task_state(task_id) == "queued"
    finally:
        reopened.close()


def test_access_token_verifier_uses_constant_time_digest_comparison(monkeypatch):
    from gateway.worker_control_plane import auth

    calls = []
    original = auth.hmac.compare_digest

    def tracked(left, right):
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(auth.hmac, "compare_digest", tracked)
    digest = auth.token_hash("opaque-access-token")
    assert auth.verify_access_token("opaque-access-token", digest) is True
    assert auth.verify_access_token("wrong-access-token", digest) is False
    assert len(calls) == 2
    assert all(len(left) == len(right) == 64 for left, right in calls)


@pytest.mark.asyncio
async def test_rejection_audits_persist_without_sensitive_values(control_plane):
    service, client, secret = control_plane
    bad = MockWorkerClient(client, "wrong-bootstrap-secret")
    assert (await bad.register())[0] == 401

    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    original_registration = worker.registration_id
    worker.registration_id = str(uuid.uuid4())
    assert (await worker.heartbeat())[0] == 409
    worker.registration_id = original_registration

    assert (await worker.poll("audit-conflict"))[0] == 204
    changed = worker.base() | {
        "registration_id": str(uuid.uuid4()),
        "capabilities": ["system.echo"],
        "max_tasks": 1,
        "wait_seconds": 0,
    }
    response = await client.post(
        "/worker/v1/tasks/poll",
        headers=worker.headers("audit-conflict"),
        json=changed,
    )
    assert response.status == 409

    task_id = service.create_test_echo_task({"message": "audit"}, "audit-task")
    _, envelope = await worker.poll("audit-lease")
    task = envelope["task"]
    service.advance_for_test(service.settings.ack_deadline_seconds)
    assert (await worker.ack(task, key="audit-late-ack"))[0] == 410

    _, envelope = await worker.poll("audit-redelivery")
    task = envelope["task"]
    assert (await worker.ack(task, key="audit-ack"))[0] == 200
    wrong_hash = dict(task)
    wrong_hash["payload_hash"] = "0" * 64
    assert (await worker.result(wrong_hash, request_key="audit-result"))[0] == 422
    service.revoke_test_worker()

    audit = service.audit_text()
    required = {
        "worker_revoked",
        "credential_failed",
        "registration_rejected",
        "idempotency_conflict",
        "heartbeat_rejected",
        "poll_rejected",
        "ack_rejected",
        "result_rejected",
    }
    assert all(event in audit for event in required)
    credential_rows = service.store.conn.execute(
        "SELECT token_hash,salt FROM worker_credentials"
    ).fetchall()
    forbidden = [secret, worker.access_token, "wrong-bootstrap-secret"]
    forbidden.extend(value for row in credential_rows for value in row if value)
    assert all(value not in audit for value in forbidden)
    assert "audit" not in audit
    assert service.task_state(task_id) == "running"


@pytest.mark.asyncio
async def test_ack_is_rejected_exactly_at_deadline(control_plane):
    service, _, secret = control_plane
    worker = MockWorkerClient(control_plane[1], secret)
    assert (await worker.register())[0] == 201
    task_id = service.create_test_echo_task({"message": "boundary"}, "ack-boundary")
    _, envelope = await worker.poll("ack-boundary-poll")
    service.advance_for_test(service.settings.ack_deadline_seconds)
    status, _ = await worker.ack(envelope["task"], key="ack-boundary-key")
    assert status == 410
    assert service.task_state(task_id) == "queued"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("path_id", "arbitrary-local-path"),
        ("mode", "write"),
        ("instruction", ""),
        ("instruction", "x" * (CODEX_EXECUTE_MAX_INSTRUCTION_BYTES + 1)),
        ("timeout_seconds", 59),
        ("timeout_seconds", 901),
        ("timeout_seconds", True),
    ),
)
def test_codex_execute_payload_rejects_non_allowlisted_values(
    field, value
):
    with pytest.raises(ValueError, match="invalid_task_payload"):
        validate_codex_execute_payload(_codex_payload(**{field: value}))


def test_codex_execute_instruction_accepts_exact_8192_utf8_bytes():
    payload = _codex_payload(
        instruction="é" * (CODEX_EXECUTE_MAX_INSTRUCTION_BYTES // 2)
    )

    assert validate_codex_execute_payload(payload) == payload


@pytest.mark.parametrize(
    "forbidden",
    (
        "shell",
        "command",
        "environment",
        "token",
        "target",
        "limits",
        "task_type",
        "max_result_bytes",
    ),
)
def test_codex_execute_payload_rejects_forbidden_fields(forbidden):
    payload = _codex_payload()
    payload[forbidden] = "forbidden"

    with pytest.raises(ValueError, match="invalid_task_payload"):
        validate_codex_execute_payload(payload)


@pytest.mark.parametrize(
    "capabilities",
    (
        ["codex.execute"],
        ["codex.execute", "system.echo"],
        ["system.echo", "codex.execute", "codex.execute"],
    ),
)
def test_codex_execute_capability_requires_exact_combined_scope(capabilities):
    with pytest.raises(ValueError, match="unsupported_capability"):
        validate_capabilities(capabilities)

    assert validate_capabilities(
        ["system.echo", "codex.execute"]
    ) == ["system.echo", "codex.execute"]


def test_codex_execute_golden_fixture_manifest_is_exact_and_canonical():
    manifest_path = GOLDEN_VECTOR_DIRECTORY / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))

    assert manifest_bytes == _canonical_json_bytes(manifest)
    assert manifest["fixture_version"] == "codex.execute.v1"
    assert set(manifest["fixtures"]) == GOLDEN_FIXTURE_NAMES
    assert {
        path.name for path in GOLDEN_VECTOR_DIRECTORY.glob("*.json")
    } == GOLDEN_FIXTURE_NAMES | {"manifest.json"}

    for name, metadata in manifest["fixtures"].items():
        raw = (GOLDEN_VECTOR_DIRECTORY / name).read_bytes()
        value = json.loads(raw.decode("utf-8"))
        assert not raw.startswith(b"\xef\xbb\xbf")
        assert raw == _canonical_json_bytes(value)
        assert len(raw) == metadata["utf8_bytes"]
        assert hashlib.sha256(raw).hexdigest() == metadata["sha256"]

    payload = _load_golden_fixture("poll_request_valid.json")
    payload_bytes = _canonical_json_bytes(payload)
    assert validate_codex_execute_payload(payload) == payload
    assert hashlib.sha256(payload_bytes).hexdigest() == (
        manifest["payload_hash"]
    )
    assert manifest["payload_hash"] == manifest["fixtures"][
        "poll_request_valid.json"
    ]["sha256"]

    capabilities = _load_golden_fixture("capability_registration.json")
    assert validate_capabilities(capabilities["capabilities"]) == [
        "system.echo",
        "codex.execute",
    ]

    for name, expected_status in {
        "result_completed.json": "completed",
        "result_failed.json": "failed",
        "result_rejected.json": "rejected",
        "result_timed_out.json": "timed_out",
    }.items():
        result = _load_golden_fixture(name)
        inner = validate_codex_execute_result(result["stdout"])
        assert result["status"] == expected_status
        assert result["stderr"] == ""
        assert result["status"] == inner["status"]
        assert result["exit_code"] == inner["exit_code"]
        assert result["duration_ms"] == inner["duration_ms"]
        assert result["payload_hash"] == manifest["payload_hash"]

    completed_bytes = (
        GOLDEN_VECTOR_DIRECTORY / "result_completed.json"
    ).read_bytes()
    duplicate_bytes = (
        GOLDEN_VECTOR_DIRECTORY / "duplicate_result.json"
    ).read_bytes()
    assert duplicate_bytes == completed_bytes
    assert hashlib.sha256(completed_bytes).hexdigest() == (
        manifest["result_hash"]
    )
    assert manifest["result_hash"] == manifest["fixtures"][
        "result_completed.json"
    ]["sha256"]

    invalid = _load_golden_fixture(
        "poll_request_invalid_extra_field.json"
    )
    with pytest.raises(ValueError, match="invalid_task_payload"):
        validate_codex_execute_payload(invalid)


@pytest.mark.parametrize(
    ("status", "failure_code"),
    (
        ("failed", "guard_rejected"),
        ("rejected", "codex_failed"),
        ("timed_out", "worker_error"),
    ),
)
def test_codex_execute_failure_codes_are_status_specific(
    status, failure_code
):
    with pytest.raises(ValueError, match="invalid_result"):
        validate_codex_execute_result(
            _codex_inner(
                status=status,
                failure_code=failure_code,
                exit_code=1,
            )
        )


@pytest.mark.parametrize(
    "stdout",
    (
        '{"status":"completed"} trailing',
        'prefix {"status":"completed"}',
        '{}{}',
        '{"classification":"success","duration_ms":0,"exit_code":0,'
        '"failure_code":null,"guards":{"read_only":true},'
        '"status":"completed","summary":"ok","extra":true}',
    ),
)
def test_codex_execute_result_requires_one_exact_closed_json_object(stdout):
    with pytest.raises(ValueError, match="invalid_result"):
        validate_codex_execute_result(stdout)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("vector_name", "expected_task_state"),
    (
        ("failed", "failed"),
        ("rejected", "rejected"),
        ("timed_out", "failed"),
    ),
)
async def test_codex_execute_noncompleted_golden_results_are_accepted(
    codex_control_plane, vector_name, expected_task_state
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    assert (await worker.register(
        capabilities=["system.echo", "codex.execute"]
    ))[0] == 201
    task_id = service.enqueue_codex_execute(
        _codex_payload(), f"golden-{vector_name}-task"
    )
    _, envelope = await worker.poll(f"golden-{vector_name}-poll")
    task = envelope["task"]
    assert (await worker.ack(
        task, key=f"golden-{vector_name}-ack"
    ))[0] == 200
    vector = _load_golden_fixture(f"result_{vector_name}.json")

    status, body = await worker.result(
        task,
        status=vector["status"],
        stdout=vector["stdout"],
        stderr=vector["stderr"],
        exit_code=vector["exit_code"],
        duration_ms=vector["duration_ms"],
        started_at=vector["started_at"],
        finished_at=vector["finished_at"],
        result_key=vector["result_idempotency_key"],
        request_key=f"golden-{vector_name}-result",
    )

    assert status == 200
    assert body["task_state"] == expected_task_state
    assert service.result_count(task_id) == 1
    assert (
        f'"safe_failure_code":'
        f'{json.dumps(json.loads(vector["stdout"])["failure_code"])}'
    ) in service.audit_text()


@pytest.mark.asyncio
async def test_codex_execute_capability_lifecycle_and_safe_audit(
    codex_control_plane, monkeypatch
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    capabilities = ["system.echo", "codex.execute"]
    assert (await worker.register(capabilities=capabilities))[0] == 201
    access_observations = []
    original_access = service.auth.access

    def access_inside_transaction(connection, token):
        access_observations.append(connection.in_transaction)
        return original_access(connection, token)

    monkeypatch.setattr(service.auth, "access", access_inside_transaction)
    assert (await worker.heartbeat())[0] == 200
    payload = _codex_payload(
        instruction="PRIVATE-INSTRUCTION-MUST-NOT-ENTER-AUDIT"
    )

    task_id = service.enqueue_codex_execute(payload, "codex-create-1")
    assert service.enqueue_codex_execute(payload, "codex-create-1") == task_id
    with pytest.raises(WorkerControlPlaneError) as exc:
        service.enqueue_codex_execute(
            _codex_payload(instruction="second"),
            "codex-create-2",
        )
    assert (exc.value.code, exc.value.status) == ("state_conflict", 409)

    status, body = await worker.poll(
        "codex-unauthorized-poll", capabilities=["system.echo"]
    )
    assert status == 422
    assert body["error"]["code"] == "unsupported_capability"

    status, envelope = await worker.poll("codex-poll")
    assert status == 200
    task = envelope["task"]
    assert task["task_id"] == task_id
    assert task["task_type"] == "codex.execute"
    assert task["payload_hash"] == service.store.conn.execute(
        "SELECT payload_hash FROM worker_tasks WHERE task_id=?", (task_id,)
    ).fetchone()["payload_hash"]
    assert (await worker.ack(task, key="codex-ack"))[0] == 200
    private_result = _codex_inner(
        summary="PRIVATE-RESULT-MUST-NOT-ENTER-AUDIT",
        duration_ms=125,
    )
    status, result = await worker.result(
        task,
        stdout=private_result,
        duration_ms=125,
        request_key="codex-result",
    )
    assert status == 200
    assert result["task_state"] == "completed"
    status, request_replay = await worker.result(
        task,
        stdout=private_result,
        duration_ms=125,
        request_key="codex-result",
    )
    assert status == 200
    assert request_replay == result
    status, result_replay = await worker.result(
        task,
        stdout=private_result,
        duration_ms=125,
        request_key="codex-result-retry",
    )
    assert status == 200
    assert result_replay["duplicate"] is True
    assert service.task_state(task_id) == "completed"
    assert service.result_count(task_id) == 1
    assert len(access_observations) >= 6
    assert all(access_observations)

    audit = service.audit_text()
    assert "PRIVATE-INSTRUCTION-MUST-NOT-ENTER-AUDIT" not in audit
    assert "PRIVATE-RESULT-MUST-NOT-ENTER-AUDIT" not in audit
    assert provisioned["secret"] not in audit
    assert worker.access_token not in audit
    assert '"path_id":"hermes-server-worker"' in audit
    assert '"mode":"read_only"' in audit
    assert f'"result_size_bytes":{len(private_result.encode())}' in audit


@pytest.mark.asyncio
async def test_codex_execute_result_identity_and_inner_schema_are_enforced(
    codex_control_plane
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    assert (await worker.register(
        capabilities=["system.echo", "codex.execute"]
    ))[0] == 201
    task_id = service.enqueue_codex_execute(
        _codex_payload(), "codex-result-validation"
    )
    _, envelope = await worker.poll("codex-result-poll")
    task = envelope["task"]
    assert task["task_id"] == task_id
    assert (await worker.ack(task, key="codex-result-ack"))[0] == 200

    status, body = await worker.result(
        task,
        stdout="not-json",
        request_key="codex-invalid-json",
    )
    assert status == 422
    assert body["error"]["code"] == "invalid_result"
    assert service.result_count(task_id) == 0

    mismatched = dict(task)
    mismatched["payload_hash"] = "0" * 64
    status, body = await worker.result(
        mismatched,
        stdout=_codex_inner(),
        request_key="codex-wrong-hash",
    )
    assert status == 422
    assert body["error"]["code"] == "invalid_result"
    assert service.result_count(task_id) == 0

    mismatched = dict(task)
    mismatched["trace_id"] = str(uuid.uuid4())
    status, body = await worker.result(
        mismatched,
        stdout=_codex_inner(),
        request_key="codex-wrong-trace",
    )
    assert status == 422
    assert body["error"]["code"] == "invalid_result"
    assert service.result_count(task_id) == 0

    mismatched_inner = _codex_inner(
        status="failed",
        classification="execution_failure",
        failure_code="codex_failed",
        exit_code=1,
        duration_ms=1,
    )
    status, body = await worker.result(
        task,
        stdout=mismatched_inner,
        status="completed",
        exit_code=0,
        duration_ms=1,
        request_key="codex-outer-inner-mismatch",
    )
    assert status == 422
    assert body["error"]["code"] == "invalid_result"
    assert service.result_count(task_id) == 0


@pytest.mark.asyncio
async def test_codex_execute_full_32k_result_contract_is_http_reachable(
    codex_control_plane
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    assert (await worker.register(
        capabilities=["system.echo", "codex.execute"]
    ))[0] == 201
    task_id = service.enqueue_codex_execute(
        _codex_payload(), "codex-http-result-capacity"
    )
    _, envelope = await worker.poll("codex-http-capacity-poll")
    task = envelope["task"]
    assert task["task_id"] == task_id
    assert (await worker.ack(task, key="codex-http-capacity-ack"))[0] == 200

    empty_summary = _codex_inner(summary="x")
    stdout = _codex_inner(
        summary="x" * (
            CODEX_EXECUTE_MAX_RESULT_BYTES
            - len(empty_summary.encode())
            + 1
        )
    )
    assert len(stdout.encode()) == CODEX_EXECUTE_MAX_RESULT_BYTES
    status, body = await worker.result(
        task,
        stdout=stdout,
        request_key="codex-http-capacity-result",
    )

    assert status == 200
    assert body["task_state"] == "completed"
    assert service.result_count(task_id) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stdout_size", "expected_status", "expected_results"),
    ((4096, 200, 1), (4097, 413, 0)),
)
async def test_system_echo_keeps_existing_4096_byte_stdout_limit(
    control_plane, stdout_size, expected_status, expected_results
):
    service, client, secret = control_plane
    worker = MockWorkerClient(client, secret)
    assert (await worker.register())[0] == 201
    message = "x" * 4096 if stdout_size == 4096 else "echo-limit"
    task_id = service.create_test_echo_task(
        {"message": message}, f"echo-limit-{stdout_size}"
    )
    _, envelope = await worker.poll(f"echo-limit-{stdout_size}-poll")
    task = envelope["task"]
    assert (await worker.ack(
        task, key=f"echo-limit-{stdout_size}-ack"
    ))[0] == 200

    status, _ = await worker.result(
        task,
        stdout="x" * stdout_size,
        status="completed" if stdout_size == 4096 else "failed",
        exit_code=0 if stdout_size == 4096 else 1,
        result_key=f"echo-limit-{stdout_size}",
        request_key=f"echo-limit-{stdout_size}-result",
    )

    assert status == expected_status
    assert service.result_count(task_id) == expected_results


@pytest.mark.asyncio
async def test_transport_oversize_is_413_not_malformed_request(
    codex_control_plane
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    assert (await worker.register(
        capabilities=["system.echo", "codex.execute"]
    ))[0] == 201
    task_id = service.enqueue_codex_execute(
        _codex_payload(), "codex-transport-oversize"
    )
    _, envelope = await worker.poll("codex-transport-oversize-poll")
    task = envelope["task"]
    assert (await worker.ack(task, key="codex-transport-oversize-ack"))[0] == 200
    body = worker.base() | {
        "task_id": task_id,
        "delivery_id": task["delivery_id"],
        "task_type": "codex.execute",
        "status": "completed",
        "stdout": "x" * 300000,
        "stderr": "",
        "exit_code": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:00Z",
        "duration_ms": 0,
        "result_idempotency_key": "transport-oversize",
        "payload_hash": task["payload_hash"],
        "trace_id": task["trace_id"],
    }

    response = await client.post(
        f"/worker/v1/tasks/{task_id}/result",
        headers=worker.headers("codex-transport-oversize-result"),
        json=body,
    )
    error_body = await response.json()

    assert response.status == 413
    assert error_body["error"]["code"] == "payload_too_large"
    assert service.result_count(task_id) == 0


@pytest.mark.asyncio
async def test_codex_execute_timing_stderr_and_outer_extra_field_are_strict(
    codex_control_plane
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    assert (await worker.register(
        capabilities=["system.echo", "codex.execute"]
    ))[0] == 201
    task_id = service.enqueue_codex_execute(
        _codex_payload(timeout_seconds=60),
        "codex-timing-strict",
    )
    _, envelope = await worker.poll("codex-timing-poll")
    task = envelope["task"]
    assert (await worker.ack(task, key="codex-timing-ack"))[0] == 200

    status, body = await worker.result(
        task,
        stdout=_codex_inner(duration_ms=1),
        duration_ms=1,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T01:00:00Z",
        request_key="codex-timing-mismatch",
    )
    assert status == 422
    assert body["error"]["code"] == "invalid_result"

    status, body = await worker.result(
        task,
        stdout=_codex_inner(),
        stderr="forbidden",
        request_key="codex-stderr",
    )
    assert status == 422
    assert body["error"]["code"] == "invalid_result"

    result_body = worker.base() | {
        "task_id": task_id,
        "delivery_id": task["delivery_id"],
        "task_type": "codex.execute",
        "status": "completed",
        "stdout": _codex_inner(),
        "stderr": "",
        "exit_code": 0,
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:00:00Z",
        "duration_ms": 0,
        "result_idempotency_key": "completed-null-failure",
        "payload_hash": task["payload_hash"],
        "trace_id": task["trace_id"],
        "failure_code": "top-level-forbidden",
    }
    response = await client.post(
        f"/worker/v1/tasks/{task_id}/result",
        headers=worker.headers("codex-null-failure-code"),
        json=result_body,
    )
    assert response.status == 400
    assert (await response.json())["error"]["code"] == "malformed_request"
    assert service.result_count(task_id) == 0


@pytest.mark.asyncio
async def test_codex_execute_lease_covers_declared_execution_timeout(
    codex_control_plane
):
    service, client, provisioned = codex_control_plane
    worker = MockWorkerClient(client, provisioned["secret"])
    assert (await worker.register(
        capabilities=["system.echo", "codex.execute"]
    ))[0] == 201
    task_id = service.enqueue_codex_execute(
        _codex_payload(timeout_seconds=120),
        "codex-long-execution",
    )
    _, envelope = await worker.poll("codex-long-poll")
    task = envelope["task"]
    assert (await worker.ack(task, key="codex-long-ack"))[0] == 200

    service.advance_for_test(61)
    status, body = await worker.result(
        task,
        stdout=_codex_inner(duration_ms=61000),
        duration_ms=61000,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:01:01Z",
        request_key="codex-long-result",
    )

    assert status == 200
    assert body["task_state"] == "completed"
    assert service.result_count(task_id) == 1


@pytest.mark.asyncio
async def test_echo_only_access_cannot_poll_codex_task(control_plane):
    service, _, secret = control_plane
    worker = MockWorkerClient(control_plane[1], secret)
    assert (await worker.register())[0] == 201
    task_id = service.enqueue_codex_execute(_codex_payload(), "codex-authz")

    status, body = await worker.poll(
        "codex-authz-poll", capabilities=["codex.execute"]
    )

    assert status == 422
    assert body["error"]["code"] == "unsupported_capability"
    assert service.task_state(task_id) == "queued"
