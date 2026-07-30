"""Security contract for the RC1 WCP commissioning operator path."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.worker_control_plane.app import create_worker_control_plane_app
from gateway.worker_control_plane.registration_v2 import (
    APPROVED_HEAD,
    BRANCH,
    CAPABILITIES,
    HOST,
    PATH_DIGEST,
    PATH_ID,
    REMOTE,
    build_handoff_envelope,
)
from gateway.worker_control_plane.runtime import (
    commissioning_postcheck,
    delete_verified_legacy_bootstrap_artifact,
    inspect_legacy_bootstrap_artifact,
    pilot_test_settings,
    provision_local_worker,
    provision_registration_v2_handoff,
)
from gateway.worker_control_plane.service import WorkerControlPlaneService
from gateway.worker_control_plane.errors import WorkerControlPlaneError


EXPECTED_HEAD = "ac8989ae9012ae70eb5f12d1a78260471b0a9728"
OLD_HEAD = "4092825b22184ad9820b4899b49fb1f833ac0b19"
WORKER_IP = "100.110.252.84"


def test_cross_repository_handoff_contract_fixture_is_generated_exactly():
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "registration_v2_handoff_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    row = {
        "registration_transaction_id": fixture[
            "registration_transaction_id"
        ],
        "worker_id": fixture["worker_id"],
        "instance_id": fixture["instance_id"],
        "bootstrap_credential_id": fixture[
            "bootstrap_credential_id"
        ],
        "bootstrap_binding_id": fixture["bootstrap_binding_id"],
        "host": fixture["host"],
        "path_id": fixture["path_id"],
        "path_digest": fixture["target_identity"]["path_digest"],
        "remote": fixture["target_identity"]["remote"],
        "branch": fixture["target_identity"]["branch"],
        "approved_head": fixture["target_identity"]["approved_head"],
        "capabilities_json": json.dumps(
            fixture["capabilities"], separators=(",", ":")
        ),
        "issued_at": fixture["issued_at"],
        "expires_at": fixture["expires_at"],
    }
    assert (
        build_handoff_envelope(row, fixture["bootstrap_secret"])
        == fixture
    )


def _settings(tmp_path):
    return pilot_test_settings(tmp_path / "pilot")


def _register_body(instance_id, transaction_id):
    return {
        "protocol_version": 2,
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
        "worker_name": "Hermes Server Worker",
        "worker_version": "1.0.0",
        "capabilities": list(CAPABILITIES),
        "host": HOST,
        "path_id": PATH_ID,
        "target_identity": {
            "path_digest": PATH_DIGEST,
            "remote": REMOTE,
            "branch": BRANCH,
            "approved_head": APPROVED_HEAD,
        },
        "registration_transaction_id": transaction_id,
    }


def _read_and_remove(path):
    value = path.read_text(encoding="ascii")
    path.unlink()
    return value


def _provision_and_retrieve(settings, instance_id, transaction_id):
    provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
        ttl_seconds=900,
    )
    service = WorkerControlPlaneService(settings)
    transfer = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    envelope = service.retrieve_registration_v2_handoff(
        transaction_id,
        "server-a-worker",
        instance_id,
        WORKER_IP,
        lambda _name: _read_and_remove(transfer),
    )
    return service, envelope


def test_authoritative_head_and_capabilities_are_exact():
    assert APPROVED_HEAD == EXPECTED_HEAD
    assert APPROVED_HEAD != OLD_HEAD
    assert CAPABILITIES == ["system.echo", "codex.execute"]


def test_register_requires_exact_retrieved_handoff(tmp_path):
    settings = _settings(tmp_path)
    service = WorkerControlPlaneService(settings)
    try:
        provisioned = service.provision_worker(
            ttl_seconds=900,
            single_use=True,
            capabilities=list(CAPABILITIES),
        )
        with pytest.raises(WorkerControlPlaneError) as rejected:
            service.register_worker_v2(
                _register_body(str(uuid.uuid4()), str(uuid.uuid4())),
                provisioned["secret"],
            )
        assert (rejected.value.code, rejected.value.status) == (
            "invalid_credential",
            401,
        )
        assert service.store.conn.execute(
            "SELECT COUNT(*) FROM worker_registration_transactions_v2"
        ).fetchone()[0] == 0
    finally:
        service.close()


@pytest.mark.asyncio
async def test_handoff_is_bound_single_use_and_secret_is_not_reported(
    tmp_path,
):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    report = provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
        ttl_seconds=900,
    )
    encoded = json.dumps(report, sort_keys=True)
    assert "secret" not in encoded.lower()
    assert report["capabilities"] == ["system.echo", "codex.execute"]
    assert report["target_identity"]["approved_head"] == EXPECTED_HEAD
    transfer = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    secret = transfer.read_text(encoding="ascii")
    service = WorkerControlPlaneService(settings)
    client = TestClient(
        TestServer(create_worker_control_plane_app(settings, service))
    )
    await client.start_server()
    params = {
        "registration_transaction_id": transaction_id,
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
    }
    try:
        wrong = await client.get(
            "/worker-control-plane/v2/registration/bootstrap",
            params=params,
            headers={"X-Forwarded-For": "100.110.252.85"},
        )
        assert wrong.status == 401
        assert transfer.exists()
        response = await client.get(
            "/worker-control-plane/v2/registration/bootstrap",
            params=params,
            headers={"X-Forwarded-For": WORKER_IP},
        )
        assert response.status == 200
        envelope = await response.json()
        assert envelope["bootstrap_secret"] == secret
        assert envelope["registration_transaction_id"] == transaction_id
        assert envelope["instance_id"] == instance_id
        assert envelope["capabilities"] == [
            "system.echo",
            "codex.execute",
        ]
        assert len(envelope["authentication_tag"]) == 64
        assert response.headers["Cache-Control"] == "no-store"
        assert not transfer.exists()
        status, issued = service.register_worker_v2(
            _register_body(instance_id, transaction_id),
            envelope["bootstrap_secret"],
        )
        assert status == 201
        assert issued["registration_transaction_id"] == transaction_id
        consumed = service.store.conn.execute(
            "SELECT consumed_at FROM worker_registration_handoffs_v2 "
            "WHERE registration_transaction_id=?",
            (transaction_id,),
        ).fetchone()[0]
        assert consumed is not None
        with pytest.raises(WorkerControlPlaneError) as register_replay:
            service.register_worker_v2(
                _register_body(instance_id, transaction_id),
                envelope["bootstrap_secret"],
            )
        assert (register_replay.value.code, register_replay.value.status) == (
            "invalid_credential",
            401,
        )
        replay = await client.get(
            "/worker-control-plane/v2/registration/bootstrap",
            params=params,
            headers={"X-Forwarded-For": WORKER_IP},
        )
        assert replay.status == 401
        row = service.store.conn.execute(
            "SELECT state,retrieved_at FROM "
            "worker_registration_handoffs_v2 "
            "WHERE registration_transaction_id=?",
            (transaction_id,),
        ).fetchone()
        assert row["state"] == "retrieved"
        assert row["retrieved_at"] is not None
    finally:
        await client.close()
        service.close()


def test_register_handoff_rollback_is_atomic(tmp_path):
    for stage in ("after_registration_insert", "before_handoff_consume"):
        root = tmp_path / stage
        root.mkdir()
        settings = _settings(root)
        instance_id = str(uuid.uuid4())
        transaction_id = str(uuid.uuid4())
        service, envelope = _provision_and_retrieve(
            settings, instance_id, transaction_id
        )
        service.close()

        def fail(selected):
            if selected == stage:
                raise sqlite3.OperationalError("injected_register_failure")

        service = WorkerControlPlaneService(
            settings, register_v2_test_hook=fail
        )
        try:
            audit_before = service.store.conn.execute(
                "SELECT COUNT(*) FROM worker_audit_log"
            ).fetchone()[0]
            with pytest.raises(
                sqlite3.OperationalError,
                match="injected_register_failure",
            ):
                service.register_worker_v2(
                    _register_body(instance_id, transaction_id),
                    envelope["bootstrap_secret"],
                )
            assert service.store.conn.execute(
                "SELECT COUNT(*) FROM worker_registration_transactions_v2"
            ).fetchone()[0] == 0
            assert service.store.conn.execute(
                "SELECT COUNT(*) FROM worker_credentials "
                "WHERE kind='access'"
            ).fetchone()[0] == 0
            assert service.store.conn.execute(
                "SELECT COUNT(*) FROM worker_instances"
            ).fetchone()[0] == 0
            handoff = service.store.conn.execute(
                "SELECT state,consumed_at FROM "
                "worker_registration_handoffs_v2 "
                "WHERE registration_transaction_id=?",
                (transaction_id,),
            ).fetchone()
            assert tuple(handoff) == ("retrieved", None)
            assert service.store.conn.execute(
                "SELECT COUNT(*) FROM worker_audit_log"
            ).fetchone()[0] == audit_before
        finally:
            service.close()


def test_concurrent_register_consumes_handoff_once(tmp_path):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    setup, envelope = _provision_and_retrieve(
        settings, instance_id, transaction_id
    )
    setup.close()
    lock_held = threading.Event()
    release = threading.Event()
    second_attempted = threading.Event()
    second_completed = threading.Event()

    def hold_after_insert(stage):
        if stage == "after_registration_insert":
            lock_held.set()
            assert release.wait(timeout=5)

    first_service = WorkerControlPlaneService(
        settings,
        register_v2_test_hook=hold_after_insert,
    )
    second_service = WorkerControlPlaneService(settings)
    raw_connection = second_service.store.conn

    class SignalingConnection:
        def __getattr__(self, name):
            return getattr(raw_connection, name)

        def execute(self, sql, parameters=()):
            if sql == "BEGIN IMMEDIATE":
                second_attempted.set()
            return raw_connection.execute(sql, parameters)

    second_service.store.conn = SignalingConnection()
    body = _register_body(instance_id, transaction_id)

    def register(service):
        return service.register_worker_v2(
            body, envelope["bootstrap_secret"]
        )

    def second_register():
        try:
            return register(second_service)
        finally:
            second_completed.set()

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(register, first_service)
            assert lock_held.wait(timeout=5)
            second = executor.submit(second_register)
            assert second_attempted.wait(timeout=5)
            assert not second_completed.is_set()
            release.set()
            assert first.result(timeout=5)[0] == 201
            with pytest.raises(WorkerControlPlaneError) as rejected:
                second.result(timeout=5)
            assert (rejected.value.code, rejected.value.status) == (
                "invalid_credential",
                401,
            )
        assert first_service.store.conn.execute(
            "SELECT COUNT(*) FROM worker_registration_transactions_v2"
        ).fetchone()[0] == 1
        assert first_service.store.conn.execute(
            "SELECT COUNT(*) FROM worker_credentials WHERE kind='access'"
        ).fetchone()[0] == 1
        assert first_service.store.conn.execute(
            "SELECT COUNT(*) FROM worker_registration_handoffs_v2 "
            "WHERE consumed_at IS NOT NULL"
        ).fetchone()[0] == 1
    finally:
        release.set()
        first_service.close()
        second_service.close()


def test_handoff_no_clobber_and_postcheck_is_query_only(tmp_path):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
    )
    with pytest.raises(ValueError):
        provision_registration_v2_handoff(
            settings,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            expected_source_ip=WORKER_IP,
        )
    connection = sqlite3.connect(settings.db_path)
    before = connection.total_changes
    connection.close()
    report = commissioning_postcheck(
        settings,
        registration_transaction_id=transaction_id,
    )
    assert report["registration"] is None
    assert report["handoff"]["state"] == "pending"
    assert report["handoff"]["capabilities_json"] == [
        "system.echo",
        "codex.execute",
    ]
    assert report["integrity"] == {
        "quick_check": "ok",
        "foreign_key_errors": 0,
        "pending_tasks": 0,
        "audit_secret_redaction": True,
    }
    assert report["db_writes"] == 0
    assert before == 0
    assert "secret_file_name" not in report["handoff"]


def test_handoff_expiry_and_file_failure_are_deterministic(tmp_path):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
    )
    service = WorkerControlPlaneService(settings)
    try:
        with pytest.raises(OSError, match="simulated"):
            service.retrieve_registration_v2_handoff(
                transaction_id,
                "server-a-worker",
                instance_id,
                WORKER_IP,
                lambda _: (_ for _ in ()).throw(OSError("simulated")),
            )
        state = service.store.conn.execute(
            "SELECT state FROM worker_registration_handoffs_v2 "
            "WHERE registration_transaction_id=?",
            (transaction_id,),
        ).fetchone()[0]
        assert state == "retrieved"
        with pytest.raises(WorkerControlPlaneError) as replay:
            service.retrieve_registration_v2_handoff(
                transaction_id,
                "server-a-worker",
                instance_id,
                WORKER_IP,
                lambda _: "must-not-run",
            )
        assert (replay.value.code, replay.value.status) == (
            "invalid_credential",
            401,
        )
    finally:
        service.close()

    expired_root = tmp_path / "expired"
    expired_root.mkdir()
    settings = _settings(expired_root)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
    )
    connection = sqlite3.connect(settings.db_path)
    connection.execute(
        "UPDATE worker_registration_handoffs_v2 SET expires_at=? "
        "WHERE registration_transaction_id=?",
        ("2020-01-01T00:00:00Z", transaction_id),
    )
    connection.commit()
    connection.close()
    service = WorkerControlPlaneService(settings)
    try:
        with pytest.raises(WorkerControlPlaneError) as expired:
            service.retrieve_registration_v2_handoff(
                transaction_id,
                "server-a-worker",
                instance_id,
                WORKER_IP,
                lambda _: "must-not-run",
            )
        assert (expired.value.code, expired.value.status) == (
            "invalid_credential",
            401,
        )
        state = service.store.conn.execute(
            "SELECT state FROM worker_registration_handoffs_v2 "
            "WHERE registration_transaction_id=?",
            (transaction_id,),
        ).fetchone()[0]
        assert state == "expired"
    finally:
        service.close()


def test_legacy_cleanup_requires_proven_expired_identity_and_audits(
    tmp_path,
):
    settings = _settings(tmp_path)
    legacy = settings.approved_test_root / "bootstrap.secret"
    provision_local_worker(settings, legacy, ttl_seconds=1)
    connection = sqlite3.connect(settings.db_path)
    connection.execute(
        "UPDATE worker_credentials SET expires_at=? WHERE kind='bootstrap'",
        ("2020-01-01T00:00:00Z",),
    )
    connection.commit()
    connection.close()
    evidence = inspect_legacy_bootstrap_artifact(
        settings, "bootstrap.secret"
    )
    assert evidence["orphan_verified"] is True
    assert evidence["mode"] == "0600"
    result = delete_verified_legacy_bootstrap_artifact(
        settings, "bootstrap.secret"
    )
    assert result == {
        "file_name": "bootstrap.secret",
        "orphan_verified": True,
        "deleted": True,
        "audit_event": "legacy_bootstrap_artifact_deleted",
    }
    assert not legacy.exists()
    connection = sqlite3.connect(settings.db_path)
    audit = connection.execute(
        "SELECT event_type,details_json FROM worker_audit_log "
        "ORDER BY audit_id DESC LIMIT 1"
    ).fetchone()
    connection.close()
    assert audit == (
        "legacy_bootstrap_artifact_deleted",
        '{"file_name":"bootstrap.secret"}',
    )


def test_legacy_cleanup_rejects_symlink_and_ambiguous_secret(tmp_path):
    settings = _settings(tmp_path)
    service = WorkerControlPlaneService(settings)
    service.close()
    outside = tmp_path / "outside"
    outside.write_text("not-a-credential", encoding="ascii")
    os.chmod(outside, 0o600)
    link = settings.approved_test_root / "bootstrap.secret"
    link.symlink_to(outside)
    with pytest.raises((OSError, ValueError)):
        inspect_legacy_bootstrap_artifact(settings, "bootstrap.secret")
    link.unlink()
    link.write_text("unknown-secret", encoding="ascii")
    os.chmod(link, 0o600)
    with pytest.raises(ValueError, match="ambiguous"):
        inspect_legacy_bootstrap_artifact(settings, "bootstrap.secret")
