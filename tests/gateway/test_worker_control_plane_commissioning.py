"""Security contract for the RC1 WCP commissioning operator path."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

from gateway.worker_control_plane.app import create_worker_control_plane_app
from gateway.worker_control_plane.registration_v2 import (
    APPROVED_HEAD,
    CAPABILITIES,
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


EXPECTED_HEAD = "dbdc56792d1926fb19b7e22e1a282fd96a82cd76"
OLD_HEAD = "4092825b22184ad9820b4899b49fb1f833ac0b19"
WORKER_IP = "100.110.252.84"


def _settings(tmp_path):
    return pilot_test_settings(tmp_path / "pilot")


def test_authoritative_head_and_capabilities_are_exact():
    assert APPROVED_HEAD == EXPECTED_HEAD
    assert APPROVED_HEAD != OLD_HEAD
    assert CAPABILITIES == ["system.echo", "codex.execute"]


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
        assert await response.text() == secret
        assert response.headers["Cache-Control"] == "no-store"
        assert not transfer.exists()
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
