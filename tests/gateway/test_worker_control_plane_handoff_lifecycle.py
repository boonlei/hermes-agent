"""Exact operator lifecycle tests for expired Registration-v2 handoffs."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from gateway.worker_control_plane import runtime as runtime_module
from gateway.worker_control_plane.handoff_lifecycle import (
    expire_expired_orphan_handoff,
)
from gateway.worker_control_plane.registration_v2 import (
    APPROVED_HEAD,
    BRANCH,
    CAPABILITIES,
    HOST,
    PATH_DIGEST,
    PATH_ID,
    REMOTE,
)
from gateway.worker_control_plane.runtime import (
    _format_handoff_lifecycle_report,
    _prepare_expired_handoff_artifact,
    build_parser,
    expire_registration_v2_handoff,
    pilot_test_settings,
    provision_registration_v2_handoff,
)
from gateway.worker_control_plane.service import WorkerControlPlaneService


WORKER_ID = "server-a-worker"
WORKER_IP = "100.110.252.84"
EXPIRED_AT = "2020-01-01T00:00:00Z"


def _settings(tmp_path):
    return pilot_test_settings(tmp_path / "pilot")


def _expired_orphan(tmp_path):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
    )
    connection = sqlite3.connect(settings.db_path)
    credential_id = connection.execute(
        "SELECT bootstrap_credential_id FROM "
        "worker_registration_handoffs_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()[0]
    connection.execute(
        "UPDATE worker_registration_handoffs_v2 SET expires_at=? "
        "WHERE registration_transaction_id=?",
        (EXPIRED_AT, transaction_id),
    )
    connection.execute(
        "UPDATE worker_credentials SET expires_at=? "
        "WHERE credential_id=?",
        (EXPIRED_AT, credential_id),
    )
    connection.commit()
    connection.close()
    return settings, instance_id, transaction_id, credential_id


def _execute_direct(
    settings,
    instance_id,
    transaction_id,
    credential_id,
    *,
    test_hook=None,
    prepare_artifact=None,
):
    root_fd = os.open(settings.approved_test_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        prepare = prepare_artifact or (
            lambda name, terminal, sanitized, device, inode: (
                _prepare_expired_handoff_artifact(
                root_fd,
                settings.approved_test_root,
                name,
                terminal,
                sanitized,
                device,
                inode,
                )
            )
        )
        return expire_expired_orphan_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            prepare_artifact=prepare,
            test_hook=test_hook,
        )
    finally:
        os.close(root_fd)


def _snapshot(settings, transaction_id, credential_id):
    connection = sqlite3.connect(settings.db_path)
    handoff = connection.execute(
        "SELECT state,retrieved_at,consumed_at FROM "
        "worker_registration_handoffs_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()
    bootstrap = connection.execute(
        "SELECT revoked_at,consumed_at FROM worker_credentials "
        "WHERE credential_id=?",
        (credential_id,),
    ).fetchone()
    audit = connection.execute(
        "SELECT count(*) FROM worker_audit_log"
    ).fetchone()[0]
    connection.close()
    return handoff, bootstrap, audit


def test_dry_run_matches_current_expired_orphan_without_writes(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    before = _snapshot(settings, transaction_id, credential_id)
    report = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=False,
    )
    assert report["status"] == "eligible"
    assert report["mode"] == "dry-run"
    assert report["eligible"] is True
    assert report["idempotent"] is False
    assert report["handoff_state"] == "pending"
    assert report["bootstrap_state"] == "expired"
    assert report["db_writes"] == 0
    assert report["artifact"]["mode"] == "0600"
    assert _snapshot(settings, transaction_id, credential_id) == before


def test_execute_terminalizes_rows_and_removes_artifact(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    report = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert report["status"] == "completed"
    assert report["handoff_state"] == "expired"
    assert report["bootstrap_state"] == "revoked"
    assert report["artifact_cleanup"] is True
    assert not artifact.exists()
    connection = sqlite3.connect(settings.db_path)
    assert connection.execute(
        "SELECT state FROM worker_registration_handoffs_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()[0] == "expired"
    assert connection.execute(
        "SELECT revoked_at IS NOT NULL FROM worker_credentials "
        "WHERE credential_id=?",
        (credential_id,),
    ).fetchone()[0] == 1
    assert connection.execute(
        "SELECT count(*) FROM worker_audit_log WHERE event_type IN "
        "('registration_v2_handoff_operator_expired',"
        "'bootstrap_credential_operator_revoked',"
        "'registration_v2_handoff_artifact_deleted')",
    ).fetchone()[0] == 3
    assert connection.execute(
        "PRAGMA foreign_key_check"
    ).fetchone() is None
    connection.close()


@pytest.mark.parametrize(
    "failure_stage",
    (
        "before_handoff_update",
        "after_handoff_update",
        "after_bootstrap_update",
        "before_lifecycle_audit",
    ),
)
def test_database_or_audit_failure_rolls_back_everything(
    tmp_path, failure_stage
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    before = _snapshot(settings, transaction_id, credential_id)

    def fail(stage):
        if stage == failure_stage:
            raise sqlite3.OperationalError(f"fail at {stage}")

    with pytest.raises(sqlite3.OperationalError, match="fail at"):
        _execute_direct(
            settings,
            instance_id,
            transaction_id,
            credential_id,
            test_hook=fail,
        )
    assert artifact.is_file()
    assert not Path(f"{artifact}.expired").exists()
    assert _snapshot(settings, transaction_id, credential_id) == before


def test_unexpired_handoff_is_rejected_without_mutation(tmp_path):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    provisioned = provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
    )
    with pytest.raises(ValueError, match="handoff is not expired"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=provisioned["credential_id"],
            execute=False,
        )


def test_consumed_handoff_is_rejected_without_mutation(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    connection = sqlite3.connect(settings.db_path)
    connection.execute(
        "UPDATE worker_registration_handoffs_v2 SET consumed_at=? "
        "WHERE registration_transaction_id=?",
        ("2020-01-02T00:00:00Z", transaction_id),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="handoff is already consumed"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=False,
        )


def _register_body(instance_id, transaction_id):
    return {
        "protocol_version": 2,
        "worker_id": WORKER_ID,
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


def test_registration_linked_handoff_is_rejected(tmp_path):
    settings = _settings(tmp_path)
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        expected_source_ip=WORKER_IP,
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    service = WorkerControlPlaneService(settings)
    try:
        envelope = service.retrieve_registration_v2_handoff(
            transaction_id,
            WORKER_ID,
            instance_id,
            WORKER_IP,
            lambda _: artifact.read_text(encoding="ascii"),
        )
        secret = envelope["bootstrap_secret"]
        service.register_worker_v2(
            _register_body(instance_id, transaction_id),
            secret,
        )
        credential_id = envelope["bootstrap_credential_id"]
    finally:
        service.close()
    with pytest.raises(
        ValueError, match="referenced by a Registration-v2 transaction"
    ):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=False,
        )


@pytest.mark.parametrize(
    ("field", "expected"),
    (
        ("worker_id", "worker_id does not match handoff"),
        ("instance_id", "instance_id does not match handoff"),
        ("bootstrap_credential_id", "bootstrap credential does not match"),
    ),
)
def test_wrong_exact_identifier_is_rejected(tmp_path, field, expected):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    values = {
        "worker_id": WORKER_ID,
        "instance_id": instance_id,
        "registration_transaction_id": transaction_id,
        "bootstrap_credential_id": credential_id,
    }
    values[field] = (
        "wrong-worker" if field == "worker_id" else str(uuid.uuid4())
    )
    with pytest.raises(ValueError, match=expected):
        expire_registration_v2_handoff(
            settings,
            execute=False,
            **values,
        )


def test_exact_replay_is_idempotent_without_duplicate_audit(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    first = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    second = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert first["idempotent"] is False
    assert second["idempotent"] is True
    connection = sqlite3.connect(settings.db_path)
    events = connection.execute(
        "SELECT event_type,count(*) FROM worker_audit_log "
        "WHERE event_type LIKE '%operator%' "
        "OR event_type='registration_v2_handoff_artifact_deleted' "
        "GROUP BY event_type ORDER BY event_type"
    ).fetchall()
    connection.close()
    assert events == [
        ("bootstrap_credential_operator_revoked", 1),
        ("registration_v2_handoff_artifact_deleted", 1),
        ("registration_v2_handoff_operator_expired", 1),
    ]


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        ("missing_audit", "lacks exact operator lifecycle audit"),
        ("future_expiry", "terminal handoff expiry is inconsistent"),
        ("retrieved", "terminal handoff was previously retrieved"),
    ),
)
def test_ambiguous_terminal_state_is_not_an_idempotent_replay(
    tmp_path, mutation, expected
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    connection = sqlite3.connect(settings.db_path)
    if mutation == "missing_audit":
        connection.execute(
            "DELETE FROM worker_audit_log "
            "WHERE event_type='bootstrap_credential_operator_revoked' "
            "AND reason_code=?",
            (credential_id,),
        )
    elif mutation == "future_expiry":
        connection.execute(
            "UPDATE worker_registration_handoffs_v2 SET expires_at=? "
            "WHERE registration_transaction_id=?",
            ("2099-01-01T00:00:00Z", transaction_id),
        )
    else:
        connection.execute(
            "UPDATE worker_registration_handoffs_v2 SET retrieved_at=? "
            "WHERE registration_transaction_id=?",
            (EXPIRED_AT, transaction_id),
        )
    connection.commit()
    connection.close()

    with pytest.raises(ValueError, match=expected):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=True,
        )


def test_pending_handoff_with_revoked_bootstrap_is_rejected(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    connection = sqlite3.connect(settings.db_path)
    connection.execute(
        "UPDATE worker_credentials SET revoked_at=? WHERE credential_id=?",
        (EXPIRED_AT, credential_id),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="already revoked"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=False,
        )


def test_mismatched_replay_after_success_is_rejected(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    with pytest.raises(ValueError, match="bootstrap credential does not match"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=str(uuid.uuid4()),
            execute=True,
        )


def test_concurrent_cleanup_has_one_transition_and_one_audit_set(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    barrier = threading.Barrier(2)

    def no_file_prepare(_name, _terminal, _sanitized, _device, _inode):
        return (
            None,
            lambda: {"sanitized": True, "device": 1, "inode": 1},
            lambda: {"deleted": True},
            {"test": "no-file"},
        )

    def run():
        barrier.wait(timeout=5)
        return expire_expired_orphan_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            prepare_artifact=no_file_prepare,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(run) for _ in range(2)]
        results = [future.result(timeout=10) for future in futures]
    assert sorted(result["idempotent"] for result in results) == [False, True]
    connection = sqlite3.connect(settings.db_path)
    assert connection.execute(
        "SELECT count(*) FROM worker_audit_log WHERE event_type IN "
        "('registration_v2_handoff_operator_expired',"
        "'bootstrap_credential_operator_revoked',"
        "'registration_v2_handoff_artifact_deleted')"
    ).fetchone()[0] == 3
    connection.close()


def test_artifact_symlink_and_no_clobber_are_rejected(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    secret = artifact.read_bytes()
    artifact.unlink()
    artifact.symlink_to(settings.db_path)
    with pytest.raises(
        (OSError, ValueError),
        match="Too many levels|symbolic|destination is unsafe",
    ):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=False,
        )
    artifact.unlink()
    artifact.write_bytes(secret)
    artifact.chmod(0o600)
    staged = Path(f"{artifact}.expired")
    staged.write_bytes(b"occupied")
    staged.chmod(0o600)
    with pytest.raises(ValueError, match="staging state is ambiguous"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=True,
        )


def test_atomic_staging_does_not_clobber_racing_destination(
    tmp_path, monkeypatch
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    staged = Path(f"{artifact}.expired")
    original = runtime_module._rename_noreplace

    def race(source, destination, *, source_dir_fd, destination_dir_fd):
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=destination_dir_fd,
        )
        os.write(descriptor, b"racing-destination")
        os.close(descriptor)
        original(
            source,
            destination,
            source_dir_fd=source_dir_fd,
            destination_dir_fd=destination_dir_fd,
        )

    monkeypatch.setattr(runtime_module, "_rename_noreplace", race)
    with pytest.raises(FileExistsError):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=True,
        )
    assert artifact.is_file()
    assert staged.read_bytes() == b"racing-destination"
    handoff, bootstrap, _ = _snapshot(
        settings, transaction_id, credential_id
    )
    assert handoff[0] == "pending"
    assert bootstrap == (None, None)


def test_atomic_rollback_does_not_clobber_racing_destination(
    tmp_path, monkeypatch
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    staged = Path(f"{artifact}.expired")
    original = runtime_module._rename_noreplace
    calls = 0

    def race_rollback(
        source, destination, *, source_dir_fd, destination_dir_fd
    ):
        nonlocal calls
        calls += 1
        if calls == 2:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=destination_dir_fd,
            )
            os.write(descriptor, b"racing-rollback")
            os.close(descriptor)
        original(
            source,
            destination,
            source_dir_fd=source_dir_fd,
            destination_dir_fd=destination_dir_fd,
        )

    def fail_after_handoff(stage):
        if stage == "after_handoff_update":
            raise RuntimeError("force database rollback")

    monkeypatch.setattr(
        runtime_module, "_rename_noreplace", race_rollback
    )
    with pytest.raises(FileExistsError):
        _execute_direct(
            settings,
            instance_id,
            transaction_id,
            credential_id,
            test_hook=fail_after_handoff,
        )
    assert artifact.read_bytes() == b"racing-rollback"
    assert staged.is_file()
    handoff, bootstrap, _ = _snapshot(
        settings, transaction_id, credential_id
    )
    assert handoff[0] == "pending"
    assert bootstrap == (None, None)


def test_moved_staged_artifact_is_not_reported_deleted(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    root_fd = os.open(
        settings.approved_test_root, os.O_RDONLY | os.O_DIRECTORY
    )
    escaped = settings.approved_test_root / "moved-artifact"
    try:
        def prepare(name, terminal, sanitized, device, inode):
            rollback, sanitize, finalize, evidence = (
                _prepare_expired_handoff_artifact(
                    root_fd,
                    settings.approved_test_root,
                    name,
                    terminal,
                    sanitized,
                    device,
                    inode,
                )
            )
            staged_name = f"{name}.expired"

            def move_then_finalize():
                os.rename(
                    staged_name,
                    escaped.name,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
                return finalize()

            return rollback, sanitize, move_then_finalize, evidence

        report = expire_expired_orphan_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            prepare_artifact=prepare,
        )
    finally:
        os.close(root_fd)
    assert report["status"] == "cleanup_required"
    assert report["artifact_cleanup"] is False
    assert escaped.is_file()
    connection = sqlite3.connect(settings.db_path)
    deleted_audits = connection.execute(
        "SELECT count(*) FROM worker_audit_log "
        "WHERE event_type='registration_v2_handoff_artifact_deleted' "
        "AND reason_code=?",
        (transaction_id,),
    ).fetchone()[0]
    connection.close()
    assert deleted_audits == 0
    assert escaped.stat().st_size == 0
    resumed = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert resumed["status"] == "completed"


def test_artifact_open_by_another_process_is_rejected(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "handle=open(sys.argv[1],'rb');"
                "print('ready',flush=True);"
                "sys.stdin.read(1)"
            ),
            str(artifact),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        with pytest.raises(ValueError, match="open by another process"):
            expire_registration_v2_handoff(
                settings,
                worker_id=WORKER_ID,
                instance_id=instance_id,
                registration_transaction_id=transaction_id,
                bootstrap_credential_id=credential_id,
                execute=False,
            )
    finally:
        if process.stdin is not None:
            process.stdin.write("x")
            process.stdin.flush()
        process.wait(timeout=5)


def test_indeterminate_process_descriptor_scan_fails_closed(
    tmp_path, monkeypatch
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import sys;"
                "handle=open(sys.argv[1],'rb');"
                "print('ready',flush=True);"
                "sys.stdin.read(1)"
            ),
            str(artifact),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    original_iterdir = Path.iterdir
    denied = Path(f"/proc/{process.pid}/fd")

    def permission_denied(path):
        if path == denied:
            raise PermissionError("simulated proc restriction")
        return original_iterdir(path)

    try:
        assert process.stdout is not None
        assert process.stdout.readline().strip() == "ready"
        monkeypatch.setattr(Path, "iterdir", permission_denied)
        with pytest.raises(ValueError, match="indeterminate"):
            expire_registration_v2_handoff(
                settings,
                worker_id=WORKER_ID,
                instance_id=instance_id,
                registration_transaction_id=transaction_id,
                bootstrap_credential_id=credential_id,
                execute=False,
            )
    finally:
        if process.stdin is not None:
            process.stdin.write("x")
            process.stdin.flush()
        process.wait(timeout=5)


def test_cleanup_required_state_can_be_resumed_idempotently(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    root_fd = os.open(settings.approved_test_root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        def prepare(name, terminal, sanitized, device, inode):
            assert terminal is False
            rollback, sanitize, _finalize, evidence = (
                _prepare_expired_handoff_artifact(
                    root_fd,
                    settings.approved_test_root,
                    name,
                    terminal,
                    sanitized,
                    device,
                    inode,
                )
            )

            def fail_finalize():
                raise OSError("simulated artifact deletion failure")

            return rollback, sanitize, fail_finalize, evidence

        report = expire_expired_orphan_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            prepare_artifact=prepare,
        )
    finally:
        os.close(root_fd)
    assert report["status"] == "cleanup_required"
    resumed = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert resumed["status"] == "completed"
    assert resumed["idempotent"] is True


def test_hard_crash_staging_residue_is_recovered(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    staged = Path(f"{artifact}.expired")
    crashed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import os,sys;"
                "source=sys.argv[1];destination=sys.argv[2];"
                "os.rename(source,destination);"
                "fd=os.open(os.path.dirname(source),os.O_RDONLY);"
                "os.fsync(fd);os._exit(91)"
            ),
            str(artifact),
            str(staged),
        ],
        check=False,
    )
    assert crashed.returncode == 91
    assert not artifact.exists()
    assert staged.is_file()

    dry_run = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=False,
    )
    assert dry_run["status"] == "eligible"
    assert dry_run["artifact"]["recovery_staged"] is True
    completed = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert completed["status"] == "completed"
    assert completed["idempotent"] is False
    assert not artifact.exists()
    assert not staged.exists()


def test_artifact_audit_failure_is_safe_to_retry(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )

    def fail_artifact_audit(stage):
        if stage == "before_artifact_audit":
            raise RuntimeError("simulated artifact audit failure")

    first = _execute_direct(
        settings,
        instance_id,
        transaction_id,
        credential_id,
        test_hook=fail_artifact_audit,
    )
    assert first["status"] == "cleanup_required"
    assert first["artifact_cleanup"] is True
    assert first["artifact_audit_complete"] is False
    assert first["safe_reason"] == "RuntimeError"

    resumed = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert resumed["status"] == "completed"
    assert resumed["idempotent"] is True
    connection = sqlite3.connect(settings.db_path)
    artifact_audits = connection.execute(
        "SELECT count(*) FROM worker_audit_log "
        "WHERE event_type='registration_v2_handoff_artifact_deleted' "
        "AND reason_code=?",
        (transaction_id,),
    ).fetchone()[0]
    connection.close()
    assert artifact_audits == 1


def test_unlink_fsync_failure_recovers_from_sanitized_proof(
    tmp_path, monkeypatch
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    staged = Path(f"{artifact}.expired")
    original_fsync = runtime_module.os.fsync
    failed = False

    def fail_after_unlink(descriptor):
        nonlocal failed
        if not failed and not artifact.exists() and not staged.exists():
            failed = True
            raise OSError("simulated directory fsync failure")
        return original_fsync(descriptor)

    monkeypatch.setattr(runtime_module.os, "fsync", fail_after_unlink)
    first = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert first["status"] == "cleanup_required"
    assert first["artifact_sanitized"] is True
    assert not artifact.exists()
    assert not staged.exists()

    resumed = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert resumed["status"] == "completed"
    assert resumed["idempotent"] is True


def test_sanitization_retries_short_positional_writes(
    tmp_path, monkeypatch
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    original_pwrite = runtime_module.os.pwrite
    calls = 0

    def short_write(descriptor, data, offset):
        nonlocal calls
        calls += 1
        return original_pwrite(descriptor, data[:1], offset)

    monkeypatch.setattr(runtime_module.os, "pwrite", short_write)
    report = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert report["status"] == "completed"
    assert calls > 1


def test_sanitization_zero_progress_is_cleanup_required(
    tmp_path, monkeypatch
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    monkeypatch.setattr(
        runtime_module.os, "pwrite", lambda *_args, **_kwargs: 0
    )
    report = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    assert report["status"] == "cleanup_required"
    assert report["artifact_sanitized"] is False
    connection = sqlite3.connect(settings.db_path)
    sanitized_audits = connection.execute(
        "SELECT count(*) FROM worker_audit_log "
        "WHERE event_type='registration_v2_handoff_artifact_sanitized' "
        "AND reason_code=?",
        (transaction_id,),
    ).fetchone()[0]
    connection.close()
    assert sanitized_audits == 0


def test_terminal_absence_without_sanitized_proof_is_rejected(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    connection = sqlite3.connect(settings.db_path)
    connection.execute(
        "DELETE FROM worker_audit_log WHERE event_type IN "
        "('registration_v2_handoff_artifact_sanitized',"
        "'registration_v2_handoff_artifact_deleted') "
        "AND reason_code=?",
        (transaction_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="absence is unproven"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=True,
        )


def test_verified_deletion_rejects_reappeared_artifact(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    staged = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret.expired"
    )
    staged.write_bytes(b"unrelated")
    staged.chmod(0o600)
    with pytest.raises(ValueError, match="reappeared"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=True,
        )


def test_artifact_audit_provenance_is_exact(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    connection = sqlite3.connect(settings.db_path)
    connection.execute(
        "UPDATE worker_audit_log SET outcome='wrong' "
        "WHERE event_type='registration_v2_handoff_artifact_deleted' "
        "AND reason_code=?",
        (transaction_id,),
    )
    connection.commit()
    connection.close()
    with pytest.raises(ValueError, match="audit history is ambiguous"):
        expire_registration_v2_handoff(
            settings,
            worker_id=WORKER_ID,
            instance_id=instance_id,
            registration_transaction_id=transaction_id,
            bootstrap_credential_id=credential_id,
            execute=True,
        )


def test_secret_is_absent_from_reports_and_audit(tmp_path):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    artifact = (
        settings.approved_test_root
        / f".registration-v2-handoff-{transaction_id}.secret"
    )
    secret = artifact.read_text(encoding="ascii")
    report = expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    connection = sqlite3.connect(settings.db_path)
    audit = "\n".join(
        value or ""
        for row in connection.execute(
            "SELECT details_json FROM worker_audit_log"
        )
        for value in row
    )
    connection.close()
    assert secret not in json.dumps(report, sort_keys=True)
    assert secret not in audit
    assert "bootstrap_secret" not in audit.lower()


def test_new_provision_succeeds_after_cleanup_with_one_active_handoff(
    tmp_path,
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    expire_registration_v2_handoff(
        settings,
        worker_id=WORKER_ID,
        instance_id=instance_id,
        registration_transaction_id=transaction_id,
        bootstrap_credential_id=credential_id,
        execute=True,
    )
    fresh_id = str(uuid.uuid4())
    fresh = provision_registration_v2_handoff(
        settings,
        instance_id=instance_id,
        registration_transaction_id=fresh_id,
        expected_source_ip=WORKER_IP,
    )
    assert fresh["registration_transaction_id"] == fresh_id
    connection = sqlite3.connect(settings.db_path)
    active = connection.execute(
        "SELECT count(*) FROM worker_registration_handoffs_v2 h "
        "JOIN worker_credentials b ON b.credential_id="
        "h.bootstrap_credential_id "
        "WHERE h.state='pending' AND b.revoked_at IS NULL "
        "AND b.consumed_at IS NULL"
    ).fetchone()[0]
    connection.close()
    assert active == 1


def test_cli_requires_explicit_mode_and_formats_safe_summary():
    parser = build_parser()
    base = [
        "commission",
        "handoff",
        "expire",
        "--worker-id",
        WORKER_ID,
        "--instance-id",
        str(uuid.uuid4()),
        "--transaction-id",
        str(uuid.uuid4()),
        "--credential-id",
        str(uuid.uuid4()),
    ]
    with pytest.raises(SystemExit):
        parser.parse_args(base)
    parsed = parser.parse_args([*base, "--dry-run", "--output", "text"])
    assert parsed.dry_run is True
    text = _format_handoff_lifecycle_report(
        {
            "status": "eligible",
            "mode": "dry-run",
            "eligible": True,
            "registration_transaction_id": parsed.transaction_id,
            "worker_id": WORKER_ID,
            "instance_id": parsed.instance_id,
            "bootstrap_credential_id": parsed.credential_id,
            "handoff_state": "pending",
            "bootstrap_state": "expired",
            "summary": "exact expired orphan is eligible",
        }
    )
    assert "STATUS: eligible" in text
    assert "SUMMARY: exact expired orphan is eligible" in text


def test_main_emits_machine_readable_success_and_rejection(
    tmp_path, monkeypatch, capsys
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    monkeypatch.setattr(runtime_module, "pilot_settings", lambda: settings)
    base = [
        "commission",
        "handoff",
        "expire",
        "--worker-id",
        WORKER_ID,
        "--instance-id",
        instance_id,
        "--transaction-id",
        transaction_id,
        "--credential-id",
        credential_id,
        "--dry-run",
        "--output",
        "json",
    ]
    assert runtime_module.main(base) == 0
    success = json.loads(capsys.readouterr().out)
    assert success["status"] == "eligible"
    assert success["eligible"] is True

    wrong = [*base]
    wrong[wrong.index(credential_id)] = str(uuid.uuid4())
    assert runtime_module.main(wrong) == 2
    rejected_output = capsys.readouterr()
    rejected = json.loads(rejected_output.out)
    assert rejected["status"] == "blocked"
    assert rejected["eligible"] is False
    assert "Traceback" not in rejected_output.err
    assert "secret" not in rejected_output.out.lower()


def test_main_text_cleanup_required_is_nonzero(
    tmp_path, monkeypatch, capsys
):
    settings, instance_id, transaction_id, credential_id = _expired_orphan(
        tmp_path
    )
    monkeypatch.setattr(runtime_module, "pilot_settings", lambda: settings)

    def cleanup_required(*_args, **kwargs):
        return {
            "status": "cleanup_required",
            "mode": "execute",
            "eligible": True,
            "registration_transaction_id": (
                kwargs["registration_transaction_id"]
            ),
            "worker_id": kwargs["worker_id"],
            "instance_id": kwargs["instance_id"],
            "bootstrap_credential_id": (
                kwargs["bootstrap_credential_id"]
            ),
            "handoff_state": "expired",
            "bootstrap_state": "revoked",
            "summary": "database terminalized; cleanup requires retry",
            "safe_reason": "OSError",
        }

    monkeypatch.setattr(
        runtime_module,
        "expire_registration_v2_handoff",
        cleanup_required,
    )
    code = runtime_module.main(
        [
            "commission",
            "handoff",
            "expire",
            "--worker-id",
            WORKER_ID,
            "--instance-id",
            instance_id,
            "--transaction-id",
            transaction_id,
            "--credential-id",
            credential_id,
            "--execute",
            "--output",
            "text",
        ]
    )
    assert code == 3
    output = capsys.readouterr()
    assert "STATUS: cleanup_required" in output.out
    assert "SAFE_REASON: OSError" in output.out
    assert "Traceback" not in output.err
