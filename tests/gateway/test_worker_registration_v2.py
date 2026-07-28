"""Behavioral contract tests for recoverable Worker registration v2."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from gateway.worker_control_plane.app import create_worker_control_plane_app
from gateway.worker_control_plane.config import WorkerControlPlaneSettings
from gateway.worker_control_plane.service import WorkerControlPlaneService
from tests.gateway.worker_control_plane_helpers import MockWorkerClient


HOST = "DESKTOP-87SSHTU"
PATH_ID = "hermes-server-worker"
REMOTE = "https://github.com/boonlei/HermesServerWorker.git"
BRANCH = "main"
APPROVED_HEAD = "4092825b22184ad9820b4899b49fb1f833ac0b19"
CAPABILITIES = ["system.echo", "codex.execute"]
PATH_DIGEST = hashlib.sha256(
    b"windows-path-v1|desktop-87sshtu|c:\\hermesserverworker"
).hexdigest()
REGISTER_PATH = "/worker-control-plane/v2/register"
RECOVER_PATH = "/worker-control-plane/v2/registration/recover"
CONFIRM_PATH = "/worker-control-plane/v2/registration/confirm"


class MutableClock:
    def __init__(self):
        self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.value

    def advance(self, seconds: int):
        self.value += timedelta(seconds=seconds)


def target_identity(**overrides):
    identity = {
        "path_digest": PATH_DIGEST,
        "remote": REMOTE,
        "branch": BRANCH,
        "approved_head": APPROVED_HEAD,
    }
    identity.update(overrides)
    return identity


def register_body(instance_id: str, transaction_id: str, **overrides):
    body = {
        "protocol_version": 2,
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
        "worker_name": "Hermes Server Worker",
        "worker_version": "0.1.0",
        "capabilities": list(CAPABILITIES),
        "host": HOST,
        "path_id": PATH_ID,
        "target_identity": target_identity(),
        "registration_transaction_id": transaction_id,
    }
    body.update(overrides)
    return body


def recovery_body(instance_id: str, transaction_id: str, **overrides):
    body = {
        "protocol_version": 2,
        "worker_id": "server-a-worker",
        "instance_id": instance_id,
        "registration_transaction_id": transaction_id,
        "host": HOST,
        "path_id": PATH_ID,
        "target_identity": target_identity(),
    }
    body.update(overrides)
    return body


def confirmation_body(
    instance_id: str,
    transaction_id: str,
    registration_id: str,
    credential_id: str,
    token: str,
):
    body = recovery_body(instance_id, transaction_id) | {
        "registration_id": registration_id,
        "credential_id": credential_id,
    }
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    body["installation_proof"] = hmac.new(
        token.encode("utf-8"), canonical, hashlib.sha256
    ).hexdigest()
    return body


@pytest_asyncio.fixture
async def registration_v2(tmp_path):
    clock = MutableClock()
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db",
        approved_test_root=tmp_path,
    )
    service = WorkerControlPlaneService(settings, clock=clock)
    provisioned = service.provision_worker(capabilities=CAPABILITIES)
    client = TestClient(
        TestServer(create_worker_control_plane_app(settings, service))
    )
    await client.start_server()
    try:
        yield service, client, provisioned, clock, settings
    finally:
        await client.close()
        service.close()


async def register_v2(client, secret, body):
    response = await client.post(
        REGISTER_PATH,
        headers={"Authorization": f"Worker-Bootstrap {secret}"},
        json=body,
    )
    return response.status, await response.json()


async def recover_v2(client, secret, body):
    response = await client.post(
        RECOVER_PATH,
        headers={"Authorization": f"Worker-Bootstrap {secret}"},
        json=body,
    )
    return response.status, await response.json()


async def confirm_v2(client, token, body):
    response = await client.post(
        CONFIRM_PATH,
        headers={"Authorization": f"Bearer {token}"},
        json=body,
    )
    return response.status, await response.json()


@pytest.mark.asyncio
async def test_register_v2_accepts_exact_schema_and_issues_pending(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())

    status, body = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )

    assert status == 201
    assert set(body) == {
        "protocol_version",
        "registration_id",
        "credential_id",
        "registration_transaction_id",
        "issued_at",
        "expires_at",
        "capabilities",
        "host",
        "path_id",
        "target_identity",
        "access_token",
        "state",
    }
    assert body["protocol_version"] == 2
    assert body["registration_transaction_id"] == transaction_id
    assert body["capabilities"] == CAPABILITIES
    assert body["host"] == HOST
    assert body["path_id"] == PATH_ID
    assert body["target_identity"] == target_identity()
    assert body["state"] == "issued_pending_confirmation"
    assert body["access_token"]
    transaction = service.store.conn.execute(
        "SELECT * FROM worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()
    assert transaction["state"] == "issued_pending_confirmation"


@pytest.mark.asyncio
async def test_register_v2_rejects_unknown_and_duplicate_json_keys(
    registration_v2,
):
    _, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    unknown = register_body(instance_id, transaction_id) | {"shell": "id"}

    status, body = await register_v2(
        client, provisioned["secret"], unknown
    )
    assert status == 400
    assert body["error"]["code"] == "malformed_request"

    raw = json.dumps(register_body(instance_id, transaction_id))
    raw = raw[:-1] + ',"host":"DESKTOP-87SSHTU"}'
    response = await client.post(
        REGISTER_PATH,
        headers={
            "Authorization": f"Worker-Bootstrap {provisioned['secret']}",
            "Content-Type": "application/json",
        },
        data=raw.encode("utf-8"),
    )
    assert response.status == 400
    assert (await response.json())["error"]["code"] == "malformed_request"

    nested = json.dumps(register_body(instance_id, transaction_id))
    nested = nested.replace(
        f'"path_digest": "{PATH_DIGEST}"',
        f'"path_digest": "{PATH_DIGEST}",'
        f'"path_digest": "{PATH_DIGEST}"',
    )
    response = await client.post(
        REGISTER_PATH,
        headers={
            "Authorization": f"Worker-Bootstrap {provisioned['secret']}",
            "Content-Type": "application/json",
        },
        data=nested.encode("utf-8"),
    )
    assert response.status == 400
    assert (await response.json())["error"]["code"] == "malformed_request"


@pytest.mark.asyncio
async def test_v2_is_explicit_and_wrong_protocol_is_rejected(
    registration_v2,
):
    _, client, provisioned, _, _ = registration_v2
    for wrong_version in ("1.0", 2.0, True):
        body = register_body(
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            protocol_version=wrong_version,
        )
        status, response = await register_v2(
            client,
            provisioned["secret"],
            body,
        )
        assert status == 422
        assert response["error"]["code"] == "unsupported_protocol"

    response = await client.post(
        "/worker/v1/register",
        headers={
            "Authorization": f"Worker-Bootstrap {provisioned['secret']}"
        },
        json=register_body(str(uuid.uuid4()), str(uuid.uuid4())),
    )
    assert response.status == 400
    assert (await response.json())["error"]["code"] == "malformed_request"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    (
        {"instance_id": "not-a-uuid"},
        {"instance_id": "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF"},
        {"registration_transaction_id": "not-a-uuid"},
        {"worker_name": ""},
        {"worker_name": " \t "},
        {"worker_version": "v2\nforged"},
        {"worker_version": "x" * 257},
    ),
)
async def test_register_v2_rejects_malformed_bounded_identity(
    registration_v2,
    overrides,
):
    _, client, provisioned, _, _ = registration_v2
    body = register_body(str(uuid.uuid4()), str(uuid.uuid4()))
    body.update(overrides)

    status, response = await register_v2(
        client,
        provisioned["secret"],
        body,
    )

    assert status == 400
    assert response["error"]["code"] == "malformed_request"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("host", "OTHER-HOST"),
        ("path_id", "other-path"),
        ("target_identity", target_identity(remote="https://example.invalid/x")),
        ("target_identity", target_identity(branch="dev")),
        ("target_identity", target_identity(approved_head="0" * 40)),
        ("target_identity", target_identity(path_digest="A" * 64)),
    ),
)
async def test_register_v2_rejects_wrong_fixed_identity(
    registration_v2, field, value
):
    _, client, provisioned, _, _ = registration_v2
    body = register_body(str(uuid.uuid4()), str(uuid.uuid4()))
    body[field] = value

    status, response = await register_v2(
        client, provisioned["secret"], body
    )

    assert status == 422
    assert response["error"]["code"] == "invalid_target_identity"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "capabilities",
    (
        ["codex.execute", "system.echo"],
        ["system.echo"],
        ["system.echo", "codex.execute", "shell"],
        ["system.echo", "codex.execute", "codex.execute"],
    ),
)
async def test_register_v2_capabilities_are_exact_and_canonical(
    registration_v2, capabilities
):
    _, client, provisioned, _, _ = registration_v2
    body = register_body(
        str(uuid.uuid4()),
        str(uuid.uuid4()),
        capabilities=capabilities,
    )

    status, response = await register_v2(
        client, provisioned["secret"], body
    )

    assert status == 422
    assert response["error"]["code"] == "unsupported_capability"


@pytest.mark.asyncio
async def test_same_transaction_retry_and_recovery_return_same_token(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    request = register_body(instance_id, transaction_id)

    first_status, first = await register_v2(
        client, provisioned["secret"], request
    )
    retry_status, retry = await register_v2(
        client, provisioned["secret"], request
    )
    recover_status, recovered = await recover_v2(
        client,
        provisioned["secret"],
        recovery_body(instance_id, transaction_id),
    )

    assert first_status == 201
    assert retry_status == 200
    assert recover_status == 200
    assert retry == first
    assert recovered == first
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_registration_transactions_v2"
    ).fetchone()[0] == 1
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_credentials WHERE kind='access'"
    ).fetchone()[0] == 1
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_instances"
    ).fetchone()[0] == 1


@pytest.mark.asyncio
async def test_transaction_reuse_with_changed_request_is_conflict(
    registration_v2,
):
    _, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    request = register_body(instance_id, transaction_id)
    assert (await register_v2(client, provisioned["secret"], request))[0] == 201
    changed = register_body(
        instance_id, transaction_id, worker_version="0.2.0"
    )

    status, body = await register_v2(
        client, provisioned["secret"], changed
    )

    assert status == 409
    assert body["error"]["code"] == "idempotency_conflict"


@pytest.mark.asyncio
async def test_wrong_identity_cannot_recover(registration_v2):
    _, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    assert (
        await register_v2(
            client,
            provisioned["secret"],
            register_body(instance_id, transaction_id),
        )
    )[0] == 201

    status, body = await recover_v2(
        client,
        provisioned["secret"],
        recovery_body(str(uuid.uuid4()), transaction_id),
    )

    assert status == 401
    assert body["error"]["code"] == "invalid_credential"


@pytest.mark.asyncio
async def test_recovery_failure_has_safe_request_and_audit_evidence(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )

    response = await client.post(
        RECOVER_PATH,
        headers={
            "Authorization": f"Worker-Bootstrap {provisioned['secret']}"
        },
        json=recovery_body(str(uuid.uuid4()), transaction_id),
    )

    assert response.status == 401
    assert response.headers["X-Request-ID"]
    audit_id = int(response.headers["X-Audit-Event-ID"])
    audit = service.store.conn.execute(
        "SELECT event_type,outcome,reason_code,details_json "
        "FROM worker_audit_log WHERE audit_id=?",
        (audit_id,),
    ).fetchone()
    assert audit["event_type"] == "registration_rejected"
    assert audit["outcome"] == "rejected"
    assert audit["reason_code"] == "invalid_credential"
    details = json.loads(audit["details_json"])
    assert details["request_id"] == response.headers["X-Request-ID"]
    assert details["registration_lifecycle_outcome"] == "recovery_rejected"
    assert issued["access_token"] not in audit["details_json"]
    assert provisioned["secret"] not in audit["details_json"]


@pytest.mark.asyncio
async def test_expired_pending_transaction_cannot_recover(registration_v2):
    service, client, provisioned, clock, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    status, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )
    assert status == 201
    clock.advance(service.settings.token_ttl_seconds + 1)

    status, body = await recover_v2(
        client,
        provisioned["secret"],
        recovery_body(instance_id, transaction_id),
    )

    assert status == 410
    assert body["error"]["code"] == "registration_expired"
    transaction = service.store.conn.execute(
        "SELECT state,escrow_ciphertext FROM "
        "worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()
    assert tuple(transaction) == ("expired", None)
    credential = service.store.conn.execute(
        "SELECT revoked_at FROM worker_credentials WHERE credential_id=?",
        (issued["credential_id"],),
    ).fetchone()
    assert credential["revoked_at"] is not None


@pytest.mark.asyncio
async def test_pending_expiry_allows_same_bootstrap_until_its_own_expiry(
    registration_v2,
):
    service, client, provisioned, clock, _ = registration_v2
    instance_id = str(uuid.uuid4())
    first_transaction_id = str(uuid.uuid4())
    _, first = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, first_transaction_id),
    )
    clock.advance(service.settings.token_ttl_seconds + 1)

    second_transaction_id = str(uuid.uuid4())
    status, second = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, second_transaction_id),
    )

    assert status == 201
    assert second["credential_id"] != first["credential_id"]
    first_state = service.store.conn.execute(
        "SELECT state,escrow_ciphertext FROM "
        "worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (first_transaction_id,),
    ).fetchone()
    assert tuple(first_state) == ("expired", None)
    bootstrap = service.store.conn.execute(
        "SELECT consumed_at,revoked_at FROM worker_credentials "
        "WHERE credential_id=?",
        (provisioned["credential_id"],),
    ).fetchone()
    assert tuple(bootstrap) == (None, None)


@pytest.mark.asyncio
async def test_pending_credential_cannot_poll(registration_v2):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )
    response = await client.post(
        "/worker/v1/tasks/poll",
        headers={
            "Authorization": f"Bearer {issued['access_token']}",
            "Idempotency-Key": "pending-poll",
        },
        json={
            "worker_id": "server-a-worker",
            "instance_id": instance_id,
            "registration_id": issued["registration_id"],
            "capabilities": CAPABILITIES,
            "max_tasks": 1,
            "wait_seconds": 0,
        },
    )

    assert response.status in {401, 410}
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_deliveries"
    ).fetchone()[0] == 0


@pytest.mark.asyncio
async def test_confirm_activates_credential_and_retires_bootstrap(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )
    confirmation = confirmation_body(
        instance_id,
        transaction_id,
        issued["registration_id"],
        issued["credential_id"],
        issued["access_token"],
    )

    status, confirmed = await confirm_v2(
        client, issued["access_token"], confirmation
    )
    repeat_status, repeated = await confirm_v2(
        client, issued["access_token"], confirmation
    )

    assert status == 200
    assert repeat_status == 200
    assert repeated == confirmed
    assert confirmed == {
        "registration_id": issued["registration_id"],
        "credential_id": issued["credential_id"],
        "registration_transaction_id": transaction_id,
        "state": "confirmed",
        "confirmed_at": confirmed["confirmed_at"],
    }
    bootstrap = service.store.conn.execute(
        "SELECT consumed_at,revoked_at FROM worker_credentials "
        "WHERE credential_id=?",
        (provisioned["credential_id"],),
    ).fetchone()
    assert bootstrap["consumed_at"] is not None
    assert bootstrap["revoked_at"] is not None
    transaction = service.store.conn.execute(
        "SELECT state,escrow_salt,escrow_nonce,escrow_ciphertext "
        "FROM worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()
    assert tuple(transaction) == ("confirmed", None, None, None)

    poll = await client.post(
        "/worker/v1/tasks/poll",
        headers={
            "Authorization": f"Bearer {issued['access_token']}",
            "Idempotency-Key": "confirmed-poll",
        },
        json={
            "worker_id": "server-a-worker",
            "instance_id": instance_id,
            "registration_id": issued["registration_id"],
            "capabilities": CAPABILITIES,
            "max_tasks": 1,
            "wait_seconds": 0,
        },
    )
    assert poll.status == 204


@pytest.mark.asyncio
async def test_confirming_rotation_supersedes_prior_v2_lifecycle(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    first_transaction_id = str(uuid.uuid4())
    _, first = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, first_transaction_id),
    )
    first_confirmation = confirmation_body(
        instance_id,
        first_transaction_id,
        first["registration_id"],
        first["credential_id"],
        first["access_token"],
    )
    assert (
        await confirm_v2(
            client,
            first["access_token"],
            first_confirmation,
        )
    )[0] == 200

    next_bootstrap = service.provision_worker(
        capabilities=CAPABILITIES
    )
    second_transaction_id = str(uuid.uuid4())
    _, second = await register_v2(
        client,
        next_bootstrap["secret"],
        register_body(instance_id, second_transaction_id),
    )
    second_confirmation = confirmation_body(
        instance_id,
        second_transaction_id,
        second["registration_id"],
        second["credential_id"],
        second["access_token"],
    )
    assert (
        await confirm_v2(
            client,
            second["access_token"],
            second_confirmation,
        )
    )[0] == 200

    lifecycles = service.store.conn.execute(
        "SELECT registration_transaction_id,state FROM "
        "worker_registration_transactions_v2 ORDER BY issued_at"
    ).fetchall()
    assert [(row[0], row[1]) for row in lifecycles] == [
        (first_transaction_id, "superseded"),
        (second_transaction_id, "confirmed"),
    ]
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_instances"
    ).fetchone()[0] == 1
    old_credential = service.store.conn.execute(
        "SELECT revoked_at FROM worker_credentials WHERE credential_id=?",
        (first["credential_id"],),
    ).fetchone()
    assert old_credential["revoked_at"] is not None


@pytest.mark.asyncio
async def test_invalid_confirmation_proof_does_not_activate(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )
    confirmation = confirmation_body(
        instance_id,
        transaction_id,
        issued["registration_id"],
        issued["credential_id"],
        issued["access_token"],
    )
    confirmation["installation_proof"] = "0" * 64

    status, body = await confirm_v2(
        client, issued["access_token"], confirmation
    )

    assert status == 401
    assert body["error"]["code"] == "invalid_credential"
    transaction = service.store.conn.execute(
        "SELECT state FROM worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()
    assert transaction["state"] == "issued_pending_confirmation"


@pytest.mark.asyncio
async def test_recovery_is_bounded_and_terminal_states_never_disclose(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    request = recovery_body(instance_id, transaction_id)
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )

    for _ in range(5):
        status, recovered = await recover_v2(
            client, provisioned["secret"], request
        )
        assert status == 200
        assert recovered["access_token"] == issued["access_token"]
    status, body = await recover_v2(
        client, provisioned["secret"], request
    )
    assert status == 429
    assert body["error"]["code"] == "rate_limited"

    confirmation = confirmation_body(
        instance_id,
        transaction_id,
        issued["registration_id"],
        issued["credential_id"],
        issued["access_token"],
    )
    assert (
        await confirm_v2(client, issued["access_token"], confirmation)
    )[0] == 200
    status, body = await recover_v2(
        client, provisioned["secret"], request
    )
    assert status == 401
    assert body["error"]["code"] == "invalid_credential"
    assert issued["access_token"] not in json.dumps(body)
    assert service.store.conn.execute(
        "SELECT recovery_count FROM worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()["recovery_count"] == 5


def test_registration_v2_transaction_rollback_preserves_bootstrap(
    tmp_path, monkeypatch
):
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db",
        approved_test_root=tmp_path,
    )
    service = WorkerControlPlaneService(settings, clock=MutableClock())
    provisioned = service.provision_worker(capabilities=CAPABILITIES)
    original_audit = service._audit

    def fail_after_writes(connection, event, **fields):
        if event == "registration_v2_issued":
            raise RuntimeError("forced_transaction_rollback")
        return original_audit(connection, event, **fields)

    monkeypatch.setattr(service, "_audit", fail_after_writes)
    with pytest.raises(RuntimeError, match="forced_transaction_rollback"):
        service.register_worker_v2(
            register_body(str(uuid.uuid4()), str(uuid.uuid4())),
            provisioned["secret"],
        )

    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_registration_transactions_v2"
    ).fetchone()[0] == 0
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_credentials WHERE kind='access'"
    ).fetchone()[0] == 0
    assert service.store.conn.execute(
        "SELECT count(*) FROM worker_instances"
    ).fetchone()[0] == 0
    bootstrap = service.store.conn.execute(
        "SELECT consumed_at,revoked_at FROM worker_credentials "
        "WHERE credential_id=?",
        (provisioned["credential_id"],),
    ).fetchone()
    assert tuple(bootstrap) == (None, None)
    service.close()


def test_concurrent_same_transaction_serializes_to_one_credential(tmp_path):
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db",
        approved_test_root=tmp_path,
    )
    first_service = WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    provisioned = first_service.provision_worker(
        capabilities=CAPABILITIES
    )
    second_service = WorkerControlPlaneService(
        settings, clock=MutableClock()
    )
    body = register_body(str(uuid.uuid4()), str(uuid.uuid4()))

    def issue(service):
        return service.register_worker_v2(body, provisioned["secret"])

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(issue, (first_service, second_service))
            )
        assert {status for status, _ in outcomes} == {200, 201}
        assert outcomes[0][1] == outcomes[1][1]
        assert first_service.store.conn.execute(
            "SELECT count(*) FROM worker_registration_transactions_v2"
        ).fetchone()[0] == 1
        assert first_service.store.conn.execute(
            "SELECT count(*) FROM worker_credentials WHERE kind='access'"
        ).fetchone()[0] == 1
    finally:
        second_service.close()
        first_service.close()


@pytest.mark.asyncio
async def test_revoking_bootstrap_revokes_pending_transaction(
    registration_v2,
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )

    service.revoke_bootstrap_credential(
        "server-a-worker", provisioned["credential_id"]
    )

    transaction = service.store.conn.execute(
        "SELECT state,escrow_ciphertext FROM "
        "worker_registration_transactions_v2 "
        "WHERE registration_transaction_id=?",
        (transaction_id,),
    ).fetchone()
    assert tuple(transaction) == ("revoked", None)
    credential = service.store.conn.execute(
        "SELECT revoked_at FROM worker_credentials WHERE credential_id=?",
        (issued["credential_id"],),
    ).fetchone()
    assert credential["revoked_at"] is not None
    status, body = await recover_v2(
        client,
        provisioned["secret"],
        recovery_body(instance_id, transaction_id),
    )
    assert status == 401
    assert body["error"]["code"] == "invalid_credential"


@pytest.mark.asyncio
async def test_pending_recovery_survives_server_restart(tmp_path):
    clock = MutableClock()
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db",
        approved_test_root=tmp_path,
    )
    service = WorkerControlPlaneService(settings, clock=clock)
    provisioned = service.provision_worker(capabilities=CAPABILITIES)
    client = TestClient(
        TestServer(create_worker_control_plane_app(settings, service))
    )
    await client.start_server()
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )
    await client.close()
    service.close()

    restarted = WorkerControlPlaneService(settings, clock=clock)
    restarted_client = TestClient(
        TestServer(create_worker_control_plane_app(settings, restarted))
    )
    await restarted_client.start_server()
    try:
        status, recovered = await recover_v2(
            restarted_client,
            provisioned["secret"],
            recovery_body(instance_id, transaction_id),
        )
        assert status == 200
        assert recovered == issued
    finally:
        await restarted_client.close()
        restarted.close()


def test_restart_reaps_expired_pending_without_recovery_request(tmp_path):
    clock = MutableClock()
    settings = WorkerControlPlaneSettings.for_test(
        tmp_path / "worker-control-plane.db",
        approved_test_root=tmp_path,
    )
    service = WorkerControlPlaneService(settings, clock=clock)
    provisioned = service.provision_worker(capabilities=CAPABILITIES)
    transaction_id = str(uuid.uuid4())
    _, issued = service.register_worker_v2(
        register_body(str(uuid.uuid4()), transaction_id),
        provisioned["secret"],
    )
    clock.advance(service.settings.token_ttl_seconds + 1)
    service.close()

    restarted = WorkerControlPlaneService(settings, clock=clock)
    try:
        transaction = restarted.store.conn.execute(
            "SELECT state,escrow_salt,escrow_nonce,escrow_ciphertext "
            "FROM worker_registration_transactions_v2 "
            "WHERE registration_transaction_id=?",
            (transaction_id,),
        ).fetchone()
        assert tuple(transaction) == ("expired", None, None, None)
        credential = restarted.store.conn.execute(
            "SELECT revoked_at FROM worker_credentials "
            "WHERE credential_id=?",
            (issued["credential_id"],),
        ).fetchone()
        assert credential["revoked_at"] is not None
        assert restarted.store.conn.execute(
            "SELECT count(*) FROM worker_audit_log "
            "WHERE event_type='registration_v2_expired'"
        ).fetchone()[0] == 1
    finally:
        restarted.close()


def test_migration_rejects_constraint_incompatible_existing_v2_table(
    tmp_path,
):
    database = tmp_path / "worker-control-plane.db"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE schema_migrations(
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        CREATE TABLE worker_registration_transactions_v2(
            registration_transaction_id TEXT PRIMARY KEY,
            protocol_version INTEGER NOT NULL CHECK(protocol_version=2),
            worker_id TEXT NOT NULL
                REFERENCES workers(worker_id) ON DELETE CASCADE,
            instance_id TEXT NOT NULL,
            worker_name TEXT NOT NULL,
            worker_version TEXT NOT NULL,
            registration_id TEXT NOT NULL
                REFERENCES worker_instances(registration_id),
            bootstrap_credential_id TEXT NOT NULL
                REFERENCES worker_credentials(credential_id),
            credential_id TEXT NOT NULL UNIQUE
                REFERENCES worker_credentials(credential_id),
            request_hash TEXT NOT NULL,
            host BLOB,
            path_id TEXT NOT NULL,
            path_digest TEXT NOT NULL,
            remote TEXT NOT NULL,
            branch TEXT NOT NULL,
            approved_head TEXT NOT NULL,
            capabilities_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN (
                'issued_pending_confirmation','confirmed','superseded',
                'revoked','expired'
            )),
            issued_at TEXT NOT NULL,
            expires_at TEXT,
            confirmed_at TEXT,
            superseded_at TEXT,
            revoked_at TEXT,
            escrow_salt BLOB,
            escrow_nonce BLOB,
            escrow_ciphertext BLOB,
            recovery_count INTEGER NOT NULL DEFAULT 0
                CHECK(recovery_count>=0),
            last_recovered_at TEXT,
            UNIQUE(worker_id,registration_transaction_id)
        );
        """
    )
    connection.close()
    database.chmod(0o600)
    settings = WorkerControlPlaneSettings.for_test(
        database,
        approved_test_root=tmp_path,
    )

    with pytest.raises(
        sqlite3.DatabaseError,
        match="registration v2 transaction schema is incompatible",
    ):
        WorkerControlPlaneService(settings, clock=MutableClock())

    verification = sqlite3.connect(database)
    try:
        assert verification.execute(
            "SELECT count(*) FROM schema_migrations"
        ).fetchone()[0] == 0
        assert verification.execute(
            "SELECT count(*) FROM sqlite_master "
            "WHERE type='index' "
            "AND name='idx_registration_transactions_v2_state'"
        ).fetchone()[0] == 0
    finally:
        verification.close()


@pytest.mark.asyncio
async def test_plaintext_token_never_enters_database_audit_or_errors(
    registration_v2, caplog
):
    service, client, provisioned, _, _ = registration_v2
    instance_id = str(uuid.uuid4())
    transaction_id = str(uuid.uuid4())
    _, issued = await register_v2(
        client,
        provisioned["secret"],
        register_body(instance_id, transaction_id),
    )
    token = issued["access_token"]
    dump = "\n".join(service.store.conn.iterdump())
    assert token not in dump
    assert provisioned["secret"] not in dump
    assert token not in service.audit_text()
    assert provisioned["secret"] not in service.audit_text()

    response = await client.post(
        RECOVER_PATH,
        headers={"Authorization": "Worker-Bootstrap wrong-secret"},
        json=recovery_body(instance_id, transaction_id),
    )
    assert response.status == 401
    assert token not in await response.text()
    assert provisioned["secret"] not in await response.text()
    assert token not in caplog.text
    assert provisioned["secret"] not in caplog.text


@pytest.mark.asyncio
async def test_v1_system_echo_registration_remains_compatible(
    registration_v2,
):
    service, client, _, _, _ = registration_v2
    service.revoke_bootstrap_credential(
        "server-a-worker",
        service.store.conn.execute(
            "SELECT credential_id FROM worker_credentials "
            "WHERE kind='bootstrap' AND revoked_at IS NULL"
        ).fetchone()["credential_id"],
    )
    secret = service.provision_worker(capabilities=["system.echo"])["secret"]
    worker = MockWorkerClient(client, secret)

    status, body = await worker.register()

    assert status == 201
    assert body["accepted_capabilities"] == ["system.echo"]
