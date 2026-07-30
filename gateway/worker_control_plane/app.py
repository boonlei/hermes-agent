"""Standalone aiohttp app factory for tests and the loopback-only pilot."""
from __future__ import annotations

import json
import ipaddress
import os
import stat
import uuid
from aiohttp import web

from .config import WorkerControlPlaneSettings
from .errors import WorkerControlPlaneError, error
from .models import (
    validate_capabilities,
    require_uuid,
    require_timestamp,
    require_worker_id,
)
from .service import WorkerControlPlaneService
from .registration_v2 import (
    CONFIRM_FIELDS,
    RECOVERY_FIELDS,
    REGISTER_FIELDS as REGISTER_V2,
    STATUS_FIELDS,
    validate_confirmation_request,
    validate_recovery_request,
    validate_register_request,
    validate_status_request,
)

SERVICE_KEY: web.AppKey[WorkerControlPlaneService] = web.AppKey(
    "worker_control_plane_service", WorkerControlPlaneService
)

REGISTER = {"protocol_version", "worker_id", "instance_id", "worker_name", "worker_version", "capabilities"}
HEARTBEAT = {"worker_id", "instance_id", "registration_id", "status", "current_task_id", "worker_time"}
POLL = {"worker_id", "instance_id", "registration_id", "capabilities", "max_tasks", "wait_seconds"}
ACK = {"worker_id", "instance_id", "registration_id", "delivery_id", "accepted", "reason", "worker_time"}
RESULT = {"worker_id", "instance_id", "registration_id", "delivery_id", "task_id", "task_type", "status", "stdout", "stderr", "exit_code", "started_at", "finished_at", "duration_ms", "result_idempotency_key", "payload_hash", "trace_id"}
HANDOFF_QUERY = {
    "registration_transaction_id",
    "worker_id",
    "instance_id",
}


def _verified_proxy_source(request: web.Request) -> str:
    if request.remote not in {"127.0.0.1", "::1"}:
        raise error("invalid_credential")
    values = request.headers.getall("X-Forwarded-For", [])
    if len(values) != 1 or "," in values[0]:
        raise error("invalid_credential")
    try:
        address = ipaddress.ip_address(values[0])
    except ValueError:
        raise error("invalid_credential") from None
    tailnet = ipaddress.ip_network("100.64.0.0/10")
    if address.version != 4 or address not in tailnet:
        raise error("invalid_credential")
    return address.compressed


def _read_and_remove_handoff_secret(
    settings: WorkerControlPlaneSettings, file_name: str
) -> str:
    prefix = ".registration-v2-handoff-"
    suffix = ".secret"
    if (
        not file_name.startswith(prefix)
        or not file_name.endswith(suffix)
        or "/" in file_name
        or "\\" in file_name
    ):
        raise error("invalid_credential")
    try:
        uuid.UUID(file_name[len(prefix) : -len(suffix)])
    except ValueError:
        raise error("invalid_credential") from None
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_fd = os.open(settings.approved_test_root, flags)
    descriptor = -1
    try:
        root_info = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) != 0o700
        ):
            raise error("invalid_credential")
        descriptor = os.open(
            file_name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_fd,
        )
        opened = os.fstat(descriptor)
        current = os.stat(file_name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino)
            != (current.st_dev, current.st_ino)
            or opened.st_size > 128
        ):
            raise error("invalid_credential")
        raw = os.read(descriptor, 129)
        try:
            secret = raw.decode("ascii")
        except UnicodeDecodeError:
            raise error("invalid_credential") from None
        if not secret or len(raw) > 128 or not secret.isprintable():
            raise error("invalid_credential")
        latest = os.stat(file_name, dir_fd=root_fd, follow_symlinks=False)
        if (latest.st_dev, latest.st_ino) != (opened.st_dev, opened.st_ino):
            raise error("invalid_credential")
        os.unlink(file_name, dir_fd=root_fd)
        os.fsync(root_fd)
        return secret
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(root_fd)

def _token(request: web.Request, scheme: str) -> str:
    value = request.headers.get("Authorization", "")
    prefix = scheme + " "
    if not value.startswith(prefix) or not value[len(prefix):]:
        raise error("invalid_credential")
    return value[len(prefix):]

def _key(request: web.Request) -> str:
    key = request.headers.get("Idempotency-Key")
    if not key or len(key) > 128 or any(ord(ch) < 33 or ord(ch) > 126 for ch in key):
        raise error("malformed_request")
    return key

async def _json(
    request: web.Request,
    fields: set[str],
    optional_fields: set[str] | None = None,
) -> dict:
    def no_duplicates(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate_json_key")
            value[key] = item
        return value

    try:
        raw = await request.read()
        body = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=no_duplicates,
        )
    except web.HTTPRequestEntityTooLarge:
        raise
    except Exception:
        raise error("malformed_request") from None
    optional_fields = optional_fields or set()
    if (
        not isinstance(body, dict)
        or not fields <= set(body)
        or set(body) - fields - optional_fields
    ):
        raise error("malformed_request")
    return body


def _registration_v2_error(exc: ValueError) -> WorkerControlPlaneError:
    code = str(exc)
    if code in {
        "invalid_credential",
        "invalid_target_identity",
        "unsupported_capability",
        "unsupported_protocol",
    }:
        return error(code)
    return error("malformed_request")

def _identity(body: dict) -> None:
    require_worker_id(body["worker_id"])
    require_uuid(body["instance_id"], "instance_id")
    require_uuid(body["registration_id"], "registration_id")

def _register(body: dict) -> None:
    if body["protocol_version"] != "1.0" or not isinstance(body["worker_name"], str) or not body["worker_name"] or not isinstance(body["worker_version"], str) or not body["worker_version"]:
        raise error("unsupported_protocol")
    require_worker_id(body["worker_id"])
    require_uuid(body["instance_id"], "instance_id")
    try:
        capabilities = validate_capabilities(body["capabilities"])
    except ValueError:
        raise error("unsupported_capability")
    if capabilities != ["system.echo"]:
        raise error("unsupported_protocol")

def _heartbeat(body: dict) -> None:
    _identity(body)
    if body["status"] not in {"idle", "busy"}:
        raise error("malformed_request")
    if body["current_task_id"] is not None:
        require_uuid(body["current_task_id"], "current_task_id")
    require_timestamp(body["worker_time"], "worker_time")

def _poll(body: dict) -> None:
    _identity(body)
    try:
        validate_capabilities(body["capabilities"])
    except ValueError:
        raise error("unsupported_capability")
    if type(body["max_tasks"]) is not int or type(body["wait_seconds"]) is not int:
        raise error("malformed_request")
    if body["max_tasks"] != 1 or body["wait_seconds"] != 0:
        raise error("malformed_request")

def _ack(body: dict) -> None:
    _identity(body); require_uuid(body["delivery_id"], "delivery_id"); require_timestamp(body["worker_time"], "worker_time")
    if not isinstance(body["accepted"], bool) or (body["reason"] is not None and body["reason"] not in {"temporary", "permanent"}):
        raise error("malformed_request")
    if body["accepted"] != (body["reason"] is None):
        raise error("malformed_request")

def _result(body: dict, route_task_id: str) -> None:
    _identity(body); require_uuid(body["delivery_id"], "delivery_id"); require_uuid(body["task_id"], "task_id"); require_uuid(body["trace_id"], "trace_id")
    if body["task_id"] != route_task_id or body["task_type"] not in {"system.echo", "codex.execute"} or body["status"] not in {"completed", "failed", "rejected", "cancelled", "expired", "timed_out"}:
        raise error("invalid_result")
    if not isinstance(body["stdout"], str) or not isinstance(body["stderr"], str) or type(body["exit_code"]) is not int or type(body["duration_ms"]) is not int or body["duration_ms"] < 0:
        raise error("invalid_result")
    if not isinstance(body["result_idempotency_key"], str) or not body["result_idempotency_key"] or len(body["result_idempotency_key"]) > 128:
        raise error("invalid_result")
    if not isinstance(body["payload_hash"], str) or len(body["payload_hash"]) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in body["payload_hash"]):
        raise error("invalid_result")
    require_timestamp(body["started_at"], "started_at"); require_timestamp(body["finished_at"], "finished_at")

def _failure(exc: WorkerControlPlaneError) -> web.Response:
    request_id = exc.request_id or str(uuid.uuid4())
    headers = {"X-Request-ID": request_id}
    if exc.audit_id is not None:
        headers["X-Audit-Event-ID"] = str(exc.audit_id)
    return web.json_response({"error": {"code": exc.code, "message": exc.message, "retryable": exc.retryable, "trace_id": request_id}}, status=exc.status, headers=headers)

def _http_failure(exc: web.HTTPException) -> web.Response:
    if isinstance(exc, web.HTTPNotFound):
        code, message = "not_found", "Not found"
    elif isinstance(exc, web.HTTPMethodNotAllowed):
        code, message = "method_not_allowed", "Method not allowed"
    else:
        code, message = "http_error", "HTTP request failed"
    headers = {}
    if isinstance(exc, web.HTTPMethodNotAllowed):
        headers["Allow"] = exc.headers["Allow"]
    return web.json_response(
        {"error": {"code": code, "message": message, "retryable": False, "trace_id": str(uuid.uuid4())}},
        status=exc.status,
        headers=headers,
    )

def create_worker_control_plane_app(settings: WorkerControlPlaneSettings, service: WorkerControlPlaneService | None = None) -> web.Application:
    if not settings.enabled or settings.test_mode == settings.pilot_mode:
        raise ValueError("Worker Control Plane requires one isolated mode")
    svc = service or WorkerControlPlaneService(settings)
    app = web.Application(client_max_size=settings.max_body_bytes)
    app[SERVICE_KEY] = svc

    @web.middleware
    async def errors(request: web.Request, handler):
        try:
            return await handler(request)
        except WorkerControlPlaneError as exc:
            return _failure(exc)
        except web.HTTPRequestEntityTooLarge:
            return _failure(error("payload_too_large"))
        except web.HTTPException as exc:
            return _http_failure(exc)
        except (TypeError, ValueError, KeyError):
            return _failure(error("malformed_request"))
        except Exception:
            return _failure(WorkerControlPlaneError("internal_error", 503, True, "Temporarily unavailable"))

    app.middlewares.append(errors)
    def audited(event: str):
        def decorate(handler):
            async def wrapped(request: web.Request):
                try:
                    return await handler(request)
                except WorkerControlPlaneError as exc:
                    svc.record_rejection(event, reason_code=exc.code)
                    if exc.code == "invalid_credential":
                        svc.record_rejection("credential_failed", reason_code=exc.code)
                    if exc.code == "idempotency_conflict":
                        svc.record_rejection("idempotency_conflict", reason_code=exc.code)
                    raise
                except (TypeError, ValueError, KeyError):
                    exc = error("malformed_request")
                    svc.record_rejection(event, reason_code=exc.code)
                    raise exc
            return wrapped
        return decorate

    async def health(request: web.Request):
        svc.check_health()
        return web.json_response({"status": "ok"})

    async def register(request: web.Request):
        request_id = str(uuid.uuid4())
        body = None
        try:
            body = await _json(request, REGISTER)
            _register(body)
            evidence = {}
            status, response = svc.register_worker(
                body,
                _token(request, "Worker-Bootstrap"),
                request_id=request_id,
                evidence=evidence,
            )
            return web.json_response(
                response,
                status=status,
                headers={
                    "X-Request-ID": request_id,
                    "X-Audit-Event-ID": str(evidence["audit_id"]),
                },
            )
        except WorkerControlPlaneError as exc:
            context = exc.safe_context or {}
            if exc.audit_id is None:
                exc.request_id = request_id
                exc.audit_id = svc.record_registration_failure(
                    request_id=request_id,
                    worker_id=context.get("worker_id") or (body.get("worker_id") if isinstance(body, dict) and isinstance(body.get("worker_id"), str) else None),
                    instance_id=context.get("instance_id") or (body.get("instance_id") if isinstance(body, dict) and isinstance(body.get("instance_id"), str) else None),
                    credential_id=context.get("credential_id"),
                    registration_id=context.get("registration_id"),
                    http_status=exc.status,
                    error_code=exc.code,
                    lifecycle_outcome=context.get("registration_lifecycle_outcome", "request_rejected"),
                )
            raise
        except (TypeError, ValueError, KeyError):
            exc = error("malformed_request")
            exc.request_id = request_id
            exc.audit_id = svc.record_registration_failure(
                request_id=request_id,
                worker_id=body.get("worker_id") if isinstance(body, dict) and isinstance(body.get("worker_id"), str) else None,
                instance_id=body.get("instance_id") if isinstance(body, dict) and isinstance(body.get("instance_id"), str) else None,
                credential_id=None,
                registration_id=None,
                http_status=exc.status,
                error_code=exc.code,
                lifecycle_outcome="request_rejected",
            )
            raise exc

    async def register_v2(request: web.Request):
        request_id = str(uuid.uuid4())
        body = None
        try:
            body = await _json(request, REGISTER_V2)
            try:
                validate_register_request(body)
            except ValueError as exc:
                raise _registration_v2_error(exc) from None
            evidence = {}
            status, response = svc.register_worker_v2(
                body,
                _token(request, "Worker-Bootstrap"),
                request_id=request_id,
                evidence=evidence,
            )
            return web.json_response(
                response,
                status=status,
                headers={
                    "X-Request-ID": request_id,
                    "X-Audit-Event-ID": str(evidence["audit_id"]),
                },
            )
        except WorkerControlPlaneError as exc:
            context = exc.safe_context or {}
            if exc.audit_id is None:
                exc.request_id = request_id
                exc.audit_id = svc.record_registration_failure(
                    request_id=request_id,
                    worker_id=context.get("worker_id") or (
                        body.get("worker_id")
                        if isinstance(body, dict)
                        and isinstance(body.get("worker_id"), str)
                        else None
                    ),
                    instance_id=context.get("instance_id") or (
                        body.get("instance_id")
                        if isinstance(body, dict)
                        and isinstance(body.get("instance_id"), str)
                        else None
                    ),
                    credential_id=context.get("credential_id"),
                    registration_id=context.get("registration_id"),
                    http_status=exc.status,
                    error_code=exc.code,
                    lifecycle_outcome=context.get(
                        "registration_lifecycle_outcome",
                        "request_rejected",
                    ),
                )
            raise
        except (TypeError, ValueError, KeyError):
            exc = error("malformed_request")
            exc.request_id = request_id
            exc.audit_id = svc.record_registration_failure(
                request_id=request_id,
                worker_id=(
                    body.get("worker_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("worker_id"), str)
                    else None
                ),
                instance_id=(
                    body.get("instance_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("instance_id"), str)
                    else None
                ),
                credential_id=None,
                registration_id=None,
                http_status=exc.status,
                error_code=exc.code,
                lifecycle_outcome="request_rejected",
            )
            raise exc
    async def recover_registration(request: web.Request):
        request_id = str(uuid.uuid4())
        body = None
        try:
            body = await _json(request, RECOVERY_FIELDS)
            try:
                validate_recovery_request(body)
            except ValueError as exc:
                raise _registration_v2_error(exc) from None
            evidence = {}
            response = svc.recover_registration_v2(
                body,
                _token(request, "Worker-Bootstrap"),
                request_id=request_id,
                evidence=evidence,
            )
            return web.json_response(
                response,
                headers={
                    "X-Request-ID": request_id,
                    "X-Audit-Event-ID": str(evidence["audit_id"]),
                },
            )
        except WorkerControlPlaneError as exc:
            exc.request_id = request_id
            exc.audit_id = svc.record_registration_failure(
                request_id=request_id,
                worker_id=(
                    body.get("worker_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("worker_id"), str)
                    else None
                ),
                instance_id=(
                    body.get("instance_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("instance_id"), str)
                    else None
                ),
                credential_id=None,
                registration_id=None,
                http_status=exc.status,
                error_code=exc.code,
                lifecycle_outcome="recovery_rejected",
            )
            raise

    async def confirm_registration(request: web.Request):
        request_id = str(uuid.uuid4())
        body = None
        try:
            body = await _json(request, CONFIRM_FIELDS)
            try:
                validate_confirmation_request(body)
            except ValueError as exc:
                raise _registration_v2_error(exc) from None
            evidence = {}
            response = svc.confirm_registration_v2(
                body,
                _token(request, "Bearer"),
                request_id=request_id,
                evidence=evidence,
            )
            headers = {"X-Request-ID": request_id}
            if evidence.get("audit_id") is not None:
                headers["X-Audit-Event-ID"] = str(evidence["audit_id"])
            return web.json_response(response, headers=headers)
        except WorkerControlPlaneError as exc:
            exc.request_id = request_id
            exc.audit_id = svc.record_registration_failure(
                request_id=request_id,
                worker_id=(
                    body.get("worker_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("worker_id"), str)
                    else None
                ),
                instance_id=(
                    body.get("instance_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("instance_id"), str)
                    else None
                ),
                credential_id=(
                    body.get("credential_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("credential_id"), str)
                    else None
                ),
                registration_id=(
                    body.get("registration_id")
                    if isinstance(body, dict)
                    and isinstance(body.get("registration_id"), str)
                    else None
                ),
                http_status=exc.status,
                error_code=exc.code,
                lifecycle_outcome="confirmation_rejected",
            )
            raise
    async def registration_status(request: web.Request):
        query = request.query
        if (
            set(query) != STATUS_FIELDS
            or any(len(query.getall(field)) != 1 for field in STATUS_FIELDS)
        ):
            raise error("malformed_request")
        try:
            identity = validate_status_request(
                {field: query[field] for field in STATUS_FIELDS}
            )
        except ValueError:
            raise error("malformed_request") from None
        response = svc.registration_status(
            _token(request, "Bearer"),
            identity["instance_id"],
            identity["registration_id"],
        )
        return web.json_response(response)
    async def registration_handoff(request: web.Request):
        query = request.query
        if (
            set(query) != HANDOFF_QUERY
            or any(len(query.getall(field)) != 1 for field in HANDOFF_QUERY)
        ):
            raise error("malformed_request")
        try:
            transaction_id = str(
                uuid.UUID(query["registration_transaction_id"])
            )
            instance_id = str(uuid.UUID(query["instance_id"]))
        except ValueError:
            raise error("malformed_request") from None
        source_ip = _verified_proxy_source(request)
        envelope = svc.retrieve_registration_v2_handoff(
            transaction_id,
            query["worker_id"],
            instance_id,
            source_ip,
            lambda file_name: _read_and_remove_handoff_secret(
                settings, file_name
            ),
        )
        return web.json_response(
            envelope,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )
    @audited("heartbeat_rejected")
    async def heartbeat(request: web.Request):
        body = await _json(request, HEARTBEAT); _heartbeat(body)
        return web.json_response(svc.heartbeat(body, _token(request, "Bearer")))
    @audited("poll_rejected")
    async def poll(request: web.Request):
        body = await _json(request, POLL); _poll(body)
        response = svc.poll_one_task(body, _token(request, "Bearer"), _key(request))
        return web.Response(status=204) if response is None else web.json_response(response)
    @audited("ack_rejected")
    async def ack(request: web.Request):
        body = await _json(request, ACK); _ack(body)
        return web.json_response(svc.ack_delivery(request.match_info["task_id"], body, _token(request, "Bearer"), _key(request)))
    @audited("result_rejected")
    async def result(request: web.Request):
        body = await _json(request, RESULT); _result(body, request.match_info["task_id"])
        return web.json_response(svc.submit_result(request.match_info["task_id"], body, _token(request, "Bearer"), _key(request)))
    app.router.add_get(
        "/health",
        health,
        allow_head=False,
    )
    app.router.add_post("/worker/v1/register", register)
    app.router.add_post("/worker-control-plane/v2/register", register_v2)
    app.router.add_post(
        "/worker-control-plane/v2/registration/recover",
        recover_registration,
    )
    app.router.add_post(
        "/worker-control-plane/v2/registration/confirm",
        confirm_registration,
    )
    app.router.add_get(
        "/worker-control-plane/v2/registration/status",
        registration_status,
        allow_head=False,
    )
    app.router.add_get(
        "/worker-control-plane/v2/registration/bootstrap",
        registration_handoff,
        allow_head=False,
    )
    app.router.add_post("/worker/v1/heartbeat", heartbeat)
    app.router.add_post("/worker/v1/tasks/poll", poll)
    app.router.add_post("/worker/v1/tasks/{task_id}/ack", ack)
    app.router.add_post("/worker/v1/tasks/{task_id}/result", result)
    return app
