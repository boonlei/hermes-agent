"""Standalone aiohttp app factory for tests and the loopback-only pilot."""
from __future__ import annotations

import uuid
from aiohttp import web

from .config import WorkerControlPlaneSettings
from .errors import WorkerControlPlaneError, error
from .models import require_uuid, require_timestamp, require_worker_id
from .service import WorkerControlPlaneService

SERVICE_KEY: web.AppKey[WorkerControlPlaneService] = web.AppKey(
    "worker_control_plane_service", WorkerControlPlaneService
)

REGISTER = {"protocol_version", "worker_id", "instance_id", "worker_name", "worker_version", "capabilities"}
HEARTBEAT = {"worker_id", "instance_id", "registration_id", "status", "current_task_id", "worker_time"}
POLL = {"worker_id", "instance_id", "registration_id", "capabilities", "max_tasks", "wait_seconds"}
ACK = {"worker_id", "instance_id", "registration_id", "delivery_id", "accepted", "reason", "worker_time"}
RESULT = {"worker_id", "instance_id", "registration_id", "delivery_id", "task_id", "task_type", "status", "stdout", "stderr", "exit_code", "started_at", "finished_at", "duration_ms", "result_idempotency_key", "payload_hash", "trace_id"}

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

async def _json(request: web.Request, fields: set[str]) -> dict:
    try:
        body = await request.json()
    except Exception:
        raise error("malformed_request") from None
    if not isinstance(body, dict) or set(body) != fields:
        raise error("malformed_request")
    return body

def _identity(body: dict) -> None:
    require_worker_id(body["worker_id"])
    require_uuid(body["instance_id"], "instance_id")
    require_uuid(body["registration_id"], "registration_id")

def _register(body: dict) -> None:
    if body["protocol_version"] != "1.0" or not isinstance(body["worker_name"], str) or not body["worker_name"] or not isinstance(body["worker_version"], str) or not body["worker_version"]:
        raise error("unsupported_protocol")
    require_worker_id(body["worker_id"])
    require_uuid(body["instance_id"], "instance_id")
    if body["capabilities"] != ["system.echo"]:
        raise error("unsupported_capability")

def _heartbeat(body: dict) -> None:
    _identity(body)
    if body["status"] not in {"idle", "busy"}:
        raise error("malformed_request")
    if body["current_task_id"] is not None:
        require_uuid(body["current_task_id"], "current_task_id")
    require_timestamp(body["worker_time"], "worker_time")

def _poll(body: dict) -> None:
    _identity(body)
    if body["capabilities"] != ["system.echo"]:
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
    if body["task_id"] != route_task_id or body["task_type"] != "system.echo" or body["status"] not in {"completed", "failed", "rejected", "cancelled", "expired"}:
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
            body = await _json(request, REGISTER); _register(body)
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
    app.router.add_post("/worker/v1/heartbeat", heartbeat)
    app.router.add_post("/worker/v1/tasks/poll", poll)
    app.router.add_post("/worker/v1/tasks/{task_id}/ack", ack)
    app.router.add_post("/worker/v1/tasks/{task_id}/result", result)
    return app
