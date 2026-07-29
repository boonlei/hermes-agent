"""Test-only in-process client for the isolated Worker Control Plane."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid


class MockWorkerClient:
    def __init__(self, client, bootstrap_secret: str, *, worker_id: str = "server-a-worker"):
        self.client = client
        self.bootstrap_secret = bootstrap_secret
        self.worker_id = worker_id
        self.instance_id = str(uuid.uuid4())
        self.registration_id = None
        self.access_token = None
        self.capabilities = ["system.echo"]

    async def register(
        self,
        *,
        capabilities=None,
        protocol_version="1.0",
        worker_version="0.1.0",
    ):
        requested_capabilities = (
            ["system.echo"] if capabilities is None else capabilities
        )
        if requested_capabilities == ["system.echo", "codex.execute"]:
            transaction_id = str(uuid.uuid4())
            path_digest = hashlib.sha256(
                b"windows-path-v1|desktop-87sshtu|"
                b"c:\\hermesserverworker-deploy"
            ).hexdigest()
            target_identity = {
                "path_digest": path_digest,
                "remote": (
                    "https://github.com/boonlei/HermesServerWorker.git"
                ),
                "branch": "main",
                "approved_head": (
                    "4092825b22184ad9820b4899b49fb1f833ac0b19"
                ),
            }
            register_body = {
                "protocol_version": 2,
                "worker_id": self.worker_id,
                "instance_id": self.instance_id,
                "worker_name": "test worker",
                "worker_version": worker_version,
                "capabilities": requested_capabilities,
                "host": "DESKTOP-87SSHTU",
                "path_id": "hermes-server-worker",
                "target_identity": target_identity,
                "registration_transaction_id": transaction_id,
            }
            response = await self.client.post(
                "/worker-control-plane/v2/register",
                headers={
                    "Authorization": (
                        f"Worker-Bootstrap {self.bootstrap_secret}"
                    )
                },
                json=register_body,
            )
            body = await response.json()
            if response.status not in (200, 201):
                return response.status, body
            confirmation = {
                "protocol_version": 2,
                "worker_id": self.worker_id,
                "instance_id": self.instance_id,
                "registration_transaction_id": transaction_id,
                "registration_id": body["registration_id"],
                "host": "DESKTOP-87SSHTU",
                "path_id": "hermes-server-worker",
                "target_identity": target_identity,
                "credential_id": body["credential_id"],
            }
            canonical = json.dumps(
                confirmation,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            confirmation["installation_proof"] = hmac.new(
                body["access_token"].encode("utf-8"),
                canonical,
                hashlib.sha256,
            ).hexdigest()
            confirmed = await self.client.post(
                "/worker-control-plane/v2/registration/confirm",
                headers={
                    "Authorization": f"Bearer {body['access_token']}"
                },
                json=confirmation,
            )
            if confirmed.status != 200:
                return confirmed.status, await confirmed.json()
            self.registration_id = body["registration_id"]
            self.access_token = body["access_token"]
            self.capabilities = requested_capabilities
            return response.status, body
        response = await self.client.post(
            "/worker/v1/register",
            headers={"Authorization": f"Worker-Bootstrap {self.bootstrap_secret}"},
            json={"protocol_version": protocol_version, "worker_id": self.worker_id,
                  "instance_id": self.instance_id, "worker_name": "test worker",
                  "worker_version": worker_version, "capabilities": requested_capabilities},
        )
        body = await response.json()
        if response.status in (200, 201):
            self.registration_id = body["registration_id"]
            self.access_token = body["access_token"]
            self.capabilities = requested_capabilities
        return response.status, body

    def headers(self, key=None):
        data = {"Authorization": f"Bearer {self.access_token}"}
        if key:
            data["Idempotency-Key"] = key
        return data

    def base(self):
        return {"worker_id": self.worker_id, "instance_id": self.instance_id,
                "registration_id": self.registration_id}

    async def heartbeat(self, status="idle", current_task_id=None):
        data = self.base() | {"status": status, "current_task_id": current_task_id,
                              "worker_time": "2026-01-01T00:00:00Z"}
        response = await self.client.post("/worker/v1/heartbeat", headers=self.headers(), json=data)
        return response.status, await response.json()

    async def poll(self, key="poll-1", *, capabilities=None):
        data = self.base() | {
            "capabilities": self.capabilities if capabilities is None else capabilities,
            "max_tasks": 1,
            "wait_seconds": 0,
        }
        response = await self.client.post("/worker/v1/tasks/poll", headers=self.headers(key), json=data)
        return response.status, (await response.json() if response.status != 204 else None)

    async def ack(self, task, accepted=True, reason=None, key="ack-1"):
        data = self.base() | {"delivery_id": task["delivery_id"], "accepted": accepted,
                              "reason": reason, "worker_time": "2026-01-01T00:00:00Z"}
        response = await self.client.post(f'/worker/v1/tasks/{task["task_id"]}/ack', headers=self.headers(key), json=data)
        return response.status, await response.json()

    async def result(
        self,
        task,
        *,
        stdout=None,
        stderr="",
        status="completed",
        exit_code=0,
        duration_ms=0,
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:00:00Z",
        result_key="result-1",
        request_key="request-result-1",
    ):
        if task["task_type"] == "system.echo":
            default_stdout = task["payload"]["message"]
        else:
            failure_codes = {
                "failed": "codex_failed",
                "rejected": "guard_rejected",
                "timed_out": "timeout",
            }
            default_stdout = json.dumps(
                {
                    "classification": (
                        "success" if status == "completed" else status
                    ),
                    "duration_ms": duration_ms,
                    "exit_code": exit_code,
                    "failure_code": failure_codes.get(status),
                    "guards": {"read_only": True},
                    "status": status,
                    "summary": "bounded test result",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        message = default_stdout if stdout is None else stdout
        data = self.base() | {"task_id": task["task_id"], "delivery_id": task["delivery_id"],
            "task_type": task["task_type"], "status": status, "stdout": message, "stderr": stderr,
            "exit_code": exit_code, "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": duration_ms, "result_idempotency_key": result_key,
            "payload_hash": task["payload_hash"],
            "trace_id": task["trace_id"]}
        response = await self.client.post(f'/worker/v1/tasks/{task["task_id"]}/result', headers=self.headers(request_key), json=data)
        return response.status, await response.json()
