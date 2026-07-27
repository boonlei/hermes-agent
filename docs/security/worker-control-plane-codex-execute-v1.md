# Worker Control Plane `codex.execute` V1

## Status and scope

This document defines the first restricted `codex.execute` capability for the
Hermes Worker Control Plane (WCP). WCP schedules and tracks the task; it does
not execute Codex, interpret the instruction, construct shell commands, or
choose a filesystem path.

V1 is intentionally fixed to one reviewed target:

- worker: `server-a-worker`
- host: `DESKTOP-87SSHTU`
- repository: `boonlei/HermesServerWorker`
- path identifier: `hermes-server-worker`
- branch: `main`
- mode: `read_only`

No live task, Worker implementation, deployment, or commissioning is part of
this change.

## Payload contract

The canonical payload has exactly these fields:

```json
{
  "task_type": "codex.execute",
  "target": {
    "host": "DESKTOP-87SSHTU",
    "repository": "boonlei/HermesServerWorker",
    "path_id": "hermes-server-worker",
    "branch": "main",
    "expected_head": "<40-char lowercase git SHA>"
  },
  "instruction": {
    "task_id": "<1-128 character bounded identifier>",
    "text": "<1-16384 UTF-8 bytes>",
    "mode": "read_only"
  },
  "limits": {
    "timeout_seconds": 900,
    "max_result_bytes": 32768
  }
}
```

Validation is closed at every object boundary. Unknown fields, including
`shell`, `command`, `environment`, `credential`, `token`, and arbitrary path
fields, are rejected rather than ignored.

Additional limits:

- `expected_head`: lowercase hexadecimal Git SHA, exactly 40 characters.
- `instruction.task_id`: ASCII identifier matching
  `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`.
- `instruction.text`: non-empty, at most 16 KiB encoded as UTF-8.
- `timeout_seconds`: integer from 60 through 900, excluding booleans.
- `max_result_bytes`: integer from 1 through 32768, excluding booleans.

The payload is canonicalized with sorted JSON keys, UTF-8 encoding, and compact
separators before its SHA-256 hash is stored.

## Capability and assignment model

Bootstrap and access credentials carry a closed JSON capability list.
Registration may request only the exact capability scope authorized by the
bootstrap credential. The issued access credential inherits that scope.

Poll requires the request capability list to exactly match the access
credential scope. A task is eligible only when:

- `worker_tasks.worker_id` equals the authenticated worker;
- `worker_tasks.task_type` is in the access credential capability scope;
- the task is queued and available.

The V1 administrative creation path assigns `codex.execute` only to
`server-a-worker`. It does not accept a target host, repository, branch, or
local path from the caller; those values are fixed by this contract.

## State machine and concurrency

`codex.execute` uses the existing WCP lifecycle:

`queued -> leased -> running -> completed|failed|rejected`

It uses the existing delivery, ACK, lease expiry, retry, dead-letter,
idempotency, and registration-lifecycle boundaries. There is no alternate
execution or result endpoint.

Access credential, registration lifecycle, and capability authorization are
read and verified inside the same `BEGIN IMMEDIATE` transaction as every
Heartbeat, Poll, ACK, or Result mutation. A registration revocation cannot
race between authentication and the protected business mutation.

The `codex.execute` delivery lease covers the ACK deadline, the task's
declared `timeout_seconds`, and a fixed five-second result-submission grace.
This prevents a valid execution longer than the legacy 60-second echo lease
from being requeued and executed twice.

At most one `codex.execute` task may be active globally. Active means
`queued`, `leased`, or `running`. Creation is serialized by the existing
`BEGIN IMMEDIATE` transaction:

1. Resolve an existing creation idempotency key.
2. Reject a changed payload for that key.
3. Return the existing task for an identical retry.
4. Reject when another active `codex.execute` task exists.
5. Insert the new assigned task and safe audit record.

## Result contract

The existing result envelope remains authoritative for task, delivery,
registration, payload-hash, trace, timing, and idempotency checks.

For `codex.execute`:

- task type, task ID, delivery ID, payload hash, and trace ID must match;
- the delivery must be acknowledged and unexpired;
- `stdout` plus `stderr`, encoded as UTF-8, must not exceed the task's
  `max_result_bytes`, with an absolute ceiling of 32768 bytes;
- `duration_ms` must be non-negative and no greater than
  `timeout_seconds * 1000`;
- `finished_at - started_at` must also be within the declared timeout and
  must agree with `duration_ms` within 1000 milliseconds;
- a completed result must omit `failure_code`;
- a non-completed result must include a safe failure code matching
  `[a-z][a-z0-9_]{0,63}`;
- unknown result fields remain rejected.

The HTTP transport envelope is bounded at 256 KiB so a decoded 32 KiB result
remains reachable even with worst-case JSON escaping. Decoded UTF-8 result
limits remain authoritative. A transport-envelope violation returns the safe
413 `payload_too_large` error.

The full result is stored in the existing result table. Audit records contain
only bounded metadata and never contain full stdout or stderr.

## Audit contract

Permitted `codex.execute` audit metadata:

- task, delivery, result, worker, registration, and trace IDs;
- repository, path identifier, branch, and expected head;
- mode and final status;
- duration in milliseconds;
- bounded result size in bytes;
- safe failure code.

Audit records must not contain:

- bootstrap secrets, access tokens, or Authorization headers;
- credential hashes, salts, or environment variables;
- the full Codex instruction;
- full stdout or stderr;
- the full task payload.

## Threat model

### Assets

- Worker access and bootstrap credentials.
- Repository identity and expected Git revision.
- The read-only instruction and its bounded result.
- Task/delivery/result integrity and idempotency state.
- Registration lifecycle and capability authorization.

### Trust boundaries

1. An administrator creates a structured task through the local pilot CLI or
   service boundary.
2. WCP persists the validated payload and assigns it to an authorized worker.
3. An authenticated Worker polls, ACKs, and submits a result.
4. Audit consumers read a deliberately reduced metadata projection.

The instruction text is untrusted data. It is not a workflow directive for
WCP and must never become a shell command, environment mutation, filesystem
path, SQL fragment, or audit message.

### Threats and controls

| Threat | Control |
| --- | --- |
| Target substitution | Exact host/repository/path-id/branch allowlist and lowercase SHA validation |
| Write-capable instruction mode | Only literal `read_only` is accepted |
| Smuggled shell, environment, token, or path fields | Closed schemas at all nesting levels |
| Unauthorized worker leases task | Worker assignment plus credential-scoped capability equality |
| Capability escalation after registration | Access credential stores immutable lifecycle capability scope |
| Concurrent duplicate execution | One-active transaction guard and delivery uniqueness |
| Idempotency-key reuse with changed payload | Canonical request hash comparison and conflict rejection |
| Task or delivery substitution in result | Existing task/delivery/registration/hash/trace checks |
| Oversized instruction or result | UTF-8 byte limits before persistence |
| Timeout evasion | Result duration bounded by task timeout |
| Audit exfiltration | Explicit safe metadata projection; no instruction or result bodies |
| Stale registration lifecycle replay | Existing credential-scoped dedup and delivery invalidation |
| SQL or filesystem injection | Parameterized SQL; payload contains no filesystem path |

### Residual risks

- V1 cannot prove that a future Worker actually enforced read-only execution;
  that requires a separately reviewed Worker implementation and host controls.
- Result text is persisted as business data and may contain sensitive material
  produced by the Worker. It is bounded and excluded from audit, but retention
  and operator access remain deployment concerns.
- Fixed allowlists must be changed through reviewed source changes; there is no
  runtime override in V1.

## Verification requirements

- Fresh and migrated SQLite schemas preserve existing `system.echo` data.
- Existing lifecycle migration timestamps remain unchanged.
- All allowlist, size, type, and closed-schema rejection cases execute real
  validators.
- Concurrent creation produces one active task.
- Unauthorized capabilities cannot lease a task.
- Result matching, size, timeout, idempotency, and audit redaction are tested
  through the real in-process HTTP/service path.
- Existing `system.echo` tests remain unchanged in behavior.
