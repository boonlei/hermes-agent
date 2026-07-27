# Worker Control Plane `codex.execute` V1

## Status and scope

This document defines the canonical cross-repository contract for the first
restricted `codex.execute` capability. The Hermes Worker Control Plane (WCP)
validates, assigns, and records the task through the existing
task/delivery/ACK/Result lifecycle. It does not execute Codex, construct shell
commands, accept a filesystem path, or select a repository.

V1 is fixed to:

- worker: `server-a-worker`
- path identifier: `hermes-server-worker`
- mode: `read_only`

No live task, Worker implementation, merge, deployment, or commissioning is
part of this change.

## Canonical Poll payload

The `payload` delivered by Poll is a closed, flat JSON object:

```json
{
  "path_id": "hermes-server-worker",
  "mode": "read_only",
  "instruction": "<1-8192 UTF-8 bytes>",
  "timeout_seconds": 60
}
```

The object has exactly four fields. Unknown fields and the former nested
`target`, `instruction`, and `limits` objects are rejected. In particular,
V1 has no shell, command, environment, credential, token, arbitrary path,
expected-head, or per-task result-limit field.

Validation rules:

- `path_id` is exactly `hermes-server-worker`.
- `mode` is exactly `read_only`.
- `instruction` is a non-empty string of at most 8192 UTF-8 bytes.
- `timeout_seconds` is an integer from 60 through 900; booleans are rejected.

The WCP hashes the validated object using sorted JSON keys, UTF-8, and compact
separators. The fixed vectors in
`tests/gateway/fixtures/worker_control_plane/codex_execute_v1/` define the
exact Poll and Result bytes shared with the Worker repository; `manifest.json`
records every fixture SHA-256 and UTF-8 byte count.

## Capability and assignment

Any bootstrap or access credential capable of leasing `codex.execute` must
have exactly this ordered scope:

```json
["system.echo", "codex.execute"]
```

The existing `system.echo`-only scope remains valid for echo workers. A
`codex.execute`-only scope, reordered scope, duplicate capability, or
additional capability is rejected.

Task assignment remains fixed to `server-a-worker`. Poll requires the request
capabilities to exactly match the access credential scope, and a task is
eligible only when its worker and task type match that authenticated scope.

## State machine and concurrency

`codex.execute` uses the existing lifecycle:

`queued -> leased -> running -> completed|failed|rejected|timed_out`

There is no alternate execution or result endpoint. Existing registration,
authentication, ACK, lease, retry, deduplication, and result idempotency
boundaries remain authoritative.

At most one `codex.execute` task may be active globally. Active means queued,
leased, or running. Creation executes under `BEGIN IMMEDIATE`:

1. resolve an existing creation idempotency key;
2. reject reuse with a changed payload;
3. return the existing task for an identical replay;
4. reject a different active `codex.execute` task;
5. insert the new assigned task and bounded audit metadata.

The delivery lease covers the declared execution timeout plus the existing
ACK and fixed result-submission grace periods.

## Canonical Result contract

The existing Hermes Result envelope is unchanged. No top-level
`failure_code` is added. Existing task, delivery, registration, payload-hash,
trace, timing, status, exit-code, and idempotency checks continue to apply.

For `codex.execute`, outer `stderr` must be exactly the empty string. Outer
`stdout` must contain exactly one canonical compact JSON object: no prefix,
suffix, whitespace variation, or second JSON value is accepted. Its schema is
closed and contains:

```json
{
  "status": "completed",
  "classification": "success",
  "failure_code": null,
  "summary": "bounded summary",
  "exit_code": 0,
  "duration_ms": 1200,
  "guards": {
    "read_only": true
  },
  "truncated": false
}
```

`truncated` is optional; every other field is required. Rules:

- `status` is `completed`, `failed`, `rejected`, or `timed_out`.
- `classification` and guard names are safe bounded identifiers.
- `guards` has at most 32 boolean entries.
- `summary` is non-empty and bounded by the fixed stdout limit.
- `exit_code` and `duration_ms` are integers; duration is non-negative.
- `completed` requires `failure_code: null` and `exit_code: 0`.
- `failed` requires a non-zero exit and `codex_failed` or `worker_error`.
- `rejected` requires a non-zero exit and `guard_rejected` or
  `repository_mismatch`.
- `timed_out` requires a non-zero exit and `timeout`.
- outer `status`, `exit_code`, and `duration_ms` exactly equal the inner
  values.

Invalid JSON, a non-canonical serialization, an unknown or missing field,
status/failure mismatch, outer/inner mismatch, non-empty stderr, or oversized
stdout is rejected without storing a result.

The fixed `codex.execute` stdout ceiling is 32768 UTF-8 bytes. It is not
task-configurable. Existing `system.echo` combined stdout/stderr semantics and
its 4096-byte ceiling are unchanged.

## Audit contract

The full bounded stdout is stored only in the existing business Result row.
Audit records contain a reduced projection:

- task, delivery, result, worker, registration, and trace IDs;
- path identifier and mode;
- status, duration, bounded result size, and safe failure code.

Audit records never contain the instruction, stdout, stderr, payload, secrets,
tokens, Authorization headers, credential hashes, or environment variables.

## Threat model

| Threat | Control |
| --- | --- |
| Arbitrary target or local path | Only the fixed `path_id`; no caller-provided path, host, repo, or branch |
| Write-capable execution | Only literal `read_only` is accepted |
| Shell/environment/credential smuggling | Flat closed schema rejects all extra fields |
| Capability escalation | Exact ordered `["system.echo","codex.execute"]` scope |
| Concurrent duplicate execution | Transactional single-active guard and delivery uniqueness |
| Creation replay with changed payload | Canonical payload hash and idempotency conflict |
| Result substitution | Existing task/delivery/registration/hash/trace verification |
| Ambiguous or forged Result | One canonical inner JSON object plus exact outer/inner matching |
| Oversized instruction or output | UTF-8 byte limits before persistence |
| Status/failure confusion | Status-specific failure-code allowlists |
| Audit exfiltration | Explicit metadata projection; no instruction or result body |

Residual risk: the WCP contract cannot by itself prove that the future Worker
enforces host-side read-only execution. That requires a separately reviewed
Worker implementation and deployment controls.

## Shared golden vectors

The stable fixture contains:

- canonical Poll payload bytes and exact SHA-256;
- the exact combined capability registration scope;
- completed, failed, rejected, and timed-out Result envelopes;
- a closed-schema invalid-extra-field case;
- a duplicate Result replay expectation.

The Worker repository must copy this JSON file byte-for-byte and verify its
file SHA-256 during the second cross-repository review.

## Verification requirements

- Payload allowlist, UTF-8 limits, type checks, and closed-schema failures.
- Fixed 32768-byte `codex.execute` stdout limit and unchanged 4096-byte echo
  behavior.
- Canonical inner JSON, status-specific failures, and exact outer matching.
- Concurrent single-active enforcement and duplicate idempotency behavior.
- Unauthorized capability rejection.
- Safe audit projection with no instruction or result content.
- Golden vectors loaded and validated by the component tests.
- Existing migrations and `system.echo` tests remain green.
