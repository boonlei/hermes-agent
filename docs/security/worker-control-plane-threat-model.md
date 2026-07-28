# Hermes Agent Security Threat Model

## Overview

Hermes Agent is a single-tenant personal agent with CLI, gateway, desktop,
plugin, and task-execution surfaces. The Worker Control Plane under
`gateway/worker_control_plane` is a loopback-only/Tailnet pilot service that
authenticates a fixed Worker, issues bounded credentials, leases tasks, and
accepts ACK and Result messages.

The primary assets are operator credentials, Worker bootstrap and access
credentials, task payload and result integrity, registration identity,
SQLite lifecycle state, audit evidence, and the host resources reachable by
an authorized Worker.

## Threat Model, Trust Boundaries, and Assumptions

- OS isolation is the load-bearing boundary described by `SECURITY.md`.
  In-process filtering is defense in depth, not containment.
- The network boundary is Tailnet plus a loopback-only WCP listener.
  Every Worker operation still requires explicit protocol authentication.
- Bootstrap possession authorizes only bounded registration lifecycle
  operations. Pending access credentials authorize confirmation only.
  Confirmed credentials authorize only their exact capabilities.
- SQLite and the WCP process run under the operator account. Database theft is
  considered credential-at-rest exposure even though that account is inside
  the operator trust envelope; plaintext recoverable tokens are therefore
  prohibited.
- Worker request bodies, headers, transaction IDs, identity metadata, and
  idempotency keys are attacker-controlled until validated.
- Runtime configuration, migrations, allowlists, fixed identity constants,
  and approved repository heads are operator/developer-controlled.
- The fixed Worker is assumed to generate a high-entropy bootstrap secret and
  protect its local credential directory. Raw local paths are not public wire
  inputs.

Security invariants:

1. No task protocol mutation occurs without a confirmed, unexpired, exact
   Worker credential.
2. Registration retry and recovery never create a second registration or
   credential for one transaction.
3. A pending credential is unusable for Heartbeat, Poll, ACK, and Result.
4. Token recovery requires both the original bootstrap and exact transaction
   identity.
5. Bootstrap retirement and credential activation commit atomically.
6. SQLite, logs, errors, audit records, and response metadata never contain a
   plaintext token or bootstrap secret.
7. V1 registrations remain compatible and cannot bypass v2 state checks.

## Attack Surface, Mitigations, and Attacker Stories

Registration endpoints accept JSON and Authorization headers. Closed schemas,
duplicate-key rejection, fixed host/path/repository/head values, canonical
capability ordering, bounded strings, UUID validation, and `BEGIN IMMEDIATE`
transactions prevent parser ambiguity, capability smuggling, and concurrent
duplicate issuance. Registration v2 has distinct `/worker-control-plane/v2`
routes and an integer protocol discriminator; a v1 request is never silently
reinterpreted as v2.

An attacker with only a transaction ID cannot recover a token: recovery also
requires the original bootstrap, exact identity, an unexpired pending state,
and an available shared Register-replay/Recover disclosure count. Authenticated
failed recovery attempts consume the same budget. AES-256-GCM authenticates escrow
and canonical identity; HKDF uses a per-transaction salt. Token and proof
comparisons use constant-time primitives.

An attacker with a pending token cannot Poll or submit protocol messages.
They can only confirm the matching pending transaction with an exact
installation proof. Confirmation atomically activates that credential and
retires the bootstrap and previous access lifecycle.

Database theft exposes token hashes and encrypted escrow, not plaintext
tokens. Offline recovery still depends on the high-entropy bootstrap. Audit
records omit Authorization, secrets, escrow data, and full bodies.

Relevant failure modes include:

- JSON duplicate-key or alternate-schema confusion;
- identity substitution across host, path, repository, branch, or head;
- concurrent Register creating duplicate active credentials;
- recovery after confirmation, revocation, supersession, or expiry;
- confirmation activating a credential before durable Worker installation;
- crash between credential issue and confirmation;
- migration rollback or restart losing pending recovery;
- log/error/audit leakage; and
- v1 behavior accidentally inheriting v2 restrictions.

Out of scope are attacks requiring pre-existing operator-account write access
to the protected WCP source/configuration, or public exposure that bypasses
the documented Tailnet/loopback deployment posture. Those remain operational
misconfiguration risks rather than in-process containment failures.

## Severity Calibration

- Critical: unauthenticated remote task execution; plaintext credential
  disclosure outside the trust envelope; bypass allowing an unconfirmed
  credential to execute `codex.execute`.
- High: cross-identity recovery of a pending token; duplicate active
  credential issuance under retry/concurrency; confirmation without token
  possession; destructive migration corrupting live lifecycle state.
- Medium: recoverable denial of commissioning, missing transition audit,
  bounded rate-limit bypass without token disclosure, or stale encrypted
  escrow retained after a terminal state.
- Low: non-secret diagnostic inconsistency, documentation drift, or a
  defense-in-depth improvement that does not cross the documented boundary.

Repository: boonlei/hermes-agent
Version: d98eaddbf7bb08d03bc4dadad260b8e29e529059
