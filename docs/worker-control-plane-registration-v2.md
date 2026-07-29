# Worker Control Plane Registration Transaction V2

## Purpose

Registration v2 lets the fixed `DESKTOP-87SSHTU` Worker commission one
`["system.echo","codex.execute"]` access credential without entering the task
protocol. Registration, recovery, and confirmation form one bounded,
idempotent transaction.

V1 `system.echo` registration remains available at `POST /worker/v1/register`
with its existing six-field request and immediate activation semantics. A
six-field v1 request cannot obtain `codex.execute`; dual capability requires
the v2 identity contract.

## Fixed identity

The v2 contract accepts exactly:

- host: `DESKTOP-87SSHTU`
- path ID: `hermes-server-worker`
- remote: `https://github.com/boonlei/HermesServerWorker.git`
- branch: `main`
- approved head: `4092825b22184ad9820b4899b49fb1f833ac0b19`
- capabilities, in canonical order:
  `["system.echo","codex.execute"]`
- path digest
  `e8f0e3d56567d83c62ce7c3cc72e84188ee217660680b153e41f25e97c546a95`

The digest is SHA-256 over the UTF-8 canonical identity
`windows-path-v1|desktop-87sshtu|c:\hermesserverworker-deploy`. It binds the
approved production Worker checkout without sending the raw path over the
wire. The former dirty-checkout identity at `c:\hermesserverworker` has no
alias or equivalence and is rejected by Register, Recover, and Confirm.

## Register v2

`POST /worker-control-plane/v2/register` uses
`Authorization: Worker-Bootstrap <secret>`. V2 is a separate endpoint and is
never inferred from a v1 body. Both versions are closed schemas. JSON
duplicate keys at any nesting level are rejected before validation.
UUID fields use canonical lowercase hyphenated text. Bounded descriptive
strings must contain non-whitespace text and no ASCII control characters.

The v2 request is:

```json
{
  "protocol_version": 2,
  "worker_id": "server-a-worker",
  "instance_id": "<uuid>",
  "worker_name": "<bounded non-empty string>",
  "worker_version": "<bounded non-empty string>",
  "capabilities": ["system.echo", "codex.execute"],
  "host": "DESKTOP-87SSHTU",
  "path_id": "hermes-server-worker",
  "target_identity": {
    "path_digest": "<lowercase sha256>",
    "remote": "https://github.com/boonlei/HermesServerWorker.git",
    "branch": "main",
    "approved_head": "4092825b22184ad9820b4899b49fb1f833ac0b19"
  },
  "registration_transaction_id": "<uuid>"
}
```

The server verifies the bootstrap, fixed identity, registration uniqueness,
and capability scope in one `BEGIN IMMEDIATE` transaction. It creates one
pending access credential and one transaction. The credential is not usable
for Heartbeat, Poll, ACK, or Result until confirmation.

An exact replay with the same transaction ID returns the same registration,
credential, token, expiry, and identity response. A changed request using the
same transaction ID fails with `idempotency_conflict`.

The deployed identity is the established bounded worker ID
`server-a-worker`; it is intentionally preserved instead of inventing a new
UUID identity and duplicating the Worker.

## Token escrow

The access token is random and its SHA-256 verifier is stored in
`worker_credentials`. The recoverable token is stored only as AES-256-GCM
ciphertext.

The wrapping key is derived with HKDF-SHA-256 from the high-entropy bootstrap
secret, a per-transaction random salt, and the fixed info string
`hermes-wcp-registration-v2-token-wrap`. Canonical transaction identity is
authenticated as AEAD additional data.

Consequences:

- SQLite never contains a plaintext access token.
- Restart recovery requires possession of the same bootstrap secret.
- Changing any bound identity field makes decryption or validation fail.
- Confirming, revoking, superseding, or expiring a transaction clears its
  escrow columns.

## Recovery

`POST /worker-control-plane/v2/registration/recover` also uses
`Authorization: Worker-Bootstrap <secret>`.

Its closed request contains:

```json
{
  "protocol_version": 2,
  "worker_id": "server-a-worker",
  "instance_id": "<uuid>",
  "registration_transaction_id": "<uuid>",
  "host": "DESKTOP-87SSHTU",
  "path_id": "hermes-server-worker",
  "target_identity": {
    "path_digest": "<lowercase sha256>",
    "remote": "https://github.com/boonlei/HermesServerWorker.git",
    "branch": "main",
    "approved_head": "4092825b22184ad9820b4899b49fb1f833ac0b19"
  }
}
```

Recovery is allowed only while the transaction is
`issued_pending_confirmation`, before its expiry, with the original
bootstrap and exact identity. It returns the same Register v2 response and
does not rotate credentials. Register replays and recovery calls share a
limit of five post-issuance token disclosures per transaction; further
requests return `rate_limited`. Authenticated recovery attempts count before
identity validation, preventing a valid bootstrap from making unlimited
guesses.

## Confirmation

`POST /worker-control-plane/v2/registration/confirm` uses
`Authorization: Bearer <pending-access-token>`.

The closed request contains the recovery identity plus `registration_id`,
`credential_id`, and `installation_proof`. The proof is lowercase
HMAC-SHA-256 using the access token as key over canonical compact JSON of
every other confirmation field. It is a fixed 64-hex proof, not free-form
attestation. The Worker computes it only after atomically installing and
rereading the credential.

On confirmation, one `BEGIN IMMEDIATE` transaction:

1. verifies token hash, proof, transaction state, expiry, and exact identity;
2. retires the previously linked access credential, if different;
3. links and activates the pending credential and registration;
4. consumes and revokes the bootstrap;
5. changes the transaction to `confirmed` and clears escrow; and
6. writes transition audit records without secrets.

Repeated exact confirmation is idempotent. No confirmed response returns an
access token.

## Authentication-only status

`GET /worker-control-plane/v2/registration/status` requires
`Authorization: Bearer <confirmed-access-token>` and exactly two query
parameters: canonical lowercase `instance_id` and `registration_id` UUIDs.
The token, registration, instance, confirmed transaction, expiry, and exact
`["system.echo","codex.execute"]` capability set must all match.

The closed JSON response contains only `protocol_version`, `worker_id`,
`instance_id`, `registration_id`, `credential_id`, `state`, `capabilities`,
and `expires_at`. It never returns token, verifier, escrow, bootstrap, or
secret material. The endpoint performs only bounded SQLite reads: it does not
open a write transaction, write audit records, Poll, claim or create a task,
create a delivery, ACK, submit a Result, or execute Codex.

## States and transitions

Allowed states are:

- `issued_pending_confirmation`
- `confirmed`
- `superseded`
- `revoked`
- `expired`

Only `issued_pending_confirmation -> confirmed` activates a credential.
Expiry is fail-closed and revokes the pending credential. Other terminal
states cannot recover or disclose a token. Pending expiry clears escrow and
revokes only the pending access credential; it does not consume the
bootstrap. Expiry is transactionally reaped on service startup and authenticated
lifecycle requests. The same bootstrap may start a new transaction until its
own bounded expiry. After bootstrap expiry, operator reprovisioning is
required.

## Audit and compatibility

Audit records include safe transaction, registration, credential, worker,
instance, host, path ID, state, request ID, and outcome identifiers. They
never include bootstrap secrets, access tokens, escrow material, raw paths,
Authorization, or full request bodies.

The migration is additive. It verifies required column types/nullability,
primary and unique keys, foreign keys, state/protocol checks, and the expiry
index before recording migration metadata. An incompatible pre-existing
table fails the transaction without a migration row. Existing v1 rows have
no transaction row and keep their established behavior. Poll, ACK, Result,
and `codex.execute` result contracts are unchanged.
