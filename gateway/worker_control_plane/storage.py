"""Dedicated SQLite persistence for the test-only control plane."""
from __future__ import annotations
import os
import sqlite3
import stat
from contextlib import contextmanager

from .config import (
    WorkerControlPlaneSettings,
    resolve_pilot_database_path,
    resolve_test_database_path,
)

CURRENT_LIFECYCLE_VERSION = 3
LIFECYCLE_MIGRATION_V3 = "worker_control_plane_bootstrap_lifecycle_v3"
CAPABILITY_MIGRATION_V4 = "worker_control_plane_codex_execute_v4"
REGISTRATION_TRANSACTION_MIGRATION_V5 = (
 "worker_control_plane_registration_transaction_v5"
)

WORKER_TASKS_SCHEMA = (
 "CREATE TABLE IF NOT EXISTS worker_tasks("
 "task_id TEXT PRIMARY KEY, "
 "task_type TEXT NOT NULL CHECK(task_type IN ('system.echo','codex.execute')), "
 "payload_json TEXT NOT NULL, payload_hash TEXT NOT NULL, state TEXT NOT NULL, "
 "created_at TEXT NOT NULL, available_at TEXT NOT NULL, leased_until TEXT, "
 "attempt INTEGER NOT NULL, max_attempts INTEGER NOT NULL, "
 "creation_idempotency_key TEXT NOT NULL UNIQUE, trace_id TEXT NOT NULL, "
 "worker_id TEXT NOT NULL REFERENCES workers(worker_id))"
)

SCHEMA_STATEMENTS = (
 "CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)",
 "CREATE TABLE IF NOT EXISTS workers(worker_id TEXT PRIMARY KEY, worker_name TEXT NOT NULL, allowed_capabilities TEXT NOT NULL, enabled INTEGER NOT NULL, revoked_at TEXT)",
 "CREATE TABLE IF NOT EXISTS worker_credentials(credential_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL REFERENCES workers(worker_id), kind TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, salt TEXT, issued_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, single_use INTEGER NOT NULL DEFAULT 0 CHECK(single_use IN (0,1)), consumed_at TEXT, lifecycle_version INTEGER NOT NULL DEFAULT 0 CHECK(lifecycle_version IN (0,3)), capabilities_json TEXT NOT NULL DEFAULT '[\"system.echo\"]')",
 "CREATE TABLE IF NOT EXISTS worker_instances(registration_id TEXT PRIMARY KEY, worker_id TEXT NOT NULL REFERENCES workers(worker_id), instance_id TEXT NOT NULL, status TEXT NOT NULL, worker_version TEXT NOT NULL, protocol_version TEXT NOT NULL, registered_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, access_credential_id TEXT NOT NULL REFERENCES worker_credentials(credential_id), current_task_id TEXT, UNIQUE(worker_id, instance_id))",
 "CREATE TABLE IF NOT EXISTS worker_registration_transactions_v2("
 "registration_transaction_id TEXT PRIMARY KEY, "
 "protocol_version INTEGER NOT NULL CHECK(protocol_version=2), "
 "worker_id TEXT NOT NULL REFERENCES workers(worker_id), "
 "instance_id TEXT NOT NULL, "
 "worker_name TEXT NOT NULL, worker_version TEXT NOT NULL, "
 "registration_id TEXT NOT NULL REFERENCES worker_instances(registration_id), "
 "bootstrap_credential_id TEXT NOT NULL REFERENCES worker_credentials(credential_id), "
 "credential_id TEXT NOT NULL UNIQUE REFERENCES worker_credentials(credential_id), "
 "request_hash TEXT NOT NULL, host TEXT NOT NULL, path_id TEXT NOT NULL, "
 "path_digest TEXT NOT NULL, remote TEXT NOT NULL, branch TEXT NOT NULL, "
 "approved_head TEXT NOT NULL, capabilities_json TEXT NOT NULL, "
 "state TEXT NOT NULL CHECK(state IN "
 "('issued_pending_confirmation','confirmed','superseded','revoked','expired')), "
 "issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, confirmed_at TEXT, "
 "superseded_at TEXT, revoked_at TEXT, "
 "escrow_salt BLOB, escrow_nonce BLOB, escrow_ciphertext BLOB, "
 "recovery_count INTEGER NOT NULL DEFAULT 0 CHECK(recovery_count>=0), "
 "last_recovered_at TEXT, "
 "UNIQUE(worker_id,registration_transaction_id))",
 WORKER_TASKS_SCHEMA,
 "CREATE TABLE IF NOT EXISTS worker_deliveries(delivery_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES worker_tasks(task_id), worker_id TEXT NOT NULL, registration_id TEXT NOT NULL REFERENCES worker_instances(registration_id), attempt INTEGER NOT NULL, state TEXT NOT NULL, leased_at TEXT NOT NULL, ack_deadline_at TEXT NOT NULL, lease_expires_at TEXT NOT NULL, acknowledged_at TEXT, finished_at TEXT, UNIQUE(task_id, attempt))",
 "CREATE TABLE IF NOT EXISTS worker_results(result_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES worker_tasks(task_id), delivery_id TEXT NOT NULL UNIQUE REFERENCES worker_deliveries(delivery_id), result_idempotency_key TEXT NOT NULL, result_hash TEXT NOT NULL, status TEXT NOT NULL, stdout TEXT NOT NULL, stderr TEXT NOT NULL, exit_code INTEGER, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, duration_ms INTEGER NOT NULL, accepted_at TEXT NOT NULL, UNIQUE(task_id, result_idempotency_key))",
 "CREATE TABLE IF NOT EXISTS worker_request_dedup(worker_id TEXT NOT NULL, registration_id TEXT NOT NULL, method TEXT NOT NULL, route TEXT NOT NULL, task_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_body_hash TEXT NOT NULL, response_status INTEGER NOT NULL, response_json TEXT NOT NULL, PRIMARY KEY(worker_id, idempotency_key))",
 "CREATE TABLE IF NOT EXISTS worker_audit_log(audit_id INTEGER PRIMARY KEY, occurred_at TEXT NOT NULL, event_type TEXT NOT NULL, worker_id TEXT, instance_id TEXT, registration_id TEXT, task_id TEXT, delivery_id TEXT, trace_id TEXT, outcome TEXT NOT NULL, reason_code TEXT, details_json TEXT)",
)
class WorkerControlPlaneStore:
 def __init__(self, settings: WorkerControlPlaneSettings):
  if not isinstance(settings, WorkerControlPlaneSettings):
   raise TypeError("WorkerControlPlaneStore requires validated settings")
  if not settings.enabled or settings.test_mode == settings.pilot_mode:
   raise ValueError("Worker Control Plane storage requires one isolated mode")
  if settings.pilot_mode and not settings.test_pilot_mode:
   root,path=resolve_pilot_database_path(settings.approved_test_root,settings.db_path)
  else:
   root,path=resolve_test_database_path(settings.approved_test_root,settings.db_path,allow_test_pilot_filename=settings.test_pilot_mode)
  if root != settings.approved_test_root:
   raise ValueError("approved test root changed after settings validation")
  try:
   info=os.lstat(path)
  except FileNotFoundError:
   info=None
  if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
   raise ValueError("database file is unsafe")
  self.conn=sqlite3.connect(path, check_same_thread=False); os.chmod(path,0o600); self.conn.row_factory=sqlite3.Row
  self.conn.execute("PRAGMA foreign_keys=ON"); self.conn.execute("PRAGMA synchronous=FULL"); self.conn.execute("PRAGMA secure_delete=ON"); self.conn.execute("PRAGMA cell_size_check=ON")
  try: self.conn.execute("PRAGMA journal_mode=WAL")
  except sqlite3.DatabaseError: self.conn.execute("PRAGMA journal_mode=DELETE")
  task_sql_row=self.conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='worker_tasks'").fetchone()
  task_columns={row["name"] for row in self.conn.execute("PRAGMA table_info(worker_tasks)")}
  task_sql=task_sql_row["sql"] if task_sql_row is not None else ""
  rebuild_tasks=bool(task_sql_row) and ("worker_id" not in task_columns or "codex.execute" not in task_sql)
  if rebuild_tasks:
   self.conn.execute("PRAGMA foreign_keys=OFF")
  try:
   self.conn.execute("BEGIN IMMEDIATE")
   for statement in SCHEMA_STATEMENTS:
    self.conn.execute(statement)
   columns={row["name"]:row for row in self.conn.execute("PRAGMA table_info(worker_credentials)")}
   if "single_use" not in columns:
    self.conn.execute("ALTER TABLE worker_credentials ADD COLUMN single_use INTEGER NOT NULL DEFAULT 0 CHECK(single_use IN (0,1))")
   if "consumed_at" not in columns:
    self.conn.execute("ALTER TABLE worker_credentials ADD COLUMN consumed_at TEXT")
   if "lifecycle_version" not in columns:
    self.conn.execute("ALTER TABLE worker_credentials ADD COLUMN lifecycle_version INTEGER NOT NULL DEFAULT 0 CHECK(lifecycle_version IN (0,3))")
   if "capabilities_json" not in columns:
    self.conn.execute("ALTER TABLE worker_credentials ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '[\"system.echo\"]'")
   columns={row["name"]:row for row in self.conn.execute("PRAGMA table_info(worker_credentials)")}
   expected={
    "single_use":("INTEGER",1,"0"),
    "consumed_at":("TEXT",0,None),
    "lifecycle_version":("INTEGER",1,"0"),
    "capabilities_json":("TEXT",1,"'[\"system.echo\"]'"),
   }
   for name,(kind,not_null,default) in expected.items():
    row=columns.get(name)
    if row is None or (row["type"].upper(),row["notnull"],row["dflt_value"]) != (kind,not_null,default):
     raise sqlite3.DatabaseError("worker credential lifecycle schema is incompatible")
   if rebuild_tasks:
    self.conn.execute("DROP TABLE IF EXISTS worker_tasks_v4")
    self.conn.execute(WORKER_TASKS_SCHEMA.replace(
     "IF NOT EXISTS worker_tasks", "worker_tasks_v4", 1
    ))
    self.conn.execute(
     "INSERT INTO worker_tasks_v4("
     "task_id,task_type,payload_json,payload_hash,state,created_at,"
     "available_at,leased_until,attempt,max_attempts,"
     "creation_idempotency_key,trace_id,worker_id"
     ") SELECT task_id,task_type,payload_json,payload_hash,state,created_at,"
     "available_at,leased_until,attempt,max_attempts,"
     "creation_idempotency_key,trace_id,'server-a-worker' FROM worker_tasks"
    )
    self.conn.execute("DROP TABLE worker_tasks")
    self.conn.execute("ALTER TABLE worker_tasks_v4 RENAME TO worker_tasks")
   self.conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_queue ON worker_tasks(state,available_at,created_at)")
   self.conn.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_lease ON worker_deliveries(state,lease_expires_at)")
   self.conn.execute(
    "CREATE INDEX IF NOT EXISTS idx_registration_transactions_v2_state "
    "ON worker_registration_transactions_v2(state,expires_at)"
   )
   registration_v2_info={
    row["name"]:row for row in self.conn.execute(
     "PRAGMA table_info(worker_registration_transactions_v2)"
    )
   }
   required_registration_v2_columns={
    "registration_transaction_id","protocol_version","worker_id",
    "instance_id","worker_name","worker_version","registration_id",
    "bootstrap_credential_id","credential_id","request_hash","host",
    "path_id","path_digest","remote","branch","approved_head",
    "capabilities_json","state","issued_at","expires_at","confirmed_at",
    "superseded_at","revoked_at","escrow_salt","escrow_nonce",
    "escrow_ciphertext","recovery_count","last_recovered_at",
   }
   if not required_registration_v2_columns <= set(registration_v2_info):
    raise sqlite3.DatabaseError(
     "registration v2 transaction schema is incompatible"
    )
   expected_registration_v2_columns={
    "registration_transaction_id":("TEXT",0,1,None),
    "protocol_version":("INTEGER",1,0,None),
    "worker_id":("TEXT",1,0,None),
    "instance_id":("TEXT",1,0,None),
    "worker_name":("TEXT",1,0,None),
    "worker_version":("TEXT",1,0,None),
    "registration_id":("TEXT",1,0,None),
    "bootstrap_credential_id":("TEXT",1,0,None),
    "credential_id":("TEXT",1,0,None),
    "request_hash":("TEXT",1,0,None),
    "host":("TEXT",1,0,None),
    "path_id":("TEXT",1,0,None),
    "path_digest":("TEXT",1,0,None),
    "remote":("TEXT",1,0,None),
    "branch":("TEXT",1,0,None),
    "approved_head":("TEXT",1,0,None),
    "capabilities_json":("TEXT",1,0,None),
    "state":("TEXT",1,0,None),
    "issued_at":("TEXT",1,0,None),
    "expires_at":("TEXT",1,0,None),
    "confirmed_at":("TEXT",0,0,None),
    "superseded_at":("TEXT",0,0,None),
    "revoked_at":("TEXT",0,0,None),
    "escrow_salt":("BLOB",0,0,None),
    "escrow_nonce":("BLOB",0,0,None),
    "escrow_ciphertext":("BLOB",0,0,None),
    "recovery_count":("INTEGER",1,0,"0"),
    "last_recovered_at":("TEXT",0,0,None),
   }
   for name,expected in expected_registration_v2_columns.items():
    row=registration_v2_info[name]
    actual=(
     row["type"].upper(),row["notnull"],row["pk"],row["dflt_value"]
    )
    if actual!=expected:
     raise sqlite3.DatabaseError(
      "registration v2 transaction schema is incompatible"
     )
   transaction_sql_row=self.conn.execute(
    "SELECT sql FROM sqlite_master WHERE type='table' "
    "AND name='worker_registration_transactions_v2'"
   ).fetchone()
   transaction_sql="".join(
    (transaction_sql_row["sql"] if transaction_sql_row else "").split()
   ).lower()
   required_checks=(
    "check(protocol_version=2)",
    "check(statein('issued_pending_confirmation','confirmed',"
    "'superseded','revoked','expired'))",
    "check(recovery_count>=0)",
   )
   if not all(check in transaction_sql for check in required_checks):
    raise sqlite3.DatabaseError(
     "registration v2 transaction schema is incompatible"
    )
   unique_indexes=set()
   for index in self.conn.execute(
    "PRAGMA index_list(worker_registration_transactions_v2)"
   ):
    columns=tuple(
     row["name"] for row in self.conn.execute(
      "SELECT name FROM pragma_index_info(?)",
      (index["name"],),
     )
    )
    if index["unique"]:
     unique_indexes.add(columns)
   if (
    ("credential_id",) not in unique_indexes
    or ("worker_id","registration_transaction_id") not in unique_indexes
   ):
    raise sqlite3.DatabaseError(
     "registration v2 transaction schema is incompatible"
    )
   foreign_keys={
    (
     row["from"],row["table"],row["to"],row["on_update"],
     row["on_delete"],row["match"],
    )
    for row in self.conn.execute(
     "PRAGMA foreign_key_list(worker_registration_transactions_v2)"
    )
   }
   expected_foreign_keys={
    ("worker_id","workers","worker_id","NO ACTION","NO ACTION","NONE"),
    (
     "registration_id","worker_instances","registration_id",
     "NO ACTION","NO ACTION","NONE",
    ),
    (
     "bootstrap_credential_id","worker_credentials","credential_id",
     "NO ACTION","NO ACTION","NONE",
    ),
    (
     "credential_id","worker_credentials","credential_id",
     "NO ACTION","NO ACTION","NONE",
    ),
   }
   if foreign_keys!=expected_foreign_keys:
    raise sqlite3.DatabaseError(
     "registration v2 transaction schema is incompatible"
    )
   state_index=tuple(
   row["name"] for row in self.conn.execute(
     "SELECT name FROM pragma_index_info("
     "'idx_registration_transactions_v2_state')"
   )
   )
   if state_index!=("state","expires_at"):
    raise sqlite3.DatabaseError(
     "registration v2 transaction schema is incompatible"
    )
   self.conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(?,datetime('now'))",("worker_control_plane_schema_v1",))
   self.conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(?,datetime('now'))",("worker_control_plane_bootstrap_lifecycle_v2",))
   self.conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(?,datetime('now'))",(LIFECYCLE_MIGRATION_V3,))
   self.conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(?,datetime('now'))",(CAPABILITY_MIGRATION_V4,))
   self.conn.execute(
    "INSERT OR IGNORE INTO schema_migrations VALUES(?,datetime('now'))",
    (REGISTRATION_TRANSACTION_MIGRATION_V5,),
   )
   if self.conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
    raise sqlite3.DatabaseError("worker control plane foreign key check failed")
   self.conn.commit()
  except BaseException:
   try: self.conn.rollback()
   finally:
    if rebuild_tasks:
     self.conn.execute("PRAGMA foreign_keys=ON")
    self.conn.close()
   raise
  if rebuild_tasks:
   self.conn.execute("PRAGMA foreign_keys=ON")
  if self.conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
   self.conn.close()
   raise sqlite3.DatabaseError("worker control plane foreign keys are disabled")
 @contextmanager
 def transaction(self):
  try:
   self.conn.execute("BEGIN IMMEDIATE"); yield self.conn; self.conn.commit()
  except Exception: self.conn.rollback(); raise
 def check_health(self):
  row=self.conn.execute("SELECT 1").fetchone()
  if row is None or row[0] != 1: raise RuntimeError("storage health check failed")
 def close(self): self.conn.close()
