"""Small transactional domain service for allowlisted Worker capabilities."""
from __future__ import annotations
import json, os, secrets, uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from cryptography.exceptions import InvalidTag
from .auth import bootstrap_record, verify_bootstrap, new_access_token, verify_access_token
from .config import WorkerControlPlaneSettings
from .errors import WorkerControlPlaneError, error
from .models import (
 CODEX_EXECUTE_WORKER_ID,
 CODEX_EXECUTE_MAX_RESULT_BYTES,
 CODEX_EXECUTE_RESULT_GRACE_SECONDS,
 canonical_json_hash,
 validate_capabilities,
 validate_codex_execute_payload,
 validate_codex_execute_result,
 validate_system_echo_payload,
)
from .registration_v2 import (
 CAPABILITIES as REGISTRATION_V2_CAPABILITIES,
 MAX_RECOVERIES,
 PENDING_STATE,
 WrappedToken,
 identity_aad,
 request_hash,
 unwrap_token,
 verify_installation_proof,
 wrap_token,
)
from .storage import CURRENT_LIFECYCLE_VERSION, WorkerControlPlaneStore

_NO_REPLAY = object()

class WorkerAuthService:
 def __init__(self, store, now, now_datetime): self.store,self.now,self.now_datetime=store,now,now_datetime
 def bootstrap(self, c, worker_id, secret):
  rows=c.execute("SELECT c.*,w.enabled,w.allowed_capabilities FROM worker_credentials c JOIN workers w USING(worker_id) WHERE c.worker_id=? AND c.kind='bootstrap'",(worker_id,)).fetchall()
  def matches(candidate):
   try:
    return verify_bootstrap(secret,candidate['salt'],candidate['token_hash'])
   except (TypeError, ValueError):
    return False
  row=next((candidate for candidate in rows if matches(candidate)),None)
  if not row or not row['enabled'] or row['revoked_at'] or row['consumed_at'] or row['lifecycle_version']!=CURRENT_LIFECYCLE_VERSION: raise error('invalid_credential')
  expires_at=row['expires_at']
  if not isinstance(expires_at,str): raise error('invalid_credential')
  try:
   expiry=datetime.fromisoformat(expires_at.replace('Z','+00:00'))
  except ValueError:
   raise error('invalid_credential') from None
  if expiry.tzinfo is None or expiry.astimezone(timezone.utc)<=self.now_datetime(): raise error('invalid_credential')
  return row
 def access(self, c, token):
  rows=c.execute("SELECT c.worker_id,c.credential_id,c.token_hash,c.expires_at,c.revoked_at,c.consumed_at,c.lifecycle_version,c.capabilities_json,w.allowed_capabilities,w.enabled,i.instance_id,i.registration_id,i.status FROM worker_credentials c JOIN workers w USING(worker_id) JOIN worker_instances i ON i.access_credential_id=c.credential_id AND i.worker_id=c.worker_id WHERE c.kind='access'").fetchall()
  row=next((candidate for candidate in rows if verify_access_token(token,candidate['token_hash'])),None)
  if row is None: raise error('invalid_credential')
  if row['lifecycle_version']!=CURRENT_LIFECYCLE_VERSION or row['consumed_at'] is not None: raise error('invalid_credential')
  if not row['enabled'] or row['revoked_at']: raise error('worker_revoked')
  if not isinstance(row['expires_at'],str) or row['expires_at'] <= self.now(): raise error('invalid_credential')
  if row['status'] != 'active': raise error('registration_expired')
  try:
   capabilities=validate_capabilities(json.loads(row['capabilities_json']))
   allowed=validate_capabilities(json.loads(row['allowed_capabilities']))
  except (TypeError,ValueError,json.JSONDecodeError):
   raise error('invalid_credential') from None
  if not set(capabilities)<=set(allowed): raise error('invalid_credential')
  return row

class WorkerControlPlaneService:
 def __init__(self, settings, *, clock: Callable[[], datetime] | None = None):
  if not settings.enabled or settings.test_mode == settings.pilot_mode: raise ValueError('isolated mode required')
  self.settings=settings; self.store=WorkerControlPlaneStore(settings); self._clock=clock or (lambda: datetime.now(timezone.utc)); self.auth=WorkerAuthService(self.store,self.now,self._now_datetime)
  self.reap_expired_registration_v2()
 def _now_datetime(self):
  value=self._clock()
  if not isinstance(value,datetime) or value.tzinfo is None: raise RuntimeError('clock must return timezone-aware datetime')
  return value.astimezone(timezone.utc)
 def now(self): return self._now_datetime().isoformat().replace('+00:00','Z')
 def advance_for_test(self, seconds):
  advance=getattr(self._clock,'advance',None)
  if advance is None: raise RuntimeError('test clock was not injected')
  advance(seconds)
 def check_health(self): self.store.check_health()
 def registration_status(self, token, instance_id, registration_id):
  row=self.auth.access(self.store.conn,token)
  self._assert_context(
   row,
   {
    'worker_id':row['worker_id'],
    'instance_id':instance_id,
    'registration_id':registration_id,
   },
  )
  transaction=self.store.conn.execute(
   "SELECT state,capabilities_json,expires_at FROM "
   "worker_registration_transactions_v2 WHERE registration_id=? "
   "AND credential_id=? AND instance_id=?",
   (registration_id,row['credential_id'],instance_id),
  ).fetchone()
  if transaction is None or transaction['state']!='confirmed':
   raise error('invalid_credential')
  try:
   capabilities=validate_capabilities(json.loads(row['capabilities_json']))
   transaction_capabilities=validate_capabilities(
    json.loads(transaction['capabilities_json'])
   )
  except (TypeError,ValueError,json.JSONDecodeError):
   raise error('invalid_credential') from None
  if (
   capabilities!=REGISTRATION_V2_CAPABILITIES
   or transaction_capabilities!=REGISTRATION_V2_CAPABILITIES
   or transaction['expires_at']!=row['expires_at']
  ):
   raise error('invalid_credential')
  return {
   'protocol_version':2,
   'worker_id':row['worker_id'],
   'instance_id':row['instance_id'],
   'registration_id':row['registration_id'],
   'credential_id':row['credential_id'],
   'state':'confirmed',
   'capabilities':capabilities,
   'expires_at':row['expires_at'],
  }
 def close(self): self.store.close()
 def _audit(self,c,event,**fields):
  safe={k:v for k,v in fields.items() if k in {'worker_id','instance_id','registration_id','task_id','delivery_id','trace_id','outcome','reason_code'}}
  details=fields.get('details')
  details_json=json.dumps(details,sort_keys=True,separators=(',',':')) if details is not None else None
  cursor=c.execute("INSERT INTO worker_audit_log(occurred_at,event_type,worker_id,instance_id,registration_id,task_id,delivery_id,trace_id,outcome,reason_code,details_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(self.now(),event,safe.get('worker_id'),safe.get('instance_id'),safe.get('registration_id'),safe.get('task_id'),safe.get('delivery_id'),safe.get('trace_id'),safe.get('outcome','ok'),safe.get('reason_code'),details_json))
  return cursor.lastrowid
 def record_rejection(self,event,**fields):
  with self.store.transaction() as c: return self._audit(c,event,outcome='rejected',**fields)
 def record_registration_failure(self, *, request_id, worker_id, instance_id, credential_id, registration_id, http_status, error_code, lifecycle_outcome):
  details={'request_id':request_id,'http_status':http_status,'error_code':error_code,'worker_id':worker_id,'instance_id':instance_id,'credential_id':credential_id,'registration_lifecycle_outcome':lifecycle_outcome}
  with self.store.transaction() as c:
   if error_code=='invalid_credential':
    self._audit(c,'credential_failed',worker_id=worker_id,instance_id=instance_id,registration_id=registration_id,outcome='rejected',reason_code=error_code)
   return self._audit(c,'registration_rejected',worker_id=worker_id,instance_id=instance_id,registration_id=registration_id,outcome='rejected',reason_code=error_code,details=details)
 def provision_worker(self, *, secret=None, ttl_seconds=900, single_use=True, capabilities=None, install_credential=None):
  if not (self.settings.test_mode or self.settings.pilot_mode): raise RuntimeError('isolated mode required')
  if type(ttl_seconds) is not int or not 1<=ttl_seconds<=900: raise ValueError('bootstrap TTL must be between 1 and 900 seconds')
  if type(single_use) is not bool: raise ValueError('single_use must be boolean')
  capabilities=validate_capabilities(
   ['system.echo'] if capabilities is None else capabilities
  ); capabilities_json=json.dumps(capabilities,separators=(',',':'))
  secret=secret or secrets.token_urlsafe(32); salt,digest=bootstrap_record(secret); credential_id=str(uuid.uuid4())
  issued_datetime=self._now_datetime(); issued_at=issued_datetime.isoformat().replace('+00:00','Z'); expires_at=(issued_datetime+timedelta(seconds=ttl_seconds)).isoformat().replace('+00:00','Z')
  rollback_file=None; finalize_file=None
  try:
   with self.store.transaction() as c:
    c.execute("INSERT INTO workers(worker_id,worker_name,allowed_capabilities,enabled,revoked_at) VALUES(?,?,?,1,NULL) ON CONFLICT(worker_id) DO UPDATE SET worker_name=excluded.worker_name,allowed_capabilities=excluded.allowed_capabilities,enabled=1,revoked_at=NULL",('server-a-worker','Hermes local pilot worker',capabilities_json))
    if c.execute("SELECT 1 FROM worker_credentials WHERE worker_id=? AND kind='bootstrap' AND revoked_at IS NULL",('server-a-worker',)).fetchone():
     raise ValueError('an unrevoked bootstrap credential already exists')
    c.execute("INSERT INTO worker_credentials(credential_id,worker_id,kind,token_hash,salt,issued_at,expires_at,revoked_at,single_use,consumed_at,lifecycle_version,capabilities_json) VALUES(?,?,?,?,?,?,?,?,?,NULL,?,?)",(credential_id,'server-a-worker','bootstrap',digest,salt,issued_at,expires_at,None,int(single_use),CURRENT_LIFECYCLE_VERSION,capabilities_json)); self._audit(c,'worker_provisioned',worker_id='server-a-worker',reason_code=credential_id)
    if install_credential is not None: rollback_file,finalize_file=install_credential()
  except Exception:
   if rollback_file is not None: rollback_file()
   raise
  if finalize_file is not None: finalize_file()
  return {'secret':secret,'credential_id':credential_id,'issued_at':issued_at,'expires_at':expires_at,'single_use':single_use,'capabilities':capabilities}
 def seed_test_worker(self):
  if not self.settings.test_mode: raise RuntimeError('test mode required')
  return self.provision_worker()['secret']
 def list_bootstrap_credentials(self,worker_id):
  rows=self.store.conn.execute("SELECT credential_id,worker_id,issued_at,expires_at,revoked_at,single_use,consumed_at,lifecycle_version FROM worker_credentials WHERE worker_id=? AND kind='bootstrap' ORDER BY issued_at,credential_id",(worker_id,)).fetchall()
  result=[]
  for row in rows:
   if row['consumed_at'] is not None: state='consumed'
   elif row['revoked_at'] is not None: state='revoked'
   elif row['lifecycle_version']!=CURRENT_LIFECYCLE_VERSION: state='legacy_ineligible'
   elif row['expires_at'] is None: state='invalid'
   else:
    try:
     expiry=datetime.fromisoformat(row['expires_at'].replace('Z','+00:00'))
     state='expired' if expiry.tzinfo is None or expiry.astimezone(timezone.utc)<=self._now_datetime() else 'active'
    except ValueError:
     state='invalid'
   result.append({'credential_id':row['credential_id'],'worker_id':row['worker_id'],'issued_at':row['issued_at'],'expires_at':row['expires_at'],'single_use':bool(row['single_use']),'consumed_at':row['consumed_at'],'revoked_at':row['revoked_at'],'lifecycle_version':row['lifecycle_version'],'state':state})
  return result
 def revoke_bootstrap_credential(self,worker_id,credential_id):
  with self.store.transaction() as c:
   row=c.execute("SELECT credential_id FROM worker_credentials WHERE worker_id=? AND credential_id=? AND kind='bootstrap' AND revoked_at IS NULL",(worker_id,credential_id)).fetchone()
   if not row: raise ValueError('credential target not found or already revoked')
   revoked_at=self.now()
   pending=c.execute(
    "SELECT * FROM worker_registration_transactions_v2 "
    "WHERE worker_id=? AND bootstrap_credential_id=? AND state=?",
    (worker_id,credential_id,PENDING_STATE),
   ).fetchall()
   changed=c.execute("UPDATE worker_credentials SET revoked_at=? WHERE worker_id=? AND credential_id=? AND kind='bootstrap' AND revoked_at IS NULL",(revoked_at,worker_id,credential_id)).rowcount
   if changed!=1: raise ValueError('credential target changed during revocation')
   for transaction in pending:
    c.execute(
     "UPDATE worker_registration_transactions_v2 SET state='revoked',"
     "revoked_at=?,escrow_salt=NULL,escrow_nonce=NULL,"
     "escrow_ciphertext=NULL WHERE registration_transaction_id=? "
     "AND state=?",
     (
      revoked_at,transaction['registration_transaction_id'],
      PENDING_STATE,
     ),
    )
    c.execute(
     "UPDATE worker_credentials SET revoked_at=? WHERE credential_id=? "
     "AND revoked_at IS NULL",
     (revoked_at,transaction['credential_id']),
    )
    c.execute(
     "UPDATE worker_instances SET status='revoked' "
     "WHERE registration_id=? AND access_credential_id=? AND status=?",
     (
      transaction['registration_id'],transaction['credential_id'],
      PENDING_STATE,
     ),
    )
    self._audit(
     c,
     'registration_v2_revoked',
     worker_id=worker_id,
     instance_id=transaction['instance_id'],
     registration_id=transaction['registration_id'],
     outcome='revoked',
     reason_code='bootstrap_credential_revoked',
     details={
      'registration_transaction_id':transaction[
       'registration_transaction_id'
      ],
      'credential_id':transaction['credential_id'],
      'state':'revoked',
     },
    )
   self._audit(c,'bootstrap_credential_revoked',worker_id=worker_id,reason_code=credential_id)
  return {'credential_id':credential_id,'worker_id':worker_id,'revoked_at':revoked_at,'state':'revoked'}
 def list_registrations(self,worker_id):
  rows=self.store.conn.execute("SELECT i.worker_id,i.instance_id,i.registration_id,i.status,i.worker_version,i.protocol_version,i.registered_at,i.last_seen_at,i.current_task_id,w.enabled,w.revoked_at AS worker_revoked_at FROM worker_instances i JOIN workers w USING(worker_id) WHERE i.worker_id=? ORDER BY i.registered_at,i.registration_id",(worker_id,)).fetchall()
  return [{'worker_id':row['worker_id'],'instance_id':row['instance_id'],'registration_id':row['registration_id'],'status':row['status'],'worker_version':row['worker_version'],'protocol_version':row['protocol_version'],'registered_at':row['registered_at'],'last_seen_at':row['last_seen_at'],'current_task_id':row['current_task_id'],'worker_enabled':bool(row['enabled']),'worker_revoked_at':row['worker_revoked_at']} for row in rows]
 def revoke_registration(self,worker_id,instance_id,registration_id):
  with self.store.transaction() as c:
   row=c.execute("SELECT registration_id,access_credential_id FROM worker_instances WHERE worker_id=? AND instance_id=? AND registration_id=? AND status='active'",(worker_id,instance_id,registration_id)).fetchone()
   if not row: raise ValueError('registration target not found or not active')
   revoked_at=self.now()
   changed=c.execute("UPDATE worker_instances SET status='revoked' WHERE worker_id=? AND instance_id=? AND registration_id=? AND status='active'",(worker_id,instance_id,registration_id)).rowcount
   if changed!=1: raise ValueError('registration target changed during revocation')
   c.execute("UPDATE worker_credentials SET revoked_at=? WHERE credential_id=? AND revoked_at IS NULL",(revoked_at,row['access_credential_id']))
   transaction=c.execute(
    "SELECT registration_transaction_id,credential_id "
    "FROM worker_registration_transactions_v2 "
    "WHERE registration_id=? AND credential_id=? AND state='confirmed'",
    (registration_id,row['access_credential_id']),
   ).fetchone()
   if transaction:
    c.execute(
     "UPDATE worker_registration_transactions_v2 SET state='revoked',"
     "revoked_at=?,escrow_salt=NULL,escrow_nonce=NULL,"
     "escrow_ciphertext=NULL WHERE registration_transaction_id=?",
     (revoked_at,transaction['registration_transaction_id']),
    )
    self._audit(
     c,
     'registration_v2_revoked',
     worker_id=worker_id,
     instance_id=instance_id,
     registration_id=registration_id,
     outcome='revoked',
     reason_code='registration_revoked',
     details={
      'registration_transaction_id':transaction[
       'registration_transaction_id'
      ],
      'credential_id':transaction['credential_id'],
      'state':'revoked',
     },
    )
   self._invalidate_registration_deliveries(c,registration_id)
   self._audit(c,'registration_revoked',worker_id=worker_id,instance_id=instance_id,registration_id=registration_id)
  return {'worker_id':worker_id,'instance_id':instance_id,'registration_id':registration_id,'status':'revoked','revoked_at':revoked_at}
 def revoke_test_worker(self):
  with self.store.transaction() as c:
   c.execute("UPDATE workers SET enabled=0,revoked_at=? WHERE worker_id='server-a-worker'",(self.now(),)); self._audit(c,'worker_revoked',worker_id='server-a-worker')
 def _codex_audit_details(self,payload,**extra):
  return {'path_id':payload['path_id'],'mode':payload['mode'],**extra}
 def _enqueue_task(self,task_type,payload,key,worker_id):
  if not (self.settings.test_mode or self.settings.pilot_mode): raise RuntimeError('isolated mode required')
  if not isinstance(key,str) or not 1<=len(key)<=128 or not key.isascii() or not key.isprintable(): raise error('malformed_request')
  task_id=str(uuid.uuid4()); trace=str(uuid.uuid4()); encoded=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':')); h=canonical_json_hash(payload)
  with self.store.transaction() as c:
   existing=c.execute("SELECT task_id,task_type,worker_id,payload_hash FROM worker_tasks WHERE creation_idempotency_key=?",(key,)).fetchone()
   if existing:
    if (existing['task_type'],existing['worker_id'],existing['payload_hash']) != (task_type,worker_id,h): raise error('state_conflict')
    return existing['task_id']
   if task_type=='codex.execute' and c.execute("SELECT 1 FROM worker_tasks WHERE task_type='codex.execute' AND state IN ('queued','leased','running')").fetchone():
    raise error('state_conflict')
   c.execute("INSERT INTO worker_tasks(task_id,task_type,payload_json,payload_hash,state,created_at,available_at,leased_until,attempt,max_attempts,creation_idempotency_key,trace_id,worker_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(task_id,task_type,encoded,h,'queued',self.now(),self.now(),None,0,self.settings.max_attempts,key,trace,worker_id))
   if task_type=='codex.execute':
    self._audit(c,'codex_task_created',worker_id=worker_id,task_id=task_id,trace_id=trace,details=self._codex_audit_details(payload,status='queued'))
   else:
    self._audit(c,'test_task_created',task_id=task_id,trace_id=trace)
  return task_id
 def enqueue_system_echo(self,payload,key):
  payload=validate_system_echo_payload(payload,self.settings.max_stdout_bytes)
  return self._enqueue_task('system.echo',payload,key,'server-a-worker')
 def enqueue_codex_execute(self,payload,key,worker_id=CODEX_EXECUTE_WORKER_ID):
  if worker_id!=CODEX_EXECUTE_WORKER_ID: raise error('unsupported_capability')
  try:
   payload=validate_codex_execute_payload(payload)
  except ValueError:
   raise error('invalid_task_payload') from None
  return self._enqueue_task('codex.execute',payload,key,worker_id)
 def create_test_echo_task(self,payload,key):
  if not self.settings.test_mode: raise RuntimeError('test mode required')
  return self.enqueue_system_echo(payload,key)
 def _invalidate_registration_deliveries(self,c,registration_id):
  rows=c.execute("SELECT d.delivery_id,d.task_id,d.attempt,t.max_attempts FROM worker_deliveries d JOIN worker_tasks t USING(task_id) WHERE d.registration_id=? AND d.state IN ('leased','acknowledged')",(registration_id,)).fetchall()
  for row in rows:
   task_state='dead_letter' if row['attempt']>=row['max_attempts'] else 'queued'
   c.execute("UPDATE worker_deliveries SET state='expired' WHERE delivery_id=?",(row['delivery_id'],))
   c.execute("UPDATE worker_tasks SET state=?,leased_until=NULL WHERE task_id=?",(task_state,row['task_id']))
   self._audit(c,'registration_delivery_invalidated',registration_id=registration_id,task_id=row['task_id'],delivery_id=row['delivery_id'],reason_code='registration_lifecycle_rotated')
   self._audit(c,'task_dead_lettered' if task_state=='dead_letter' else 'task_redelivered',registration_id=registration_id,task_id=row['task_id'],delivery_id=row['delivery_id'],reason_code='registration_lifecycle_rotated')
 def _retire_registration_dedup(self,c,registration_id,access_credential_id):
  retired_scope=f"{registration_id}:{access_credential_id}"
  changed=c.execute("UPDATE worker_request_dedup SET registration_id=? WHERE registration_id=?",(retired_scope,registration_id)).rowcount
  if changed:
   self._audit(c,'registration_dedup_retired',registration_id=registration_id,outcome='ok',reason_code='registration_lifecycle_rotated')
 def register_worker(self,d,secret,*,request_id=None,evidence=None):
  request_id=request_id or str(uuid.uuid4())
  worker_id=d.get('worker_id') if isinstance(d.get('worker_id'),str) else None
  iid=d.get('instance_id') if isinstance(d.get('instance_id'),str) else None
  credential_id=None; registration_id=None; lifecycle_outcome='request_rejected'
  try:
   if d.get('protocol_version')!='1.0': raise error('unsupported_protocol')
   if d.get('worker_id')!='server-a-worker': raise error('invalid_credential')
   try: requested_capabilities=validate_capabilities(d.get('capabilities'))
   except ValueError: raise error('unsupported_capability') from None
   if requested_capabilities!=['system.echo']:
    raise error('unsupported_protocol')
   try: uuid.UUID(iid)
   except Exception: raise error('malformed_request')
   with self.store.transaction() as c:
    bootstrap=self.auth.bootstrap(c,d['worker_id'],secret); credential_id=bootstrap['credential_id']
    try:
     bootstrap_capabilities=validate_capabilities(json.loads(bootstrap['capabilities_json']))
     allowed_capabilities=validate_capabilities(json.loads(bootstrap['allowed_capabilities']))
    except (TypeError,ValueError,json.JSONDecodeError):
     raise error('invalid_credential') from None
    if requested_capabilities!=bootstrap_capabilities or not set(requested_capabilities)<=set(allowed_capabilities):
     raise error('unsupported_capability')
    active=c.execute("SELECT * FROM worker_instances WHERE worker_id=? AND status='active'",(d['worker_id'],)).fetchone()
    existing=c.execute("SELECT * FROM worker_instances WHERE worker_id=? AND instance_id=?",(d['worker_id'],iid)).fetchone()
    if active and active['instance_id'] != iid:
     registration_id=active['registration_id']; lifecycle_outcome='different_active_instance'; raise error('duplicate_active_instance')
    if existing and existing['protocol_version']!=d['protocol_version']:
     registration_id=existing['registration_id']; lifecycle_outcome='immutable_metadata_conflict'; raise error('instance_conflict')
    token,thash=new_access_token(); cid=str(uuid.uuid4()); now=self.now(); expiry=(self._now_datetime()+timedelta(seconds=self.settings.token_ttl_seconds)).isoformat().replace('+00:00','Z')
    if existing:
     rid=existing['registration_id']; registration_id=rid
     self._retire_registration_dedup(c,rid,existing['access_credential_id'])
     self._invalidate_registration_deliveries(c,rid)
     c.execute("UPDATE worker_credentials SET revoked_at=? WHERE credential_id=? AND revoked_at IS NULL",(now,existing['access_credential_id']))
     event='worker_reregistered' if existing['status']=='active' else 'worker_reactivated'; lifecycle_outcome='reregistered_active' if existing['status']=='active' else 'reactivated'; status=200
    else:
     rid=str(uuid.uuid4()); registration_id=rid; status=201; event='worker_registered'; lifecycle_outcome='registered'
    capabilities_json=json.dumps(requested_capabilities,separators=(',',':'))
    c.execute("INSERT INTO worker_credentials(credential_id,worker_id,kind,token_hash,salt,issued_at,expires_at,revoked_at,single_use,consumed_at,lifecycle_version,capabilities_json) VALUES(?,?,?,?,?,?,?,?,0,NULL,?,?)",(cid,d['worker_id'],'access',thash,None,now,expiry,None,CURRENT_LIFECYCLE_VERSION,capabilities_json))
    if existing:
     c.execute("UPDATE worker_instances SET status='active',worker_version=?,access_credential_id=?,last_seen_at=?,current_task_id=NULL WHERE registration_id=?",(d['worker_version'],cid,now,rid))
    else:
     c.execute("INSERT INTO worker_instances VALUES(?,?,?,?,?,?,?,?,?,?)",(rid,d['worker_id'],iid,'active',d.get('worker_version','0'),d['protocol_version'],now,now,cid,None))
    if bootstrap['single_use']:
     consumed_at=self.now()
     changed=c.execute("UPDATE worker_credentials SET consumed_at=?,revoked_at=? WHERE credential_id=? AND consumed_at IS NULL AND revoked_at IS NULL",(consumed_at,consumed_at,bootstrap['credential_id'])).rowcount
     if changed!=1: raise error('invalid_credential')
     self._audit(c,'bootstrap_credential_consumed',worker_id=d['worker_id'],registration_id=rid,reason_code=bootstrap['credential_id'])
    audit_id=self._audit(c,event,worker_id=d['worker_id'],instance_id=iid,registration_id=rid,details={'request_id':request_id,'credential_id':bootstrap['credential_id'],'registration_lifecycle_outcome':lifecycle_outcome})
   if evidence is not None: evidence.update({'request_id':request_id,'audit_id':audit_id,'credential_id':credential_id,'registration_lifecycle_outcome':lifecycle_outcome})
   return status,{'registration_id':rid,'worker_id':d['worker_id'],'accepted_capabilities':requested_capabilities,'access_token':token,'access_token_expires_at':expiry,'heartbeat_interval_seconds':self.settings.heartbeat_seconds,'ack_deadline_seconds':self.settings.ack_deadline_seconds,'lease_seconds':self.settings.lease_seconds,'server_time':self.now()}
  except WorkerControlPlaneError as exc:
   exc.request_id=request_id; exc.safe_context={'worker_id':worker_id,'instance_id':iid,'credential_id':credential_id,'registration_id':registration_id,'registration_lifecycle_outcome':lifecycle_outcome}
   raise
  except Exception:
   exc=WorkerControlPlaneError('internal_error',503,True,'Temporarily unavailable',request_id=request_id,safe_context={'worker_id':worker_id,'instance_id':iid,'credential_id':credential_id,'registration_id':registration_id,'registration_lifecycle_outcome':'transaction_rolled_back'})
   raise exc from None
 def _registration_v2_target(self,row):
  return {
   'path_digest':row['path_digest'],
   'remote':row['remote'],
   'branch':row['branch'],
   'approved_head':row['approved_head'],
  }
 def _registration_v2_aad(self,row):
  return identity_aad(
   transaction_id=row['registration_transaction_id'],
   registration_id=row['registration_id'],
   credential_id=row['credential_id'],
   worker_id=row['worker_id'],
   instance_id=row['instance_id'],
   host=row['host'],
   path_id=row['path_id'],
   target_identity=self._registration_v2_target(row),
   capabilities=json.loads(row['capabilities_json']),
   issued_at=row['issued_at'],
   expires_at=row['expires_at'],
  )
 def _registration_v2_response(self,row,token):
  return {
   'protocol_version':2,
   'registration_id':row['registration_id'],
   'credential_id':row['credential_id'],
   'registration_transaction_id':row['registration_transaction_id'],
   'issued_at':row['issued_at'],
   'expires_at':row['expires_at'],
   'capabilities':json.loads(row['capabilities_json']),
   'host':row['host'],
   'path_id':row['path_id'],
   'target_identity':self._registration_v2_target(row),
   'access_token':token,
   'state':row['state'],
  }
 def _registration_v2_identity_matches(self,row,d):
  target=d['target_identity']
  return (
   row['protocol_version']==d['protocol_version']
   and row['worker_id']==d['worker_id']
   and row['instance_id']==d['instance_id']
   and (
    'registration_id' not in d
    or row['registration_id']==d['registration_id']
   )
   and row['host']==d['host']
   and row['path_id']==d['path_id']
   and row['path_digest']==target['path_digest']
   and row['remote']==target['remote']
   and row['branch']==target['branch']
   and row['approved_head']==target['approved_head']
  )
 def _expire_registration_v2(self,c,row):
  now=self.now()
  c.execute(
   "UPDATE worker_registration_transactions_v2 SET "
   "state='expired',escrow_salt=NULL,escrow_nonce=NULL,"
   "escrow_ciphertext=NULL WHERE registration_transaction_id=? "
   "AND state=?",
   (row['registration_transaction_id'],PENDING_STATE),
  )
  c.execute(
   "UPDATE worker_credentials SET revoked_at=? WHERE credential_id=? "
   "AND revoked_at IS NULL",
   (now,row['credential_id']),
  )
  c.execute(
   "UPDATE worker_instances SET status='expired' WHERE registration_id=? "
   "AND access_credential_id=? AND status=?",
   (row['registration_id'],row['credential_id'],PENDING_STATE),
  )
  self._audit(
   c,
   'registration_v2_expired',
   worker_id=row['worker_id'],
   instance_id=row['instance_id'],
   registration_id=row['registration_id'],
   outcome='expired',
   reason_code='registration_expired',
   details={
    'registration_transaction_id':row['registration_transaction_id'],
    'credential_id':row['credential_id'],
    'state':'expired',
   },
  )
 def reap_expired_registration_v2(self):
  with self.store.transaction() as c:
   rows=c.execute(
    "SELECT * FROM worker_registration_transactions_v2 "
    "WHERE state=? AND expires_at<=?",
    (PENDING_STATE,self.now()),
   ).fetchall()
   for row in rows:
    self._expire_registration_v2(c,row)
  return len(rows)
 def _recover_registration_v2_token(self,row,secret):
  try:
   return unwrap_token(
    secret,
    WrappedToken(
     row['escrow_salt'],
     row['escrow_nonce'],
     row['escrow_ciphertext'],
    ),
    self._registration_v2_aad(row),
   )
  except (InvalidTag, TypeError, ValueError, UnicodeError):
   raise error('invalid_credential') from None
 def register_worker_v2(self,d,secret,*,request_id=None,evidence=None):
  request_id=request_id or str(uuid.uuid4())
  failure=None
  response=None
  audit_id=None
  replayed=False
  with self.store.transaction() as c:
   bootstrap=self.auth.bootstrap(c,d['worker_id'],secret)
   try:
    bootstrap_capabilities=validate_capabilities(
     json.loads(bootstrap['capabilities_json'])
    )
    allowed_capabilities=validate_capabilities(
     json.loads(bootstrap['allowed_capabilities'])
    )
   except (TypeError,ValueError,json.JSONDecodeError):
    raise error('invalid_credential') from None
   if (
    bootstrap_capabilities!=REGISTRATION_V2_CAPABILITIES
    or allowed_capabilities!=REGISTRATION_V2_CAPABILITIES
   ):
    raise error('unsupported_capability')
   transaction=c.execute(
    "SELECT * FROM worker_registration_transactions_v2 "
    "WHERE registration_transaction_id=?",
    (d['registration_transaction_id'],),
   ).fetchone()
   if transaction is not None:
    replayed=True
    if (
     transaction['bootstrap_credential_id']!=bootstrap['credential_id']
     or transaction['request_hash']!=request_hash(d)
    ):
     raise error('idempotency_conflict')
    if transaction['state']!=PENDING_STATE:
     raise error('state_conflict')
    if transaction['expires_at']<=self.now():
     self._expire_registration_v2(c,transaction)
     failure=error('registration_expired')
    elif transaction['recovery_count']>=MAX_RECOVERIES:
     failure=error('rate_limited')
    else:
     token=self._recover_registration_v2_token(transaction,secret)
     c.execute(
      "UPDATE worker_registration_transactions_v2 SET "
      "recovery_count=recovery_count+1,last_recovered_at=? "
      "WHERE registration_transaction_id=?",
      (self.now(),d['registration_transaction_id']),
     )
     response=self._registration_v2_response(transaction,token)
     audit_id=self._audit(
      c,
      'registration_v2_replayed',
      worker_id=d['worker_id'],
      instance_id=d['instance_id'],
      registration_id=transaction['registration_id'],
      details={
       'request_id':request_id,
       'registration_transaction_id':d[
        'registration_transaction_id'
       ],
       'credential_id':transaction['credential_id'],
       'state':PENDING_STATE,
      },
     )
   else:
    expired_pending=c.execute(
     "SELECT * FROM worker_registration_transactions_v2 "
     "WHERE worker_id=? AND state=? AND expires_at<=?",
     (d['worker_id'],PENDING_STATE,self.now()),
    ).fetchall()
    for expired in expired_pending:
     self._expire_registration_v2(c,expired)
    active=c.execute(
     "SELECT * FROM worker_instances WHERE worker_id=? AND status='active'",
     (d['worker_id'],),
    ).fetchone()
    existing=c.execute(
     "SELECT * FROM worker_instances WHERE worker_id=? AND instance_id=?",
     (d['worker_id'],d['instance_id']),
    ).fetchone()
    if active and active['instance_id']!=d['instance_id']:
     raise error('duplicate_active_instance')
    if existing and existing['current_task_id'] is not None:
     raise error('instance_conflict')
    if existing and c.execute(
     "SELECT 1 FROM worker_deliveries WHERE registration_id=? "
     "AND state IN ('leased','acknowledged')",
     (existing['registration_id'],),
    ).fetchone():
     raise error('state_conflict')
    if c.execute(
     "SELECT 1 FROM worker_registration_transactions_v2 "
     "WHERE worker_id=? AND state=?",
     (d['worker_id'],PENDING_STATE),
    ).fetchone():
     raise error('state_conflict')
    token,token_digest=new_access_token()
    credential_id=str(uuid.uuid4())
    registration_id=(
     existing['registration_id'] if existing else str(uuid.uuid4())
    )
    issued_at=self.now()
    expires_at=(
     self._now_datetime()
     + timedelta(seconds=self.settings.token_ttl_seconds)
    ).isoformat().replace('+00:00','Z')
    capabilities_json=json.dumps(
     REGISTRATION_V2_CAPABILITIES,separators=(',',':')
    )
    c.execute(
     "INSERT INTO worker_credentials("
     "credential_id,worker_id,kind,token_hash,salt,issued_at,expires_at,"
     "revoked_at,single_use,consumed_at,lifecycle_version,"
     "capabilities_json) VALUES(?,?,?,?,?,?,?,?,0,NULL,?,?)",
     (
      credential_id,d['worker_id'],'access',token_digest,None,issued_at,
      expires_at,None,CURRENT_LIFECYCLE_VERSION,capabilities_json,
     ),
    )
    if not existing:
     c.execute(
      "INSERT INTO worker_instances VALUES(?,?,?,?,?,?,?,?,?,?)",
      (
       registration_id,d['worker_id'],d['instance_id'],PENDING_STATE,
       d['worker_version'],d['protocol_version'],issued_at,issued_at,
       credential_id,None,
      ),
     )
    target=d['target_identity']
    provisional={
     'registration_transaction_id':d['registration_transaction_id'],
     'registration_id':registration_id,
     'credential_id':credential_id,
     'worker_id':d['worker_id'],
     'instance_id':d['instance_id'],
     'host':d['host'],
     'path_id':d['path_id'],
     'path_digest':target['path_digest'],
     'remote':target['remote'],
     'branch':target['branch'],
     'approved_head':target['approved_head'],
     'capabilities_json':capabilities_json,
     'issued_at':issued_at,
     'expires_at':expires_at,
    }
    wrapped=wrap_token(
     secret,
     token,
     self._registration_v2_aad(provisional),
     random_bytes=os.urandom,
    )
    c.execute(
     "INSERT INTO worker_registration_transactions_v2("
     "registration_transaction_id,protocol_version,worker_id,instance_id,"
     "worker_name,worker_version,registration_id,"
     "bootstrap_credential_id,credential_id,request_hash,host,path_id,"
     "path_digest,remote,branch,approved_head,capabilities_json,state,"
     "issued_at,expires_at,confirmed_at,superseded_at,revoked_at,"
     "escrow_salt,escrow_nonce,escrow_ciphertext,recovery_count,"
     "last_recovered_at) VALUES("
     "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,?,?,?,0,NULL)",
     (
      d['registration_transaction_id'],d['protocol_version'],d['worker_id'],
      d['instance_id'],d['worker_name'],d['worker_version'],
      registration_id,bootstrap['credential_id'],credential_id,
      request_hash(d),d['host'],d['path_id'],target['path_digest'],
      target['remote'],target['branch'],target['approved_head'],
      capabilities_json,PENDING_STATE,issued_at,expires_at,
      wrapped.salt,wrapped.nonce,wrapped.ciphertext,
     ),
    )
    transaction=c.execute(
     "SELECT * FROM worker_registration_transactions_v2 "
     "WHERE registration_transaction_id=?",
     (d['registration_transaction_id'],),
    ).fetchone()
    response=self._registration_v2_response(transaction,token)
    audit_id=self._audit(
     c,
     'registration_v2_issued',
     worker_id=d['worker_id'],
     instance_id=d['instance_id'],
     registration_id=registration_id,
     details={
      'request_id':request_id,
      'registration_transaction_id':d['registration_transaction_id'],
      'credential_id':credential_id,
      'host':d['host'],
      'path_id':d['path_id'],
      'state':PENDING_STATE,
     },
    )
  if failure is not None:
   raise failure
  if evidence is not None:
   evidence.update({
    'request_id':request_id,
    'audit_id':audit_id,
    'credential_id':response['credential_id'],
    'registration_lifecycle_outcome':PENDING_STATE,
   })
  return (200 if replayed else 201),response
 def recover_registration_v2(self,d,secret,*,request_id=None,evidence=None):
  request_id=request_id or str(uuid.uuid4())
  failure=None
  response=None
  audit_id=None
  with self.store.transaction() as c:
   bootstrap=self.auth.bootstrap(c,d['worker_id'],secret)
   transaction=c.execute(
    "SELECT * FROM worker_registration_transactions_v2 "
    "WHERE registration_transaction_id=?",
    (d['registration_transaction_id'],),
   ).fetchone()
   if (
    transaction is None
    or transaction['bootstrap_credential_id']!=bootstrap['credential_id']
   ):
    failure=error('invalid_credential')
   elif transaction['recovery_count']>=MAX_RECOVERIES:
    failure=error('rate_limited')
   else:
    c.execute(
     "UPDATE worker_registration_transactions_v2 SET "
     "recovery_count=recovery_count+1,last_recovered_at=? "
     "WHERE registration_transaction_id=?",
     (self.now(),d['registration_transaction_id']),
    )
    if not self._registration_v2_identity_matches(transaction,d):
     failure=error('invalid_credential')
    elif transaction['state']!=PENDING_STATE:
     failure=error('state_conflict')
    elif transaction['expires_at']<=self.now():
     self._expire_registration_v2(c,transaction)
     failure=error('registration_expired')
    else:
     token=self._recover_registration_v2_token(transaction,secret)
     response=self._registration_v2_response(transaction,token)
     audit_id=self._audit(
      c,
      'registration_v2_recovered',
      worker_id=d['worker_id'],
      instance_id=d['instance_id'],
      registration_id=transaction['registration_id'],
      details={
       'request_id':request_id,
       'registration_transaction_id':d['registration_transaction_id'],
       'credential_id':transaction['credential_id'],
       'host':d['host'],
       'path_id':d['path_id'],
       'state':PENDING_STATE,
      },
     )
  if failure is not None:
   raise failure
  if evidence is not None:
   evidence.update({'request_id':request_id,'audit_id':audit_id})
  return response
 def confirm_registration_v2(self,d,token,*,request_id=None,evidence=None):
  request_id=request_id or str(uuid.uuid4())
  failure=None
  response=None
  audit_id=None
  with self.store.transaction() as c:
   transaction=c.execute(
    "SELECT t.*,c.token_hash,c.revoked_at AS credential_revoked_at "
    "FROM worker_registration_transactions_v2 t "
    "JOIN worker_credentials c ON c.credential_id=t.credential_id "
    "WHERE t.registration_transaction_id=?",
    (d['registration_transaction_id'],),
   ).fetchone()
   if (
    transaction is None
    or transaction['credential_id']!=d['credential_id']
    or not self._registration_v2_identity_matches(transaction,d)
    or not verify_access_token(token,transaction['token_hash'])
    or not verify_installation_proof(token,d)
   ):
    failure=error('invalid_credential')
   elif transaction['state']=='confirmed':
    response={
     'registration_id':transaction['registration_id'],
     'credential_id':transaction['credential_id'],
     'registration_transaction_id':transaction[
      'registration_transaction_id'
     ],
     'state':'confirmed',
     'confirmed_at':transaction['confirmed_at'],
    }
   elif transaction['state']!=PENDING_STATE:
    failure=error('state_conflict')
   elif transaction['expires_at']<=self.now():
    self._expire_registration_v2(c,transaction)
    failure=error('registration_expired')
   elif transaction['credential_revoked_at'] is not None:
    failure=error('invalid_credential')
   else:
    instance=c.execute(
     "SELECT * FROM worker_instances WHERE registration_id=? "
     "AND worker_id=? AND instance_id=?",
     (
      transaction['registration_id'],transaction['worker_id'],
      transaction['instance_id'],
     ),
    ).fetchone()
    if instance is None:
     failure=error('state_conflict')
    else:
     previous_credential_id=instance['access_credential_id']
     if previous_credential_id!=transaction['credential_id']:
      self._retire_registration_dedup(
       c,instance['registration_id'],previous_credential_id
      )
      self._invalidate_registration_deliveries(
       c,instance['registration_id']
      )
      c.execute(
       "UPDATE worker_credentials SET revoked_at=? "
       "WHERE credential_id=? AND revoked_at IS NULL",
       (self.now(),previous_credential_id),
      )
      previous_transaction=c.execute(
       "SELECT registration_transaction_id FROM "
       "worker_registration_transactions_v2 WHERE credential_id=? "
       "AND state='confirmed'",
       (previous_credential_id,),
      ).fetchone()
      if previous_transaction:
       c.execute(
        "UPDATE worker_registration_transactions_v2 SET "
        "state='superseded',superseded_at=? "
        "WHERE registration_transaction_id=? AND state='confirmed'",
        (
         self.now(),previous_transaction['registration_transaction_id'],
        ),
       )
       self._audit(
        c,
        'registration_v2_superseded',
        worker_id=transaction['worker_id'],
        instance_id=transaction['instance_id'],
        registration_id=transaction['registration_id'],
        outcome='superseded',
        reason_code='registration_lifecycle_rotated',
        details={
         'registration_transaction_id':previous_transaction[
          'registration_transaction_id'
         ],
         'credential_id':previous_credential_id,
         'state':'superseded',
        },
       )
     confirmed_at=self.now()
     c.execute(
     "UPDATE worker_instances SET status='active',"
      "worker_version=?,protocol_version='2',"
      "access_credential_id=?,last_seen_at=?,current_task_id=NULL "
      "WHERE registration_id=?",
      (
       transaction['worker_version'],transaction['credential_id'],confirmed_at,
       transaction['registration_id'],
      ),
     )
     changed=c.execute(
      "UPDATE worker_credentials SET consumed_at=?,revoked_at=? "
      "WHERE credential_id=? AND kind='bootstrap' "
      "AND consumed_at IS NULL AND revoked_at IS NULL",
      (
       confirmed_at,confirmed_at,
       transaction['bootstrap_credential_id'],
      ),
     ).rowcount
     if changed!=1:
      raise error('invalid_credential')
     c.execute(
      "UPDATE worker_registration_transactions_v2 SET "
      "state='confirmed',confirmed_at=?,escrow_salt=NULL,"
      "escrow_nonce=NULL,escrow_ciphertext=NULL "
      "WHERE registration_transaction_id=? AND state=?",
      (
       confirmed_at,transaction['registration_transaction_id'],
       PENDING_STATE,
      ),
     )
     self._audit(
      c,
      'bootstrap_credential_consumed',
      worker_id=transaction['worker_id'],
      instance_id=transaction['instance_id'],
      registration_id=transaction['registration_id'],
      reason_code=transaction['bootstrap_credential_id'],
     )
     audit_id=self._audit(
      c,
      'registration_v2_confirmed',
      worker_id=transaction['worker_id'],
      instance_id=transaction['instance_id'],
      registration_id=transaction['registration_id'],
      details={
       'request_id':request_id,
       'registration_transaction_id':transaction[
        'registration_transaction_id'
       ],
       'credential_id':transaction['credential_id'],
       'host':transaction['host'],
       'path_id':transaction['path_id'],
       'state':'confirmed',
      },
     )
     response={
      'registration_id':transaction['registration_id'],
      'credential_id':transaction['credential_id'],
      'registration_transaction_id':transaction[
       'registration_transaction_id'
      ],
      'state':'confirmed',
      'confirmed_at':confirmed_at,
     }
  if failure is not None:
   raise failure
  if evidence is not None:
   evidence.update({'request_id':request_id,'audit_id':audit_id})
  return response
 def _context(self,c,token,d):
  row=self.auth.access(c,token)
  return self._assert_context(row,d)
 def _assert_context(self,row,d):
  if d.get('worker_id')!=row['worker_id'] or d.get('instance_id')!=row['instance_id']: raise error('worker_not_authorized')
  rid=d.get('registration_id');
  if rid is not None and rid!=row['registration_id']: raise error('state_conflict')
  return row
 def _dedup_replay(self,c,row,d,key,method,route,task_id=''):
  lifecycle_key=f"{row['credential_id']}:{key}"
  existing=c.execute("SELECT * FROM worker_request_dedup WHERE worker_id=? AND idempotency_key=?",(row['worker_id'],lifecycle_key)).fetchone()
  if not existing:
   existing=c.execute("SELECT * FROM worker_request_dedup WHERE worker_id=? AND registration_id=? AND idempotency_key=?",(row['worker_id'],row['registration_id'],key)).fetchone()
  if not existing: return _NO_REPLAY
  expected=(str(d.get('registration_id') or ''),method,route,task_id,canonical_json_hash(d))
  actual=(existing['registration_id'],existing['method'],existing['route'],existing['task_id'],existing['request_body_hash'])
  if actual!=expected: raise error('idempotency_conflict')
  return json.loads(existing['response_json'])
 def _dedup_store(self,c,row,d,key,method,route,task_id,response,status):
  lifecycle_key=f"{row['credential_id']}:{key}"
  c.execute("INSERT INTO worker_request_dedup VALUES(?,?,?,?,?,?,?,?,?)",(row['worker_id'],str(d.get('registration_id') or ''),method,route,task_id,lifecycle_key,canonical_json_hash(d),status,json.dumps(response)))
 def heartbeat(self,d,token):
  if d.get('status') not in ('idle','busy'): raise error('malformed_request')
  with self.store.transaction() as c:
   row=self._context(c,token,d)
   c.execute("UPDATE worker_instances SET last_seen_at=?,current_task_id=? WHERE registration_id=?",(self.now(),d.get('current_task_id'),row['registration_id'])); self._audit(c,'heartbeat_received',worker_id=row['worker_id'],instance_id=row['instance_id'],registration_id=row['registration_id'])
  return {'accepted':True,'server_time':self.now(),'next_heartbeat_seconds':self.settings.heartbeat_seconds,'configuration_changed':False,'revoked':False}
 def _reap(self,c):
  # Security boundary: ACK is valid only while now < ack_deadline_at.
  # Equality is expired, and acknowledged work expires at lease equality.
  rows=c.execute("SELECT d.*,t.max_attempts FROM worker_deliveries d JOIN worker_tasks t USING(task_id) WHERE (d.state='leased' AND d.ack_deadline_at<=?) OR (d.state='acknowledged' AND d.lease_expires_at<=?)",(self.now(),self.now())).fetchall()
  for r in rows:
   attempt=r['attempt']; new='dead_letter' if attempt>=r['max_attempts'] else 'queued'
   c.execute("UPDATE worker_deliveries SET state='expired' WHERE delivery_id=?",(r['delivery_id'],)); c.execute("UPDATE worker_tasks SET state=?,leased_until=NULL WHERE task_id=?",(new,r['task_id'])); self._audit(c,'lease_expired',task_id=r['task_id'],delivery_id=r['delivery_id']); self._audit(c,'task_dead_lettered' if new=='dead_letter' else 'task_redelivered',task_id=r['task_id'],delivery_id=r['delivery_id'])
 def _dead_letter_exhausted_queued(self,c):
  rows=c.execute("SELECT task_id FROM worker_tasks WHERE state='queued' AND attempt>=max_attempts").fetchall()
  for row in rows:
   c.execute("UPDATE worker_tasks SET state='dead_letter',leased_until=NULL WHERE task_id=?",(row['task_id'],)); self._audit(c,'task_dead_lettered',task_id=row['task_id'],reason_code='max_attempts')
 def reap_expired_deliveries(self):
  with self.store.transaction() as c: self._reap(c)
 def poll_one_task(self,d,token,key):
  with self.store.transaction() as c:
   row=self.auth.access(c,token)
   replay=self._dedup_replay(c,row,d,key,'POST','/worker/v1/tasks/poll')
   if replay is not _NO_REPLAY:
    self._audit(c,'poll_replayed',worker_id=row['worker_id']); return replay
   self._assert_context(row,d)
   try:
    capabilities=validate_capabilities(d.get('capabilities'))
    authorized=validate_capabilities(json.loads(row['capabilities_json']))
   except (TypeError,ValueError,json.JSONDecodeError):
    raise error('unsupported_capability') from None
   if type(d.get('max_tasks')) is not int or type(d.get('wait_seconds')) is not int or d.get('max_tasks')!=1 or d.get('wait_seconds')!=0 or capabilities!=authorized: raise error('unsupported_capability')
   self._reap(c); self._dead_letter_exhausted_queued(c)
   active=c.execute("SELECT 1 FROM worker_deliveries WHERE registration_id=? AND state IN ('leased','acknowledged')",(row['registration_id'],)).fetchone()
   if active: raise error('state_conflict')
   placeholders=','.join('?' for _ in capabilities)
   task=c.execute(f"SELECT * FROM worker_tasks WHERE state='queued' AND worker_id=? AND task_type IN ({placeholders}) ORDER BY available_at,created_at,rowid LIMIT 1",(row['worker_id'],*capabilities)).fetchone(); self._audit(c,'poll_received',worker_id=row['worker_id'])
   if not task:
    self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/poll','',None,204); self._audit(c,'poll_no_task',worker_id=row['worker_id']); return None
   payload=json.loads(task['payload_json'])
   current=self._now_datetime(); attempt=task['attempt']+1; did=str(uuid.uuid4()); ack=(current+timedelta(seconds=self.settings.ack_deadline_seconds)).isoformat().replace('+00:00','Z')
   lease_seconds=self.settings.lease_seconds
   if task['task_type']=='codex.execute':
    lease_seconds=self.settings.ack_deadline_seconds+payload['timeout_seconds']+CODEX_EXECUTE_RESULT_GRACE_SECONDS
   lease=(current+timedelta(seconds=lease_seconds)).isoformat().replace('+00:00','Z')
   c.execute("UPDATE worker_tasks SET state='leased',attempt=?,leased_until=? WHERE task_id=?",(attempt,lease,task['task_id'])); c.execute("INSERT INTO worker_deliveries VALUES(?,?,?,?,?,?,?,?,?,?,?)",(did,task['task_id'],row['worker_id'],row['registration_id'],attempt,'leased',self.now(),ack,lease,None,None)); env={'task':{'task_id':task['task_id'],'delivery_id':did,'task_type':task['task_type'],'payload':payload,'payload_hash':task['payload_hash'],'trace_id':task['trace_id'],'attempt':attempt,'max_attempts':task['max_attempts'],'ack_deadline_at':ack,'lease_expires_at':lease}}
   details=self._codex_audit_details(payload,status='leased') if task['task_type']=='codex.execute' else None
   self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/poll','',env,200); self._audit(c,'task_leased',worker_id=row['worker_id'],task_id=task['task_id'],delivery_id=did,trace_id=task['trace_id'],details=details); return env
 def ack_delivery(self,task_id,d,token,key):
  late=False; out=None
  with self.store.transaction() as c:
   row=self.auth.access(c,token)
   replay=self._dedup_replay(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/ack',task_id)
   if replay is not _NO_REPLAY: return replay
   self._assert_context(row,d); self._reap(c)
   delivery=c.execute("SELECT d.*,t.attempt AS task_attempt,t.max_attempts AS task_max_attempts,t.task_type,t.payload_json,t.trace_id FROM worker_deliveries d JOIN worker_tasks t USING(task_id) WHERE d.delivery_id=? AND d.task_id=?",(d.get('delivery_id'),task_id)).fetchone()
   if not delivery: raise error('stale_delivery')
   if delivery['worker_id']!=row['worker_id'] or delivery['registration_id']!=row['registration_id']: raise error('worker_not_authorized')
   if delivery['state']=='expired':
    late=True
   elif delivery['state']!='leased':
    raise error('state_conflict')
   else:
    accepted=d.get('accepted'); reason=d.get('reason')
    if accepted is True: ds,ts,event='acknowledged','running','task_acknowledged'
    elif accepted is False and reason=='temporary' and delivery['task_attempt']>=delivery['task_max_attempts']: ds,ts,event='rejected','dead_letter','task_dead_lettered'
    elif accepted is False and reason=='temporary': ds,ts,event='rejected','queued','task_rejected'
    elif accepted is False and reason=='permanent': ds,ts,event='rejected','rejected','task_rejected'
    else: raise error('malformed_request')
    payload=json.loads(delivery['payload_json'])
    details=self._codex_audit_details(payload,status=ts) if delivery['task_type']=='codex.execute' else None
    c.execute("UPDATE worker_deliveries SET state=?,acknowledged_at=? WHERE delivery_id=?",(ds,self.now() if accepted else None,delivery['delivery_id'])); c.execute("UPDATE worker_tasks SET state=?,leased_until=CASE WHEN ?='running' THEN leased_until ELSE NULL END WHERE task_id=?",(ts,ts,task_id)); out={'accepted':bool(accepted),'task_state':ts,'lease_expires_at':delivery['lease_expires_at'],'server_time':self.now()}; self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/ack',task_id,out,200); self._audit(c,event,worker_id=row['worker_id'],task_id=task_id,delivery_id=delivery['delivery_id'],trace_id=delivery['trace_id'],reason_code=reason,details=details)
  if late: raise error('lease_expired')
  return out
 def submit_result(self,task_id,d,token,key):
  late=False; out=None
  if d.get('task_id') != task_id or d.get('task_type') not in ('system.echo','codex.execute') or d.get('status') not in ('completed','failed','rejected','cancelled','expired','timed_out'): raise error('invalid_result')
  if not isinstance(d.get('stdout'),str) or not isinstance(d.get('stderr'),str): raise error('invalid_result')
  if type(d.get('duration_ms')) is not int or d['duration_ms']<0: raise error('invalid_result')
  try:
   started=datetime.fromisoformat(d['started_at'].replace('Z','+00:00'))
   finished=datetime.fromisoformat(d['finished_at'].replace('Z','+00:00'))
  except (AttributeError,TypeError,ValueError):
   raise error('invalid_result') from None
  if started.tzinfo is None or finished.tzinfo is None or finished<started: raise error('invalid_result')
  elapsed_ms=round((finished-started).total_seconds()*1000)
  with self.store.transaction() as c:
   row=self.auth.access(c,token)
   replay=self._dedup_replay(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/result',task_id)
   if replay is not _NO_REPLAY: return replay
   self._assert_context(row,d); self._reap(c); delivery=c.execute("SELECT d.*,t.payload_hash,t.payload_json,t.trace_id,t.task_type,t.state AS task_state FROM worker_deliveries d JOIN worker_tasks t USING(task_id) WHERE d.delivery_id=? AND d.task_id=?",(d.get('delivery_id'),task_id)).fetchone()
   if not delivery: raise error('stale_delivery')
   if delivery['worker_id']!=row['worker_id'] or delivery['registration_id']!=row['registration_id']: raise error('worker_not_authorized')
   if delivery['task_type']!=d.get('task_type'): raise error('invalid_result')
   payload=json.loads(delivery['payload_json'])
   if delivery['task_type']=='system.echo':
    result_size=len(d['stdout'].encode())
    if d['status']=='timed_out': raise error('invalid_result')
    if len(d['stdout'].encode())>self.settings.max_stdout_bytes or len(d['stderr'].encode())>self.settings.max_stderr_bytes: raise error('payload_too_large')
   else:
    if d['stderr']!='': raise error('invalid_result')
    try:
     result_size=len(d['stdout'].encode('utf-8'))
    except UnicodeEncodeError:
     raise error('invalid_result') from None
    if result_size>CODEX_EXECUTE_MAX_RESULT_BYTES: raise error('payload_too_large')
    try: inner=validate_codex_execute_result(d['stdout'])
    except ValueError: raise error('invalid_result') from None
    timeout_ms=payload['timeout_seconds']*1000
    if d.get('duration_ms')>timeout_ms or elapsed_ms>timeout_ms or abs(d['duration_ms']-elapsed_ms)>1000: raise error('invalid_result')
    if (d['status'],d.get('exit_code'),d['duration_ms']) != (inner['status'],inner['exit_code'],inner['duration_ms']): raise error('invalid_result')
   result_hash=canonical_json_hash(d); existing=c.execute("SELECT result_hash FROM worker_results WHERE task_id=? AND result_idempotency_key=?",(task_id,d.get('result_idempotency_key'))).fetchone()
   if existing:
    if existing['result_hash']!=result_hash: raise error('idempotency_conflict')
    out={'accepted':True,'duplicate':True,'task_state':delivery['task_state'],'server_time':self.now()}; self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/result',task_id,out,200); return out
   if delivery['state']=='expired':
    late=True
   elif delivery['state']!='acknowledged':
    raise error('state_conflict')
   else:
    if d.get('payload_hash')!=delivery['payload_hash'] or d.get('trace_id')!=delivery['trace_id']: raise error('invalid_result')
    if delivery['task_type']=='system.echo':
     message=payload['message']
     if d['status']=='completed' and (d['stdout']!=message or d['stderr']!='' or d.get('exit_code')!=0): raise error('invalid_result')
    result_id=str(uuid.uuid4())
    c.execute("INSERT INTO worker_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(result_id,task_id,delivery['delivery_id'],d['result_idempotency_key'],result_hash,d['status'],d['stdout'],d['stderr'],d.get('exit_code'),d['started_at'],d['finished_at'],d['duration_ms'],self.now()))
    state='completed' if d['status']=='completed' else ('rejected' if d['status']=='rejected' else 'failed')
    details=self._codex_audit_details(payload,status=d['status'],duration_ms=d['duration_ms'],result_size_bytes=result_size,safe_failure_code=inner['failure_code'],result_id=result_id) if delivery['task_type']=='codex.execute' else None
    c.execute("UPDATE worker_deliveries SET state='completed',finished_at=? WHERE delivery_id=?",(self.now(),delivery['delivery_id'])); c.execute("UPDATE worker_tasks SET state=?,leased_until=NULL WHERE task_id=?",(state,task_id)); out={'accepted':True,'duplicate':False,'task_state':state,'server_time':self.now()}; self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/result',task_id,out,200); self._audit(c,'result_accepted',worker_id=row['worker_id'],task_id=task_id,delivery_id=delivery['delivery_id'],trace_id=delivery['trace_id'],details=details)
  if late: raise error('lease_expired')
  return out
 def task_state(self,task_id): return self.store.conn.execute("SELECT state FROM worker_tasks WHERE task_id=?",(task_id,)).fetchone()['state']
 def result_count(self,task_id): return self.store.conn.execute("SELECT count(*) FROM worker_results WHERE task_id=?",(task_id,)).fetchone()[0]
 def audit_text(self): return '\n'.join(str(tuple(r)) for r in self.store.conn.execute("SELECT * FROM worker_audit_log"))
