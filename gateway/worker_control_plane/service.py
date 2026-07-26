"""Small transactional domain service for test-only system.echo."""
from __future__ import annotations
import json, secrets, uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from .auth import bootstrap_record, verify_bootstrap, new_access_token, verify_access_token
from .config import WorkerControlPlaneSettings
from .errors import error
from .models import canonical_json_hash, validate_system_echo_payload
from .storage import CURRENT_LIFECYCLE_VERSION, WorkerControlPlaneStore

_NO_REPLAY = object()

class WorkerAuthService:
 def __init__(self, store, now, now_datetime): self.store,self.now,self.now_datetime=store,now,now_datetime
 def bootstrap(self, c, worker_id, secret):
  rows=c.execute("SELECT c.*,w.enabled FROM worker_credentials c JOIN workers w USING(worker_id) WHERE c.worker_id=? AND c.kind='bootstrap'",(worker_id,)).fetchall()
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
 def access(self, token):
  rows=self.store.conn.execute("SELECT c.worker_id,c.credential_id,c.token_hash,c.expires_at,c.revoked_at,w.enabled,i.instance_id,i.registration_id,i.status FROM worker_credentials c JOIN workers w USING(worker_id) JOIN worker_instances i ON i.access_credential_id=c.credential_id WHERE c.kind='access'").fetchall()
  row=next((candidate for candidate in rows if verify_access_token(token,candidate['token_hash'])),None)
  if row is None: raise error('invalid_credential')
  if not row['enabled'] or row['revoked_at']: raise error('worker_revoked')
  if row['expires_at'] <= self.now(): raise error('invalid_credential')
  if row['status'] != 'active': raise error('registration_expired')
  return row

class WorkerControlPlaneService:
 def __init__(self, settings, *, clock: Callable[[], datetime] | None = None):
  if not settings.enabled or settings.test_mode == settings.pilot_mode: raise ValueError('isolated mode required')
  self.settings=settings; self.store=WorkerControlPlaneStore(settings); self._clock=clock or (lambda: datetime.now(timezone.utc)); self.auth=WorkerAuthService(self.store,self.now,self._now_datetime)
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
 def close(self): self.store.close()
 def _audit(self,c,event,**fields):
  safe={k:v for k,v in fields.items() if k in {'worker_id','instance_id','registration_id','task_id','delivery_id','trace_id','outcome','reason_code'}}
  c.execute("INSERT INTO worker_audit_log(occurred_at,event_type,worker_id,instance_id,registration_id,task_id,delivery_id,trace_id,outcome,reason_code) VALUES(?,?,?,?,?,?,?,?,?,?)",(self.now(),event,safe.get('worker_id'),safe.get('instance_id'),safe.get('registration_id'),safe.get('task_id'),safe.get('delivery_id'),safe.get('trace_id'),safe.get('outcome','ok'),safe.get('reason_code')))
 def record_rejection(self,event,**fields):
  with self.store.transaction() as c: self._audit(c,event,outcome='rejected',**fields)
 def provision_worker(self, *, secret=None, ttl_seconds=900, single_use=True, install_credential=None):
  if not (self.settings.test_mode or self.settings.pilot_mode): raise RuntimeError('isolated mode required')
  if type(ttl_seconds) is not int or not 1<=ttl_seconds<=900: raise ValueError('bootstrap TTL must be between 1 and 900 seconds')
  if type(single_use) is not bool: raise ValueError('single_use must be boolean')
  secret=secret or secrets.token_urlsafe(32); salt,digest=bootstrap_record(secret); credential_id=str(uuid.uuid4())
  issued_datetime=self._now_datetime(); issued_at=issued_datetime.isoformat().replace('+00:00','Z'); expires_at=(issued_datetime+timedelta(seconds=ttl_seconds)).isoformat().replace('+00:00','Z')
  rollback_file=None; finalize_file=None
  try:
   with self.store.transaction() as c:
    c.execute("INSERT INTO workers(worker_id,worker_name,allowed_capabilities,enabled,revoked_at) VALUES(?,?,?,1,NULL) ON CONFLICT(worker_id) DO UPDATE SET worker_name=excluded.worker_name,allowed_capabilities=excluded.allowed_capabilities,enabled=1,revoked_at=NULL",('server-a-worker','Hermes local pilot worker','[\"system.echo\"]'))
    if c.execute("SELECT 1 FROM worker_credentials WHERE worker_id=? AND kind='bootstrap' AND revoked_at IS NULL",('server-a-worker',)).fetchone():
     raise ValueError('an unrevoked bootstrap credential already exists')
    c.execute("INSERT INTO worker_credentials(credential_id,worker_id,kind,token_hash,salt,issued_at,expires_at,revoked_at,single_use,consumed_at,lifecycle_version) VALUES(?,?,?,?,?,?,?,?,?,NULL,?)",(credential_id,'server-a-worker','bootstrap',digest,salt,issued_at,expires_at,None,int(single_use),CURRENT_LIFECYCLE_VERSION)); self._audit(c,'worker_provisioned',worker_id='server-a-worker',reason_code=credential_id)
    if install_credential is not None: rollback_file,finalize_file=install_credential()
  except Exception:
   if rollback_file is not None: rollback_file()
   raise
  if finalize_file is not None: finalize_file()
  return {'secret':secret,'credential_id':credential_id,'issued_at':issued_at,'expires_at':expires_at,'single_use':single_use}
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
   changed=c.execute("UPDATE worker_credentials SET revoked_at=? WHERE worker_id=? AND credential_id=? AND kind='bootstrap' AND revoked_at IS NULL",(revoked_at,worker_id,credential_id)).rowcount
   if changed!=1: raise ValueError('credential target changed during revocation')
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
   self._audit(c,'registration_revoked',worker_id=worker_id,instance_id=instance_id,registration_id=registration_id)
  return {'worker_id':worker_id,'instance_id':instance_id,'registration_id':registration_id,'status':'revoked','revoked_at':revoked_at}
 def revoke_test_worker(self):
  with self.store.transaction() as c:
   c.execute("UPDATE workers SET enabled=0,revoked_at=? WHERE worker_id='server-a-worker'",(self.now(),)); self._audit(c,'worker_revoked',worker_id='server-a-worker')
 def enqueue_system_echo(self,payload,key):
  if not (self.settings.test_mode or self.settings.pilot_mode): raise RuntimeError('isolated mode required')
  payload=validate_system_echo_payload(payload,self.settings.max_stdout_bytes); task_id=str(uuid.uuid4()); trace=str(uuid.uuid4()); encoded=json.dumps(payload,ensure_ascii=False,sort_keys=True,separators=(',',':'))
  with self.store.transaction() as c:
   existing=c.execute("SELECT task_id,payload_hash FROM worker_tasks WHERE creation_idempotency_key=?",(key,)).fetchone()
   h=canonical_json_hash(payload)
   if existing:
    if existing['payload_hash'] != h: raise error('state_conflict')
    return existing['task_id']
   c.execute("INSERT INTO worker_tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(task_id,'system.echo',encoded,h,'queued',self.now(),self.now(),None,0,self.settings.max_attempts,key,trace)); self._audit(c,'test_task_created',task_id=task_id,trace_id=trace)
  return task_id
 def create_test_echo_task(self,payload,key):
  if not self.settings.test_mode: raise RuntimeError('test mode required')
  return self.enqueue_system_echo(payload,key)
 def register_worker(self,d,secret):
  if d.get('protocol_version')!='1.0': raise error('unsupported_protocol')
  if d.get('worker_id')!='server-a-worker' or d.get('capabilities') != ['system.echo']: raise error('unsupported_capability' if d.get('worker_id')=='server-a-worker' else 'invalid_credential')
  iid=d.get('instance_id')
  try: uuid.UUID(iid)
  except Exception: raise error('malformed_request')
  with self.store.transaction() as c:
   bootstrap=self.auth.bootstrap(c,d['worker_id'],secret)
   active=c.execute("SELECT * FROM worker_instances WHERE worker_id=? AND status='active'",(d['worker_id'],)).fetchone()
   if active and active['instance_id'] != iid: self._audit(c,'registration_rejected',worker_id=d['worker_id'],outcome='rejected',reason_code='duplicate_active_instance'); raise error('duplicate_active_instance')
   token,thash=new_access_token(); cid=str(uuid.uuid4()); expiry=(self._now_datetime()+timedelta(seconds=self.settings.token_ttl_seconds)).isoformat().replace('+00:00','Z')
   if active:
    c.execute("UPDATE worker_credentials SET revoked_at=? WHERE credential_id=?",(self.now(),active['access_credential_id'])); rid=active['registration_id']; status=200; event='worker_reregistered'
   else:
    rid=str(uuid.uuid4()); status=201; event='worker_registered'
   c.execute("INSERT INTO worker_credentials(credential_id,worker_id,kind,token_hash,salt,issued_at,expires_at,revoked_at,single_use,consumed_at,lifecycle_version) VALUES(?,?,?,?,?,?,?,?,0,NULL,?)",(cid,d['worker_id'],'access',thash,None,self.now(),expiry,None,CURRENT_LIFECYCLE_VERSION))
   if active: c.execute("UPDATE worker_instances SET access_credential_id=?,last_seen_at=? WHERE registration_id=?",(cid,self.now(),rid))
   else: c.execute("INSERT INTO worker_instances VALUES(?,?,?,?,?,?,?,?,?,?)",(rid,d['worker_id'],iid,'active',d.get('worker_version','0'),d['protocol_version'],self.now(),self.now(),cid,None))
   if bootstrap['single_use']:
    consumed_at=self.now()
    changed=c.execute("UPDATE worker_credentials SET consumed_at=?,revoked_at=? WHERE credential_id=? AND consumed_at IS NULL AND revoked_at IS NULL",(consumed_at,consumed_at,bootstrap['credential_id'])).rowcount
    if changed!=1: raise error('invalid_credential')
    self._audit(c,'bootstrap_credential_consumed',worker_id=d['worker_id'],registration_id=rid,reason_code=bootstrap['credential_id'])
   self._audit(c,event,worker_id=d['worker_id'],instance_id=iid,registration_id=rid)
  return status,{'registration_id':rid,'worker_id':d['worker_id'],'accepted_capabilities':['system.echo'],'access_token':token,'access_token_expires_at':expiry,'heartbeat_interval_seconds':self.settings.heartbeat_seconds,'ack_deadline_seconds':self.settings.ack_deadline_seconds,'lease_seconds':self.settings.lease_seconds,'server_time':self.now()}
 def _context(self,token,d):
  row=self.auth.access(token)
  return self._assert_context(row,d)
 def _assert_context(self,row,d):
  if d.get('worker_id')!=row['worker_id'] or d.get('instance_id')!=row['instance_id']: raise error('worker_not_authorized')
  rid=d.get('registration_id');
  if rid is not None and rid!=row['registration_id']: raise error('state_conflict')
  return row
 def _dedup_replay(self,c,row,d,key,method,route,task_id=''):
  existing=c.execute("SELECT * FROM worker_request_dedup WHERE worker_id=? AND idempotency_key=?",(row['worker_id'],key)).fetchone()
  if not existing: return _NO_REPLAY
  expected=(str(d.get('registration_id') or ''),method,route,task_id,canonical_json_hash(d))
  actual=(existing['registration_id'],existing['method'],existing['route'],existing['task_id'],existing['request_body_hash'])
  if actual!=expected: raise error('idempotency_conflict')
  return json.loads(existing['response_json'])
 def _dedup_store(self,c,row,d,key,method,route,task_id,response,status):
  c.execute("INSERT INTO worker_request_dedup VALUES(?,?,?,?,?,?,?,?,?)",(row['worker_id'],str(d.get('registration_id') or ''),method,route,task_id,key,canonical_json_hash(d),status,json.dumps(response)))
 def heartbeat(self,d,token):
  row=self._context(token,d)
  if d.get('status') not in ('idle','busy'): raise error('malformed_request')
  with self.store.transaction() as c:
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
  row=self.auth.access(token)
  with self.store.transaction() as c:
   replay=self._dedup_replay(c,row,d,key,'POST','/worker/v1/tasks/poll')
   if replay is not _NO_REPLAY:
    self._audit(c,'poll_replayed',worker_id=row['worker_id']); return replay
   self._assert_context(row,d)
   if type(d.get('max_tasks')) is not int or type(d.get('wait_seconds')) is not int or d.get('max_tasks')!=1 or d.get('wait_seconds')!=0 or d.get('capabilities')!=['system.echo']: raise error('unsupported_capability')
   self._reap(c); self._dead_letter_exhausted_queued(c)
   active=c.execute("SELECT 1 FROM worker_deliveries WHERE registration_id=? AND state IN ('leased','acknowledged')",(row['registration_id'],)).fetchone()
   if active: raise error('state_conflict')
   task=c.execute("SELECT * FROM worker_tasks WHERE state='queued' ORDER BY available_at,created_at,rowid LIMIT 1").fetchone(); self._audit(c,'poll_received',worker_id=row['worker_id'])
   if not task:
    self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/poll','',None,204); self._audit(c,'poll_no_task',worker_id=row['worker_id']); return None
   current=self._now_datetime(); attempt=task['attempt']+1; did=str(uuid.uuid4()); ack=(current+timedelta(seconds=self.settings.ack_deadline_seconds)).isoformat().replace('+00:00','Z'); lease=(current+timedelta(seconds=self.settings.lease_seconds)).isoformat().replace('+00:00','Z')
   c.execute("UPDATE worker_tasks SET state='leased',attempt=?,leased_until=? WHERE task_id=?",(attempt,lease,task['task_id'])); c.execute("INSERT INTO worker_deliveries VALUES(?,?,?,?,?,?,?,?,?,?,?)",(did,task['task_id'],row['worker_id'],row['registration_id'],attempt,'leased',self.now(),ack,lease,None,None)); env={'task':{'task_id':task['task_id'],'delivery_id':did,'task_type':'system.echo','payload':json.loads(task['payload_json']),'payload_hash':task['payload_hash'],'trace_id':task['trace_id'],'attempt':attempt,'max_attempts':task['max_attempts'],'ack_deadline_at':ack,'lease_expires_at':lease}}
   self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/poll','',env,200); self._audit(c,'task_leased',worker_id=row['worker_id'],task_id=task['task_id'],delivery_id=did,trace_id=task['trace_id']); return env
 def ack_delivery(self,task_id,d,token,key):
  row=self.auth.access(token)
  late=False; out=None
  with self.store.transaction() as c:
   replay=self._dedup_replay(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/ack',task_id)
   if replay is not _NO_REPLAY: return replay
   self._assert_context(row,d); self._reap(c)
   delivery=c.execute("SELECT d.*,t.attempt AS task_attempt,t.max_attempts AS task_max_attempts FROM worker_deliveries d JOIN worker_tasks t USING(task_id) WHERE d.delivery_id=? AND d.task_id=?",(d.get('delivery_id'),task_id)).fetchone()
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
    c.execute("UPDATE worker_deliveries SET state=?,acknowledged_at=? WHERE delivery_id=?",(ds,self.now() if accepted else None,delivery['delivery_id'])); c.execute("UPDATE worker_tasks SET state=?,leased_until=CASE WHEN ?='running' THEN leased_until ELSE NULL END WHERE task_id=?",(ts,ts,task_id)); out={'accepted':bool(accepted),'task_state':ts,'lease_expires_at':delivery['lease_expires_at'],'server_time':self.now()}; self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/ack',task_id,out,200); self._audit(c,event,worker_id=row['worker_id'],task_id=task_id,delivery_id=delivery['delivery_id'],reason_code=reason)
  if late: raise error('lease_expired')
  return out
 def submit_result(self,task_id,d,token,key):
  row=self.auth.access(token)
  late=False; out=None
  if d.get('task_id') != task_id or d.get('task_type')!='system.echo' or d.get('status') not in ('completed','failed','rejected','cancelled','expired'): raise error('invalid_result')
  if not isinstance(d.get('stdout'),str) or not isinstance(d.get('stderr'),str) or len(d['stdout'].encode())>self.settings.max_stdout_bytes or len(d['stderr'].encode())>self.settings.max_stderr_bytes: raise error('payload_too_large')
  with self.store.transaction() as c:
   replay=self._dedup_replay(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/result',task_id)
   if replay is not _NO_REPLAY: return replay
   self._assert_context(row,d); self._reap(c); delivery=c.execute("SELECT d.*,t.payload_hash,t.payload_json,t.trace_id,t.task_type,t.state AS task_state FROM worker_deliveries d JOIN worker_tasks t USING(task_id) WHERE d.delivery_id=? AND d.task_id=?",(d.get('delivery_id'),task_id)).fetchone()
   if not delivery: raise error('stale_delivery')
   if delivery['worker_id']!=row['worker_id'] or delivery['registration_id']!=row['registration_id']: raise error('worker_not_authorized')
   if delivery['task_type']!=d.get('task_type'): raise error('invalid_result')
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
    message=json.loads(delivery['payload_json'])['message']
    if d['status']=='completed' and (d['stdout']!=message or d['stderr']!='' or d.get('exit_code')!=0): raise error('invalid_result')
    c.execute("INSERT INTO worker_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(str(uuid.uuid4()),task_id,delivery['delivery_id'],d['result_idempotency_key'],result_hash,d['status'],d['stdout'],d['stderr'],d.get('exit_code'),d['started_at'],d['finished_at'],d['duration_ms'],self.now()))
    state='completed' if d['status']=='completed' else ('rejected' if d['status']=='rejected' else 'failed'); c.execute("UPDATE worker_deliveries SET state='completed',finished_at=? WHERE delivery_id=?",(self.now(),delivery['delivery_id'])); c.execute("UPDATE worker_tasks SET state=?,leased_until=NULL WHERE task_id=?",(state,task_id)); out={'accepted':True,'duplicate':False,'task_state':state,'server_time':self.now()}; self._dedup_store(c,row,d,key,'POST','/worker/v1/tasks/{task_id}/result',task_id,out,200); self._audit(c,'result_accepted',worker_id=row['worker_id'],task_id=task_id,delivery_id=delivery['delivery_id'],trace_id=delivery['trace_id'])
  if late: raise error('lease_expired')
  return out
 def task_state(self,task_id): return self.store.conn.execute("SELECT state FROM worker_tasks WHERE task_id=?",(task_id,)).fetchone()['state']
 def result_count(self,task_id): return self.store.conn.execute("SELECT count(*) FROM worker_results WHERE task_id=?",(task_id,)).fetchone()[0]
 def audit_text(self): return '\n'.join(str(tuple(r)) for r in self.store.conn.execute("SELECT * FROM worker_audit_log"))
