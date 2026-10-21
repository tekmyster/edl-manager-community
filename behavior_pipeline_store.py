"""Durable two-request ownership/charges; versioned legacy read/recovery only. No network while holding a writer lock."""
import contextlib,datetime as dt,json,os,pathlib,sqlite3,time,uuid

SCHEMA='''
CREATE TABLE IF NOT EXISTS pipeline_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
INSERT OR IGNORE INTO pipeline_schema VALUES(1,3);
CREATE TABLE IF NOT EXISTS pipeline_plans(id TEXT PRIMARY KEY,packet TEXT NOT NULL,config TEXT NOT NULL,input_key TEXT NOT NULL,owner TEXT NOT NULL,process TEXT NOT NULL,state TEXT NOT NULL,created TEXT NOT NULL,deadline REAL NOT NULL,assessment TEXT NOT NULL UNIQUE,outcome TEXT,provider TEXT NOT NULL,topology TEXT NOT NULL DEFAULT 'full-joint-draft-revision-1');
CREATE INDEX IF NOT EXISTS pipeline_packet ON pipeline_plans(packet,config,created);
CREATE INDEX IF NOT EXISTS pipeline_compaction ON pipeline_plans(created,id) WHERE outcome IS NOT NULL AND state IN ('completed','failed');
CREATE TABLE IF NOT EXISTS pipeline_stages(parent TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal IN(1,2)),request_id TEXT NOT NULL UNIQUE,request_hash TEXT,state TEXT NOT NULL,charged_day TEXT,entered TEXT,receipt TEXT,metadata TEXT,PRIMARY KEY(parent,ordinal));
CREATE TABLE IF NOT EXISTS pipeline_reservations(parent TEXT PRIMARY KEY,day TEXT NOT NULL,held INTEGER NOT NULL CHECK(held BETWEEN 0 AND 2));
CREATE INDEX IF NOT EXISTS pipeline_reserved_day ON pipeline_reservations(day,held);
CREATE TABLE IF NOT EXISTS pipeline_active(slot INTEGER PRIMARY KEY CHECK(slot=1),parent TEXT NOT NULL UNIQUE);
'''

class Refused(ValueError):pass

def process_token(pid=None):
 pid=pid or os.getpid()
 if os.name=='posix':
  try:
   text=pathlib.Path('/proc',str(pid),'stat').read_text();return str(pid)+':'+text[text.rfind(')')+2:].split()[19]
  except FileNotFoundError:return None
  except (OSError,IndexError):return 'unknown'
 # os.kill(pid,0) is unsafe on Windows. Query creation/exit metadata only.
 import ctypes as c
 from ctypes import wintypes as w
 k=c.WinDLL('kernel32',use_last_error=True);k.OpenProcess.argtypes=[w.DWORD,w.BOOL,w.DWORD];k.OpenProcess.restype=w.HANDLE
 k.CloseHandle.argtypes=[w.HANDLE];k.GetProcessTimes.argtypes=[w.HANDLE,c.POINTER(w.FILETIME),c.POINTER(w.FILETIME),c.POINTER(w.FILETIME),c.POINTER(w.FILETIME)];k.GetExitCodeProcess.argtypes=[w.HANDLE,c.POINTER(w.DWORD)]
 h=k.OpenProcess(0x1000,False,pid)
 if not h:return None if c.get_last_error()==87 else 'unknown'
 try:
  code=w.DWORD()
  if not k.GetExitCodeProcess(h,c.byref(code)) or code.value!=259:return None
  a,b,d,e=w.FILETIME(),w.FILETIME(),w.FILETIME(),w.FILETIME()
  if not k.GetProcessTimes(h,c.byref(a),c.byref(b),c.byref(d),c.byref(e)):return 'unknown'
  return str(pid)+':'+str((a.dwHighDateTime<<32)|a.dwLowDateTime)
 finally:k.CloseHandle(h)

def alive(token):
 if token=='unknown':return True
 actual=process_token(int(token.split(':')[0]));return actual=='unknown' or actual==token

def captured(brain,ident,stage,evidence,request,input_key):
 """Read only the expected parent's already finalized private capture."""
 from behavior_pipeline import request_digest
 from behavior_request_evidence import read,sha
 from behavior_generation import parse_wire
 expected=pathlib.Path(brain.path).with_suffix('.request-evidence')/ident/('stage%d'%stage)
 if evidence is None or evidence.path.resolve()!=expected.resolve():raise Refused('pipeline_owned_capture')
 request_bytes=(expected/'request.json').read_bytes();saved=json.loads(request_bytes);binding=read(expected/'binding.json');capture=read(expected/'capture.json');finalized=read(expected/'finalization.json');outcome=read(expected/'outcome.json')
 rawbody=(expected/'raw-response.bin').read_bytes();raw=(expected/'choice-content.utf8').read_bytes().decode('utf-8')
 owner=evidence.capture
 if owner is None or not owner.done.is_set() or not owner.closed or not owner.complete or owner.error or not owner.sealed:raise Refused('pipeline_owned_capture')
 with owner.lock:owned_raw=bytes(owner.data)
 if rawbody!=owned_raw:raise Refused('pipeline_owned_capture')
 if sha(request_bytes)!=request_digest(request) or saved!=request or binding!={'input_key':input_key,'request_sha256':request_digest(request)} or capture.get('sha256')!=sha(rawbody) or not capture.get('complete_application_body') or not capture.get('snapshot_evidence_complete') or not finalized.get('complete') or outcome.get('status')!='validated':raise Refused('pipeline_owned_capture')
 frames=[parse_wire(line.decode()) for line in rawbody.splitlines() if line.strip()]
 if not frames or any(not isinstance(f,dict) for f in frames):raise Refused('pipeline_owned_capture')
 actual=''.join(f.get('message',{}).get('content','') for f in frames)
 if actual!=raw or frames[-1].get('done') is not True or frames[-1].get('done_reason')=='length' or any(f.get('model')!=request['model'] for f in frames):raise Refused('pipeline_owned_capture')
 return raw

class Ledger:
 def __init__(self,brain,check=lambda:None,hook=lambda phase:None):
  self.brain=brain;self.path=brain.path;self.check=check;self.hook=hook;self.verify=None;self.packet_hash=None;self.bound_request=None;self.bound_requests={};self.draft_receipt=None
  with self.connection() as db:
   if db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_schema'").fetchone():
    version=db.execute('SELECT version FROM pipeline_schema WHERE id=1').fetchone()[0]
    if version==3:return
    if version not in (1,2):raise Refused('pipeline_schema_review_required')
  def initialize(db):
   exists=db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_schema'").fetchone()
   if not exists:
    # The caller owns one short transaction; no executescript implicit commit.
    for statement in SCHEMA.split(';'):
     if statement.strip():db.execute(statement)
   version=db.execute('SELECT version FROM pipeline_schema WHERE id=1').fetchone()[0]
   if version==1:
    db.execute("ALTER TABLE pipeline_plans ADD COLUMN topology TEXT NOT NULL DEFAULT 'account-then-selection-1'")
    # Never resume old generation. Preserve final-pending outcomes and all
    # charged usage/child receipts; only ownership/reservations are fenced.
    db.execute("UPDATE pipeline_plans SET state='uncertain' WHERE state NOT IN ('completed','failed','final_pending','uncertain','review')")
    db.execute('UPDATE pipeline_reservations SET held=0')
    db.execute('DELETE FROM pipeline_active')
    db.execute('UPDATE pipeline_schema SET version=2 WHERE id=1')
   elif version not in (2,3):raise Refused('pipeline_schema_review_required')
   db.execute("CREATE TABLE IF NOT EXISTS pipeline_legacy_barriers(packet TEXT NOT NULL,config TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(packet,config))")
   db.execute("CREATE TABLE IF NOT EXISTS pipeline_drafts(parent TEXT PRIMARY KEY,raw TEXT NOT NULL,canonical TEXT NOT NULL,rendering TEXT NOT NULL,receipt TEXT NOT NULL,revision_request TEXT,revision_input_key TEXT)")
   db.execute("CREATE TABLE IF NOT EXISTS pipeline_finals(parent TEXT PRIMARY KEY,raw TEXT NOT NULL,canonical TEXT NOT NULL,rendering TEXT NOT NULL,receipt TEXT NOT NULL)")
   db.execute("CREATE TRIGGER IF NOT EXISTS final_capture_immutable BEFORE UPDATE ON pipeline_finals BEGIN SELECT RAISE(ABORT,'Final capture immutable'); END")
   if version!=3 or not exists:
    # Installed3.17 has jobs, assessments, usage and a private journal, but no
    # pipeline tables. Preserve them and fence every consumed logical packet.
    db.execute("INSERT INTO pipeline_legacy_barriers SELECT packet_id,config_id,state FROM jobs WHERE 1 ON CONFLICT(packet,config) DO UPDATE SET state=excluded.state WHERE pipeline_legacy_barriers.state='completed' AND excluded.state!='completed'")
    db.execute("INSERT INTO pipeline_legacy_barriers SELECT packet_id,config_id,status FROM assessments WHERE 1 ON CONFLICT(packet,config) DO UPDATE SET state=excluded.state WHERE pipeline_legacy_barriers.state='completed' AND excluded.state!='completed'")
    db.execute("INSERT INTO pipeline_legacy_barriers SELECT packet,config,state FROM pipeline_plans WHERE topology!='full-joint-draft-revision-1' ON CONFLICT(packet,config) DO UPDATE SET state=excluded.state WHERE pipeline_legacy_barriers.state='completed' AND excluded.state!='completed'")
    db.execute("UPDATE pipeline_plans SET state='uncertain' WHERE topology!='full-joint-draft-revision-1' AND state NOT IN ('completed','failed','final_pending','uncertain','review')")
    db.execute("UPDATE pipeline_reservations SET held=0 WHERE parent IN (SELECT id FROM pipeline_plans WHERE topology!='full-joint-draft-revision-1')")
    db.execute("DELETE FROM pipeline_active WHERE parent IN (SELECT id FROM pipeline_plans WHERE topology!='full-joint-draft-revision-1')")
    db.execute('UPDATE pipeline_schema SET version=3 WHERE id=1')
   db.execute("CREATE TRIGGER IF NOT EXISTS draft_immutable BEFORE UPDATE OF raw,canonical,rendering,receipt ON pipeline_drafts BEGIN SELECT RAISE(ABORT,'Draft immutable'); END")
   db.execute("CREATE TRIGGER IF NOT EXISTS revision_immutable BEFORE UPDATE OF revision_request,revision_input_key ON pipeline_drafts WHEN OLD.revision_request IS NOT NULL BEGIN SELECT RAISE(ABORT,'Revision immutable'); END")
   db.execute("CREATE TRIGGER IF NOT EXISTS joint_one_child_insert BEFORE INSERT ON pipeline_stages WHEN NEW.ordinal!=1 AND (SELECT topology FROM pipeline_plans WHERE id=NEW.parent)='joint-keyed-purpose-1' BEGIN SELECT RAISE(ABORT,'Joint plan allows one child'); END")
   db.execute("CREATE TRIGGER IF NOT EXISTS joint_one_child_update BEFORE UPDATE OF ordinal,parent ON pipeline_stages WHEN NEW.ordinal!=1 AND (SELECT topology FROM pipeline_plans WHERE id=NEW.parent)='joint-keyed-purpose-1' BEGIN SELECT RAISE(ABORT,'Joint plan allows one child'); END")
   db.execute("CREATE TRIGGER IF NOT EXISTS topology_immutable BEFORE UPDATE OF topology ON pipeline_plans WHEN NEW.topology!=OLD.topology BEGIN SELECT RAISE(ABORT,'Plan topology immutable'); END")
  self.tx(initialize)
 @contextlib.contextmanager
 def connection(self,live=True):
  if live:self.check()
  db=sqlite3.connect(str(self.path),timeout=.025);db.row_factory=sqlite3.Row
  try:db.execute('PRAGMA synchronous=FULL');yield db
  finally:db.close()
 def tx(self,fn,live=True):
  end=time.monotonic()+.25
  while True:
   if live:self.check()
   try:
    with self.connection(live) as db:
     db.execute('BEGIN IMMEDIATE')
     try:
      value=fn(db)
      if live:self.check()
      db.commit();return value
     except BaseException:db.rollback();raise
   except sqlite3.OperationalError as e:
    from behavior_persistence import contention
    if not contention(e) or time.monotonic()>=end:raise
    time.sleep(.005)
 def inspect(self,packet,config):
  with self.connection() as db:
   rows=db.execute('SELECT * FROM pipeline_plans WHERE packet=? ORDER BY rowid DESC',(packet,)).fetchall()
   for row in rows:
    if row['state'] in ('failed','uncertain','review','final_pending'):return dict(row)
    if row['config']==config:
     if row['state']!='completed':return dict(row)
     return dict(row)
   if db.execute("SELECT 1 FROM pipeline_legacy_barriers WHERE packet=? AND (config=? OR state!='completed')",(packet,config)).fetchone():raise Refused('persistence_review_required')
   return None
 def begin(self,packet,config,input_key,cfg,deadline,refs,*,_committed=lambda ident:None):
  from behavior_ai import digest,now
  ident=uuid.uuid4().hex;owner=uuid.uuid4().hex;assessment=str(uuid.uuid4());day=now()[:10];created=now();process=process_token();provider=digest([cfg['endpoint'],cfg['model']])
  def insert(db):
   if db.execute("SELECT 1 FROM pipeline_plans WHERE topology!='full-joint-draft-revision-1' AND state NOT IN ('completed','failed') LIMIT 1").fetchone():raise Refused('persistence_review_required')
   old=db.execute("SELECT state FROM pipeline_plans WHERE packet=? AND (config=? OR state!='completed') LIMIT 1",(packet,config)).fetchone()
   if db.execute("SELECT 1 FROM pipeline_legacy_barriers WHERE packet=? AND (config=? OR state!='completed')",(packet,config)).fetchone():raise Refused('persistence_review_required')
   if old:raise Refused('persistence_review_required')
   active=db.execute('SELECT p.* FROM pipeline_active a JOIN pipeline_plans p ON p.id=a.parent').fetchone()
   if active:
    if alive(active['process']):raise Refused('leased_or_exhausted')
    self._uncertain(db,active['id']);db.execute('DELETE FROM pipeline_active WHERE parent=?',(active['id'],))
   current=db.execute('SELECT c.packet_id FROM current_packets c JOIN packets p ON p.ip=c.ip WHERE p.id=?',(packet,)).fetchone()
   if not current or current[0]!=packet:raise Refused('superseded_before_request')
   if db.execute("SELECT 1 FROM pipeline_legacy_barriers WHERE state NOT IN ('completed','failed') LIMIT 1").fetchone():raise Refused('persistence_review_required')
   # Existing one-pass pending/running work is not reinterpreted as a new job.
   if db.execute("SELECT 1 FROM jobs WHERE packet_id=? AND state='running' LIMIT 1",(packet,)).fetchone():raise Refused('persistence_review_required')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=?',(day,)).fetchone()[0]
   if cfg['daily_budget'] is not None and used+held+2>cfg['daily_budget']:raise Refused('budget')
   db.execute('INSERT INTO pipeline_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(ident,packet,config,input_key,owner,process,'stage1_ready',created,deadline,assessment,None,provider,'full-joint-draft-revision-1'))
   for stage in (1,2):db.execute('INSERT INTO pipeline_stages VALUES(?,?,?,?,?,?,?,?,?)',(ident,stage,digest([ident,stage])[:32],None,'planned',None,None,None,None))
   db.execute('INSERT INTO pipeline_reservations VALUES(?,?,2)',(ident,day));db.execute('INSERT INTO pipeline_active VALUES(1,?)',(ident,))
   db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?) ON CONFLICT(packet_id,config_id) DO UPDATE SET id=excluded.id,state=excluded.state,lease=excluded.lease,attempts=jobs.attempts+1,updated=excluded.updated',(owner,packet,config,'running',deadline+30,1,created))
   for ref in refs:db.execute("INSERT OR IGNORE INTO retention_refs SELECT 'pipeline',?,id FROM packets WHERE id=?",(ident,ref))
  self.hook('before_reservation');self.tx(insert);_committed(ident);self.hook('after_reservation');return ident
 def recover_active(self):
  def commit(db):
   plan=db.execute('SELECT p.* FROM pipeline_active a JOIN pipeline_plans p ON p.id=a.parent').fetchone()
   if plan:
    job=db.execute('SELECT id,state,lease FROM jobs WHERE packet_id=? AND config_id=?',(plan['packet'],plan['config'])).fetchone()
    if not alive(plan['process']) or plan['deadline']<=time.time() or not job or job['id']!=plan['owner'] or job['state']!='running' or job['lease']<=time.time():self._uncertain(db,plan['id'])
  self.tx(commit,live=False)
 def plan(self,ident):
  with self.connection() as db:return dict(db.execute('SELECT * FROM pipeline_plans WHERE id=?',(ident,)).fetchone())
 def guard(self,db,ident,config,allow_expired=False):
  from behavior_ai import now
  plan=db.execute('SELECT * FROM pipeline_plans WHERE id=?',(ident,)).fetchone()
  if not plan or plan['topology']!='full-joint-draft-revision-1' or plan['config']!=config or plan['process']!=process_token() or not plan['state'].endswith(('ready','claimed','entered','validated')):raise Refused('pipeline_ownership_lost')
  if not allow_expired and plan['deadline']<=time.time():raise Refused('deadline_expired')
  job=db.execute("SELECT id,state,lease FROM jobs WHERE packet_id=? AND config_id=?",(plan['packet'],config)).fetchone()
  current=db.execute('SELECT c.packet_id FROM current_packets c JOIN packets p ON p.ip=c.ip WHERE p.id=?',(plan['packet'],)).fetchone()
  if not job or job['id']!=plan['owner'] or job['state']!='running' or job['lease']<=time.time():raise Refused('pipeline_ownership_lost')
  if not current or current[0]!=plan['packet']:raise Refused('superseded_before_request')
  if self.packet_hash is not None:
   from behavior_pipeline import hash_value
   source=db.execute('SELECT content FROM packets WHERE id=?',(plan['packet'],)).fetchone()
   if not source or hash_value(json.loads(source[0]))!=self.packet_hash:raise Refused('input_identity_changed')
  if not db.execute('SELECT 1 FROM pipeline_active WHERE parent=?',(ident,)).fetchone():raise Refused('pipeline_ownership_lost')
  from behavior_pipeline import request_digest
  for ordinal,bound in self.bound_requests.items():
   row=db.execute('SELECT state,request_hash,receipt FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,ordinal)).fetchone()
   if row and row['state']!='planned':
    expected={'input_key':plan['input_key'],'request':bound,'draft_receipt':self.draft_receipt if ordinal==2 else None}
    if row['request_hash']!=request_digest(bound) or not row['receipt'] or json.loads(row['receipt'])!=expected:raise Refused('pipeline_entry_identity')
  if self.draft_receipt is not None:
   draft=db.execute('SELECT receipt FROM pipeline_drafts WHERE parent=?',(ident,)).fetchone()
   if not draft or json.loads(draft[0])!=self.draft_receipt:raise Refused('pipeline_draft_identity')
  return plan
 def claim(self,ident,stage,config,request_hash,budget,receipt_hash=None,*,_committed=lambda request:None):
  if stage not in (1,2):raise Refused('revision_stage_not_allowed')
  def commit(db):
   from behavior_ai import now
   day=now()[:10]
   plan=self.guard(db,ident,config)
   if plan['state']!=('stage1_ready' if stage==1 else 'stage1_validated'):raise Refused('pipeline_stage_order')
   if stage==2:
    draft=db.execute('SELECT revision_request FROM pipeline_drafts WHERE parent=?',(ident,)).fetchone()
    if not draft or not draft[0] or json.loads(draft[0])!=self.bound_requests.get(2):raise Refused('pipeline_draft_identity')
   row=db.execute('SELECT * FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,stage)).fetchone()
   if not row or row['state']!='planned':raise Refused('pipeline_duplicate_claim')
   held=db.execute('SELECT * FROM pipeline_reservations WHERE parent=?',(ident,)).fetchone();remaining=held['held']
   if remaining<1:raise Refused('pipeline_reservation_missing')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];others=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=? AND parent!=?',(day,ident)).fetchone()[0]
   if budget is not None and used+others+remaining>budget:raise Refused('budget')
   db.execute('UPDATE pipeline_reservations SET day=? WHERE parent=?',(day,ident))
   bound=self.bound_requests.get(stage,self.bound_request)
   db.execute("UPDATE pipeline_stages SET request_hash=?,state='claimed',receipt=? WHERE parent=? AND ordinal=?",(request_hash,json.dumps({'input_key':plan['input_key'],'request':bound,'draft_receipt':self.draft_receipt if stage==2 else None},allow_nan=False),ident,stage));db.execute('UPDATE pipeline_plans SET state=? WHERE id=?',('stage%d_claimed'%stage,ident));return row['request_id']
  self.hook('before_claim%d'%stage)
  if self.verify is not None:budget=self.verify()['daily_budget']
  result=self.tx(commit);_committed(result);self.hook('after_claim%d'%stage);return result
 def entry(self,ident,stage,config,request_hash,budget=None,receipt_hash=None):
  if stage not in (1,2):raise Refused('revision_stage_not_allowed')
  def commit(db):
   from behavior_ai import now
   self.guard(db,ident,config);row=db.execute('SELECT * FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,stage)).fetchone()
   if row['state']!='claimed' or row['request_hash']!=request_hash:raise Refused('pipeline_entry_identity')
   day=now()[:10]
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];others=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=? AND parent!=?',(day,ident)).fetchone()[0]
   own=db.execute('SELECT held FROM pipeline_reservations WHERE parent=?',(ident,)).fetchone()
   if not own or own[0]<1:raise Refused('pipeline_reservation_missing')
   if budget is not None and used+others+own[0]>budget:raise Refused('budget')
   reservation=db.execute('SELECT held FROM pipeline_reservations WHERE parent=?',(ident,)).fetchone()
   if not reservation or reservation[0]<1:raise Refused('pipeline_reservation_missing')
   db.execute('UPDATE pipeline_reservations SET day=?,held=held-1 WHERE parent=?',(day,ident))
   db.execute('INSERT INTO usage VALUES(?,1) ON CONFLICT(day) DO UPDATE SET requests=requests+1',(day,))
   db.execute("UPDATE pipeline_stages SET state='entered',charged_day=?,entered=? WHERE parent=? AND ordinal=?",(day,now(),ident,stage));db.execute('UPDATE pipeline_plans SET state=? WHERE id=?',('stage%d_entered'%stage,ident))
  self.hook('before_entry%d'%stage)
  if self.verify is not None:budget=self.verify()['daily_budget']
  self.tx(commit);self.hook('after_entry%d'%stage)
 def dispatch(self,ident,stage,config,request_hash,budget,receipt_hash=None):
  """Last read-only dispatch snapshot; no writer remains held during POST."""
  if stage not in (1,2):raise Refused('revision_stage_not_allowed')
  self.hook('before_dispatch%d'%stage)
  if self.verify is not None:budget=self.verify()['daily_budget']
  from behavior_ai import now
  with self.connection() as db:
   db.execute('BEGIN')
   self.guard(db,ident,config)
   row=db.execute('SELECT * FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,stage)).fetchone()
   if row['state']!='entered' or row['request_hash']!=request_hash:raise Refused('pipeline_entry_identity')
   day=now()[:10]
   if row['charged_day']!=day:raise Refused('pipeline_dispatch_day_changed')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=?',(day,)).fetchone()[0]
   if budget is not None and used+held>budget:raise Refused('budget')
   self.check()
 def final(self,ident,config,outcome,metadata,success,receipt_hash=None,*,assembly=None,evidence=None):
  def commit(db):
   plan=self.guard(db,ident,config,allow_expired=not success)
   if success and plan['state']!='stage2_entered':raise Refused('pipeline_final_order')
   if success and [tuple(r) for r in db.execute('SELECT ordinal,state FROM pipeline_stages WHERE parent=? ORDER BY ordinal',(ident,))]!=[(1,'accepted'),(2,'entered')]:raise Refused('revision_final_child_identity')
   if success:
    row=db.execute('SELECT request_id FROM pipeline_stages WHERE parent=? AND ordinal=2',(ident,)).fetchone()
    if metadata.get('request_id')!=row['request_id']:raise Refused('pipeline_final_identity')
    db.execute('INSERT INTO pipeline_finals VALUES(?,?,?,?,?)',(ident,raw,encoded(canonical).decode(),encoded(rendering).decode(),encoded(final_receipt).decode()))
   row=db.execute("SELECT ordinal,request_id FROM pipeline_stages WHERE parent=? AND state IN ('claimed','entered') ORDER BY ordinal DESC LIMIT 1",(ident,)).fetchone()
   if row:
    if metadata.get('stage')!=row['ordinal'] or metadata.get('request_id') not in (None,row['request_id']):raise Refused('pipeline_stage_metadata_identity')
    record={**metadata,'stage':row['ordinal'],'request_id':row['request_id']}
    db.execute('UPDATE pipeline_stages SET state=?,metadata=? WHERE parent=? AND ordinal=?',('accepted' if success else 'failed',json.dumps(record,allow_nan=False),ident,row['ordinal']))
   db.execute('UPDATE pipeline_plans SET state=\'final_pending\',outcome=? WHERE id=?',(json.dumps(outcome,allow_nan=False),ident));db.execute('UPDATE pipeline_reservations SET held=0 WHERE parent=?',(ident,));db.execute('DELETE FROM pipeline_active WHERE parent=?',(ident,))
  self.hook('before_final')
  if success:
   if self.verify is not None:self.verify()
   if assembly is None:raise Refused('pipeline_final_capture_required')
   from behavior_pipeline import encoded,request_digest
   from behavior_request_evidence import sha
   import behavior_synthesis as sy
   raw=captured(self.brain,ident,2,evidence,assembly.request,assembly.input_key)
   canonical=assembly.decode(raw);record=json.loads(outcome['row'][6])
   if canonical!={k:v for k,v in record.items() if k!='metadata'}:raise Refused('pipeline_final_canonical')
   rendering=sy.presentation(canonical,json.loads(assembly._plan._packet)['events'])
   final_receipt={'parent':ident,'revision_input_key':assembly.input_key,'request_sha256':assembly.request_hash,'raw_sha256':sha(raw.encode()),'canonical_sha256':request_digest(canonical),'rendering_sha256':request_digest(rendering),'draft_receipt':assembly.receipt}
  self.tx(commit,live=success);self.hook('after_final')
 def accept_draft(self,ident,config,pipe,canonical,metadata,evidence):
  """Validate this parent's own durable capture before committing child authority."""
  from behavior_pipeline import request_digest,encoded
  import behavior_synthesis as sy
  from behavior_request_evidence import read,sha
  self.hook('before_accept1');self.check()
  raw=captured(self.brain,ident,1,evidence,pipe.request,pipe.input_key)
  if pipe.decode(raw)!=canonical:raise Refused('pipeline_draft_canonical')
  rendering=sy.presentation(canonical,pipe.packet['events'])
  receipt={'parent':ident,'plan_input_key':pipe.input_key,'draft_request_sha256':pipe.request_hash,'draft_wire_sha256':sha(raw.encode()),'draft_canonical_sha256':request_digest(canonical),'draft_rendering_sha256':request_digest(rendering),'identity_sha256':__import__('behavior_pipeline').hash_value(pipe.identity)}
  def commit(db):
   plan=self.guard(db,ident,config)
   if plan['input_key']!=pipe.input_key or plan['state']!='stage1_entered':raise Refused('pipeline_draft_order')
   row=db.execute('SELECT request_id,request_hash,state FROM pipeline_stages WHERE parent=? AND ordinal=1',(ident,)).fetchone()
   if not row or row['request_hash']!=pipe.request_hash or row['state']!='entered' or metadata.get('request_id')!=row['request_id']:raise Refused('pipeline_draft_identity')
   db.execute('INSERT INTO pipeline_drafts VALUES(?,?,?,?,?,NULL,NULL)',(ident,raw,encoded(canonical).decode(),encoded(rendering).decode(),encoded(receipt).decode()))
   db.execute("UPDATE pipeline_stages SET state='accepted',metadata=? WHERE parent=? AND ordinal=1",(json.dumps(metadata,allow_nan=False),ident))
   db.execute("UPDATE pipeline_plans SET state='stage1_validated' WHERE id=?",(ident,))
  if self.verify is not None:self.verify()
  self.tx(commit);self.hook('after_accept1')
 def revision(self,ident,config,pipe):
  """No raw-draft argument: lineage can only come from this owned ledger."""
  with self.connection() as db:
   plan=self.guard(db,ident,config)
   row=db.execute('SELECT * FROM pipeline_drafts WHERE parent=?',(ident,)).fetchone()
   stages=list(db.execute('SELECT ordinal,state FROM pipeline_stages WHERE parent=? ORDER BY ordinal',(ident,)))
   if plan['state']!='stage1_validated' or plan['input_key']!=pipe.input_key or not row or [tuple(r) for r in stages]!=[(1,'accepted'),(2,'planned')]:raise Refused('pipeline_draft_order')
   draft=dict(row)
  revision=pipe._revision(ident,draft['raw'],json.loads(draft['canonical']),json.loads(draft['rendering']),self.check)
  if revision.receipt!=json.loads(draft['receipt']):raise Refused('pipeline_draft_identity')
  def bind(db):
   self.guard(db,ident,config)
   current=db.execute('SELECT * FROM pipeline_drafts WHERE parent=?',(ident,)).fetchone()
   if dict(current)!=draft:raise Refused('pipeline_draft_identity')
   if current['revision_request'] is not None:raise Refused('pipeline_duplicate_revision')
   db.execute('UPDATE pipeline_drafts SET revision_request=?,revision_input_key=? WHERE parent=?',(__import__('behavior_pipeline').encoded(revision.request).decode(),revision.input_key,ident))
  self.hook('before_revision');self.tx(bind);self.hook('after_revision')
  self.bound_requests[2]=revision.request;self.draft_receipt=revision.receipt
  return revision
 def receipts(self,ident):
  with self.connection() as db:return [json.loads(r[0]) for r in db.execute('SELECT metadata FROM pipeline_stages WHERE parent=? AND metadata IS NOT NULL ORDER BY ordinal',(ident,))]
 def charges(self,ident):
  with self.connection() as db:return db.execute('SELECT count(*) FROM pipeline_stages WHERE parent=? AND charged_day IS NOT NULL',(ident,)).fetchone()[0]
 def _uncertain(self,db,ident):
  db.execute("UPDATE pipeline_plans SET state='uncertain' WHERE id=? AND state NOT IN ('final_pending','completed','failed')",(ident,));db.execute('UPDATE pipeline_reservations SET held=0 WHERE parent=?',(ident,));db.execute('DELETE FROM pipeline_active WHERE parent=?',(ident,))
 def uncertain(self,ident):self.tx(lambda db:self._uncertain(db,ident),live=False)
 def recovered(self,ident,status):
  if status not in ('completed','failed','superseded'):return
  def commit(db):
   plan=db.execute('SELECT * FROM pipeline_plans WHERE id=?',(ident,)).fetchone()
   if not plan or plan['state'] not in ('final_pending','completed','failed'):raise Refused('pipeline_recovery_state')
   desired='completed' if status=='completed' else 'failed'
   if plan['state'] in ('completed','failed') and plan['state']!=desired:raise Refused('pipeline_terminal_immutable')
   db.execute('UPDATE pipeline_plans SET state=? WHERE id=?',(desired,ident));db.execute("DELETE FROM retention_refs WHERE kind='pipeline' AND owner=?",(ident,));db.execute('DELETE FROM pipeline_active WHERE parent=?',(ident,))
  self.tx(commit)

def summary(brain):
 try:
  with brain.connect() as db:
   if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_reservations'").fetchone():return {'reserved':0,'uncertain':0,'plans':0}
   held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations').fetchone()[0]
   uncertain=db.execute("SELECT count(*) FROM pipeline_stages s JOIN pipeline_plans p ON p.id=s.parent WHERE p.state IN ('uncertain','review') AND s.state IN ('claimed','entered') AND s.charged_day IS NOT NULL").fetchone()[0]
   return {'reserved':held,'uncertain':uncertain,'plans':1}
 except sqlite3.Error:return {'reserved':None,'uncertain':None,'plans':1}

def compact(db,limit,cut):
 """Bounded retention cursor; keep consumed-claim tombstones and uncertainty.

 The caller owns the existing retention transaction. No schema initialization,
 model preparation or new database connection occurs on this path.
 """
 if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_schema'").fetchone():return {'scanned':0,'compacted':0}
 row=db.execute("SELECT value FROM retention_state WHERE name='sweep_pipeline'").fetchone();cursor=json.loads(row[0]) if row else ['','']
 rows=db.execute("SELECT id,created,assessment FROM pipeline_plans WHERE outcome IS NOT NULL AND state IN ('completed','failed') AND created<? AND (created,id)>(?,?) ORDER BY created,id LIMIT ?",(cut,*cursor,limit)).fetchall();count=0
 for row in rows:
  if db.execute('SELECT 1 FROM assessments WHERE id=?',(row['assessment'],)).fetchone():continue
  if db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_drafts'").fetchone():db.execute('DELETE FROM pipeline_drafts WHERE parent=?',(row['id'],))
  if db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_finals'").fetchone():db.execute('DELETE FROM pipeline_finals WHERE parent=?',(row['id'],))
  db.execute('UPDATE pipeline_plans SET outcome=NULL WHERE id=?',(row['id'],));db.execute('UPDATE pipeline_stages SET receipt=NULL,metadata=NULL WHERE parent=?',(row['id'],));count+=1
 db.execute("INSERT OR REPLACE INTO retention_state VALUES('sweep_pipeline',?)",(json.dumps([rows[-1]['created'],rows[-1]['id']] if len(rows)==limit else ['','']),))
 return {'scanned':len(rows),'compacted':count}
