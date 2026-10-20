"""Durable two-request ownership/charges. No network while holding a writer lock."""
import contextlib,datetime as dt,json,os,pathlib,sqlite3,time,uuid

SCHEMA='''
CREATE TABLE IF NOT EXISTS pipeline_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
INSERT OR IGNORE INTO pipeline_schema VALUES(1,1);
CREATE TABLE IF NOT EXISTS pipeline_plans(id TEXT PRIMARY KEY,packet TEXT NOT NULL,config TEXT NOT NULL,input_key TEXT NOT NULL,owner TEXT NOT NULL,process TEXT NOT NULL,state TEXT NOT NULL,created TEXT NOT NULL,deadline REAL NOT NULL,assessment TEXT NOT NULL UNIQUE,outcome TEXT,provider TEXT NOT NULL);
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

class Ledger:
 def __init__(self,brain,check=lambda:None,hook=lambda phase:None):
  self.brain=brain;self.path=brain.path;self.check=check;self.hook=hook;self.verify=None;self.packet_hash=None
  with self.connection() as db:
   if db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_schema'").fetchone():
    if db.execute('SELECT version FROM pipeline_schema WHERE id=1').fetchone()[0]!=1:raise Refused('pipeline_schema_review_required')
    return
   db.executescript('BEGIN IMMEDIATE;'+SCHEMA+'COMMIT;')
   if db.execute('SELECT version FROM pipeline_schema WHERE id=1').fetchone()[0]!=1:raise Refused('pipeline_schema_review_required')
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
    if row['state'] in ('failed','uncertain','review'):return dict(row)
    if row['config']==config:
     if row['state']!='completed':return dict(row)
     saved=db.execute('SELECT expires FROM assessments WHERE id=?',(row['assessment'],)).fetchone()
     from behavior_ai import now
     if saved and saved[0]>now():return dict(row)
   return None
 def begin(self,packet,config,input_key,cfg,deadline,refs):
  from behavior_ai import digest,now
  ident=uuid.uuid4().hex;owner=uuid.uuid4().hex;assessment=str(uuid.uuid4());day=now()[:10];created=now();process=process_token();provider=digest([cfg['endpoint'],cfg['model']])
  def insert(db):
   old=db.execute("SELECT state FROM pipeline_plans WHERE packet=? AND state NOT IN ('completed') LIMIT 1",(packet,)).fetchone()
   if old:raise Refused('persistence_review_required')
   active=db.execute('SELECT p.* FROM pipeline_active a JOIN pipeline_plans p ON p.id=a.parent').fetchone()
   if active:
    if alive(active['process']):raise Refused('leased_or_exhausted')
    self._uncertain(db,active['id']);db.execute('DELETE FROM pipeline_active WHERE parent=?',(active['id'],))
   current=db.execute('SELECT c.packet_id FROM current_packets c JOIN packets p ON p.ip=c.ip WHERE p.id=?',(packet,)).fetchone()
   if not current or current[0]!=packet:raise Refused('superseded_before_request')
   # Existing one-pass pending/running work is not reinterpreted as a new job.
   if db.execute("SELECT 1 FROM jobs WHERE packet_id=? AND state='running' LIMIT 1",(packet,)).fetchone():raise Refused('persistence_review_required')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=?',(day,)).fetchone()[0]
   if cfg['daily_budget'] is not None and used+held+2>cfg['daily_budget']:raise Refused('budget')
   db.execute('INSERT INTO pipeline_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(ident,packet,config,input_key,owner,process,'stage1_ready',created,deadline,assessment,None,provider))
   for stage in (1,2):db.execute('INSERT INTO pipeline_stages VALUES(?,?,?,?,?,?,?,?,?)',(ident,stage,digest([ident,stage])[:32],None,'planned',None,None,None,None))
   db.execute('INSERT INTO pipeline_reservations VALUES(?,?,2)',(ident,day));db.execute('INSERT INTO pipeline_active VALUES(1,?)',(ident,))
   db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?) ON CONFLICT(packet_id,config_id) DO UPDATE SET id=excluded.id,state=excluded.state,lease=excluded.lease,attempts=jobs.attempts+1,updated=excluded.updated',(owner,packet,config,'running',deadline+30,1,created))
   for ref in refs:db.execute("INSERT OR IGNORE INTO retention_refs SELECT 'pipeline',?,id FROM packets WHERE id=?",(ident,ref))
  self.hook('before_reservation');self.tx(insert);self.hook('after_reservation');return ident
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
  if not plan or plan['config']!=config or plan['process']!=process_token() or not plan['state'].endswith(('ready','claimed','entered','validated')):raise Refused('pipeline_ownership_lost')
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
  return plan
 def frozen_identity(self,db,ident,expected):
  from behavior_pipeline import hash_value
  row=db.execute("SELECT receipt FROM pipeline_stages WHERE parent=? AND ordinal=1 AND state='accepted'",(ident,)).fetchone()
  if expected is None or not row or hash_value(json.loads(row[0]))!=expected:raise Refused('pipeline_frozen_identity_changed')
 def claim(self,ident,stage,config,request_hash,budget,receipt_hash=None):
  def commit(db):
   from behavior_ai import now
   day=now()[:10]
   plan=self.guard(db,ident,config)
   if plan['state']!=('stage1_ready' if stage==1 else 'stage1_validated'):raise Refused('pipeline_stage_order')
   if stage==2:self.frozen_identity(db,ident,receipt_hash)
   row=db.execute('SELECT * FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,stage)).fetchone()
   if not row or row['state']!='planned':raise Refused('pipeline_duplicate_claim')
   held=db.execute('SELECT * FROM pipeline_reservations WHERE parent=?',(ident,)).fetchone();remaining=held['held']
   if remaining<1:raise Refused('pipeline_reservation_missing')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];others=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=? AND parent!=?',(day,ident)).fetchone()[0]
   if budget is not None and used+others+remaining>budget:raise Refused('budget')
   db.execute('UPDATE pipeline_reservations SET day=?,held=held-1 WHERE parent=? AND held>0',(day,ident))
   db.execute('INSERT INTO usage VALUES(?,1) ON CONFLICT(day) DO UPDATE SET requests=requests+1',(day,))
   db.execute("UPDATE pipeline_stages SET request_hash=?,state='claimed',charged_day=? WHERE parent=? AND ordinal=?",(request_hash,day,ident,stage));db.execute('UPDATE pipeline_plans SET state=? WHERE id=?',('stage%d_claimed'%stage,ident));return row['request_id']
  self.hook('before_claim%d'%stage)
  if self.verify is not None:budget=self.verify()['daily_budget']
  result=self.tx(commit);self.hook('after_claim%d'%stage);return result
 def entry(self,ident,stage,config,request_hash,budget=None,receipt_hash=None):
  def commit(db):
   from behavior_ai import now
   self.guard(db,ident,config);row=db.execute('SELECT * FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,stage)).fetchone()
   if row['state']!='claimed' or row['request_hash']!=request_hash:raise Refused('pipeline_entry_identity')
   if stage==2:self.frozen_identity(db,ident,receipt_hash)
   day=now()[:10]
   if row['charged_day']!=day:raise Refused('pipeline_dispatch_day_changed')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=?',(day,)).fetchone()[0]
   if budget is not None and used+held>budget:raise Refused('budget')
   db.execute("UPDATE pipeline_stages SET state='entered',entered=? WHERE parent=? AND ordinal=?",(now(),ident,stage));db.execute('UPDATE pipeline_plans SET state=? WHERE id=?',('stage%d_entered'%stage,ident))
  self.hook('before_entry%d'%stage)
  if self.verify is not None:budget=self.verify()['daily_budget']
  self.tx(commit);self.hook('after_entry%d'%stage)
 def dispatch(self,ident,stage,config,request_hash,budget,receipt_hash=None):
  """Last read-only dispatch snapshot; no writer remains held during POST."""
  from behavior_ai import now
  with self.connection() as db:
   db.execute('BEGIN')
   self.guard(db,ident,config)
   row=db.execute('SELECT * FROM pipeline_stages WHERE parent=? AND ordinal=?',(ident,stage)).fetchone()
   if row['state']!='entered' or row['request_hash']!=request_hash:raise Refused('pipeline_entry_identity')
   if stage==2:self.frozen_identity(db,ident,receipt_hash)
   day=now()[:10]
   if row['charged_day']!=day:raise Refused('pipeline_dispatch_day_changed')
   used=db.execute('SELECT coalesce(sum(requests),0) FROM usage WHERE day=?',(day,)).fetchone()[0];held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations WHERE day=?',(day,)).fetchone()[0]
   if budget is not None and used+held>budget:raise Refused('budget')
   self.check()
 def freeze(self,ident,config,receipt,metadata):
  def commit(db):
   plan=self.guard(db,ident,config)
   if plan['state']!='stage1_entered' or plan['input_key']!=receipt['input_key']:raise Refused('pipeline_freeze_identity')
   db.execute("UPDATE pipeline_stages SET state='accepted',receipt=?,metadata=? WHERE parent=? AND ordinal=1",(json.dumps(receipt,allow_nan=False),json.dumps(metadata,allow_nan=False),ident));db.execute("UPDATE pipeline_plans SET state='stage1_validated' WHERE id=?",(ident,))
  self.hook('before_freeze')
  if self.verify is not None:self.verify()
  self.tx(commit);self.hook('after_freeze')
 def frozen(self,ident):
  with self.connection() as db:
   row=db.execute("SELECT receipt FROM pipeline_stages WHERE parent=? AND ordinal=1 AND state='accepted'",(ident,)).fetchone()
   if not row:raise Refused('pipeline_receipt_missing')
   return json.loads(row[0])
 def final(self,ident,config,outcome,metadata,success,receipt_hash=None):
  def commit(db):
   plan=self.guard(db,ident,config,allow_expired=not success)
   if success and plan['state']!='stage2_entered':raise Refused('pipeline_final_order')
   if success:self.frozen_identity(db,ident,receipt_hash)
   row=db.execute("SELECT ordinal FROM pipeline_stages WHERE parent=? AND state IN ('claimed','entered') ORDER BY ordinal DESC LIMIT 1",(ident,)).fetchone()
   if row:db.execute('UPDATE pipeline_stages SET state=?,metadata=? WHERE parent=? AND ordinal=?',('accepted' if success else 'failed',json.dumps(metadata,allow_nan=False),ident,row[0]))
   db.execute('UPDATE pipeline_plans SET state=\'final_pending\',outcome=? WHERE id=?',(json.dumps(outcome,allow_nan=False),ident));db.execute('UPDATE pipeline_reservations SET held=0 WHERE parent=?',(ident,));db.execute('DELETE FROM pipeline_active WHERE parent=?',(ident,))
  self.hook('before_final')
  if success and self.verify is not None:self.verify()
  self.tx(commit,live=success);self.hook('after_final')
 def receipts(self,ident):
  with self.connection() as db:return [json.loads(r[0]) for r in db.execute('SELECT metadata FROM pipeline_stages WHERE parent=? AND metadata IS NOT NULL ORDER BY ordinal',(ident,))]
 def charges(self,ident):
  with self.connection() as db:return db.execute('SELECT count(*) FROM pipeline_stages WHERE parent=? AND charged_day IS NOT NULL',(ident,)).fetchone()[0]
 def _uncertain(self,db,ident):
  db.execute("UPDATE pipeline_plans SET state='uncertain' WHERE id=? AND state!='final_pending'",(ident,));db.execute('UPDATE pipeline_reservations SET held=0 WHERE parent=?',(ident,));db.execute('DELETE FROM pipeline_active WHERE parent=?',(ident,))
 def uncertain(self,ident):self.tx(lambda db:self._uncertain(db,ident),live=False)
 def recovered(self,ident,status):
  if status not in ('completed','failed','superseded'):return
  def commit(db):
   plan=db.execute('SELECT * FROM pipeline_plans WHERE id=?',(ident,)).fetchone()
   if not plan or plan['state'] not in ('final_pending','completed','failed'):raise Refused('pipeline_recovery_state')
   db.execute('UPDATE pipeline_plans SET state=? WHERE id=?',('completed' if status=='completed' else 'failed',ident));db.execute("DELETE FROM retention_refs WHERE kind='pipeline' AND owner=?",(ident,));db.execute('DELETE FROM pipeline_active WHERE parent=?',(ident,))
  self.tx(commit)

def summary(brain):
 try:
  with brain.connect() as db:
   if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_reservations'").fetchone():return {'reserved':0,'uncertain':0,'plans':0}
   held=db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations').fetchone()[0]
   uncertain=db.execute("SELECT count(*) FROM pipeline_stages s JOIN pipeline_plans p ON p.id=s.parent WHERE p.state IN ('uncertain','review') AND s.state IN ('claimed','entered') AND s.charged_day IS NOT NULL").fetchone()[0]
   return {'reserved':held,'uncertain':uncertain,'plans':2}
 except sqlite3.Error:return {'reserved':None,'uncertain':None,'plans':2}

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
  db.execute('UPDATE pipeline_plans SET outcome=NULL WHERE id=?',(row['id'],));db.execute('UPDATE pipeline_stages SET receipt=NULL,metadata=NULL WHERE parent=?',(row['id'],));count+=1
 db.execute("INSERT OR REPLACE INTO retention_state VALUES('sweep_pipeline',?)",(json.dumps([rows[-1]['created'],rows[-1]['id']] if len(rows)==limit else ['','']),))
 return {'scanned':len(rows),'compacted':count}
