"""Durable native sample revisions; derived delivery never runs in ingestion."""
import contextlib,copy,datetime as dt,hashlib,json,sqlite3,time

NATIVE_SCHEMA='''
CREATE TABLE IF NOT EXISTS source_sample_handoff(revision INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,ip TEXT NOT NULL,source TEXT NOT NULL,sensor TEXT NOT NULL,scope TEXT NOT NULL,seen TEXT NOT NULL,received TEXT NOT NULL,content TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS source_sample_pending ON source_sample_handoff(delivered,revision);
CREATE INDEX IF NOT EXISTS source_sample_expiry ON source_sample_handoff(seen);
'''
DERIVED_SCHEMA='''
CREATE TABLE IF NOT EXISTS source_sample_applied(id TEXT PRIMARY KEY,seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_sample_applied_expiry ON source_sample_applied(seen);
CREATE TABLE IF NOT EXISTS source_sample_equivalence(id TEXT PRIMARY KEY,seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_sample_equivalence_expiry ON source_sample_equivalence(seen);
CREATE TABLE IF NOT EXISTS source_sample_ready(ip TEXT NOT NULL,scope TEXT NOT NULL,revision INTEGER NOT NULL,seen TEXT NOT NULL,PRIMARY KEY(ip,scope));
CREATE INDEX IF NOT EXISTS source_sample_ready_expiry ON source_sample_ready(seen);
CREATE INDEX IF NOT EXISTS source_sample_ready_order ON source_sample_ready(scope,revision,ip);
'''

def scope(cfg):
 if cfg is None:return ''
 return hashlib.sha256(json.dumps([cfg.get('index_url',''),cfg.get('source_agents',{}),cfg.get('palo_location','')],sort_keys=True,separators=(',',':')).encode()).hexdigest()

def identity(address,collection,event):
 """Only selection status is redundant with an identical coherent unique proof.

 Keep the actual query window/time, source/body hashes, count and every other
 field. Error/partial reports and reports without a valid proof stay distinct.
 Return legacy aliases so capture also recognizes already retained v0.10.13 rows.
 """
 from source_observations import binding_proof
 def fingerprint(value):return hashlib.sha256(json.dumps([address,collection,value],sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
 observation=event.get('source_observation') or {};value=copy.deepcopy(event)
 aliases={fingerprint(event)}
 proof=binding_proof(observation)
 if observation.get('lookup_status') in ('complete','not_selected') and proof and proof['connection_count']==1 and observation.get('connection_count')==1 and observation.get('connection_id')==proof['connection_id'] and not observation.get('binding_state'):
  for status in ('complete','not_selected'):
   value['source_observation']['lookup_status']=status;aliases.add(fingerprint(value))
  value['source_observation'].pop('lookup_status')
 ident=fingerprint(value);aliases.add(ident)
 return ident,aliases

def initialize(db):
 db.executescript(NATIVE_SCHEMA)
 # A marker never substitutes for the schema. Existing opens only read; a
 # missing index is recreated by the DDL and incompatible columns fail here.
 db.execute('SELECT revision,id,ip,source,sensor,scope,seen,received,content,delivered FROM source_sample_handoff LIMIT 0')
 if [(r[1],r[5]) for r in db.execute('PRAGMA table_info(source_sample_handoff)') if r[5]]!=[('revision',1)]:raise ValueError('Incompatible handoff primary key')
 for name,columns in (('source_sample_pending',['delivered','revision']),('source_sample_expiry',['seen'])):
  if [r[2] for r in db.execute('PRAGMA index_info('+name+')')]!=columns:raise ValueError('Incompatible handoff index: '+name)
 unique=[r[1] for r in db.execute('PRAGMA index_list(source_sample_handoff)') if r[2]]
 if not any([r[2] for r in db.execute('PRAGMA index_info("'+name.replace('"','""')+'")')]==['id'] for name in unique):raise ValueError('Missing handoff identity uniqueness')

def maintain(store,at=None):
 cut=((at or dt.datetime.now(dt.timezone.utc))-dt.timedelta(days=30)).isoformat(timespec='seconds')
 with store.connect() as db:
  if not db.execute('SELECT 1 FROM source_sample_handoff WHERE seen<? LIMIT 1',(cut,)).fetchone():return {'deleted':0,'partial':False,'bound':5000}
  db.execute('BEGIN IMMEDIATE')
  deleted=db.execute('DELETE FROM source_sample_handoff WHERE revision IN (SELECT revision FROM source_sample_handoff WHERE seen<? ORDER BY seen LIMIT 5000)',(cut,)).rowcount
  partial=bool(db.execute('SELECT 1 FROM source_sample_handoff WHERE seen<? LIMIT 1',(cut,)).fetchone())
 return {'deleted':deleted,'partial':partial,'bound':5000}

def capture(db,address,source,sensor,details,received,source_cfg=None):
 """Same native transaction; retain samples before a later bucket replaces them."""
 from evidence_history import normalize
 try:
  activity=details.get('activity',{});activity=json.loads(activity) if isinstance(activity,str) else activity
 except (ValueError,TypeError,AttributeError):return
 if not isinstance(activity,dict) or not isinstance(activity.get('events'),list):return
 for sample in activity['events'][:500]:
  try:event=normalize(address,source,sensor,sample,received)
  except (ValueError,TypeError,AttributeError,OverflowError):continue
  if not event:continue
  content=json.dumps(event,sort_keys=True,separators=(',',':'),allow_nan=False)
  collection=scope(source_cfg);ident,aliases=identity(address,collection,event)
  if db.execute('SELECT 1 FROM source_sample_handoff WHERE id IN ('+','.join('?' for _ in aliases)+') LIMIT 1',list(aliases)).fetchone():continue
  db.execute('INSERT OR IGNORE INTO source_sample_handoff(id,ip,source,sensor,scope,seen,received,content) VALUES(?,?,?,?,?,?,?,?)',(ident,address,source,sensor,collection,event['seen'],received,content))

class Cancelled(Exception):pass

DELIVERY_COMMIT_EVENTS=16

def deliver(brain,limit=500,at=None,should_stop=None):
 """Bounded reads, short derived commits, then exact native acknowledgments.

 The public read bound remains500. Every selected chunk continues immediately;
 it is not a request/cycle quota. A failed later chunk retains earlier commits.
 """
 from evidence_history import save_events
 from behavior_persistence import contention
 started=time.monotonic();stopped=should_stop or (lambda:False)
 at=at or dt.datetime.now(dt.timezone.utc);cut=(at-dt.timedelta(days=30)).isoformat(timespec='seconds')
 totals={'read':0,'applied':0,'merged':0,'equivalent':0,'acknowledged':0,'transactions':0}
 maximum=0;transaction_seconds=0
 def outcome(status):
  return {'status':status,**totals,'bound':500,'commit_bound':DELIVERY_COMMIT_EVENTS,'transaction_seconds':round(transaction_seconds,6),'max_transaction_seconds':round(maximum,6),'seconds':round(time.monotonic()-started,6)}
 try:
  if stopped():raise Cancelled
  with brain.store.connect() as native:
   rows=[dict(r) for r in native.execute('SELECT * FROM source_sample_handoff WHERE delivered=0 ORDER BY revision LIMIT ?',(max(1,min(500,limit)),))]
  chunks=[rows[i:i+DELIVERY_COMMIT_EVENTS] for i in range(0,len(rows),DELIVERY_COMMIT_EVENTS)] or [[]]
  for number,chunk in enumerate(chunks):
   if stopped():raise Cancelled
   # Immutable parsing/identity work precedes the derived writer. Mutable
   # predecessor/receipt/audit decisions remain inside save_events' owner.
   prepared=[]
   for row in chunk:
    if row['seen']>=cut:
     event=json.loads(row['content']);ident,_=identity(row['ip'],row['scope'],event);prepared.append((row,event,ident))
   tx_started=time.monotonic()
   with brain.connect() as db:
    if not chunk and not any(db.execute('SELECT 1 FROM '+table+' WHERE seen<? LIMIT 1',(cut,)).fetchone() for table in ('source_sample_applied','source_sample_ready','source_sample_equivalence')):break
    db.execute('PRAGMA busy_timeout=100');db.execute('BEGIN IMMEDIATE')
    class Transaction:
     def connect(self):return contextlib.nullcontext(db)
    applied=merged=equivalent=0
    for row,event,ident in prepared:
     if stopped():raise Cancelled
     prior=db.execute('SELECT 1 FROM source_sample_applied WHERE id=?',(row['id'],)).fetchone()
     same=db.execute('SELECT 1 FROM source_sample_equivalence WHERE id=?',(ident,)).fetchone()
     if not prior and not same:
      save_events(Transaction(),row['ip'],[event],row['received'],row['scope']);merged+=1
      db.execute('INSERT INTO source_sample_ready VALUES(?,?,?,?) ON CONFLICT(ip,scope) DO UPDATE SET revision=max(revision,excluded.revision),seen=max(seen,excluded.seen)',(row['ip'],row['scope'],row['revision'],row['seen']))
     db.execute('INSERT OR IGNORE INTO source_sample_equivalence VALUES(?,?)',(ident,row['seen']))
     if prior:continue
     db.execute('INSERT INTO source_sample_applied VALUES(?,?)',(row['id'],row['seen']));applied+=1;equivalent+=bool(same)
    if number==0:
     db.execute('DELETE FROM source_sample_applied WHERE id IN (SELECT id FROM source_sample_applied WHERE seen<? LIMIT 5000)',(cut,))
     db.execute('DELETE FROM source_sample_ready WHERE rowid IN (SELECT rowid FROM source_sample_ready WHERE seen<? LIMIT 5000)',(cut,))
     db.execute('DELETE FROM source_sample_equivalence WHERE id IN (SELECT id FROM source_sample_equivalence WHERE seen<? LIMIT 5000)',(cut,))
   duration=time.monotonic()-tx_started;transaction_seconds+=duration;maximum=max(maximum,duration)
   totals['transactions']+=1;totals['read']+=len(chunk);totals['applied']+=applied;totals['merged']+=merged;totals['equivalent']+=equivalent
   if stopped():raise Cancelled
   if chunk:
    with brain.store.connect() as native:
     native.executemany('UPDATE source_sample_handoff SET delivered=1 WHERE revision=? AND id=?',[(r['revision'],r['id']) for r in chunk])
   totals['acknowledged']+=len(chunk)
  return outcome('delivered')
 except Cancelled:return outcome('cancelled')
 except sqlite3.OperationalError as exc:
  if not contention(exc):raise
  result=outcome('busy_retry_next_pass');result['sqlite_code']=exc.sqlite_errorcode;return result


def consume(store,stopped,finished=None,quiesce=None):
 """Drain successive bounded commits independently of serial model work.

 This runs inside the existing behavior process. Only idle/unavailable storage
 waits; a nonempty successful batch immediately proceeds to the next batch.
 An optional lifecycle signal yields only between complete deliver/ack batches.
 Without that signal, callers retain the existing drain-until-idle behavior.
 """
 from behavior_ai import Brain,settings
 brain=None;totals={'transactions':0,'read':0,'applied':0,'merged':0,'equivalent':0,'max_transaction_seconds':0}
 while not stopped.is_set() and not (quiesce and quiesce.is_set()):
  try:
   if not settings(store)['enabled']:
    if finished and finished.is_set():break
    stopped.wait(1);continue
   if brain is None:brain=Brain(store)
   if quiesce and quiesce.is_set():break
   result=deliver(brain,should_stop=stopped.is_set)
  except sqlite3.OperationalError as exc:
   from behavior_persistence import contention
   if not contention(exc):
    store._source_handoff_status={'status':'failed','error':type(exc).__name__};stopped.set();return
   result={'status':'busy_retry_next_pass','bound':500,'sqlite_code':exc.sqlite_errorcode}
  except Exception as exc:
   store._source_handoff_status={'status':'failed','error':type(exc).__name__}
   stopped.set();return
  if result.get('transactions') or result['status']=='delivered' and result['read']:
   totals['transactions']+=result.get('transactions',1)
   for k in ('read','applied','merged','equivalent'):totals[k]+=result.get(k,0)
   totals['max_transaction_seconds']=max(totals['max_transaction_seconds'],result.get('max_transaction_seconds',result['transaction_seconds']))
  store._source_handoff_status={**result,'totals':dict(totals),'at':dt.datetime.now(dt.timezone.utc).isoformat()}
  if result['status']=='cancelled':break
  if result['status']!='delivered' or not result['read']:
   if finished and finished.is_set():break
   stopped.wait(1)

def ready(brain,source_cfg=None,limit=100,addresses=None):
 from evidence_history import collection_scope
 with brain.connect() as db:
  where='scope=?';args=[collection_scope(brain,source_cfg)]
  if addresses is not None:where+=' AND ip IN (SELECT value FROM json_each(?))';args.append(json.dumps(addresses))
  return {r['ip']:r['revision'] for r in db.execute('SELECT ip,revision FROM source_sample_ready WHERE '+where+' ORDER BY revision,ip LIMIT ?',args+[max(1,min(100,limit))])}

def indexed(brain,address,revision,source_cfg=None):
 from evidence_history import collection_scope
 with brain.connect() as db:db.execute('DELETE FROM source_sample_ready WHERE ip=? AND scope=? AND revision=?',(address,collection_scope(brain,source_cfg),revision))
