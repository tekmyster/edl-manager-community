"""Durable native sample revisions; derived delivery never runs in ingestion."""
import contextlib,datetime as dt,hashlib,json,sqlite3

NATIVE_SCHEMA='''
CREATE TABLE IF NOT EXISTS source_sample_handoff(revision INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,ip TEXT NOT NULL,source TEXT NOT NULL,sensor TEXT NOT NULL,scope TEXT NOT NULL,seen TEXT NOT NULL,received TEXT NOT NULL,content TEXT NOT NULL,delivered INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS source_sample_pending ON source_sample_handoff(delivered,revision);
CREATE INDEX IF NOT EXISTS source_sample_expiry ON source_sample_handoff(seen);
'''
DERIVED_SCHEMA='''
CREATE TABLE IF NOT EXISTS source_sample_applied(id TEXT PRIMARY KEY,seen TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_sample_applied_expiry ON source_sample_applied(seen);
CREATE TABLE IF NOT EXISTS source_sample_ready(ip TEXT NOT NULL,scope TEXT NOT NULL,revision INTEGER NOT NULL,seen TEXT NOT NULL,PRIMARY KEY(ip,scope));
CREATE INDEX IF NOT EXISTS source_sample_ready_expiry ON source_sample_ready(seen);
'''

def scope(cfg):
 if cfg is None:return ''
 return hashlib.sha256(json.dumps([cfg.get('index_url',''),cfg.get('source_agents',{}),cfg.get('palo_location','')],sort_keys=True,separators=(',',':')).encode()).hexdigest()

def initialize(db):
 db.executescript(NATIVE_SCHEMA)
 cut=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)).isoformat(timespec='seconds')
 db.execute('DELETE FROM source_sample_handoff WHERE revision IN (SELECT revision FROM source_sample_handoff WHERE seen<? ORDER BY seen LIMIT 5000)',(cut,))

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
  collection=scope(source_cfg);ident=hashlib.sha256(json.dumps([address,collection,event],sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
  db.execute('INSERT OR IGNORE INTO source_sample_handoff(id,ip,source,sensor,scope,seen,received,content) VALUES(?,?,?,?,?,?,?,?)',(ident,address,source,sensor,collection,event['seen'],received,content))

def deliver(brain,limit=500,at=None):
 """Commit derived receipt/ready state first, then acknowledge exact native rows.

 A crash between commits safely replays; the applied ledger suppresses repeats.
 No native transaction or writer lock is held while derived storage is busy.
 """
 from evidence_history import save_events
 at=at or dt.datetime.now(dt.timezone.utc);cut=(at-dt.timedelta(days=30)).isoformat(timespec='seconds')
 try:
  with brain.store.connect() as native:
   rows=[dict(r) for r in native.execute('SELECT * FROM source_sample_handoff WHERE delivered=0 ORDER BY revision LIMIT ?',(max(1,min(500,limit)),))]
  with brain.connect() as db:
   # Bound lock waiting for this optional local handoff, not native ingestion.
   db.execute('PRAGMA busy_timeout=100');db.execute('BEGIN IMMEDIATE')
   class Transaction:
    def connect(self):return contextlib.nullcontext(db)
   applied=0
   for row in rows:
    if row['seen']<cut or db.execute('SELECT 1 FROM source_sample_applied WHERE id=?',(row['id'],)).fetchone():continue
    save_events(Transaction(),row['ip'],[json.loads(row['content'])],row['received'],row['scope'])
    db.execute('INSERT INTO source_sample_applied VALUES(?,?)',(row['id'],row['seen']))
    db.execute('INSERT INTO source_sample_ready VALUES(?,?,?,?) ON CONFLICT(ip,scope) DO UPDATE SET revision=max(revision,excluded.revision),seen=max(seen,excluded.seen)',(row['ip'],row['scope'],row['revision'],row['seen']))
    applied+=1
   db.execute('DELETE FROM source_sample_applied WHERE id IN (SELECT id FROM source_sample_applied WHERE seen<? LIMIT 5000)',(cut,))
   db.execute('DELETE FROM source_sample_ready WHERE rowid IN (SELECT rowid FROM source_sample_ready WHERE seen<? LIMIT 5000)',(cut,))
  # Ack only immutable revisions read above, never a newer source bucket.
  with brain.store.connect() as native:
   native.executemany('UPDATE source_sample_handoff SET delivered=1 WHERE revision=? AND id=?',[(r['revision'],r['id']) for r in rows])
  return {'status':'delivered','read':len(rows),'applied':applied,'bound':500}
 except sqlite3.OperationalError:
  return {'status':'busy_retry_next_pass','bound':500}

def ready(brain,source_cfg=None,limit=100,addresses=None):
 from evidence_history import collection_scope
 with brain.connect() as db:
  where='scope=?';args=[collection_scope(brain,source_cfg)]
  if addresses is not None:where+=' AND ip IN (SELECT value FROM json_each(?))';args.append(json.dumps(addresses))
  return {r['ip']:r['revision'] for r in db.execute('SELECT ip,revision FROM source_sample_ready WHERE '+where+' ORDER BY revision,ip LIMIT ?',args+[max(1,min(100,limit))])}

def indexed(brain,address,revision,source_cfg=None):
 from evidence_history import collection_scope
 with brain.connect() as db:db.execute('DELETE FROM source_sample_ready WHERE ip=? AND scope=? AND revision=?',(address,collection_scope(brain,source_cfg),revision))
