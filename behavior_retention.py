"""Incremental derived-data retention. Never opens or prunes the native database.

Reviews, group history, explicit investigation holds and their packets are permanent.
Current packets and live/retained assessment citations remain resolvable. Deletion
waits for a restartable reference-index backfill; transactions include sweep cursors.
"""
import datetime as dt,json,time

DEFAULTS={'packet_retention_days':90,'assessment_retention_days':90,'metrics_retention_days':90,'cleanup_batch':100}
SCHEMA='''
CREATE TABLE IF NOT EXISTS retention_refs(kind TEXT NOT NULL,owner TEXT NOT NULL,packet_id TEXT NOT NULL,PRIMARY KEY(kind,owner,packet_id));
CREATE INDEX IF NOT EXISTS retention_refs_packet ON retention_refs(packet_id,kind);
CREATE TABLE IF NOT EXISTS retention_holds(kind TEXT NOT NULL,target TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(kind,target));
CREATE TABLE IF NOT EXISTS retention_state(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS packets_retention ON packets(created,id);
CREATE INDEX IF NOT EXISTS current_packets_packet ON current_packets(packet_id);
CREATE TABLE IF NOT EXISTS analysis_queue(ip TEXT PRIMARY KEY,packet_id TEXT NOT NULL,queued TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS analysis_queue_age ON analysis_queue(queued,ip);
CREATE INDEX IF NOT EXISTS analysis_queue_packet ON analysis_queue(packet_id);
CREATE TABLE IF NOT EXISTS queue_samples(id INTEGER PRIMARY KEY,created TEXT NOT NULL,wait_seconds REAL NOT NULL,status TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS queue_samples_created ON queue_samples(created);
CREATE INDEX IF NOT EXISTS assessments_retention ON assessments(created,id);
CREATE INDEX IF NOT EXISTS links_retention ON links(created,id);
CREATE INDEX IF NOT EXISTS links_right ON links(right_packet);
CREATE INDEX IF NOT EXISTS reviews_target ON reviews(target);
CREATE INDEX IF NOT EXISTS correlation_features_packet ON correlation_features(packet_id);
CREATE INDEX IF NOT EXISTS jobs_retention ON jobs(updated,id);
CREATE INDEX IF NOT EXISTS jobs_packet ON jobs(packet_id);
CREATE INDEX IF NOT EXISTS publication_samples_retention ON publication_samples(created);
CREATE INDEX IF NOT EXISTS event_history_retention ON event_history(seen);
CREATE TRIGGER IF NOT EXISTS retention_assessment_insert AFTER INSERT ON assessments BEGIN
 INSERT OR IGNORE INTO retention_refs SELECT 'assessment',NEW.id,NEW.packet_id;
 INSERT OR IGNORE INTO retention_refs SELECT 'assessment',NEW.id,p.id FROM json_tree(NEW.result) j JOIN packets p ON p.id=j.value WHERE j.type='text';
END;
CREATE TRIGGER IF NOT EXISTS retention_assessment_delete AFTER DELETE ON assessments BEGIN
 DELETE FROM retention_refs WHERE kind='assessment' AND owner=OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS retention_revision_insert AFTER INSERT ON behavior_group_revisions BEGIN
 INSERT OR IGNORE INTO retention_refs SELECT 'revision',NEW.id,value FROM json_each(NEW.members);
END;
'''

def initialize(db):db.executescript(SCHEMA)

def hold(brain,kind,target,reason):
 """Pin a saved investigation URL before its retention deadline; never resurrects data."""
 tables={'packet':'packets','assessment':'assessments','link':'links'}
 if kind not in tables or not reason.strip() or len(reason)>500:raise ValueError('Choose an investigation item and a reason of up to 500 characters.')
 with brain.connect() as db:
  db.execute('BEGIN IMMEDIATE')
  if not db.execute('SELECT 1 FROM '+tables[kind]+' WHERE id=?',(target,)).fetchone():raise ValueError('Investigation item not found.')
  db.execute('INSERT OR REPLACE INTO retention_holds VALUES(?,?,?)',(kind,target,reason.strip()))

def backfill(db,limit):
 # Immutable legacy rows only; concurrent new inserts are covered by triggers.
 for table,kind in (('assessments','assessment'),('behavior_group_revisions','revision')):
  key='backfill_'+table;state=db.execute('SELECT value FROM retention_state WHERE name=?',(key,)).fetchone()
  if state and state[0]=='done':continue
  cursor=int(state[0]) if state else 0
  rows=db.execute('SELECT rowid,* FROM '+table+' WHERE rowid>? ORDER BY rowid LIMIT ?',(cursor,limit)).fetchall()
  for row in rows:
   if kind=='assessment':
    db.execute('INSERT OR IGNORE INTO retention_refs VALUES(?,?,?)',(kind,row['id'],row['packet_id']))
    db.execute("INSERT OR IGNORE INTO retention_refs SELECT 'assessment',?,p.id FROM json_tree(?) j JOIN packets p ON p.id=j.value WHERE j.type='text'",(row['id'],row['result']))
   else:db.execute("INSERT OR IGNORE INTO retention_refs SELECT 'revision',?,value FROM json_each(?)",(row['id'],row['members']))
  db.execute('INSERT OR REPLACE INTO retention_state VALUES(?,?)',(key,str(rows[-1]['rowid']) if len(rows)==limit else 'done'))
  return False
 return True

def pinned(db,ident,assessment_refs=True):
 return bool(db.execute("SELECT 1 FROM retention_refs WHERE packet_id=? AND (? OR kind!='assessment') LIMIT 1",(ident,int(assessment_refs))).fetchone() or
  db.execute("SELECT 1 FROM retention_holds WHERE kind='packet' AND target=?",(ident,)).fetchone() or
  db.execute('SELECT 1 FROM behavior_group_members WHERE packet_id=? LIMIT 1',(ident,)).fetchone() or
  db.execute("SELECT 1 FROM links l WHERE (left_packet=? OR right_packet=?) AND (state!='proposed' OR EXISTS(SELECT 1 FROM reviews WHERE target=l.id) OR EXISTS(SELECT 1 FROM retention_holds WHERE kind='link' AND target=l.id)) LIMIT 1",(ident,ident)).fetchone())

def cleanup(brain,cfg,at=None):
 at=at or dt.datetime.now(dt.timezone.utc);started=time.monotonic();limit=max(1,min(500,int(cfg.get('cleanup_batch',100))))
 result={'scanned':{},'deleted':{},'reference_index_ready':False}
 with brain.connect() as db:
  db.execute('PRAGMA busy_timeout=1000');db.execute('BEGIN IMMEDIATE')
  if not backfill(db,limit):return result
  result['reference_index_ready']=True
  for table,column,days in (('assessments','created','assessment_retention_days'),('links','created','packet_retention_days'),('jobs','updated','assessment_retention_days'),('packets','created','packet_retention_days')):
   cut=(at-dt.timedelta(days=int(cfg.get(days,DEFAULTS[days])))).isoformat(timespec='seconds')
   key='sweep_'+table;state=db.execute('SELECT value FROM retention_state WHERE name=?',(key,)).fetchone();cursor=json.loads(state[0]) if state else ['', '']
   rows=db.execute('SELECT * FROM '+table+' WHERE '+column+'<? AND ('+column+',id)>(?,?) ORDER BY '+column+',id LIMIT ?',(cut,*cursor,limit)).fetchall()
   deleted=0
   for row in rows:
    ident=row['id']
    kind={'packets':'packet','assessments':'assessment','links':'link','jobs':'job'}[table]
    if db.execute('SELECT 1 FROM retention_holds WHERE kind=? AND target=?',(kind,ident)).fetchone():continue
    if table=='assessments':
     if row['expires']>=at.isoformat() or pinned(db,row['packet_id'],False):continue
    elif table=='links':
     if row['state']!='proposed' or db.execute('SELECT 1 FROM reviews WHERE target=?',(ident,)).fetchone():continue
     # A retained assessment or group pins both the packet and its relationship evidence.
     if pinned(db,row['left_packet']) or pinned(db,row['right_packet']):continue
     db.execute('DELETE FROM correlation_link_evidence WHERE link_id=?',(ident,))
    elif table=='jobs':
     if row['lease']>at.timestamp():continue
    else:
     if pinned(db,ident) or db.execute('SELECT 1 FROM current_packets WHERE packet_id=?',(ident,)).fetchone():continue
     if db.execute('SELECT 1 FROM analysis_queue WHERE packet_id=? LIMIT 1',(ident,)).fetchone():continue
     if db.execute('SELECT 1 FROM assessments WHERE packet_id=? LIMIT 1',(ident,)).fetchone() or db.execute('SELECT 1 FROM jobs WHERE packet_id=? LIMIT 1',(ident,)).fetchone():continue
     if db.execute('SELECT 1 FROM links WHERE left_packet=? OR right_packet=? LIMIT 1',(ident,ident)).fetchone():continue
     for child in ('packet_feature_index','packet_feature_ready','correlation_features','correlation_ready','correlation_runs'):
      db.execute('DELETE FROM '+child+' WHERE packet_id=?',(ident,))
    db.execute('DELETE FROM '+table+' WHERE id=?',(ident,));deleted+=1
   result['scanned'][table]=len(rows);result['deleted'][table]=deleted
   db.execute('INSERT OR REPLACE INTO retention_state VALUES(?,?)',(key,json.dumps([rows[-1][column],rows[-1]['id']] if len(rows)==limit else ['', ''])))
  cut=(at-dt.timedelta(days=int(cfg.get('metrics_retention_days',90)))).isoformat(timespec='seconds')
  # Request usage for today is never removed, even with unusual clock/configuration.
  for table,column in (('analysis_counters','hour'),('publication_samples','created'),('usage','day'),('queue_samples','created')):
   end=min(cut,at.date().isoformat())
   count=db.execute('DELETE FROM '+table+' WHERE rowid IN (SELECT rowid FROM '+table+' WHERE '+column+'<? ORDER BY '+column+' LIMIT ?)',(end,limit)).rowcount
   result['deleted'][table]=count
 result['seconds']=round(time.monotonic()-started,4)
 return result
