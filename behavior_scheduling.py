"""Indexed bounded queue pools. Candidate order is not inference or latency evidence."""
import datetime as dt,json

REFRESH='''INSERT INTO queue_priority
 SELECT q.ip,p.id,coalesce(s.richness,0),coalesce(s.last_seen,''),q.queued,coalesce(s.fingerprint,'')
 FROM analysis_queue q LEFT JOIN current_packets c ON c.ip=q.ip
 JOIN packets p ON p.id=coalesce(c.packet_id,q.packet_id)
 LEFT JOIN packet_scheduling s ON s.packet_id=p.id WHERE q.ip={address}
 ON CONFLICT(ip) DO UPDATE SET packet_id=excluded.packet_id,richness=excluded.richness,last_seen=excluded.last_seen,queued=excluded.queued,fingerprint=excluded.fingerprint;'''
SCHEMA='''
CREATE TABLE IF NOT EXISTS packet_scheduling(packet_id TEXT PRIMARY KEY,richness INTEGER NOT NULL,last_seen TEXT NOT NULL,fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS queue_priority(ip TEXT PRIMARY KEY,packet_id TEXT NOT NULL,richness INTEGER NOT NULL,last_seen TEXT NOT NULL,queued TEXT NOT NULL,fingerprint TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS queue_priority_rich ON queue_priority(richness DESC,last_seen DESC,queued,ip);
CREATE INDEX IF NOT EXISTS queue_priority_recent ON queue_priority(last_seen DESC,richness DESC,queued,ip);
CREATE TRIGGER IF NOT EXISTS queue_priority_delete AFTER DELETE ON analysis_queue BEGIN DELETE FROM queue_priority WHERE ip=OLD.ip; END;
CREATE TRIGGER IF NOT EXISTS packet_scheduling_delete AFTER DELETE ON packets BEGIN DELETE FROM packet_scheduling WHERE packet_id=OLD.id; END;
'''
for table,operations,address in [('analysis_queue',('INSERT','UPDATE'), 'NEW.ip'),('current_packets',('INSERT','UPDATE'),'NEW.ip'),('packet_scheduling',('INSERT','UPDATE'),'(SELECT ip FROM packets WHERE id=NEW.packet_id)')]:
 for operation in operations:
  SCHEMA+='CREATE TRIGGER IF NOT EXISTS schedule_'+table+'_'+operation.lower()+' AFTER '+operation+' ON '+table+' BEGIN '+REFRESH.format(address=address)+' END;\n'

def index(db,ident):
 if db.execute('SELECT 1 FROM packet_scheduling WHERE packet_id=?',(ident,)).fetchone():return
 row=db.execute('SELECT content FROM packets WHERE id=?',(ident,)).fetchone()
 if not row:return
 from behavior_intelligence import profile
 p=profile(json.loads(row[0]));rich=min(4,len(p['paths']))+min(2,len(p['actions']))
 last=max((e['seen'] for e in p['events']),default='')
 db.execute('INSERT OR IGNORE INTO packet_scheduling VALUES(?,?,?,?)',(ident,rich,last,p['fingerprint']))

def backfill(brain,limit=200):
 """Restartable rowid page; reads at most 200 packet contents per pass."""
 with brain.connect() as db:
  row=db.execute("SELECT value FROM retention_state WHERE name='schedule_cursor'").fetchone();cursor=int(row[0]) if row else 0
  rows=db.execute('SELECT rowid,id FROM packets WHERE rowid>? ORDER BY rowid LIMIT ?',(cursor,max(1,min(200,limit)))).fetchall()
  for row in rows:index(db,row['id'])
  if rows:cursor=rows[-1]['rowid']
  db.execute("INSERT OR REPLACE INTO retention_state VALUES('schedule_cursor',?)",(str(cursor),))
  partial=bool(db.execute('SELECT 1 FROM packets WHERE rowid>? LIMIT 1',(cursor,)).fetchone())
 return {'scanned':len(rows),'bound':200,'partial':partial}

def schedule(db,limit=100):
 """Oldest 100 + indexed richest 64 + indexed most-recent 64; at most 228 IDs.

 The first slot is oldest. Remaining age and priority slots alternate, so leased
 or cached candidates do not consume the sole fairness position. Actual jobs
 still enforce the unchanged leases, daily quota, retry and two-request caps.
 """
 age=[r[0] for r in db.execute('SELECT ip FROM analysis_queue ORDER BY queued,ip LIMIT 100')]
 rich=[r[0] for r in db.execute('SELECT ip FROM queue_priority INDEXED BY queue_priority_rich WHERE richness>0 ORDER BY richness DESC,last_seen DESC,queued,ip LIMIT 64')]
 recent=[r[0] for r in db.execute("SELECT ip FROM queue_priority INDEXED BY queue_priority_recent WHERE last_seen>'' ORDER BY last_seen DESC,richness DESC,queued,ip LIMIT 64")]
 pool=list(dict.fromkeys(age+rich+recent));rows={}
 for address in pool:
  row=db.execute('SELECT q.ip,q.queued,q.packet_id original_packet_id,p.id packet_id,p.content,p.features FROM analysis_queue q LEFT JOIN current_packets c ON c.ip=q.ip JOIN packets p ON p.id=coalesce(c.packet_id,q.packet_id) WHERE q.ip=?',(address,)).fetchone()
  if row:rows[address]=row
 if not rows or limit<=0:return []
 from behavior_intelligence import profile
 from behavior_ai import timestamp
 ranked=[]
 for address,row in rows.items():
  p=profile(json.loads(row['content']));last=max((timestamp(e['seen']) for e in p['events']),default=None)
  ranked.append((address,p['fingerprint'],min(4,len(p['paths']))+min(2,len(p['actions'])),bool(last and last>=dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=24))))
 ordered=[];seen=set();age=[a for a in age if a in rows]
 while ranked and len(ordered)<min(100,limit):
  remaining={r[0] for r in ranked};oldest=next((a for a in age if a in remaining),None)
  if len(ordered)%2==0 and oldest:best=next(i for i,r in enumerate(ranked) if r[0]==oldest)
  else:best=max(range(len(ranked)),key=lambda i:(ranked[i][1] not in seen,ranked[i][3],ranked[i][2],-i))
  address,fingerprint,_,_=ranked.pop(best);seen.add(fingerprint);ordered.append(rows[address])
 return ordered
