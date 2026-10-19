"""Rolling new arrivals from retained observations, independent of blocking policy."""
import datetime as dt,json,threading,time
UTC=dt.timezone.utc
SCHEMA="""
CREATE TABLE IF NOT EXISTS ip_observations(ip TEXT NOT NULL,seen TEXT NOT NULL,PRIMARY KEY(ip,seen));
CREATE INDEX IF NOT EXISTS ip_observations_time ON ip_observations(seen,ip);
"""
def initialize(store):
 with store.connect() as d:
  marker=d.execute("SELECT value FROM state WHERE key='new_ip_tracking'").fetchone()
  if marker and not d.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ip_observations'").fetchone():raise ValueError('Initialized arrival history is missing')
  d.executescript(SCHEMA)
  d.execute('SELECT ip,seen FROM ip_observations LIMIT 0')
  if [(r[1],r[5]) for r in d.execute('PRAGMA table_info(ip_observations)') if r[5]]!=[('ip',1),('seen',2)]:raise ValueError('Incompatible arrival primary key')
  if [r[2] for r in d.execute('PRAGMA index_info(ip_observations_time)')]!=['seen','ip']:raise ValueError('Incompatible arrival time index')
  marker=d.execute("SELECT value FROM state WHERE key='new_ip_tracking'").fetchone()
  if marker:
   value=json.loads(marker[0])
   if not isinstance(value,dict) or not value.get('started') or dt.datetime.fromisoformat(value['started']).tzinfo is None:raise ValueError('Invalid arrival migration marker')
   return
  d.execute("BEGIN IMMEDIATE")
  # Another initializer may have completed while this connection waited.
  marker=d.execute("SELECT value FROM state WHERE key='new_ip_tracking'").fetchone()
  if marker:
   value=json.loads(marker[0])
   if not isinstance(value,dict) or not value.get('started') or dt.datetime.fromisoformat(value['started']).tzinfo is None:raise ValueError('Invalid arrival migration marker')
   return
  current=dt.datetime.now(UTC);cut=(current-dt.timedelta(days=366)).isoformat(timespec='seconds')
  # This is the real legacy backfill, not recurring initialized maintenance.
  d.execute('DELETE FROM ip_observations WHERE seen<?',(cut,))
  for query in ('SELECT ip,seen FROM evidence','SELECT ip,seen FROM source_activity','SELECT ip,seen FROM offender_returns','SELECT ip,first_seen seen FROM ips','SELECT ip,last_seen seen FROM ips'):
   d.execute('INSERT OR IGNORE INTO ip_observations SELECT ip,seen FROM ('+query+') WHERE seen>=? AND seen<=?',(cut,current.isoformat(timespec='seconds')))
  oldest=d.execute('SELECT min(seen) FROM ip_observations').fetchone()[0]
  d.execute('INSERT INTO state VALUES(?,?)',('new_ip_tracking',json.dumps({'started':current.isoformat(timespec='seconds'),'earliest_retained':oldest})))

def maintain(store,at=None):
 cut=((at or dt.datetime.now(UTC))-dt.timedelta(days=366)).isoformat(timespec='seconds')
 with store.connect() as db:
  if not db.execute('SELECT 1 FROM ip_observations WHERE seen<? LIMIT 1',(cut,)).fetchone():return {'deleted':0,'partial':False,'bound':5000}
  db.execute('BEGIN IMMEDIATE')
  deleted=db.execute('DELETE FROM ip_observations WHERE rowid IN (SELECT rowid FROM ip_observations WHERE seen<? ORDER BY seen,ip LIMIT 5000)',(cut,)).rowcount
  partial=bool(db.execute('SELECT 1 FROM ip_observations WHERE seen<? LIMIT 1',(cut,)).fetchone())
 return {'deleted':deleted,'partial':partial,'bound':5000}
def record(d,address,seen):
 d.execute('INSERT OR IGNORE INTO ip_observations VALUES(?,?)',(address,seen))

class Reports:
 def __init__(self,store):self.store=store;self.lock=threading.Lock();self.until=0;self.data=None
 def snapshot(self):
  with self.lock:
   if self.until<=time.monotonic():self.data=self.compute();self.until=time.monotonic()+15
   return self.data
 def compute(self,at=None):
  at=at or dt.datetime.now(UTC);end=at.isoformat(timespec='seconds');start=(at-dt.timedelta(hours=24)).isoformat(timespec='seconds');cut=(at-dt.timedelta(days=366)).isoformat(timespec='seconds')
  with self.store.connect(commit=False) as d:
   rows=[dict(r) for r in d.execute("""WITH arrivals AS (SELECT ip,min(seen) new_seen,max(seen) last_seen FROM ip_observations WHERE seen>=? AND seen<=? GROUP BY ip)
    SELECT a.* FROM arrivals a WHERE NOT EXISTS(SELECT 1 FROM ip_observations p WHERE p.ip=a.ip AND p.seen>=? AND p.seen<a.new_seen AND julianday(p.seen)>=julianday(a.new_seen)-365) ORDER BY a.new_seen DESC,a.ip""",(start,end,cut))]
   tracking=d.execute("SELECT value FROM state WHERE key='new_ip_tracking'").fetchone();tracking=json.loads(tracking[0]) if tracking else {}
  from core import ip
  valid=[]
  for row in rows:
   try:ip(row['ip'])
   except ValueError:continue
   valid.append(row)
  return {'generated':end,'since':start,'count':len(valid),'lookback_days':365,'rows':valid,'coverage':{'tracking_started':tracking.get('started'),'earliest_retained':tracking.get('earliest_retained'),'year_complete':bool(tracking.get('started') and tracking['started']<=cut)},'definition':'Observed in the last 24 hours, with no earlier retained observation in the 365 days preceding that arrival. Available history only; absence is not proof when coverage is incomplete.'}
