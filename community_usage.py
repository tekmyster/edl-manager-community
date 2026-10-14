"""Local compliance reporting; never changes detection, scoring or enforcement."""
import datetime as dt,threading,time
from core import ip

def usage(store,at=None):
 at=at or dt.datetime.now(dt.timezone.utc);today=at.date();start=today-dt.timedelta(days=29);month=today.replace(day=1)
 with store.connect() as db:
  db.execute('CREATE TABLE IF NOT EXISTS community_daily_usage(day TEXT PRIMARY KEY,ips INTEGER NOT NULL)')
  observed={}
  for row in db.execute('SELECT ip,substr(seen,1,10) day FROM ip_observations WHERE seen>=? AND seen<=? GROUP BY ip,day',(min(start,month).isoformat(),at.isoformat(timespec='seconds'))):
   try:ip(row['ip'])
   except ValueError:continue
   observed[row['day']]=observed.get(row['day'],0)+1
  for day,count in observed.items():db.execute('INSERT INTO community_daily_usage VALUES(?,?) ON CONFLICT(day) DO UPDATE SET ips=max(ips,excluded.ips)',(day,count))
  counts={row['day']:row['ips'] for row in db.execute('SELECT * FROM community_daily_usage WHERE day>=? AND day<=?',(min(start,month).isoformat(),today.isoformat()))}
 total=sum(count for day,count in counts.items() if day>=start.isoformat())
 bursts=sum(count>500 for day,count in counts.items() if day>=month.isoformat())
 peak=max(counts.values(),default=0);profile=store.state('community_use_class') or 'homelab'
 reasons=[]
 if profile not in ('homelab','nonprofit'):reasons.append('Enterprise use')
 if total>15000:reasons.append('30-day average exceeds 500')
 if bursts>1:reasons.append('More than one peak day this month')
 if peak>1000:reasons.append('Daily usage exceeds 1,000')
 return {'today':counts.get(today.isoformat(),0),'average':round(total/30,1),'total':total,'burst_days':bursts,'peak':peak,'use_class':profile,'license_required':bool(reasons),'reasons':reasons,'daily':counts,'window_start':start.isoformat()}


def snapshot(store):
 if not hasattr(store,'_community_usage_lock'):store._community_usage_lock=threading.Lock()
 with store._community_usage_lock:
  if getattr(store,'_community_usage_until',0)<=time.monotonic():
   store._community_usage_snapshot=usage(store);store._community_usage_until=time.monotonic()+15
  return store._community_usage_snapshot
