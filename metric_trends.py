"""Recorded tile snapshots, collected independently of list publication."""
import datetime as dt,json,pathlib
UTC=dt.timezone.utc
KEYS=('new','total','candidate','crawler','policy','blacklisted','repeat')

def initialize(store):
 with store.connect() as d:
  d.execute('CREATE TABLE IF NOT EXISTS metric_snapshots(metric TEXT NOT NULL,bucket TEXT NOT NULL,at TEXT NOT NULL,value INTEGER NOT NULL,PRIMARY KEY(metric,bucket))')
  d.execute('CREATE INDEX IF NOT EXISTS metric_snapshot_time ON metric_snapshots(at)')

def values(rows,rules,report,new_count,observed_count):
 return {'new':new_count,'total':observed_count,'candidate':sum(bool(r['auto_candidate']) for r in rows),'crawler':sum(bool(r['verified_crawler']) for r in rows),'policy':len(rules),'blacklisted':sum(r['action']=='block' for r in rules),'repeat':report['repeat_counts']['30']}

def record(store,counts,at=None):
 at=at or dt.datetime.now(UTC);at=at.astimezone(UTC)
 stamp=at.isoformat(timespec='seconds');bucket=at.replace(minute=at.minute//5*5,second=0,microsecond=0).isoformat(timespec='seconds')
 with store.connect() as d:
  d.executemany('INSERT INTO metric_snapshots VALUES(?,?,?,?) ON CONFLICT(metric,bucket) DO UPDATE SET at=excluded.at,value=excluded.value WHERE excluded.at>=metric_snapshots.at',[(k,bucket,stamp,int(counts[k])) for k in KEYS])
  d.execute('DELETE FROM metric_snapshots WHERE at<?',((at-dt.timedelta(days=366)).isoformat(timespec='seconds'),))

def hourly_arrivals(arrivals):
 end=dt.datetime.fromisoformat(arrivals['generated']);start=dt.datetime.fromisoformat(arrivals['since'])
 counts=[0]*24
 for row in arrivals['rows']:
  seen=dt.datetime.fromisoformat(row['new_seen'])
  if start<=seen<=end:counts[min(23,int((seen-start).total_seconds()//3600))]+=1
 maximum=max(counts,default=0);scale=maximum or 1
 points=[]
 for i,count in enumerate(counts):
  points.append({'x':round(8+i*224/23,2),'y':round(40-count*32/scale,2),'value':count,'start':(start+dt.timedelta(hours=i)).isoformat(),'end':(start+dt.timedelta(hours=i+1)).isoformat()})
 return {'hourly':True,'points':points,'path':' '.join(f"{p['x']},{p['y']}" for p in points),'maximum':maximum,'total':sum(counts),'first':start.isoformat(),'last':end.isoformat()}

def interval_chart(counts,start,end,kind,caption):
 maximum=max((v for v in counts if v is not None),default=0);minimum=min((v for v in counts if v is not None),default=0)
 low=0 if kind=='bars' else minimum;scale=(maximum-low) or 1;n=len(counts);width=224/n
 points=[];segments=[];segment=[];previous=None
 for i,value in enumerate(counts):
  left=start+(end-start)*i/n;right=start+(end-start)*(i+1)/n
  if value is None:
   if segment:segments.append(' '.join(segment));segment=[]
   previous=None;continue
  x=8+width*(i+(.5 if kind=='bars' else 1));y=42-(value-low)*32/scale
  p={'x':round(x,2),'y':round(y,2),'height':round(42-y,2),'bar_x':round(x-width*.36,2),'width':round(width*.72,2),'value':value,'start':left.isoformat(),'end':right.isoformat()};points.append(p)
  if kind=='steps':
   if previous:segment.append(f"{p['x']},{previous['y']}")
   segment.append(f"{p['x']},{p['y']}");previous=p
 if segment:segments.append(' '.join(segment))
 return {'intervals':True,'kind':kind,'points':points,'segments':segments,'caption':caption,'maximum':maximum,'minimum':minimum,'bin_count':n,'first':start.isoformat(),'last':end.isoformat(),'axis_start':'24h ago' if n==24 and end-start==dt.timedelta(hours=24) else 'Month start' if caption=='Returns per day' else '30d ago','axis_end':'Now','total':sum(v for v in counts if v is not None)}

def trends(store,current,report,at=None,new_report=None):
 at=at or dt.datetime.now(UTC);cut=at-dt.timedelta(days=30);series={k:[] for k in KEYS}
 with store.connect(commit=False) as d:
  for r in d.execute('SELECT metric,at,value FROM metric_snapshots WHERE at>=? ORDER BY at',(cut.isoformat(),)):
   if r['metric'] in series:series[r['metric']].append((r['at'],r['value']))
  repeat_end=dt.datetime.fromisoformat(report.get('generated',at.isoformat()));repeat_start=repeat_end-dt.timedelta(days=30)
  repeat_rows=[dict(r) for r in d.execute('SELECT ip,seen FROM offender_returns WHERE seen>=? AND seen<=?',(repeat_start.isoformat(),repeat_end.isoformat()))]
  tracking=d.execute("SELECT value FROM state WHERE key='offender_history_tracking'").fetchone();tracking=json.loads(tracking[0]) if tracking else {}
  leader=report.get('top_month');monthly=[]
  if leader:monthly=[r['seen'] for r in d.execute('SELECT seen FROM offender_returns WHERE ip=? AND seen>=? AND seen<=?',(leader['ip'],report['month_start'],repeat_end.isoformat()))]
 if new_report is None:
  from new_ips import Reports as Arrivals
  new_report=Arrivals(store).snapshot()
 hourly=hourly_arrivals(new_report)
 result={'new':interval_chart([p['value'] for p in hourly['points']],dt.datetime.fromisoformat(hourly['first']),dt.datetime.fromisoformat(hourly['last']),'bars','New IPs per hour')}
 for key in ('total','candidate','crawler','policy','blacklisted'):
  counts=[None]*30
  for stamp,value in series[key]+[(at.isoformat(),current[key])]:
   seen=dt.datetime.fromisoformat(stamp)
   if cut<=seen<=at:counts[min(29,int((seen-cut).total_seconds()//86400))]=value
  graph=interval_chart(counts,cut,at,'steps','Daily recorded totals')
  graph['delta']=current[key]-series[key][0][1] if series[key] else None
  graph['delta_since']=series[key][0][0] if series[key] else None
  graph['show_delta']=len(graph['points'])<2
  result[key]=graph
 # Repeat IPs are distinct within each day; the same IP can appear on several days.
 sets=[set() for _ in range(30)]
 for row in repeat_rows:
  seen=dt.datetime.fromisoformat(row['seen'])
  if repeat_start<=seen<=repeat_end:sets[min(29,int((seen-repeat_start).total_seconds()//86400))].add(row['ip'])
 began=dt.datetime.fromisoformat(tracking['started']) if tracking.get('started') else repeat_end
 counts=[len(group) if group or repeat_start+dt.timedelta(days=i)>=began else None for i,group in enumerate(sets)]
 result['repeat']=interval_chart(counts,repeat_start,repeat_end,'bars','Repeat IPs per day')
 month=dt.datetime.fromisoformat(report.get('month_start',repeat_end.replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat()))
 days=max(1,(repeat_end.date()-month.date()).days+1);counts=[0]*days
 for stamp in monthly:
  i=(dt.datetime.fromisoformat(stamp).date()-month.date()).days
  if 0<=i<days:counts[i]+=1
 counts=[v if v or month+dt.timedelta(days=i)>=began else None for i,v in enumerate(counts)]
 # Calendar days, with the current day's interval explicitly ending now.
 graph=interval_chart(counts,month,month+dt.timedelta(days=days),'bars','Returns per day')
 graph['last']=repeat_end.isoformat();graph['axis_end']='Today'
 for p in graph['points']:
  if dt.datetime.fromisoformat(p['end'])>repeat_end:p['end']=repeat_end.isoformat()
 result['top-month']=graph
 return result

def collect(cfg):
 from core import Store
 from offenders import Reports
 from new_ips import Reports as Arrivals
 store=Store(cfg['database']);initialize(store);reports=Reports(store)
 path=(pathlib.Path(cfg['output'])/'current').resolve()/'dashboard.json'
 try:
  if dt.datetime.now(UTC).timestamp()-path.stat().st_mtime>600:raise ValueError('Stale display snapshot')
  rows=json.loads(path.read_text())['rows']
 except (OSError,ValueError,KeyError):rows=store.all_scores()
 rows=reports.decorate(rows);observed_count=len(rows);known={r['ip'] for r in rows};rules=store.active_rules()
 rows+=reports.decorate([store.describe(value) for value in dict.fromkeys(r['value'] for r in rules if r['kind']=='ip' and r['value'] not in known)],include_historical=False)
 counts=values(rows,rules,reports.snapshot(),Arrivals(store).snapshot()['count'],observed_count)
 record(store,counts);return counts

if __name__=='__main__':
 import os
 collect(json.loads(pathlib.Path(os.environ.get('EDL_CONFIG','/etc/edl-manager/config.json')).read_text()))
