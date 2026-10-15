"""One-year native observations, effective block history and returning-IP policy."""
import datetime as dt,json,threading,time,ipaddress,bisect,pathlib
UTC=dt.timezone.utc
WINDOWS=(30,60,90,180,365)
SOURCES={'tpot','owapot','nginx','waf','crowdsec','wazuh'}

def returned(d,address,source,sensor,seen):
 if source not in SOURCES|{'palo'}:return False
 prior=d.execute('SELECT * FROM offender_blocks WHERE ip=?',(address,)).fetchone()
 if not prior or seen<=prior['first_blocked'] or seen<=prior['last_native_seen']:return False
 event=dt.datetime.fromisoformat(seen);last=dt.datetime.fromisoformat(prior['last_native_seen'])
 if event-last>dt.timedelta(days=365):return False
 bonus=25 if event-last>=dt.timedelta(days=30) else 0
 inserted=d.execute('INSERT OR IGNORE INTO offender_returns VALUES(?,?,?,?,?,?,?)',(address,source,sensor,seen,prior['previous_score'],bonus,int(source!='palo')))
 if inserted.rowcount:
  d.execute("INSERT INTO ips(ip,first_seen,last_seen) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET last_seen=max(last_seen,excluded.last_seen)",(address,seen,seen))
  d.execute('UPDATE block_retention SET last_seen=?,expires=?,last_source=? WHERE ip=? AND last_seen<?',(seen,(event+dt.timedelta(days=30)).isoformat(timespec='seconds'),source,address,seen))
 return bool(inserted.rowcount)

def contains(nets):
 indexes={4:([],[]),6:([],[])}
 for version in indexes:
  ordered=sorted(ipaddress.collapse_addresses(n for n in nets if n.version==version),key=lambda n:int(n.network_address))
  indexes[version]=([int(n.network_address) for n in ordered],[int(n.broadcast_address) for n in ordered])
 def matches(address):
  a=ipaddress.ip_address(address);starts,ends=indexes[a.version];i=bisect.bisect_right(starts,int(a))-1
  return i>=0 and int(a)<=ends[i]
 return matches

def mark_blocks(store,scores,nets,created):
 matches=contains(nets);rows=[]
 with store.connect() as d:
  latest={r['ip']:r['seen'] for r in d.execute('SELECT ip,max(seen) seen FROM source_activity GROUP BY ip')}
  for row in scores:
   if not matches(row['ip']):continue
   native=max([e['seen'] for e in row['evidence']]+[latest.get(row['ip'],''),(row.get('prior_return') or {}).get('seen',''),(row.get('retention') or {}).get('last_seen','')],default='') or created
   rows.append((row['ip'],created,created,native,max(75,row['score'])))
  # Remember exact manual selectors even if no native observation exists yet.
  known={r[0] for r in rows}
  for n in nets:
   if n.num_addresses==1 and str(n.network_address) not in known:rows.append((str(n.network_address),created,created,created,100))
  d.executemany('INSERT INTO offender_blocks VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET last_blocked=excluded.last_blocked,last_native_seen=max(offender_blocks.last_native_seen,excluded.last_native_seen),previous_score=excluded.previous_score WHERE excluded.last_native_seen>offender_blocks.last_native_seen OR excluded.previous_score!=offender_blocks.previous_score',rows)

def backfill_published(store,output):
 """One-time bounded recovery from verified, complete local EDL generations."""
 if store.state('offender_block_backfill'):return
 cutoff=(dt.datetime.now(UTC)-dt.timedelta(days=365)).isoformat(timespec='seconds');first={};last={};scanned=0;groups={};validated={}
 with store.connect(commit=False) as d:
  observed=[r['ip'] for r in d.execute('SELECT ip FROM ips')]
  latest={r['ip']:r['seen'] for r in d.execute('SELECT ip,max(seen) seen FROM evidence GROUP BY ip')}
  for r in d.execute('SELECT ip,max(seen) seen FROM source_activity GROUP BY ip'):latest[r['ip']]=max(latest.get(r['ip'],''),r['seen'])
  scores={r['ip']:r['score'] for r in d.execute('SELECT ip,score FROM block_retention')}
 for directory in pathlib.Path(output).glob('generation-*'):
  if scanned>=10000:raise RuntimeError('Block history migration volume guard')
  try:
   m=json.loads((directory/'manifest.json').read_text());created=m['created']
   if created<cutoff:continue
   data=(directory/'combined-block.txt').read_bytes()
   import hashlib
   if hashlib.sha256(data).hexdigest()!=m['sha256']['combined-block']:continue
   lines=data.decode().splitlines()
   if len(lines)!=m['counts']['combined-block']:continue
   digest=m['sha256']['combined-block']
   if digest in groups:
    group=groups[digest];group['first']=min(group['first'],created);group['last']=max(group['last'],created);scanned+=1;continue
   from core import network
   nets=[]
   for value in lines:
    if value not in validated:validated[value]=network(value)
    nets.append(validated[value])
   exact=[str(n.network_address) for n in nets if n.num_addresses==1];networks=[n for n in nets if n.num_addresses>1]
   matcher=contains(networks)
   addresses=exact+([a for a in observed if matcher(a)] if networks else [])
   ai_only=set(m.get('ai_scoring',{}).get('ai_only_ips',[]));addresses=[a for a in addresses if a not in ai_only]
   groups[digest]={'addresses':addresses,'first':created,'last':created}
   scanned+=1
  except (OSError,ValueError,KeyError,TypeError):continue
 for group in groups.values():
  for a in group['addresses']:
   first[a]=min(first.get(a,group['first']),group['first']);last[a]=max(last.get(a,group['last']),group['last'])
 with store.connect() as d:
  d.executemany('INSERT OR IGNORE INTO offender_blocks VALUES(?,?,?,?,?)',[(a,first[a],last[a],max(latest.get(a,''),first[a]),scores.get(a,75)) for a in first])
  # Recovery is reporting-only: it cannot retroactively add score or extend TTL.
  d.execute('INSERT OR IGNORE INTO offender_returns SELECT DISTINCT e.ip,e.source,e.sensor,e.seen,b.previous_score,0,0 FROM evidence e JOIN offender_blocks b ON b.ip=e.ip WHERE e.seen>b.first_blocked AND e.seen>=? AND e.source IN (?,?,?,?,?,?)',(cutoff,*sorted(SOURCES)))
  d.execute('INSERT OR REPLACE INTO state VALUES(?,?)',('offender_block_backfill',json.dumps({'generations':scanned,'earliest_block':min(first.values(),default=None),'completed':dt.datetime.now(UTC).isoformat(timespec='seconds'),'coverage':'Only verified EDL membership and locally saved native returns; not proof of Palo enforcement'})))

def maintain(store):
 current=dt.datetime.now(UTC);cut=(current-dt.timedelta(days=365)).isoformat(timespec='seconds')
 with store.connect() as d:
  if not d.execute("SELECT 1 FROM state WHERE key='offender_history_tracking'").fetchone():
   oldest=d.execute('SELECT min(first_blocked) FROM offender_blocks').fetchone()[0]
   d.execute('INSERT INTO state VALUES(?,?)',('offender_history_tracking',json.dumps({'started':current.isoformat(timespec='seconds'),'backfill_earliest':oldest,'backfill':'verified block membership and saved native returns only; incomplete historical coverage'})))
  d.execute('DELETE FROM offender_returns WHERE seen<?',(cut,))
  d.execute('DELETE FROM offender_blocks WHERE last_blocked<?',(cut,))

class Reports:
 def __init__(self,store):self.store=store;self.lock=threading.Lock();self.until=0;self.data=None
 def snapshot(self):
  with self.lock:
   if self.until>time.monotonic():return self.data
   self.data=self.compute();self.until=time.monotonic()+15
   return self.data
 def compute(self,at=None):
  at=at or dt.datetime.now(UTC);end=at.isoformat(timespec='seconds');cut=(at-dt.timedelta(days=365)).isoformat(timespec='seconds')
  month=at.replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat(timespec='seconds')
  by_ip={};daily={}
  with self.store.connect(commit=False) as d:
   d.execute('BEGIN')
   rows=d.execute('SELECT ip,substr(seen,1,10) day,min(seen) first,max(seen) last,count(*) observations FROM offender_returns WHERE seen>=? AND seen<=? GROUP BY ip,substr(seen,1,10) ORDER BY ip,day',(cut,end)).fetchall()
   owners={r['ip']:json.loads(r['metadata']) for r in d.execute('SELECT ip,metadata FROM ips')}
   tracking=d.execute("SELECT value FROM state WHERE key='offender_history_tracking'").fetchone();tracking=json.loads(tracking[0]) if tracking else {}
   fences={n:(at-dt.timedelta(days=n)).isoformat(timespec='seconds') for n in WINDOWS}
   # Exact rolling boundaries; a partial first UTC day remains partial.
   window_rows={n:{r['ip']:{'active_days':r['days'],'observations':r['observations']} for r in d.execute('SELECT ip,count(distinct substr(seen,1,10)) days,count(*) observations FROM offender_returns WHERE seen>=? AND seen<=? GROUP BY ip',(fence,end))} for n,fence in fences.items()}
   months={r['ip']:{'active_days':r['days'],'observations':r['observations']} for r in d.execute('SELECT ip,count(distinct substr(seen,1,10)) days,count(*) observations FROM offender_returns WHERE seen>=? AND seen<=? GROUP BY ip',(month,end))}
   source_rows=d.execute('SELECT ip,source,sensor FROM offender_returns WHERE seen>=? AND seen<=? GROUP BY ip,source,sensor',(cut,end)).fetchall()
   blocks=[dict(r) for r in d.execute('SELECT * FROM offender_blocks WHERE last_blocked>=?',(cut,))]
  for b in blocks:
   by_ip[b['ip']]={'ip':b['ip'],'first_seen':b['first_blocked'],'last_seen':b['last_native_seen'],'active_days':0,'observations':0,'sources':[],'organization':owners.get(b['ip'],{}).get('organization',''),'asn':str(owners.get(b['ip'],{}).get('asn','')),'previous_score':b['previous_score'],'first_blocked':b['first_blocked'],'last_blocked':b['last_blocked']}
  sources={}
  for r in source_rows:sources.setdefault(r['ip'],[]).append({'source':r['source'],'sensor':r['sensor']})
  for r in rows:
   p=by_ip.setdefault(r['ip'],{'ip':r['ip'],'first_seen':r['first'],'last_seen':r['last'],'active_days':0,'observations':0,'sources':[],'organization':owners.get(r['ip'],{}).get('organization',''),'asn':str(owners.get(r['ip'],{}).get('asn',''))});p['sources']=sources.get(r['ip'],[])
   p['last_seen']=max(p['last_seen'],r['last']);p['active_days']+=1;p['observations']+=r['observations']
   daily.setdefault(r['day'],{'day':r['day'],'ips':0,'observations':0});daily[r['day']]['ips']+=1;daily[r['day']]['observations']+=r['observations']
  counts={str(n):0 for n in WINDOWS}
  for address,p in by_ip.items():
   p['windows']={str(n):{**window_rows[n].get(address,{'active_days':0,'observations':0}),'repeat':window_rows[n].get(address,{}).get('observations',0)>=1} for n in WINDOWS}
   p['repeat_windows']=[n for n in WINDOWS if p['windows'][str(n)]['repeat']]
   p['repeat_labels']=['1 year' if n==365 else str(n)+' days' for n in p['repeat_windows']]
   p['repeat_offender']=bool(p['repeat_windows']);p['month']=months.get(address,{'active_days':0,'observations':0})
   for n in p['repeat_windows']:counts[str(n)]+=1
  leaders=sorted((p for p in by_ip.values() if p['month']['observations']),key=lambda p:(-p['month']['observations'],-p['month']['active_days'],p['ip']))
  recovery=self.store.state('offender_block_backfill') or {}
  return {'generated':end,'definition':'Previously present in the effective combined-block EDL, then observed returning. Deduplicated saved return observations; not exact attack totals or proof of Palo enforcement. Palo block hits count as returns only for known blocks and do not create a new block.','windows':list(WINDOWS),'repeat_counts':counts,'top_month':({'ip':leaders[0]['ip'],**leaders[0]['month']} if leaders else None),'month_start':month,'coverage':{'tracking_started':tracking.get('started'),'earliest_observed':min((p['first_seen'] for p in by_ip.values()),default=None),'backfill':recovery.get('coverage','No block-history recovery yet'),'window_complete':{str(n):bool(tracking.get('started') and tracking['started']<=fences[n]) for n in WINDOWS}},'ips':by_ip,'daily':sorted(daily.values(),key=lambda r:r['day'])}
 def decorate(self,rows,include_historical=True):
  report=self.snapshot();found=set();result=[]
  for row in rows:
   h=report['ips'].get(row['ip']);found.add(row['ip'])
   result.append({**row,'history_only':False,'repeat_history':h,'repeat_windows':h['repeat_windows'] if h else [],'repeat_text':text(h)})
  if include_historical:
   for address,h in report['ips'].items():
    if address in found:continue
    result.append({'ip':address,'asn':h['asn'],'organization':h['organization'],'sources':sorted({s['source'] for s in h['sources']}),'source_labels':sorted({s['source'] for s in h['sources']}),'source_details':[],'ports':[],'source_count':len({s['source'] for s in h['sources']}),'honeypot_count':0,'client_types':['Unknown'],'score':0,'auto_candidate':False,'verified_crawler':False,'enrichment_text':'Historical observation','enrichment_details':[],'enrichment_sources':[],'source_identity':{},'retention':None,'history_only':True,'repeat_history':h,'repeat_windows':h['repeat_windows'],'repeat_text':text(h)})
  return result

def text(h):
 if not h:return 'No recorded repeat activity'
 return ('Repeat offender: '+', '.join('1 year' if n==365 else str(n)+' days' for n in h['repeat_windows'])) if h['repeat_windows'] else 'Not a repeat offender'
