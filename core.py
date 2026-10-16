"""Local policy, evidence, cache and reproducible EDL snapshots."""
import datetime as dt,hashlib,ipaddress,json,os,pathlib,sqlite3,uuid,contextlib,bisect,time
from filelock import FileLock,Timeout
UTC=dt.timezone.utc
BLOCK_THRESHOLD=75
HONEYPOT_FLOOR=50
HONEYPOT_REPEAT_BONUS=25
HONEYPOT_SOURCES={'tpot','owapot'}

def display_sources(row):
 labels={'asn':'ASN','misp':'MISP','palo':'Palo','crawler':'Crawler','abuseipdb':'AbuseIPDB','virustotal':'VirusTotal','greynoise':'GreyNoise'}
 payloads=row.get('cache',{});current=now()
 active={r['provider'] for r in row.get('cache_status',[]) if r['status']=='ok' and r['expires']>current}
 found={'asn':bool(payloads.get('asn',{}).get('asn')),'misp':payloads.get('misp',{}).get('matches',0)+payloads.get('misp',{}).get('context_matches',0)>0,'palo':payloads.get('palo',{}).get('alert_records',0)>0,'crawler':row.get('verified_crawler',False),'abuseipdb':payloads.get('abuseipdb',{}).get('totalReports',0)>0,'virustotal':payloads.get('virustotal',{}).get('last_analysis_stats',{}).get('malicious',0)>0,'greynoise':bool(payloads.get('greynoise'))}
 return [labels[p] for p in labels if found[p] and (p in active or p=='crawler' and row.get('verified_crawler'))]

def display_row(row):
 keys=('ip','asn','organization','sources','source_labels','source_details','ports','source_count','honeypot_count','client_types','score','native_score','ai_bump','ai_assessment_id','ai_expires','auto_candidate','verified_crawler','enrichment_text','enrichment_details','intelligence')
 return {**{k:row[k] for k in keys if k in row},'source_identity':{'clients':row.get('source_identity',{}).get('clients',[])},'enrichment_sources':display_sources(row),'retention':({k:row['retention'][k] for k in ('expires','last_seen','last_source')} if row.get('retention') else None)}
def now():return dt.datetime.now(UTC).isoformat(timespec='seconds')
def ip(value):
 a=ipaddress.ip_address(str(value).strip())
 if getattr(a,'ipv4_mapped',None):a=a.ipv4_mapped
 if not a.is_global or a.is_multicast or '%' in str(a):raise ValueError('Only globally public unicast addresses are accepted')
 return a
def network(value):
 n=ipaddress.ip_network(value,strict=False)
 ip(n.network_address);ip(n.broadcast_address)
 if n.num_addresses>1:
  bad=list(n.network_address._constants._private_networks)
  if n.version==4:bad += [ipaddress.ip_network('100.64.0.0/10'),ipaddress.ip_network('224.0.0.0/3')]
  else:bad += [ipaddress.ip_network('ff00::/8')]
  if any(n.overlaps(b) for b in bad):raise ValueError('Network crosses a private or special-purpose address range')
 return n
def selector(value):
 value=value.strip()
 if value.upper().startswith('AS'):
  number=int(value[2:])
  if not 1<=number<=4294967295:raise ValueError('Invalid ASN')
  return 'asn','AS'+str(number),[]
 if '-' in value:
  lo,hi=[ip(v) for v in value.split('-',1)]
  if lo.version!=hi.version or int(lo)>int(hi):raise ValueError('Range must be ordered and use one address family')
  nets=list(ipaddress.summarize_address_range(lo,hi))
  for n in nets:network(str(n))
  return 'range',str(lo)+'-'+str(hi),nets
 if ' ' in value:
  parts=value.split()
  if len(parts)!=2:raise ValueError('Use address/netmask or CIDR')
  value='/'.join(parts)
 n=network(value)
 return ('ip' if n.num_addresses==1 else 'network'),str(n.network_address) if n.num_addresses==1 else str(n),[n]
def subtract(nets,allows):
 hosts={(a.version,int(a.network_address)) for a in allows if a.num_addresses==1}
 nets=[n for n in nets if n.num_addresses>1 or (n.version,int(n.network_address)) not in hosts]
 if not any(n.num_addresses>1 for n in nets):allows=[a for a in allows if a.num_addresses>1]
 for allow in allows:
  nextnets=[]
  for n in nets:
   if n.version!=allow.version or not n.overlaps(allow):nextnets.append(n)
   elif n.subnet_of(allow):pass
   elif allow.subnet_of(n):nextnets.extend(n.address_exclude(allow))
  nets=nextnets
 return list(ipaddress.collapse_addresses([n for n in nets if n.version==4]))+list(ipaddress.collapse_addresses([n for n in nets if n.version==6]))
class Store:
 def known_crawler(self,address):
  # Local operator ranges protect newly seen crawlers before background enrichment.
  if getattr(self,'_crawler_refresh',0)<time.monotonic():
   feeds=self.state('crawler_feeds') or {};ranges={4:[],6:[]}
   for values in feeds.get('data',{}).values():
    for value in values:
     try:
      n=ipaddress.ip_network(value.get('ipv4Prefix') or value.get('ipv6Prefix'));ranges[n.version].append(n)
     except (ValueError,TypeError):continue
   intervals={}
   for version,values in ranges.items():
    nets=sorted(ipaddress.collapse_addresses(values),key=lambda n:int(n.network_address))
    intervals[version]=([int(n.network_address) for n in nets],[int(n.broadcast_address) for n in nets])
   self._crawler_intervals=intervals;self._crawler_refresh=time.monotonic()+60
  a=ipaddress.ip_address(address);starts,ends=self._crawler_intervals[a.version];pos=bisect.bisect_right(starts,int(a))-1
  return pos>=0 and int(a)<=ends[pos]
 def __init__(self,path):
  self.path=str(path);pathlib.Path(path).parent.mkdir(parents=True,exist_ok=True)
  with self.connect() as d:d.executescript('''
   PRAGMA journal_mode=WAL;
   CREATE TABLE IF NOT EXISTS ips(ip TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, metadata TEXT NOT NULL DEFAULT '{}');
   CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,ip TEXT NOT NULL,source TEXT NOT NULL,sensor TEXT NOT NULL,seen TEXT NOT NULL,family TEXT NOT NULL,strength INTEGER NOT NULL,url TEXT NOT NULL DEFAULT '',details TEXT NOT NULL DEFAULT '{}');
   CREATE INDEX IF NOT EXISTS evidence_ip_time ON evidence(ip,seen);
   CREATE INDEX IF NOT EXISTS evidence_time ON evidence(seen);
   CREATE INDEX IF NOT EXISTS ips_last_seen ON ips(last_seen);
   CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY,action TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,reason TEXT NOT NULL,expires TEXT,emergency INTEGER NOT NULL DEFAULT 0,created TEXT NOT NULL,actor TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);
   CREATE TABLE IF NOT EXISTS cache(ip TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL,payload TEXT NOT NULL,fetched TEXT NOT NULL,expires TEXT NOT NULL,PRIMARY KEY(ip,provider));
   CREATE TABLE IF NOT EXISTS block_retention(ip TEXT PRIMARY KEY, first_blocked TEXT NOT NULL, last_seen TEXT NOT NULL, expires TEXT NOT NULL, last_source TEXT NOT NULL, score INTEGER NOT NULL, snapshot TEXT NOT NULL);
   CREATE INDEX IF NOT EXISTS block_retention_expires ON block_retention(expires);
   CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS source_activity(ip TEXT NOT NULL,source TEXT NOT NULL,sensor TEXT NOT NULL,seen TEXT NOT NULL,details TEXT NOT NULL,PRIMARY KEY(ip,source,sensor));
   CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,password_hash TEXT NOT NULL,version INTEGER NOT NULL DEFAULT 1);
   CREATE TABLE IF NOT EXISTS login_attempts(address TEXT PRIMARY KEY,attempts INTEGER NOT NULL,until TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS offender_blocks(ip TEXT PRIMARY KEY,first_blocked TEXT NOT NULL,last_blocked TEXT NOT NULL,last_native_seen TEXT NOT NULL,previous_score INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS offender_returns(ip TEXT NOT NULL,source TEXT NOT NULL,sensor TEXT NOT NULL,seen TEXT NOT NULL,previous_score INTEGER NOT NULL,bonus INTEGER NOT NULL,policy_event INTEGER NOT NULL,PRIMARY KEY(ip,source,sensor,seen));
   CREATE INDEX IF NOT EXISTS offender_returns_time ON offender_returns(seen,ip);
   CREATE INDEX IF NOT EXISTS offender_returns_ip_time ON offender_returns(ip,seen);
   CREATE TABLE IF NOT EXISTS api_tokens(id TEXT PRIMARY KEY,name TEXT NOT NULL,digest TEXT NOT NULL UNIQUE,created TEXT NOT NULL,expires TEXT NOT NULL,actor TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1);
  ''')
  from new_ips import initialize
  initialize(self)
  from event_history import SCHEMA
  with self.connect() as d:d.executescript(SCHEMA)
  from event_history import recover_audit
  recover_audit(self)
 @contextlib.contextmanager
 def connect(self,commit=True):
  persistent=getattr(self,'_worker_connection',None)
  d=persistent if persistent is not None else sqlite3.connect(self.path,timeout=30);d.row_factory=sqlite3.Row;d.execute('PRAGMA busy_timeout=30000')
  try:
   yield d
   if commit:d.commit()
  except Exception:d.rollback();raise
  finally:
   if persistent is None:d.close()
 def audit(self,actor,action,details):
  from event_history import audit_event
  with self.connect() as d:
   at=now();record=d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(at,actor,action,json.dumps(details)))
   audit_event(d,record.lastrowid,at,actor,action,details)
 def state(self,key,value=None):
  with self.connect() as d:
   if value is not None:d.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(key,json.dumps(value)));return value
   r=d.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone();return json.loads(r[0]) if r else None
 def cache(self,address,provider,payload,status='ok',hours=168):
  address=str(ip(address));until=(dt.datetime.now(UTC)+dt.timedelta(hours=hours)).isoformat(timespec='seconds')
  with self.connect() as d:d.execute('INSERT OR REPLACE INTO cache VALUES(?,?,?,?,?,?)',(address,provider,status,json.dumps(payload),now(),until))
 def cached(self,address,provider):
  with self.connect() as d:r=d.execute('SELECT * FROM cache WHERE ip=? AND provider=? AND expires>?',(address,provider,now())).fetchone()
  return dict(r) if r else None
 def cache_many(self,records):
  fetched=now();rows=[]
  for address,provider,payload,status,hours in records:
   rows.append((str(ip(address)),provider,status,json.dumps(payload),fetched,(dt.datetime.now(UTC)+dt.timedelta(hours=hours)).isoformat(timespec='seconds')))
  with self.connect() as d:d.executemany('INSERT OR REPLACE INTO cache VALUES(?,?,?,?,?,?)',rows)
 def add_rule(self,action,value,reason,expires,actor,emergency=False):
  return self.add_rules(action,[value],reason,expires,actor,emergency)[0]
 def add_rules(self,action,values,reason,expires,actor,emergency=False):
  if action not in ['allow','block']:raise ValueError('Action must be allow or block')
  if not reason.strip():raise ValueError('Notes / reason are required')
  if len(reason.strip())>1000:raise ValueError('Notes must be 1,000 characters or fewer.')
  selected={}
  for value in values:
   kind,value,nets=selector(value)
   if emergency and (action!='block' or kind!='ip'):raise ValueError('Emergency override is only available for an exact IP block')
   selected[value]=kind
  if not selected:raise ValueError('Select at least one address.')
  if len(selected)>250:raise ValueError('Select no more than 250 entries at a time.')
  if expires:
   expires=dt.datetime.fromisoformat(expires.replace('Z','+00:00'))
   if expires.tzinfo is None:raise ValueError('Expiry must include a timezone')
   if expires<=dt.datetime.now(UTC):raise ValueError('Expiry is in the past')
   expires=expires.astimezone(UTC).isoformat(timespec='seconds')
  created=now();rules=[];audit=[];ids=[];reason=reason.strip()
  for value,kind in selected.items():
   id=uuid.uuid4().hex;ids.append(id)
   rules.append((id,action,kind,value,reason,expires,int(emergency),created,actor))
   audit.append((created,actor,'rule.add',json.dumps({'id':id,'action':action,'value':value,'reason':reason,'expires':expires,'emergency':emergency})))
  with self.connect() as d:
   d.executemany('INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,1)',rules)
   from event_history import audit_event
   for at,who,action,details in audit:
    record=d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(at,who,action,details))
    audit_event(d,record.lastrowid,at,who,action,json.loads(details))
  return ids
 def disable_rule(self,id,actor):
  with self.connect() as d:
   r=d.execute('SELECT * FROM rules WHERE id=?',(id,)).fetchone()
   if not r:raise ValueError('Rule not found')
   if not r['enabled']:return
   from event_history import audit_event
   at=now();d.execute('UPDATE rules SET enabled=0 WHERE id=?',(id,));record=d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(at,actor,'rule.disable',json.dumps(dict(r))))
   audit_event(d,record.lastrowid,at,actor,'rule.disable',dict(r))
 def renew_block(self,address,seen,source):
  address=str(ip(address));t=dt.datetime.fromisoformat(seen.replace('Z','+00:00'))
  if t.tzinfo is None:raise ValueError('Activity time must include timezone')
  t=t.astimezone(UTC)
  if not dt.datetime.now(UTC)-dt.timedelta(days=30)<=t<=dt.datetime.now(UTC)+dt.timedelta(minutes=5):return False
  seen=t.isoformat(timespec='seconds');expires=(t+dt.timedelta(days=30)).isoformat(timespec='seconds')
  with self.connect(commit=not getattr(self,'_batch_evidence',False)) as d:
   from new_ips import record
   record(d,address,seen)
   updated=d.execute('UPDATE block_retention SET last_seen=?,expires=?,last_source=? WHERE ip=? AND last_seen<? AND first_blocked<=? AND expires>=?',(seen,expires,source,address,seen,seen,seen))
   if updated.rowcount and source=='palo':
    from offenders import returned
    returned(d,address,'palo','block hit',seen)
   return bool(updated.rowcount)
 def evidence(self,address,source,sensor,seen,family,strength,url='',details=None):
  address=str(ip(address));t=dt.datetime.fromisoformat(seen.replace('Z','+00:00'))
  if t.tzinfo is None:raise ValueError('Native event time must include timezone')
  t=t.astimezone(UTC)
  if not dt.datetime.now(UTC)-dt.timedelta(days=30)<=t<=dt.datetime.now(UTC)+dt.timedelta(minutes=5):return
  seen=t.isoformat(timespec='seconds');id=hashlib.sha256(json.dumps([address,source,sensor,seen,family,strength,url],separators=(',',':')).encode()).hexdigest()
  batching=getattr(self,'_batch_evidence',False) and getattr(self,'_worker_connection',None) is not None
  with self.connect(commit=not batching) as d:
   from new_ips import record
   record(d,address,seen)
   from offenders import returned
   returned(d,address,source,sensor,seen)
   inserted=d.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET details=excluded.details WHERE evidence.details!=excluded.details',(id,address,source,sensor,seen,family,max(0,min(int(strength),100)),url,json.dumps(details or {})))
   if source!='palo':
    d.execute('UPDATE block_retention SET last_seen=?,expires=?,last_source=? WHERE ip=? AND last_seen<? AND expires>=?',(seen,(t+dt.timedelta(days=30)).isoformat(timespec='seconds'),source,address,seen,seen))
   if inserted.rowcount:d.execute("INSERT INTO ips(ip,first_seen,last_seen) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen)",(address,seen,seen))
  if batching:
   self._evidence_pending=getattr(self,'_evidence_pending',0)+1
   if self._evidence_pending>=100:self._worker_connection.commit();self._evidence_pending=0
 def active_rules(self):
  with self.connect() as d:return [dict(r) for r in d.execute('SELECT * FROM rules WHERE enabled=1 AND (expires IS NULL OR expires>?) ORDER BY created DESC',(now(),))]
 def describe(self,address):
  self._source_configuration=self.state('source_configuration')
  address=str(ip(address));cut=(dt.datetime.now(UTC)-dt.timedelta(days=30)).isoformat(timespec='seconds')
  with self.connect() as d:
   meta=d.execute('SELECT metadata FROM ips WHERE ip=?',(address,)).fetchone()
   evidence=[dict(x) for x in d.execute('SELECT * FROM evidence WHERE ip=? AND seen>=? ORDER BY seen DESC',(address,cut))]
   caches=[dict(x) for x in d.execute('SELECT * FROM cache WHERE ip=?',(address,))]
   retention=d.execute('SELECT * FROM block_retention WHERE ip=? AND expires>?',(address,now())).fetchone()
   prior_return=d.execute('SELECT * FROM offender_returns WHERE ip=? AND policy_event=1 AND seen>=? ORDER BY seen DESC LIMIT 1',(address,cut)).fetchone()
   activity=[dict(x) for x in d.execute('SELECT * FROM source_activity WHERE ip=? AND seen>=? ORDER BY seen DESC',(address,cut))]
  return {**self.score(address,json.loads(meta[0]) if meta else {},evidence,caches,dict(retention) if retention else None,dict(prior_return) if prior_return else None),'activity':activity}
 def source_activity(self,address,source,sensor,seen,details):
  address=str(ip(address));t=dt.datetime.fromisoformat(seen.replace('Z','+00:00'))
  if t.tzinfo is None:raise ValueError('Native activity time must include timezone')
  t=t.astimezone(UTC);cut=dt.datetime.now(UTC)-dt.timedelta(days=30)
  if not cut<=t<=dt.datetime.now(UTC)+dt.timedelta(minutes=5):return
  with self.connect(commit=not getattr(self,'_batch_evidence',False)) as d:
   from new_ips import record
   record(d,address,t.isoformat(timespec='seconds'))
   from offenders import returned
   returned(d,address,source,sensor,t.isoformat(timespec='seconds'))
   d.execute('INSERT INTO source_activity VALUES(?,?,?,?,?) ON CONFLICT(ip,source,sensor) DO UPDATE SET seen=excluded.seen,details=excluded.details WHERE excluded.seen>=source_activity.seen',(address,source,sensor,t.isoformat(timespec='seconds'),json.dumps(details)))
 def score(self,address,meta,evidence,caches,retention=None,prior_return=None):
  configuration=getattr(self,'_source_configuration',None)
  if configuration is not None:
   enabled={k for k,v in configuration.get('sources',{}).items() if v} if configuration.get('index_url') else set()
   evidence=[e for e in evidence if e['source'] in enabled]
   caches=[c for c in caches if not (c['provider']=='misp' and not configuration.get('misp_url')) and not (c['provider']=='palo' and not configuration.get('palo_location'))]
  families={};sensors=set();sources=set();urls=set();palo=0;native={};source_info={};port_snapshots={}
  for e in evidence:
   if e['source']=='palo':palo+=1;continue
   families[e['family']]=max(families.get(e['family'],0),e['strength']);sensors.add(e['sensor']);sources.add(e['source'])
   details=json.loads(e.get('details','{}'));detector=details.get('detector',e['sensor'])
   source_key=(e['source'],e['sensor'] if e['source'] in HONEYPOT_SOURCES else '')
   label=('T-Pot ('+('OWAPot' if e['source']=='owapot' else e['sensor'])+')') if e['source'] in HONEYPOT_SOURCES else {'nginx':'NGINX','waf':'WAF','crowdsec':'CrowdSec','wazuh':'Wazuh'}.get(e['source'],e['source'])
   source_info.setdefault(source_key,{'source':e['source'],'sensor':source_key[1],'label':label,'ports':set()})
   if 'destination_ports' in details:
    valid=set()
    for port in details['destination_ports']:
     try:
      port=int(port)
      if 1<=port<=65535:valid.add(port)
     except (ValueError,TypeError):continue
    if e['source'] in HONEYPOT_SOURCES and ':' not in detector:
     timestamp=(e['seen'],details.get('native_counter_updated_at',e['seen']))
     if timestamp>port_snapshots.get(source_key,(('',''),set()))[0]:port_snapshots[source_key]=(timestamp,valid)
    elif e['source'] not in HONEYPOT_SOURCES:source_info[source_key]['ports'].update(valid)
   if e['url'] and e['strength']>=20:urls.add(e['url'])
   if e['source'] in HONEYPOT_SOURCES:
    # Behavioral sub-detectors are subsets of the parent honeypot's events.
    if ':' not in detector:
     key=('tpot','OWAPot') if e['source']=='owapot' or e['sensor'] in ['OWAPot','OWA-Honeypot'] else (e['source'],e['sensor'])
     count=max(1,int(details.get('native_attempt_count',1)))
     snapshot_ports=set()
     for port in details.get('destination_ports',[]):
      try:
       port=int(port)
       if 1<=port<=65535:snapshot_ports.add(port)
      except (ValueError,TypeError):continue
     sample=(e['seen'],details.get('native_counter_updated_at',e['seen']),count,sorted(snapshot_ports))
     if sample[:2]>native.get(key,('','',0,[]))[:2]:native[key]=sample
  base=max(families.values(),default=0);independent=min(20,max(0,len(families)-1)*10)
  sensor_bonus=min(10,max(0,len(sensors)-1)*3);url_bonus=min(10,max(0,len(urls)-1)*2)
  # ASN ownership and a firewall drop provide context, never maliciousness points.
  behavior_score=min(100,base+independent+sensor_bonus+url_bonus)
  event_count=sum(sample[2] for sample in native.values())
  endpoint_counts=[max(1,len(sample[3])) for sample in native.values()]
  honeypot_score=min(100,sum(HONEYPOT_FLOOR*endpoints+HONEYPOT_REPEAT_BONUS*max(0,sample[2]-endpoints) for sample,endpoints in zip(native.values(),endpoint_counts))) if native else (HONEYPOT_FLOOR if sources & HONEYPOT_SOURCES else 0)
  floor_bonus=max(0,honeypot_score-behavior_score)
  score=behavior_score+floor_bonus
  payloads={r['provider']:json.loads(r['payload']) for r in caches if r['expires']>now() and r['status']=='ok'}
  signals=[]
  def recent(value):
   try:
    t=dt.datetime.fromtimestamp(float(value),UTC) if isinstance(value,(int,float)) or str(value).isdigit() else dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
    return t.tzinfo is not None and dt.datetime.now(UTC)-dt.timedelta(days=30)<=t<=dt.datetime.now(UTC)+dt.timedelta(minutes=5)
   except (ValueError,TypeError,OverflowError,OSError):return False
  from greynoise_enrichment import assessment
  gn=payloads.get('greynoise',{})
  gn_settings=getattr(self,'_greynoise_settings',None)
  if gn_settings is None:gn_settings=self.state('greynoise_settings') or {}
  if gn_settings.get('enabled',True) and gn_settings.get('score_enabled',True) and assessment(gn,score,bool(sources))['score_signal']:signals.append('GreyNoise: malicious scanner observed within seven days')
  misp=payloads.get('misp',{})
  if misp.get('matches',0)>0 and misp.get('fresh_to_ids_and_warninglists_enforced') and recent(misp.get('snapshot_fetched')):signals.append('MISP: fresh actionable indicator, warning lists checked')
  abuse=payloads.get('abuseipdb',{})
  if abuse.get('abuseConfidenceScore',0)>=75 and abuse.get('totalReports',0)>=2 and not abuse.get('isWhitelisted') and recent(abuse.get('lastReportedAt')):signals.append('AbuseIPDB: recent high-confidence abuse reports')
  vt=payloads.get('virustotal',{})
  if vt.get('last_analysis_stats',{}).get('malicious',0)>=3 and recent(vt.get('last_analysis_date')):signals.append('VirusTotal: at least three malicious detections in a recent analysis')
  enrichment_bonus=min(25,100-score) if signals and sources else 0
  score+=enrichment_bonus
  history_floor=0
  if prior_return and (configuration is None or prior_return['source'] in enabled):
   history_floor=max(0,min(100,max(75,prior_return['previous_score'])+prior_return['bonus'])-score);score+=history_floor
   sources.add(prior_return['source'])
   source=prior_return['source'];sensor=prior_return['sensor'] if source in HONEYPOT_SOURCES else '';key=(source,sensor)
   label=('T-Pot ('+('OWAPot' if source=='owapot' else sensor)+')') if source in HONEYPOT_SOURCES else {'nginx':'NGINX','waf':'WAF','crowdsec':'CrowdSec','wazuh':'Wazuh'}.get(source,source)
   source_info.setdefault(key,{'source':source,'sensor':sensor,'label':label,'ports':set()})
  owner=payloads.get('asn',{});asn=str(owner.get('asn',meta.get('asn','')))
  palo=payloads.get('palo',{}).get('alert_records',palo)
  verified=payloads.get('crawler',{}).get('verified',False) or self.known_crawler(address)
  if not verified and meta.get('verified_operator_matches') and meta.get('snapshot_at','')>(dt.datetime.now(UTC)-dt.timedelta(days=1)).isoformat():verified=True
  reasons=[]
  if history_floor:reasons.append('Previously blocked IP returned; prior score '+str(prior_return['previous_score'])+', historical bonus '+str(prior_return['bonus']))
  if verified:reasons.append('Verified crawler/operator identity: protect from automatic block')
  if meta.get('category') in ['research-scanners-review','shared-provider-review','unknown-review']:reasons.append('Provider/research identity requires collateral-impact review')
  if not owner:reasons.append('ASN cache is missing, stale or failed')
  if owner.get('database_build_epoch') and dt.datetime.now(UTC).timestamp()-owner['database_build_epoch']>30*86400:reasons.append('ASN database is older than 30 days')
  if 'crawler' not in payloads:reasons.append('Crawler verification is missing, stale or failed')
  if any(t in owner.get('organization','').upper() for t in ['GOOGLE','MICROSOFT','AMAZON','CLOUDFLARE','FASTLY','AKAMAI','APPLE','BAIDU','YANDEX','YAHOO']) and not verified:reasons.append('Shared search/cloud/CDN network: analyst review required')
  if base<50:reasons.append('No strong behavior evidence')
  holds=[]
  if verified:holds.append('Verified crawler/operator identity: protect from automatic block')
  if score<BLOCK_THRESHOLD:holds.append('Score is below the 75% automatic block threshold')
  retention_bonus=0
  if retention and retention['expires']>now():
   retention_bonus=max(0,retention['score']-score);score+=retention_bonus
   if score>=BLOCK_THRESHOLD and not verified:
    holds=[h for h in holds if h!='Score is below the 75% automatic block threshold']
    reasons.append('Existing scored block retained until '+retention['expires']+'; latest activity: '+retention['last_source'])
  auto=score>=BLOCK_THRESHOLD and not verified
  for key,(timestamp,values) in port_snapshots.items():source_info[key]['ports']=values
  if retention:
   previous=json.loads(retention['snapshot'])
   for value in previous.get('sources',[]):sources.add(value)
   for previous_source in previous.get('source_details',[]):
    key=(previous_source['source'],previous_source['sensor'])
    if key not in source_info:source_info[key]={**previous_source,'ports':set(previous_source.get('ports',[]))}
  source_details=sorted(source_info.values(),key=lambda r:r['label'].casefold())
  for row in source_details:row['ports']=sorted(row['ports'])
  ports=sorted({p for row in source_details for p in row['ports']})
  display={'source_details':source_details,'source_labels':[row['label'] for row in source_details],'ports':ports}
  enrichment_details=[]
  for cached in sorted(caches,key=lambda r:r['provider']):
   provider=cached['provider']
   if provider=='source_type':continue
   payload=json.loads(cached['payload']);status=cached['status'] if cached['expires']>now() else 'expired'
   label={'asn':'ASN','misp':'MISP','palo':'Palo','crawler':'Crawler','abuseipdb':'AbuseIPDB','virustotal':'VirusTotal','greynoise':'GreyNoise'}.get(provider,provider)
   if status!='ok':summary=status.capitalize()
   elif provider=='misp':summary=str(payload.get('matches',0))+' actionable'+(' · '+str(payload['context_matches'])+' context' if payload.get('context_matches') else '')+(' · '+', '.join(payload.get('sources',[])) if payload.get('sources') else '')
   elif provider=='greynoise':summary=('No match' if payload.get('found') is False else payload.get('classification','Unknown').capitalize())+(' · last observed '+str(payload['last_seen']) if payload.get('last_seen') else '')+(' · '+payload['name'] if payload.get('name') not in (None,'unknown') else '')
   elif provider=='palo':summary=str(payload.get('alert_records',0))+' drop / deny records'
   elif provider=='crawler':summary='Verified' if payload.get('verified') else 'No match'
   elif provider=='asn':summary='Cached'+(' · stale database' if payload.get('database_build_epoch') and dt.datetime.now(UTC).timestamp()-payload['database_build_epoch']>30*86400 else '')
   elif provider=='abuseipdb':summary=str(payload.get('abuseConfidenceScore',0))+'% confidence'
   elif provider=='virustotal':summary=str(payload.get('last_analysis_stats',{}).get('malicious',0))+' malicious detections'
   else:summary='Cached'
   if provider=='greynoise' and status=='ok' and payload.get('found') is not False and not assessment(payload)['fresh']:summary+=' · stale observation'
   enrichment_details.append({'provider':provider,'label':label,'status':status,'summary':summary,'fetched':cached['fetched'],'expires':cached['expires']})
  enrichment_text=' · '.join(r['label']+': '+r['summary'] for r in enrichment_details) or 'Pending enrichment'
  gn_cache=next((r for r in caches if r['provider']=='greynoise'),None)
  intelligence=assessment(json.loads(gn_cache['payload']) if gn_cache else {},score-enrichment_bonus,bool(sources),valid=bool(gn_cache and gn_cache['status']=='ok' and gn_cache['expires']>now()))
  return {**display,'intelligence':intelligence,'source_identity':payloads.get('source_type',{}),'client_types':payloads.get('source_type',{}).get('types',['Unknown']),'enrichment_details':enrichment_details,'enrichment_text':enrichment_text,'source_count':len({'tpot' if v=='owapot' else v for v in sources}),'honeypot_count':len({r['label'] for r in source_details if r['source'] in HONEYPOT_SOURCES}),'retention':retention,'ip':address,'score':score,'prior_return':prior_return,'score_breakdown':{'strongest_behavior':base,'independent_family_bonus':independent,'additional_sensor_bonus':sensor_bonus,'distinct_malicious_path_bonus':url_bonus,'honeypot_floor_bonus':floor_bonus,'enrichment_bonus':enrichment_bonus,'palo_drop_bonus':0,'retention_floor_bonus':retention_bonus,'previous_block_return_floor':history_floor,'previous_block_score':prior_return['previous_score'] if prior_return else 0,'previous_block_bonus':prior_return['bonus'] if prior_return else 0},'honeypot_native_events':event_count,'honeypot_attempts':event_count,'honeypot_endpoints':sum(endpoint_counts),'enrichment_signals':signals,'sources':sorted(sources),'sensors':sorted(sensors),'distinct_paths':len(urls),'asn':asn,'organization':owner.get('organization',meta.get('organization','')),'verified_crawler':verified,'auto_candidate':auto,'holds':holds,'review_notes':reasons,'palo_context_records':palo,'metadata':meta,'cache':payloads,'cache_status':[{k:r[k] for k in ['provider','status','fetched','expires']} for r in caches],'evidence':evidence}
 def all_scores(self):
  self._greynoise_settings=self.state('greynoise_settings') or {}
  self._source_configuration=self.state('source_configuration')
  cut=(dt.datetime.now(UTC)-dt.timedelta(days=30)).isoformat(timespec='seconds')
  with self.connect() as d:
   ev={};ca={};retained={r['ip']:dict(r) for r in d.execute('SELECT * FROM block_retention WHERE expires>?',(now(),))};returns={}
   for r in d.execute('SELECT * FROM offender_returns WHERE policy_event=1 AND seen>=? ORDER BY seen',(cut,)):returns[r['ip']]=dict(r)
   for r in d.execute('SELECT * FROM evidence WHERE seen>=?',(cut,)):ev.setdefault(r['ip'],[]).append(dict(r))
   for r in d.execute('SELECT cache.* FROM cache JOIN ips ON cache.ip=ips.ip WHERE ips.last_seen>=? OR EXISTS (SELECT 1 FROM block_retention b WHERE b.ip=ips.ip AND b.expires>?)',(cut,now())):ca.setdefault(r['ip'],[]).append(dict(r))
   return [self.score(r['ip'],json.loads(r['metadata']),ev.get(r['ip'],[]),ca.get(r['ip'],[]),retained.get(r['ip']),returns.get(r['ip'])) for r in d.execute('SELECT * FROM ips WHERE (last_seen>=? AND EXISTS (SELECT 1 FROM evidence WHERE evidence.ip=ips.ip AND evidence.seen>=?)) OR EXISTS (SELECT 1 FROM block_retention b WHERE b.ip=ips.ip AND b.expires>?) OR EXISTS (SELECT 1 FROM offender_returns h WHERE h.ip=ips.ip AND h.policy_event=1 AND h.seen>=?)',(cut,cut,now(),cut))]
 def build(self,output,actor='System',*,defer_if_busy=False):
  # Commit collected evidence/cursors before waiting for another publisher.
  # Never hold SQLite's writer lock while acquiring the filesystem lock.
  anchor=getattr(self,'_worker_connection',None)
  if anchor is not None:anchor.commit()
  requested=now()
  with self.connect() as d:
   d.execute('BEGIN IMMEDIATE')
   previous=d.execute("SELECT value FROM state WHERE key='publication_request'").fetchone()
   completed=d.execute("SELECT value FROM state WHERE key='publication_completed'").fetchone()
   previous=json.loads(previous[0]) if previous else {}
   completed=json.loads(completed[0]) if completed else {}
   pending=previous.get('id') and previous.get('id')!=completed.get('request_id')
   request={'id':uuid.uuid4().hex,'requested':previous['requested'] if pending else requested,'latest_requested':requested,'actor':actor}
   d.execute('INSERT OR REPLACE INTO state VALUES(?,?)',('publication_request',json.dumps(request)))
  pathlib.Path(output).mkdir(parents=True,exist_ok=True)
  lock=FileLock(str(pathlib.Path(output)/'build.lock'),timeout=0 if defer_if_busy else 30)
  try:lock.acquire()
  except Timeout:
   if defer_if_busy:return None
   raise
  try:
   # Only a lock owner maintains/builds. A contending background cycle leaves
   # a durable request, reports publication pending and retries next interval.
   request=self.state('publication_request')
   from offenders import maintain
   maintain(self)
   manifest=self._build(output,actor)
   self.state('publication_completed',{'request_id':request['id'],'created':manifest['created']})
   return manifest
  finally:lock.release()
 def _build(self,output,actor='System'):
  from event_history import baseline,expirations,list_changes
  baseline(self,output);expirations(self,now())
  scores=self.all_scores();rules=self.active_rules();manual=[];allow=[];emergency=[]
  with self.connect() as d:
   for row in scores:
    if not row['auto_candidate'] or row['verified_crawler']:continue
    activity=[e for e in row['evidence'] if e['source']!='palo']
    if row.get('prior_return'):activity.append(row['prior_return'])
    if not activity:continue
    latest=max(activity,key=lambda e:e['seen']);seen=latest['seen']
    expires=(dt.datetime.fromisoformat(seen)+dt.timedelta(days=30)).isoformat(timespec='seconds')
    snapshot=json.dumps({'sources':row['sources'],'source_details':row['source_details']})
    d.execute('INSERT INTO block_retention VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET score=excluded.score,snapshot=excluded.snapshot,first_blocked=CASE WHEN block_retention.expires<=? THEN excluded.first_blocked ELSE block_retention.first_blocked END,last_seen=CASE WHEN block_retention.expires<=? THEN excluded.last_seen ELSE block_retention.last_seen END,last_source=CASE WHEN block_retention.expires<=? THEN excluded.last_source ELSE block_retention.last_source END,expires=CASE WHEN block_retention.expires<=? THEN excluded.expires ELSE block_retention.expires END', (row['ip'],now(),seen,expires,latest['source'],row['score'],snapshot,now(),now(),now(),now()))
  native_scores=scores
  from behavior_scoring import apply as ai_scores
  scores=ai_scores(self,scores)
  for rule in rules:
   if rule['kind']=='asn':
    n=rule['value'][2:];nets=[ipaddress.ip_network(r['ip']) for r in scores if n in r['cache'].get('asn',{}).get('asn','').split() and r['cache']['asn'].get('database_build_epoch',dt.datetime.now(UTC).timestamp())>dt.datetime.now(UTC).timestamp()-30*86400]
   else:nets=selector(rule['value'])[2]
   (emergency if rule['emergency'] else allow if rule['action']=='allow' else manual).extend(nets)
  protected=[ipaddress.ip_network(r['ip']) for r in scores if r['verified_crawler']]
  lists={'manual-block':subtract(manual,allow+protected),'manual-allow':allow,'scored-block':subtract([ipaddress.ip_network(r['ip']) for r in scores if r['auto_candidate']],allow+protected),'review-hold':[ipaddress.ip_network(r['ip']) for r in scores if not r['auto_candidate']]}
  lists['protected-crawlers']=protected
  lists['palo-drops-review']=[ipaddress.ip_network(r['ip']) for r in scores if r['palo_context_records']>0]
  for source in ['tpot','owapot','nginx','waf','crowdsec','wazuh']:
   candidates=[ipaddress.ip_network(r['ip']) for r in scores if source in r['sources'] or (source=='tpot' and 'owapot' in r['sources'])]
   lists[source+'-review']=subtract(candidates,allow+protected)
  lists['combined-block']=subtract(lists['manual-block']+lists['scored-block'],allow)+emergency
  lists['manual-block']+=emergency
  out=pathlib.Path(output);out.mkdir(parents=True,exist_ok=True);gen=out/('generation-'+uuid.uuid4().hex);gen.mkdir()
  counts={}
  for name,nets in lists.items():
   vals=sorted(set(str(n.network_address) if n.num_addresses==1 else str(n) for n in nets))
   if len(vals)>50000:raise ValueError('Publication guard: list exceeds 50,000 entries')
   (gen/(name+'.txt')).write_text(''.join(v+'\n' for v in vals),encoding='utf8');counts[name]=len(vals)
  manifest={'created':now(),'counts':counts,'mode':'production','palo_policy_managed':False,'window_days':30,'asn_rule_scope':'observed IPs only','rule_count':len(rules),'scoring_policy':{'block_threshold':BLOCK_THRESHOLD,'honeypot_minimum_score':HONEYPOT_FLOOR,'honeypot_repeat_bonus':HONEYPOT_REPEAT_BONUS,'honeypot_repeat_unit':'distinct sessions/authentication attempts per source IP; first observation per honeypot/port +50; repeats +25; newest rolling counters; behavioral subsets excluded','honeypot_sources':sorted(HONEYPOT_SOURCES),'malicious_enrichment_bonus_cap':25,'palo_drop_score':0,'retention_days':30,'retention_policy':'30 days from latest qualifying native observation; Palo block hits only renew existing blocks using native firewall timestamps','enrichment_required_for_block':False,'whitelist_and_verified_crawler_protection':True,'previous_block_history_days':365,'previous_block_return_minimum':75,'previous_block_aged_bonus':25,'previous_block_aged_after_days':30}}
  manifest['ai_scoring']={'enabled':bool((self.state('behavior_settings') or {}).get('scoring_enabled')),'maximum':10,'applied_points':round(sum(r.get('ai_bump',0) for r in scores),2),'adjusted_ips':sum(bool(r.get('ai_bump')) for r in scores),'ai_only_ips':[r['ip'] for r in scores if r.get('ai_bump') and r['auto_candidate'] and r.get('native_score',0)<75 and any(ipaddress.ip_address(r['ip']) in n for n in lists['combined-block'])]}
  # The display snapshot and EDLs share one atomic generation. Never score on a cache hit.
  display=[display_row(row) for row in scores]
  (gen/'dashboard.json').write_text(json.dumps({'created':manifest['created'],'rows':display},separators=(',',':')),encoding='utf-8')
  manifest['sha256']={name:hashlib.sha256((gen/(name+'.txt')).read_bytes()).hexdigest() for name in counts}
  (gen/'manifest.json').write_text(json.dumps(manifest,indent=2));tmp=out/'current.new'
  if tmp.exists() or tmp.is_symlink():tmp.unlink()
  tmp.symlink_to(gen.name,target_is_directory=True);os.replace(tmp,out/'current');self.state('latest_build',manifest)
  from behavior_metrics import record_publication
  record_publication(self,manifest)
  from offenders import mark_blocks
  native_combined=subtract(lists['manual-block']+subtract([ipaddress.ip_network(r['ip']) for r in native_scores if r['auto_candidate']],allow+protected),allow)+emergency
  mark_blocks(self,native_scores,native_combined,manifest['created'])
  list_changes(self,lists,manifest['created'],gen.name,actor)
  return manifest
