"""Single-flight bounded local ingestion and enrichment worker."""
import datetime as dt,fcntl,hashlib,json,logging,os,pathlib,time,urllib.request,ssl,bisect,sqlite3
import requests,maxminddb,contextlib
from core import Store,now,ip
from source_settings import effective
UTC=dt.timezone.utc
def misp_attributes(session,url,store=None):
 """Fetch a complete bounded snapshot; callers retain prior state on failure."""
 attrs=[];received=0
 # Native MISP applies warninglists after database pagination. A short or even
 # empty filtered page can precede later data. Probe through a terminal empty
 # page; native MISP versions report zero or one (the look-ahead sentinel).
 for page in range(1,102):
  if store:
   from analytics_store import event
   event(store,'misp','outbound')
  r=session.post(url+'/attributes/restSearch',json={'returnFormat':'json','type':['ip-src','ip-dst','ip-src|port','ip-dst|port'],'includeContext':True,'deleted':False,'enforceWarninglist':True,'timestamp':'30d','limit':1000,'page':page},timeout=30)
  r.raise_for_status();v=r.json()
  if not isinstance(v,dict) or 'response' not in v:raise ValueError('Unexpected MISP response')
  part=v['response'].get('Attribute') if isinstance(v['response'],dict) else v['response']
  if not isinstance(part,list) or len(part)>1000:raise ValueError('Unexpected MISP response')
  if any(not isinstance(a,dict) or not isinstance(a.get('value'),str) or not isinstance(a.get('Event',{}),dict) for a in part):raise ValueError('Unexpected MISP attribute')
  headers=getattr(r,'headers',{})
  counts=[]
  for name in ('X-Result-Count','X-Skipped-Elements-Count'):
   value=headers.get(name)
   if not isinstance(value,str) or not value.isascii() or not value.isdigit():raise ValueError('MISP pagination metadata is missing or invalid')
   counts.append(int(value))
  raw,skipped=counts
  if raw>1001 or skipped>1000 or raw<len(part)+skipped:raise ValueError('Inconsistent MISP pagination metadata')
  if not part and skipped==0 and raw<=1:return attrs
  received+=len(part)
  if page>100 or received>=100000:break
  for a in part:
   item={'value':a.get('value'),'id':a.get('id'),'timestamp':a.get('timestamp'),'to_ids':a.get('to_ids'),'source':a.get('Event',{}).get('info','MISP indicator'),'event_id':a.get('event_id')}
   if not isinstance(item['source'],str):raise ValueError('Unexpected MISP source')
   if item['source'].endswith(' [local managed IP context]'):
    comment=a.get('comment','');prefix='Local managed IP context; expires='
    if item['to_ids'] not in (False,0,'0') or not isinstance(comment,str) or not comment.startswith(prefix):raise ValueError('Managed MISP context policy mismatch')
    expiry=dt.datetime.fromisoformat(comment[len(prefix):].split(';',1)[0])
    if expiry.tzinfo is None:raise ValueError('Managed MISP context expiry requires timezone')
    item['expires']=expiry.astimezone(UTC).isoformat(timespec='seconds')
    if item['expires']<=now():continue
   attrs.append(item)
 raise ValueError('MISP volume guard: fewer than 100,000 attributes and at most 100 data pages required')
def strength(source,detector):
 d=detector.lower()
 if source=='crowdsec' and d.startswith('crowdsec-ban:'):return ('ssh' if 'ssh' in d else 'http'),75
 if source=='nginx' and d=='sensitive-path-probe':return 'http',50
 if source=='waf' and d=='coraza-interruption':return 'http',50
 if 'command-input' in d or 'file-download' in d or 'file-upload' in d:return 'ssh',75
 if 'failed-login' in d:return 'ssh',55
 if source=='wazuh':return 'authentication',55
 if source in ['nginx','waf','crowdsec']:
  if 'ssh' in d:return 'ssh',55
  if 'cve-' in d or 'suricata-major' in d:return 'http',55
  return 'http',25
 if 'cowrie' in d:return 'ssh',10
 if 'dionaea' in d:return 'transport',10
 if 'mailoney' in d:return 'mail',10
 return 'http',5
def ingest_source(s,k,d,updated,records,source_cfg=None):
 if d.get('edl_activity_json','{}')!='{}':
  try:s.source_activity(k['ip'],k['source'],k['detector'].split(':')[0],d['edl_seen_utc'],{'activity':d['edl_activity_json'],'deterministic_qualifying':d.get('edl_qualifying')!='no',**({'native_event_count':int(d['edl_native_event_count'])} if 'edl_native_event_count' in d else {}),**({'native_attempt_count':int(d['edl_native_attempt_count'])} if 'edl_native_attempt_count' in d else {}),**({'destination_ports':d['edl_dst_ports'].split(',')} if 'edl_dst_ports' in d else {})},**({'source_cfg':source_cfg} if source_cfg is not None else {}))
  except ValueError:return False
 if d.get('edl_qualifying')=='no':return False
 from permanent_policy import source_provenance
 proof=source_provenance(d,k['source'],k['detector'])
 family,points=strength(k['source'],k['detector'])
 for path in d.get('edl_path_hashes','').split(',')[:30] or ['']:
  try:s.evidence(k['ip'],k['source'],k['detector'].split(':')[0],d['edl_seen_utc'],family,points,path,{**proof,'detector':k['detector'],'records':records,'native_event_count':int(d.get('edl_native_event_count',0)),'native_counter_updated_at':updated,**({'native_attempt_count':int(d['edl_native_attempt_count'])} if 'edl_native_attempt_count' in d else {}),**({'destination_ports':d['edl_dst_ports'].split(',')} if 'edl_dst_ports' in d else {})})
  except ValueError:continue
 return True

def collect(s,cfg,include_palo=True,palo_only=False):
 cfg=effective(s,cfg)
 if not cfg.get('index_url'):return 0
 enabled={k:v for k,v in cfg['source_agents'].items() if v}
 cutoff=(dt.datetime.now(UTC)-dt.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ');after=None;processed=0
 started=dt.datetime.now(UTC);cursor=s.state('native_ingest_cursor') or {}
 sess=requests.Session();sess.auth=(cfg['index_user'],cfg['index_password']);sess.verify=cfg['index_ca']
 from requests.adapters import HTTPAdapter
 context=ssl.create_default_context(cafile=cfg['index_ca'] if isinstance(cfg['index_ca'],str) else None);context.verify_flags &= ~ssl.VERIFY_X509_STRICT
 class IndexTLS(HTTPAdapter):
  def init_poolmanager(self,*a,**kw):kw['ssl_context']=context;return super().init_poolmanager(*a,**kw)
  def build_connection_pool_key_attributes(self,request,verify,cert=None):
   host,kw=super().build_connection_pool_key_attributes(request,verify,cert);kw['ssl_context']=context;return host,kw
 sess.mount(cfg['index_url'],IndexTLS())
 if not palo_only:
  from native_ingestion import collect_partitioned
  processed=collect_partitioned(s,cfg,sess,enabled,ingest_source,started,cursor)
 if not include_palo or not cfg['palo_location']:return processed
 if (s.state('palo_status') or {}).get('expires','')>now():return processed
 try:
  palo_context={}
  with s.connect() as d:observed=[r['ip'] for r in d.execute('SELECT ip FROM ips WHERE last_seen>=? OR EXISTS (SELECT 1 FROM block_retention b WHERE b.ip=ips.ip AND b.expires>=?)',(cutoff,(dt.datetime.now(UTC)-dt.timedelta(hours=1)).isoformat(timespec='seconds')))]
  for direction,field in [('source','data.source_address'),('destination','data.destination_address')]:
   after=None
   while True:
    comp={'size':500,'sources':[{'ip':{'terms':{'field':field}}}]}
    if after:comp['after']=after
    q={'size':0,'query':{'bool':{'filter':[{'term':{'location':cfg['palo_location']}},{'range':{'timestamp':{'gte':cutoff}}},{'terms':{field:observed}},{'terms':{'data.action':['deny','drop','reset-client','reset-server','reset-both','block-ip']}}]}},'aggs':{'ips':{'composite':comp,'aggs':{'last':{'max':{'field':'timestamp'}},'native_last':{'max':{'script':{'source':"if (!doc.containsKey('data.high_resolution_timestamp') || doc['data.high_resolution_timestamp'].size()==0) return 0; try { return java.time.OffsetDateTime.parse(doc['data.high_resolution_timestamp'].value).toInstant().toEpochMilli(); } catch (Exception e) { return 0; }"}}}}}}}
    if getattr(s,'_worker_connection',None) is not None:s._worker_last_direct_commit='palo_page_before_fetch';s._worker_connection.commit()
    r=sess.post(cfg['index_url']+'/wazuh-alerts-*/_search',json=q,timeout=60);r.raise_for_status();v=r.json()
    if v.get('timed_out') or v.get('_shards',{}).get('failed'):raise ValueError('Incomplete Palo context query')
    a=v['aggregations']['ips']
    for b in a['buckets']:
     address=b['key']['ip']
     try:ip(address)
     except ValueError:continue
     drop_context=palo_context.setdefault(address,{});drop_context[direction]=b['doc_count']
     if direction=='source' and b.get('native_last',{}).get('value'):
      drop_context['_seen']=max(drop_context.get('_seen',''),dt.datetime.fromtimestamp(b['native_last']['value']/1000,UTC).isoformat(timespec='seconds'))
    s.state('palo_status',{'status':'collecting','direction':direction,'public_ips':len(palo_context),'expires':'2020-01-01T00:00:00+00:00'})
    after=a.get('after_key')
    if not after or not a['buckets']:break
    if len(palo_context)>50000:raise ValueError('Palo context volume guard')
  pending=[]
  for address in observed:
   drop_context=palo_context.get(address,{})
   counts={k:v for k,v in drop_context.items() if k!='_seen'}
   if drop_context.get('_seen'):s.renew_block(address,drop_context['_seen'],'palo')
   pending.append((address,'palo',{'alert_records':sum(counts.values()),'directional_drop_records':counts,'last_native_seen':drop_context.get('_seen'),'window_days':30,'score_contribution':0,'note':'Firewall decision context; native block hits renew an existing scored block but add no score'},'ok',1))
   if len(pending)>=256:s.cache_many(pending);pending=[]
  if pending:s.cache_many(pending)
  s.state('palo_status',{'status':'ok','scope':'public application/honeypot IPs and existing retained blocks','public_ips':len(palo_context),'completed':now(),'expires':(dt.datetime.now(UTC)+dt.timedelta(minutes=5)).isoformat(timespec='seconds')})
 except (requests.RequestException,ValueError) as e:s.state('palo_status',{'status':'error','reason':str(e)[:200]})
 return processed
def enrich(s,cfg):
 cfg=effective(s,cfg)
 misp_enabled=bool(cfg.get('misp_url'))
 rows=s.all_scores();providers={'asn':'local GeoLite2 ASN','crawler':'operator-published ranges','misp':'disabled: configure read-only API key','abuseipdb':'disabled: no API key','virustotal':'disabled: no API key'};checks=0
 # Refresh bot feeds daily, with failed refresh holding prior protections and suppressing promotion.
 feeds=s.state('crawler_feeds') or {};fresh=feeds.get('expires','')>now()
 local=pathlib.Path(cfg.get('crawler_feed_file','/var/lib/edl-manager/crawler-feeds.json'))
 if local.exists():
  v=json.loads(local.read_text())
  if v.get('fetched','')>feeds.get('fetched',''):feeds=v;s.state('crawler_feeds',feeds)
  fresh=feeds.get('expires','')>now()
 if not fresh:
  urls={'google-common':'https://developers.google.com/static/crawling/ipranges/common-crawlers.json','google-special':'https://developers.google.com/static/crawling/ipranges/special-crawlers.json','bing':'https://www.bing.com/toolbox/bingbot.json','duckduckgo':'https://duckduckgo.com/duckduckbot.json','apple':'https://search.developer.apple.com/applebot.json','openai-search':'https://openai.com/searchbot.json','openai-user':'https://openai.com/chatgpt-user.json','openai-training':'https://openai.com/gptbot.json'}
  try:
   data={}
   for name,url in urls.items():
    r=requests.get(url,timeout=20);r.raise_for_status();v=r.json();assert v.get('prefixes');data[name]=v['prefixes']
   feeds={'fetched':now(),'expires':(dt.datetime.now(UTC)+dt.timedelta(hours=24)).isoformat(timespec='seconds'),'data':data};s.state('crawler_feeds',feeds)
  except (requests.RequestException,ValueError,AssertionError) as e:providers['crawler']='feed refresh failed: new automatic promotion held';s.state('crawler_feed_error',str(e)[:200])
 import ipaddress
 nets={n:[ipaddress.ip_network(v.get('ipv4Prefix') or v.get('ipv6Prefix')) for v in items] for n,items in feeds.get('data',{}).items()}
 intervals={}
 for name,values in nets.items():
  intervals[name]={}
  for version in [4,6]:
   ranges=sorted((int(v.network_address),int(v.broadcast_address)) for v in ipaddress.collapse_addresses(v for v in values if v.version==version))
   intervals[name][version]=([lo for lo,hi in ranges],[hi for lo,hi in ranges])
 with (maxminddb.open_database(cfg['asn_database']) if cfg.get('asn_database') and pathlib.Path(cfg['asn_database']).is_file() else contextlib.nullcontext(None)) as mm:
  db_fresh=bool(mm) and time.time()-mm.metadata().build_epoch<30*86400
  if not mm:providers['asn']='Not configured'
  elif not db_fresh:providers['asn']='Local ASN database is older than 30 days; new lookups held'
  for row in rows:
   address=row['ip']
   if mm and not s.cached(address,'asn'):
    v=mm.get(address) or {};s.cache(address,'asn',{'asn':str(v.get('autonomous_system_number','')),'organization':v.get('autonomous_system_organization',''),'provider':'GeoLite2 ASN','database_build_epoch':mm.metadata().build_epoch},status=('ok' if v.get('autonomous_system_number') else 'unknown') if db_fresh else 'stale',hours=168 if db_fresh else 1);checks+=1
   if not s.cached(address,'crawler'):
    a=ipaddress.ip_address(address);value=int(a);matches=[]
    for name,versions in intervals.items():
     starts,ends=versions[a.version];pos=bisect.bisect_right(starts,value)-1
     if pos>=0 and value<=ends[pos]:matches.append(name)
    # Negative verification expires with the feed, not 24h after arbitrary processing time.
    hours=max(.05,(dt.datetime.fromisoformat(feeds.get('expires',now()))-dt.datetime.now(UTC)).total_seconds()/3600)
    s.cache(address,'crawler',{'verified':bool(matches),'matches':matches,'feeds_as_of':feeds.get('fetched')},status='ok' if feeds.get('expires','')>now() else 'stale',hours=hours);checks+=1
 # Bulk origin lookups use the optional enrichment broker; decisions/cache stay here.
 origin_file=pathlib.Path(cfg['database']).parent/'asn-enrichment.json'
 origins=json.loads(origin_file.read_text()) if origin_file.exists() else {}
 queue=[]
 for row in rows:
  address=row['ip'];v=origins.get(address,{})
  old=s.cached(address,'asn');payload=json.loads(old['payload']) if old else {}
  if v.get('expires','')>now() and (not old or v['fetched']>old['fetched'] or old['status']!='ok' or payload.get('database_build_epoch',time.time())<time.time()-30*86400):
   hours=(dt.datetime.fromisoformat(v['expires'])-dt.datetime.now(UTC)).total_seconds()/3600
   s.cache(address,'asn',v['payload'],status=v['status'],hours=hours);old=s.cached(address,'asn');payload=v['payload'];checks+=1
  if not old or old['status']!='ok' or payload.get('database_build_epoch',time.time())<time.time()-30*86400:queue.append(address)
 target=pathlib.Path(cfg['database']).parent/'asn-queue.json';temp=target.with_suffix('.new');temp.write_text(json.dumps({'requested':now(),'ips':queue}));os.replace(temp,target)
 if queue and cfg.get('asn_broker_enabled'):providers['asn']+='; '+str(len(queue))+' queued for cached origin lookup'
 file=pathlib.Path(cfg['providers_file']);keys=json.loads(file.read_text()) if file.exists() else {}
 from greynoise_enrichment import enrich as enrich_greynoise
 gn_key=keys.pop('greynoise',None)
 if cfg.get('greynoise_transport')!='ops':checks+=enrich_greynoise(s,rows,gn_key)
 if keys.get('misp') and misp_enabled:
  providers['misp']='read-only local indicator sync; cached per IP'
  snapshot=s.state('misp_snapshot') or {}
  if snapshot.get('expires','')<=now():
   try:
    from requests.adapters import HTTPAdapter
    class PinnedMISP(HTTPAdapter):
     def init_poolmanager(self,*args,**kwargs):
      if cfg.get('misp_sha256'):kwargs.update(assert_hostname=False,assert_fingerprint=cfg['misp_sha256'])
      return super().init_poolmanager(*args,**kwargs)
    ms=requests.Session();ms.mount(cfg['misp_url'],PinnedMISP());ms.verify=cfg['misp_ca'];ms.headers.update({'Authorization':keys['misp'],'Accept':'application/json'})
    attrs=misp_attributes(ms,cfg['misp_url'],s)
    expiry=min([(dt.datetime.now(UTC)+dt.timedelta(hours=6)).isoformat(timespec='seconds')]+[a['expires'] for a in attrs if a.get('expires')])
    snapshot={'fetched':now(),'expires':expiry,'generation':hashlib.sha256(json.dumps(attrs,sort_keys=True).encode()).hexdigest(),'attributes':attrs};s.state('misp_snapshot',snapshot)
    from analytics_store import event
    event(s,'misp','imports',n=len(attrs))
   except (requests.RequestException,ValueError,KeyError) as e:
    from analytics_store import event
    event(s,'misp','error')
    providers['misp']='sync failed; prior snapshot retained: '+type(e).__name__
  networks=[];exact={}
  for a in snapshot.get('attributes',[]):
   try:
    n=ipaddress.ip_network(a['value'].split('|')[0],strict=False)
    if n.num_addresses==1:exact.setdefault(str(n.network_address),[]).append(a)
    else:networks.append((n,a))
   except (ValueError,TypeError):continue
  # Prefix-index networks once, rather than testing every CIDR against every IP.
  prefix_index={4:{},6:{}}
  for n,a in networks:prefix_index[n.version].setdefault(n.prefixlen,{}).setdefault(int(n.network_address),[]).append(a)
  prefix_index={version:[(((1<<bits)-1)^((1<<(bits-prefix))-1),entries) for prefix,entries in values.items()] for version,bits,values in [(4,32,prefix_index[4]),(6,128,prefix_index[6])]}
  pending_misp=[]
  for row in rows:
   address=row['ip']
   cached=s.cached(address,'misp')
   if cached and snapshot.get('expires','')>now() and json.loads(cached['payload']).get('snapshot_generation')==snapshot.get('generation'):continue
   if snapshot.get('expires','')<=now():pending_misp.append((address,'misp',{'error':'Local indicator snapshot is unavailable or stale'},'failed',1))
   else:
    from analytics_store import events
    a=ipaddress.ip_address(address);hits=list(exact.get(address,[]))
    for mask,entries in prefix_index[a.version]:hits.extend(entries.get(int(a)&mask,[]))
    events(s,[('misp','local_query',address,1),('misp','match' if hits else 'no_match',address,1)])
    actionable=[h for h in hits if h.get('to_ids',True) in (True,1,'1')]
    hours=max(0,(dt.datetime.fromisoformat(snapshot['expires'])-dt.datetime.now(UTC)).total_seconds()-1)/3600
    pending_misp.append((address,'misp',{'matches':len(actionable),'context_matches':len(hits)-len(actionable),'attribute_ids':[h['id'] for h in hits[:20]],'sources':sorted({h.get('source','MISP indicator') for h in hits})[:8],'snapshot_generation':snapshot.get('generation'),'snapshot_fetched':snapshot['fetched'],'fresh_to_ids_and_warninglists_enforced':True,'score_contribution':25 if actionable else 0,'note':'Only fresh actionable intelligence adds points; context-only indicators add none; whitelist and crawler protection remain in force'},'ok',hours));checks+=1
   if len(pending_misp)>=256:s.cache_many(pending_misp);pending_misp=[]
  if pending_misp:s.cache_many(pending_misp)
  keys.pop('misp',None)
 # Expensive external enrichment is bounded and single-flight under the worker lock.
 pending=sorted(rows,key=lambda r:(-r['score'],r['ip']))
 for provider,key in keys.items():
  if not key or (provider=='misp' and not misp_enabled):continue
  providers[provider]='enabled; cached per IP with daily quota'
  # First-pass coverage precedes refreshes so high-score refreshes cannot starve new IPs.
  pending=sorted(rows,key=lambda r:(any(c['provider']==provider for c in r['cache_status']),min((c['fetched'] for c in r['cache_status'] if c['provider']==provider),default=''),-r['score'],r['ip']))
  today=dt.datetime.now(UTC).strftime('%Y-%m-%d');budget=s.state('quota:'+provider+':'+today) or 0;limit=200 if provider=='misp' else 25;done=0
  for row in pending:
   if done>=20 or budget>=limit:break
   address=row['ip']
   if s.cached(address,provider):continue
   # Commit claim before making the request; crashes cannot create an immediate duplicate.
   s.cache(address,provider,{},status='in-flight',hours=.25);budget+=1;s.state('quota:'+provider+':'+today,budget)
   try:
    if provider=='misp':
     r=requests.post(cfg['misp_url']+'/attributes/restSearch',headers={'Authorization':key,'Accept':'application/json'},json={'returnFormat':'json','value':address,'type':['ip-src','ip-dst'],'deleted':False,'limit':100},verify=cfg['misp_ca'],timeout=20);r.raise_for_status();v=r.json();attrs=v.get('response',{}).get('Attribute',[]) if isinstance(v.get('response'),dict) else v.get('response',[])
     payload={'matches':len(attrs),'to_ids_matches':sum(bool(a.get('to_ids')) for a in attrs),'attribute_ids':[a.get('id') for a in attrs[:20]],'note':'Intelligence match is context; requires freshness and analyst review before scoring'}
    elif provider=='abuseipdb':
     r=requests.get('https://api.abuseipdb.com/api/v2/check',headers={'Key':key,'Accept':'application/json'},params={'ipAddress':address,'maxAgeInDays':30},timeout=20);r.raise_for_status();v=r.json()['data'];payload={k:v.get(k) for k in ['abuseConfidenceScore','totalReports','lastReportedAt','isWhitelisted','usageType','isp']}
    elif provider=='virustotal':
     r=requests.get('https://www.virustotal.com/api/v3/ip_addresses/'+address,headers={'x-apikey':key},timeout=20);r.raise_for_status();v=r.json()['data']['attributes'];payload={k:v.get(k) for k in ['last_analysis_stats','last_analysis_date','reputation']}
    else:continue
    s.cache(address,provider,payload,hours=24 if provider=='misp' else 168)
   except (requests.RequestException,ValueError,KeyError) as e:s.cache(address,provider,{'error':type(e).__name__},status='failed',hours=1)
   done+=1;checks+=1
 s.state('provider_status',providers);return checks
def pipeline_timing(store,build_started,build_finished,manifest):
 """Measured batch input/publication bounds; no event-time or upstream-arrival proxy.

 Only changed non-Palo native upserts are counted. No IDs, paths, IPs, additional
 queries, receipt ledger, model calls or scoring inputs are introduced.
 """
 receipts=getattr(store,'_pipeline_receipts',{})
 if receipts.get('invalidated'):return {'status':'unmeasurable','reason':'transaction_rollback'}
 if not receipts:return {'status':'no_changed_native_evidence'}
 first,last=receipts['first'],receipts['last']
 out={'status':'published' if manifest else 'publication_pending','changed_native_upserts':receipts['changed_rows'],'first_normalized_input_received_utc':first[0],'last_normalized_input_received_utc':last[0],'boundary':'Manager Store.evidence input receipt through local atomic EDL generation; batch cohort, not individual block or source detector/network arrival','clock':'Same-process monotonic intervals; UTC receipt timestamps for correlation only'}
 if manifest:
  out.update(generation_created=manifest['created'],publication_return_observed_utc=dt.datetime.now(UTC).isoformat(timespec='microseconds'),build_seconds=round(build_finished-build_started,6),first_input_to_publication_seconds={'lower':round(max(0,build_started-first[1]),6),'upper':round(max(0,build_finished-first[1]),6)},last_input_to_publication_seconds={'lower':round(max(0,build_started-last[1]),6),'upper':round(max(0,build_finished-last[1]),6)})
 return out

def main():
 import sys
 fast='--ingest-only' in sys.argv;enrich_only='--enrich-only' in sys.argv
 cfg=json.loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text());s=Store(cfg['database'])
 with open(pathlib.Path(cfg['database']).parent/('ingest.lock' if fast else 'worker.lock'),'w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  started=now()
  s._pipeline_receipts={};s._worker_publication=None;s._worker_last_direct_commit=None
  anchor=sqlite3.connect(cfg['database']);anchor.execute('SELECT name FROM sqlite_master LIMIT 1').fetchall()
  s._worker_connection=anchor;s._batch_evidence=True
  phase='starting';maintenance={}
  try:
   phase='maintenance'
   from source_handoff import maintain as maintain_handoff
   from new_ips import maintain as maintain_arrivals
   from event_history import recover_audit
   for name,operation in (('handoff',lambda:maintain_handoff(s)),('arrivals',lambda:maintain_arrivals(s)),('audit',lambda:recover_audit(s,limit=5000))):maintenance[name]=operation()
   if fast:
    phase='collect'
    s.state('ingest_status',{'status':'running','started':started,'phase':'collecting and publishing','maintenance':maintenance})
    count=collect(s,cfg,include_palo=False)
    from source_types import refresh
    phase='source_types';refresh(s);phase='build';build_started=time.monotonic();m=s.build(cfg['output'],defer_if_busy=True);build_finished=time.monotonic()
    if m is None:logging.warning('Publication deferred: ingestion committed; another publisher is active. Retrying next cycle.')
    phase='success_status'
    coverage=s.state('native_ingest_coverage') or {'status':'complete'}
    s.state('ingest_status',{'status':('partial' if coverage['status']=='partial' else 'ok') if m else 'publication_pending','coverage':coverage,'started':started,'completed':now(),'evidence_buckets':count,'ingestion_committed':True,'publication':'published' if m else 'pending','generation':m['created'] if m else None,'maintenance':maintenance,'pipeline_timing':pipeline_timing(s,build_started,build_finished,m)})
    return
   s.state('worker_status',{'status':'running','phase':'collecting evidence','started':started,'mode':'production','maintenance':maintenance})
   phase='collect'
   count=collect(s,cfg,palo_only=enrich_only);s.state('worker_status',{'status':'running','phase':'cached enrichment','maintenance':maintenance,'started':started,'evidence_buckets':count,'mode':'production'})
   phase='enrich';checks=enrich(s,cfg)
   from source_types import refresh
   phase='source_types';refresh(s);s.state('worker_status',{'status':'running','phase':'building lists','maintenance':maintenance,'started':started,'evidence_buckets':count,'enrichment_checks':checks,'mode':'production'})
   phase='build';build_started=time.monotonic();m=s.build(cfg['output'],defer_if_busy=True);build_finished=time.monotonic()
   if m is None:logging.warning('Publication deferred: enrichment committed; another publisher is active. Retrying next cycle.')
   phase='success_status'
   s.state('worker_status',{'status':'ok' if m else 'publication_pending','started':started,'completed':now(),'evidence_buckets':count,'enrichment_checks':checks,'publication':'published' if m else 'pending','generation':m['created'] if m else None,'mode':'production','maintenance':maintenance,'pipeline_timing':pipeline_timing(s,build_started,build_finished,m)})
  except Exception as exc:
   from behavior_persistence import contention
   # This owner also covers direct commit and outside-connect failures. Never
   # let the status write commit earlier pending input from a failed unit.
   rolled_back=False
   try:anchor.rollback();rolled_back=True
   except Exception as rollback_error:
    logging.error('Native rollback failed type=%s',type(rollback_error).__name__)
   s._pipeline_receipts.clear();s._pipeline_receipts['invalidated']=True;s._evidence_pending=0
   published=s._worker_publication
   deferred=rolled_back and contention(exc)
   result={'status':'deferred' if deferred else 'error','maintenance':maintenance,'started':started,'completed':now(),'phase':phase,'error':type(exc).__name__,'sqlite_code':getattr(exc,'sqlite_errorcode',None),'last_direct_commit_boundary':s._worker_last_direct_commit,'pending_transaction':'rolled_back' if rolled_back else 'rollback_failed','prior_commits':'retained','publication':'published_bookkeeping_pending' if published else 'not_confirmed_this_pass','publication_boundary':'after_generation_swap' if published else 'before_generation_swap','pipeline_timing':{'status':'unmeasurable','reason':'transaction_rollback'}}
   if published:result['generation']=published['generation']
   if deferred:result['retry']='next_normal_pass'
   status_error=None
   try:
    # If rollback itself failed, no write on that handle is safe.
    if rolled_back:s.state('ingest_status' if fast else 'worker_status',result)
   except Exception as secondary:
    status_error=secondary
    logging.error('Native status persistence failed type=%s sqlite_code=%s',type(secondary).__name__,getattr(secondary,'sqlite_errorcode',None))
   logging.warning('Native pass incomplete status=%s phase=%s type=%s sqlite_code=%s last_direct_commit=%s pending_transaction=%s publication_boundary=%s publication=%s',result['status'],phase,type(exc).__name__,getattr(exc,'sqlite_errorcode',None),s._worker_last_direct_commit,result['pending_transaction'],result['publication_boundary'],result['publication'])
   if deferred and (status_error is None or contention(status_error)):return result
   # Preserve the primary exception, even when recording it also failed.
   raise
  finally:s._worker_connection=None;s._batch_evidence=False;s._evidence_pending=0;anchor.close()
if __name__=='__main__':main()
