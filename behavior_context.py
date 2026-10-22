"""Read-only, allowlisted context for behavioral inspection; never scoring input."""
import datetime as dt,hashlib,ipaddress,json,time,sqlite3
from behavior_ai import safe_text,timestamp,digest
from core import now

def count(value):
 try:return max(0,min(1000000000,int(value or 0)))
 except (ValueError,TypeError,OverflowError):return 0

def flag(value):return value if isinstance(value,bool) else None

def destination(value):
 try:
  a=ipaddress.ip_address(str(value))
  if a.is_global:return {'scope':'public','address':str(a)}
  if a.is_unspecified or a.is_multicast:return {'scope':'unknown'}
  return {'scope':'internal','asset_id':'asset_'+hashlib.sha256(str(a).encode()).hexdigest()[:16]}
 except ValueError:return {'scope':'unknown'}

def reference(kind,value):return {'id':'ctx_'+digest([kind,value])[:24],'kind':kind,**value}

def misp_indicators(store,snapshot,ids):
 """Index the already cached snapshot once; preserve its first-match ordering.

 Only the first twelve positions per sanitized ID can contribute to a twelve-
 item result. A packet reads at most twelve ID groups, never the whole snapshot.
 The shared index contains references to existing snapshot entries, not copies
 of provider bodies; a newly loaded snapshot replaces it.
 """
 if not ids:return []
 cached=getattr(store,'_behavior_misp_lookup',None)
 if cached is None or cached[0] is not snapshot:
  lookup={}
  for position,attribute in enumerate(snapshot.get('attributes',[])):
   group=lookup.setdefault(safe_text(attribute.get('id'),60),[])
   if len(group)<12:group.append((position,attribute))
  cached=(snapshot,lookup);store._behavior_misp_lookup=cached
 matched=sorted((position,a) for ident in ids for position,a in cached[1].get(ident,()))[:12]
 return [{'attribute_id':safe_text(a.get('id'),60),'event_id':safe_text(a.get('event_id'),60),'origin':safe_text(a.get('source'),100),'to_ids':a.get('to_ids') in (True,1,'1'),'updated_epoch':count(a.get('timestamp'))} for _,a in matched]

def context(store,row,source_cfg=None,at=None):
 at=at or dt.datetime.now(dt.timezone.utc);current=at.isoformat(timespec='seconds');result=[]
 cache={};status={}
 # Native score views intentionally omit expired payloads; analysis must label them as stale.
 with store.connect(commit=False) as db:
  for item in db.execute('SELECT provider,payload,status,fetched,expires FROM cache WHERE ip=?',(row['ip'],)):
   try:payload=json.loads(item['payload'])
   except (ValueError,TypeError):continue
   if isinstance(payload,dict):cache[item['provider']]=payload;status[item['provider']]=dict(item)
 for provider in ('misp','greynoise','crawler','asn','abuseipdb','virustotal','palo'):
  if provider not in cache:continue
  p=cache[provider];meta=status.get(provider,{})
  if not isinstance(p,dict):continue
  value={'provider':provider,'status':safe_text(meta.get('status'),30),'fetched':meta.get('fetched'),'expires':meta.get('expires'),'cache_fresh':meta.get('status')=='ok' and bool(timestamp(meta.get('expires')) and timestamp(meta['expires'])>at)}
  if provider=='misp':
   value.update(actionable_matches=count(p.get('matches')),context_matches=count(p.get('context_matches')),attribute_ids=[safe_text(v,60) for v in (p.get('attribute_ids') or [])[:12]],origins=[safe_text(v,100) for v in (p.get('sources') or [])[:6]],snapshot_generation=safe_text(p.get('snapshot_generation'),80),snapshot_fetched=p.get('snapshot_fetched'),actionable_filter_applied=p.get('fresh_to_ids_and_warninglists_enforced') is True)
   # An enforced upstream filter does not reveal which warning lists were evaluated.
   value['warning_list_details']='not supplied by the existing cache'
   value['origin_independence']='unknown; an imported feed may duplicate another provider'
   if not hasattr(store,'_behavior_misp_snapshot') or time.monotonic()-getattr(store,'_behavior_misp_snapshot_at',0)>60:
    store._behavior_misp_snapshot=store.state('misp_snapshot') or {};store._behavior_misp_snapshot_at=time.monotonic();store._behavior_misp_lookup=None
   snapshot=store._behavior_misp_snapshot;ids=set(value['attribute_ids'])
   value['indicators']=misp_indicators(store,snapshot,ids)
   value['snapshot_current']=bool(timestamp(snapshot.get('expires')) and timestamp(snapshot['expires'])>at and snapshot.get('generation')==p.get('snapshot_generation'))
  elif provider=='greynoise':
   from greynoise_enrichment import observed_fresh
   value.update(classification=p.get('classification') if p.get('classification') in ('benign','malicious','suspicious','unknown') else 'unknown',found=flag(p.get('found')),noise=flag(p.get('noise')),riot=flag(p.get('riot')),actor=safe_text(p.get('name'),100),last_seen=p.get('last_seen'),observation_fresh=observed_fresh(p,at))
  elif provider=='crawler':value.update(verified=p.get('verified') is True,operator=safe_text(p.get('operator') or p.get('name'),100))
  elif provider=='asn':value.update(asn=safe_text(p.get('asn'),20),organization=safe_text(p.get('organization'),120),database_build_epoch=p.get('database_build_epoch'),ownership_is_maliciousness=False)
  elif provider=='abuseipdb':value.update(confidence=count(p.get('abuseConfidenceScore')),reports=count(p.get('totalReports')),last_report=p.get('lastReportedAt'))
  elif provider=='virustotal':value.update(malicious_engines=count((p.get('last_analysis_stats') or {}).get('malicious')),suspicious_engines=count((p.get('last_analysis_stats') or {}).get('suspicious')))
  else:value.update(alert_records=count(p.get('alert_records')),drops=count(p.get('drops')),drop_is_independent_attack_evidence=False)
  result.append(reference('intelligence',value))
 address=row['ip']
 with store.connect(commit=False) as db:
  block=db.execute('SELECT * FROM offender_blocks WHERE ip=?',(address,)).fetchone()
  returns=[dict(r) for r in db.execute('SELECT source,sensor,seen,previous_score,bonus,policy_event FROM offender_returns WHERE ip=? AND seen>=? ORDER BY seen DESC LIMIT 1000',(address,(at-dt.timedelta(days=365)).isoformat(timespec='seconds')))]
  policy=[dict(r) for r in db.execute("SELECT at,action,details FROM policy_events WHERE kind='ip' AND target=? ORDER BY at DESC LIMIT 12",(address,))]
 if block:
  history={k:block[k] for k in ('first_blocked','last_blocked','last_native_seen','previous_score')}
  history.update(returns_by_window={str(days):sum(r['seen']>=(at-dt.timedelta(days=days)).isoformat(timespec='seconds') and bool(r['policy_event']) for r in returns) for days in (30,60,90,180,365)},returns_limited=len(returns)==1000,latest_returns=[{'source':safe_text(r['source'],30),'sensor':safe_text(r['sensor'],60),'seen':r['seen'],'native_policy_event':bool(r['policy_event'])} for r in returns[:5]],interpretation='Historical policy context; previous blocking does not prove a new attack')
  result.append(reference('block_history',history))
 for item in policy:
  details=json.loads(item['details'])
  result.append(reference('policy_history',{'seen':item['at'],'action':safe_text(item['action'],60),'list':safe_text(details.get('list'),60)}))
 # Reuse the investigation cache under the currently configured collector scope.
 if source_cfg is not None:
  from source_settings import effective
  cfg=effective(store,source_cfg)
  if cfg.get('index_url') and cfg.get('palo_location'):
   scope=hashlib.sha256((cfg['index_url']+'|'+cfg['palo_location']).encode()).hexdigest()[:16]
   saved=store.state('ip_activity:'+scope+':'+address) or {};fetched=timestamp(saved.get('fetched'))
   events=[]
   for e in saved.get('events',[]):
    seen=timestamp(e.get('seen'))
    if not seen or not at-dt.timedelta(days=30)<=seen<=at+dt.timedelta(minutes=5):continue
    events.append({'seen':seen.isoformat(timespec='seconds'),'action':safe_text(e.get('action'),40),'application':safe_text(e.get('sensor'),50),'port':safe_text(e.get('port'),8),'destination':destination(e.get('destination')),'nat_destination':destination(e.get('nat')),'rule':safe_text(e.get('rule'),100),'zone':safe_text(e.get('zone'),50),'reason':safe_text(e.get('reason'),100)})
   result.append(reference('palo_history',{'status':safe_text(saved.get('status') or 'not_cached',30),'fetched':saved.get('fetched'),'cache_fresh':bool(saved.get('status')=='ok' and fetched and 0<=(at-fetched).total_seconds()<300),'total_records':count(saved.get('total')),'available_saved_events':len(events),'sampled_events':events[:8],'destinations_limited':bool(saved.get('destinations_limited')),'drop_is_independent_attack_evidence':False,'coverage':'saved investigation samples; not a complete session history'}))
 # Preserve native-event space even when caches contain many indicators or policy records.
 while len(json.dumps(result).encode())>6500:
  removed=False
  for item in reversed(result):
   for key,minimum in [('sampled_events',2),('indicators',3),('attribute_ids',3),('origins',2),('latest_returns',2)]:
    if isinstance(item.get(key),list) and len(item[key])>minimum:item[key].pop();item['limited']=True;removed=True;break
   if removed:break
  if not removed:
   policy=next((v for v in reversed(result) if v['kind']=='policy_history'),None)
   if policy:result.remove(policy);removed=True
  if not removed:break
 for item in result:
  if item['kind']=='palo_history':item['included_events']=len(item['sampled_events'])
  item['id']='ctx_'+digest({k:v for k,v in item.items() if k!='id'})[:24]
 return result

def refresh_palo(store,source_cfg,address,budget,fetcher=None):
 """Reuse the existing exact-IP investigation cache; bounded read-only network work."""
 from source_settings import effective
 cfg=effective(store,source_cfg)
 if not cfg.get('index_url') or not cfg.get('palo_location') or not cfg.get('index_user') or not cfg.get('index_password'):return 'not_configured'
 scope=hashlib.sha256((cfg['index_url']+'|'+cfg['palo_location']).encode()).hexdigest()[:16];key='ip_activity:'+scope+':'+address
 at=dt.datetime.now(dt.timezone.utc);saved=store.state(key) or {};fetched=timestamp(saved.get('fetched'));pending=store.state('ip_activity_pending:'+key) or {};started=timestamp(pending.get('started'))
 if fetched and 0<=(at-fetched).total_seconds()<(3600 if saved.get('status')=='error' else 300):return 'cached'
 if started and 0<=(at-started).total_seconds()<90:return 'pending'
 from activity import claim_activity
 try:claimed=claim_activity(store,key,'behavior_palo_usage:'+at.date().isoformat(),budget,busy_timeout_ms=250)
 except sqlite3.OperationalError as exc:
  from behavior_persistence import contention
  if not contention(exc):raise
  return 'busy_retry_next_pass'
 if claimed!='claimed':return claimed
 try:
  if fetcher is None:
   from activity import fetch
   fetcher=fetch
  store.state(key,fetcher(cfg,address));return 'refreshed'
 except Exception:
  store.state(key,{**saved,'status':'error','fetched':now()});return 'failed'
 finally:store.state('ip_activity_pending:'+key,{})
