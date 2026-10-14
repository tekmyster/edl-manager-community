"""Read-only investigation data. This cache never contributes to scoring or TTLs."""
import datetime as dt,hashlib,ipaddress,json,ssl,threading,time
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from core import ip,now

UTC=dt.timezone.utc
FIELDS=['source_address','destination_address','destination_port','nat_destination_ip','nat_destination_port','source_zone','destination_zone','application','action','rule_name','protocol','high_resolution_timestamp','session_id','session_end_reason','bytes_sent','bytes_received','srcip','dstip','dstport','edl_source','edl_detector','edl_seen_utc','edl_dst_ports','edl_activity_json']

def timestamp(value):
 try:
  v=dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
  if v.tzinfo is None:return None
  return v.astimezone(UTC)
 except (ValueError,TypeError):return None

def address(value):
 try:
  a=ipaddress.ip_address(str(value))
  return '' if a.is_unspecified else str(a)
 except ValueError:return ''

def normalize(hit,target):
 s=hit.get('_source',{});d=s.get('data',{})
 if d.get('source_address')!=target:return None
 seen=timestamp(d.get('high_resolution_timestamp'))
 if not seen:return None
 return {'id':hit.get('_id',''),'seen':seen.isoformat(timespec='seconds'),'source':'Palo','sensor':d.get('application',''),'action':d.get('action',''),'destination':address(d.get('destination_address')),'port':str(d.get('destination_port','')),'nat':address(d.get('nat_destination_ip')),'nat_port':str(d.get('nat_destination_port','')),'path':'','rule':d.get('rule_name',''),'zone':d.get('destination_zone',''),'protocol':d.get('protocol',''),'session':str(d.get('session_id','')),'reason':d.get('session_end_reason',''),'time_basis':'Native event'}

def local_activity(row):
 events=[];summaries=[];keys=set();ids=set();cut=dt.datetime.now(UTC)-dt.timedelta(days=30)
 for e in row.get('activity',[])+row['evidence']:
  d=json.loads(e['details']) if isinstance(e['details'],str) else e['details']
  try:a=json.loads(d.get('activity','{}')) if isinstance(d.get('activity'),str) else d.get('activity',{})
  except (ValueError,TypeError):a={}
  key=(e['source'],e['sensor'])
  if e['source'] in ['crowdsec','wazuh'] and not a.get('events'):
   a={**a,'events':[{'id':e.get('id',''),'seen':e['seen'],'action':d.get('detector') or d.get('description') or 'Qualifying alert','destination':'','port':'','path':''}]}
  if key not in keys:
   keys.add(key);summaries.append({'source':e['source'],'sensor':e['sensor'],'last':e['seen'],'attempts':d.get('native_attempt_count'),'records':d.get('native_event_count'),'ports':d.get('destination_ports',[]),'actions':a.get('actions',[]),'paths':a.get('paths',[])})
  for v in a.get('events',[]):
   if not isinstance(v,dict):continue
   t=timestamp(v.get('seen'))
   if not t or t<cut or t>dt.datetime.now(UTC)+dt.timedelta(minutes=5):continue
   ident=(e['source'],e['sensor'],v.get('id'),v.get('seen'),v.get('action'))
   if ident in ids:continue
   ids.add(ident);events.append({**v,'seen':t.isoformat(timespec='seconds'),'source':e['source'],'sensor':e['sensor'],'nat':'','nat_port':'','rule':'','zone':'','time_basis':'Native event'})
 return events,summaries

def fetch(cfg,target):
 """Bounded Palo query; exact source match, all actions, native 30-day time window."""
 end=dt.datetime.now(UTC);cut=end-dt.timedelta(days=30)
 native={'script':{'script':{'lang':'painless','source':"if (!doc.containsKey('data.high_resolution_timestamp') || doc['data.high_resolution_timestamp'].size()==0) return false; try { long t=java.time.OffsetDateTime.parse(doc['data.high_resolution_timestamp'].value).toInstant().toEpochMilli(); return t>=params.cut && t<=params.end; } catch(Exception e) { return false; }",'params':{'cut':int(cut.timestamp()*1000),'end':int(end.timestamp()*1000)}}}}
 q={'size':1000,'track_total_hits':True,'sort':[{'timestamp':'desc'}],'_source':['data.'+f for f in FIELDS],'query':{'bool':{'filter':[{'term':{'location':cfg.get('palo_location','')}},{'term':{'data.source_address':target}},{'range':{'timestamp':{'gte':cut.isoformat()}}},native]}},'aggs':{'destinations':{'composite':{'size':500,'sources':[{k:{'terms':{'field':'data.'+f,'missing_bucket':True}}} for k,f in [('destination','destination_address'),('port','destination_port'),('nat','nat_destination_ip'),('nat_port','nat_destination_port'),('application','application'),('action','action'),('zone','destination_zone')]]},'aggs':{'first':{'min':{'field':'timestamp'}},'last':{'max':{'field':'timestamp'}}}}}}
 context=ssl.create_default_context(cafile=cfg['index_ca'] if isinstance(cfg['index_ca'],str) else None);context.verify_flags &= ~ssl.VERIFY_X509_STRICT
 class TLS(HTTPAdapter):
  def init_poolmanager(self,*a,**k):k['ssl_context']=context;return super().init_poolmanager(*a,**k)
  def build_connection_pool_key_attributes(self,r,v,c=None):h,k=super().build_connection_pool_key_attributes(r,v,c);k['ssl_context']=context;return h,k
 with requests.Session() as s:
  s.auth=(cfg['index_user'],cfg['index_password']);s.verify=cfg['index_ca'];s.mount(cfg['index_url'],TLS())
  r=s.post(cfg['index_url']+'/wazuh-alerts-*/_search',json=q,timeout=(5,40));r.raise_for_status();v=r.json()
 if v.get('timed_out') or v.get('_shards',{}).get('failed'):raise RuntimeError('Incomplete investigation query')
 events=[normalize(h,target) for h in v['hits']['hits']];events=[e for e in events if e]
 agg=v.get('aggregations',{}).get('destinations',{});destinations=[]
 for b in agg.get('buckets',[]):
  k=b['key'];destinations.append({**k,'destination':address(k.get('destination')),'nat':address(k.get('nat')),'count':b['doc_count']})
 return {'events':events,'destinations':destinations,'total':v['hits']['total']['value'],'destinations_limited':bool(agg.get('after_key')) and len(destinations)>=500,'fetched':now(),'cutoff':cut.isoformat(),'status':'ok'}

class ActivityCache:
 def __init__(self,store,cfg):self.store=store;self.cfg=cfg;self.pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='ip-investigation');self.lock=threading.Lock();self.pending=set()
 def get(self,target):
  target=str(ip(target));cfg=dict(self.cfg);scope=hashlib.sha256((cfg.get('index_url','')+'|'+cfg.get('palo_location','')).encode()).hexdigest()[:16];key='ip_activity:'+scope+':'+target;data=self.store.state(key) or {}
  fetched=timestamp(data.get('fetched'));fresh=fetched and (dt.datetime.now(UTC)-fetched).total_seconds()<300
  pending=self.store.state('ip_activity_pending:'+key) or {}
  active=timestamp(pending.get('started'));active=active and (dt.datetime.now(UTC)-active).total_seconds()<90
  if not fresh and not active and (self.cfg.get('index_url') and self.cfg.get('palo_location')):
   with self.lock:
    if key not in self.pending and len(self.pending)<8:
     self.pending.add(key);self.store.state('ip_activity_pending:'+key,{'started':now()});self.pool.submit(self.refresh,target,cfg,key)
     active=True
  return {**data,'loading':bool(active),'enabled':bool((self.cfg.get('index_url') and self.cfg.get('palo_location')))}
 def refresh(self,target,cfg=None,key=None):
  cfg=cfg or dict(self.cfg);key=key or 'ip_activity:'+target
  try:self.store.state(key,fetch(cfg,target))
  except Exception:
   previous=self.store.state(key) or {}
   self.store.state(key,{**previous,'status':'error','fetched':now()})
  finally:
   self.store.state('ip_activity_pending:'+key,{} )
   with self.lock:self.pending.discard(key)
