"""Derived redacted local history. Never writes native evidence or retention."""
import datetime as dt,json,re
from behavior_ai import digest,timestamp,safe_text,path_shape
from behavior_context import destination
from web_client import request_structure

SCHEMA='''
CREATE TABLE IF NOT EXISTS event_history(id TEXT NOT NULL,ip TEXT NOT NULL,source TEXT NOT NULL,sensor TEXT NOT NULL,seen TEXT NOT NULL,received TEXT NOT NULL,scope TEXT NOT NULL,content TEXT NOT NULL,PRIMARY KEY(id,scope));
CREATE INDEX IF NOT EXISTS event_history_ip_time ON event_history(ip,seen,id);
CREATE TABLE IF NOT EXISTS history_queries(ip TEXT PRIMARY KEY,scope TEXT NOT NULL,fetched TEXT NOT NULL,content TEXT NOT NULL);
'''

def initialize(db):db.executescript(SCHEMA)

def normalize(address,source,sensor,sample,received):
 if not isinstance(sample,dict):return None
 seen=timestamp(sample.get('seen'));arrival=timestamp(received)
 if not seen or not arrival or not arrival-dt.timedelta(days=30)<=seen<=arrival+dt.timedelta(minutes=5):return None
 path,names=path_shape(sample.get('path',''))
 # New sensors supply names separately after removing original query values.
 supplied=sample.get('parameter_names',names)
 names=request_structure('/?'+ '&'.join(str(v)+'=' for v in supplied[:12]))['parameter_names'] if isinstance(supplied,list) else names
 parameter_count=sample.get('parameter_count',len(names));parameter_count=parameter_count if type(parameter_count) is int and 0<=parameter_count<=32 else len(names)
 method=str(sample.get('method','')).upper();status=str(sample.get('status',''));port=str(sample.get('port',''))
 value={'seen':seen.isoformat(),'source':safe_text(source,30),'sensor':safe_text(sensor,60),'action':safe_text(sample.get('action'),80),'path':path,'parameter_names':names,'parameter_count':parameter_count,'method':method if method in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','CONNECT') else '', 'status':status if status.isdigit() and 100<=int(status)<=599 else '', 'port':port if port.isdigit() and 1<=int(port)<=65535 else '', 'destination':destination(sample.get('destination')),'client_type':safe_text(sample.get('client_type'),50),'independent_evidence':False,'native_attempts':0,'native_records':0}
 # Cached/forwarded history is conservatively ineligible for pilot points. Native
 # row samples retain their existing explicit novelty checks in the packet builder.
 metadata=sample.get('http_metadata',{})
 if isinstance(metadata,dict):
  value['http_metadata']={k:v for k,v in metadata.items() if (k=='protocol' and v in ('HTTP/1.0','HTTP/1.1','HTTP/2','HTTP/3')) or (k=='content_type' and v in ('application/json','application/x-www-form-urlencoded','multipart/form-data','text/plain','application/xml','text/xml'))}
 origin=opaque_id(sample.get('id'))
 value['provenance']={'upstream_id':origin,'collector':'configured index' if sample.get('_index_id') else 'saved source sample','collector_agent':safe_text(sample.get('_agent'),100),'record_id':opaque_id(sample.get('_index_id')),'index':opaque_id(sample.get('_index')),'indexed_at':timestamp(sample.get('_indexed_at')).isoformat() if timestamp(sample.get('_indexed_at')) else None,'time_basis':'native event','detail':'summary' if sample.get('_summary') else 'sample'}
 value['id']='hist_'+digest([address,value['source'],value['sensor'],origin,value['seen'],path,value['method'],value['status'],value['destination'],value['port'],value['action']])[:24]
 return value

def save(brain,address,source,sensor,samples,received,scope=""):
 with brain.connect() as db:
  for sample in samples[:500]:
   event=normalize(address,source,sensor,sample,received)
   if event:
    db.execute('INSERT OR IGNORE INTO event_history VALUES(?,?,?,?,?,?,?,?)',(event['id'],address,event['source'],event['sensor'],event['seen'],received,scope,json.dumps(event)))
    if event['provenance']['record_id']:
     prior=json.loads(db.execute('SELECT content FROM event_history WHERE id=? AND scope=?',(event['id'],scope)).fetchone()[0])
     if not prior['provenance'].get('record_id'):
      prior['provenance']=event['provenance'];db.execute('UPDATE event_history SET content=? WHERE id=? AND scope=?',(json.dumps(prior),event['id'],scope))

def cache_rows(brain,row,at,source_cfg=None):
 received=at.isoformat(timespec='seconds');scope=collection_scope(brain,source_cfg)
 allowed=active_sources(brain,source_cfg)
 for record in row.get('evidence',[])+row.get('activity',[]):
  if allowed is not None and record.get('source') not in allowed:continue
  try:
   details=record.get('details',{});details=json.loads(details) if isinstance(details,str) else details
   activity=details.get('activity',{});activity=json.loads(activity) if isinstance(activity,str) else activity
  except (ValueError,TypeError,AttributeError):continue
  if not isinstance(activity,dict):continue
  save(brain,row['ip'],record['source'],record['sensor'],activity.get('events',[]),received,scope)

def query(brain,address,at,limit=200,offset=0,source_cfg=None):
 cut=(at-dt.timedelta(days=30)).isoformat(timespec='seconds');end=(at+dt.timedelta(minutes=5)).isoformat(timespec='seconds')
 where='ip=? AND seen>=? AND seen<=?';args=[address,cut,end]
 if source_cfg is not None:
  from source_settings import effective
  cfg=effective(brain.store,source_cfg);enabled=cfg.get('source_agents',{}) if cfg.get('index_url') else {}
  scopes=[(source,sensor) for source,sensor in enabled.items() if sensor]
  filters=[]
  where+=' AND scope=?';args.append(collection_scope(brain,source_cfg))
  for source,sensor in scopes:
   filters.append('(source=?)');args.append(source)
  if cfg.get('index_url') and cfg.get('palo_location'):filters.append('(source=?)');args.append('palo')
  where+=' AND ('+(' OR '.join(filters) or '0')+')'
 with brain.connect() as db:
  total=db.execute('SELECT count(*) FROM event_history WHERE '+where,args).fetchone()[0]
  rows=db.execute('SELECT content,received FROM event_history WHERE '+where+' ORDER BY seen DESC,id LIMIT ? OFFSET ?',args+[max(1,min(200,limit)),max(0,offset)]).fetchall()
  saved=db.execute('SELECT content,scope FROM history_queries WHERE ip=?',(address,)).fetchone()
  if saved and source_cfg is not None and saved['scope']!=collection_scope(brain,source_cfg):saved=None
 events=[{**json.loads(r['content']),'received':r['received']} for r in rows]
 return {'events':events,'total':total,'offset':max(0,offset),'limited':total>max(0,offset)+len(events),'collection':json.loads(saved[0]) if saved else {'status':'not_queried'},'coverage':'partial','tls_fingerprints':'unavailable','header_order_fingerprints':'unavailable','receipt_basis':'first cached by EDL Manager; upstream indexing time is separate where supplied'}

def fetch(cfg,address):
 """One bounded exact-IP read of configured sources; upstream summaries stay partial."""
 import requests,ssl
 from requests.adapters import HTTPAdapter
 sources=[{'bool':{'filter':[{'term':{'data.edl_source':s}}]+([] if agent=='*' else [{'term':{'agent.name':agent}}])}} for s,agent in cfg.get('source_agents',{}).items() if agent]
 filters=[{'range':{'timestamp':{'gte':'now-30d'}}},{'term':{'data.srcip':address}}]
 general=cfg.get('source_agents',{}).get('wazuh')
 if general:sources.append({'bool':{'filter':[{'range':{'rule.level':{'gte':8}}}]+([] if general=='*' else [{'term':{'agent.name':general}}]),'must_not':[{'exists':{'field':'data.edl_source'}}]}})
 if not sources:return [],{'status':'not_configured'}
 q={'size':500,'track_total_hits':True,'sort':[{'timestamp':'desc'}],'_source':['timestamp','agent.name','rule.id','rule.description','data.edl_source','data.edl_detector','data.edl_seen_utc','data.edl_activity_json','data.dstip','data.dstport'],'query':{'bool':{'filter':filters,'should':sources,'minimum_should_match':1}}}
 context=ssl.create_default_context(cafile=cfg['index_ca']);context.verify_flags &= ~ssl.VERIFY_X509_STRICT
 class TLS(HTTPAdapter):
  def init_poolmanager(self,*a,**kw):kw['ssl_context']=context;return super().init_poolmanager(*a,**kw)
  def build_connection_pool_key_attributes(self,r,v,c=None):h,k=super().build_connection_pool_key_attributes(r,v,c);k['ssl_context']=context;return h,k
 with requests.Session() as session:
  session.auth=(cfg['index_user'],cfg['index_password']);session.verify=cfg['index_ca'];session.mount(cfg['index_url'],TLS())
  response=session.post(cfg['index_url']+'/wazuh-alerts-*/_search',json=q,timeout=(5,40));response.raise_for_status();result=response.json()
 if result.get('timed_out') or result.get('_shards',{}).get('failed'):raise RuntimeError('Incomplete history query')
 records=[]
 for hit in result['hits']['hits']:
  native=hit.get('_source',{});data=native.get('data',{});source=data.get('edl_source','wazuh');sensor=data.get('edl_detector','').split(':')[0] or 'rule:'+str(native.get('rule',{}).get('id',''))
  activity=data.get('edl_activity_json',{});
  try:activity=json.loads(activity) if isinstance(activity,str) else activity
  except (ValueError,TypeError):activity={}
  samples=activity.get('events',[]) if isinstance(activity,dict) else []
  if not samples:samples=[{'id':hit['_id'],'seen':data.get('edl_seen_utc') or native.get('timestamp'),'action':data.get('edl_detector') or 'Wazuh rule '+str(native.get('rule',{}).get('id','')),'destination':data.get('dstip'),'port':data.get('dstport'),'_summary':True}]
  records.append((source,sensor,[{**sample,'_agent':native.get('agent',{}).get('name',''),'_index_id':hit['_id'],'_index':hit.get('_index',''),'_indexed_at':native.get('timestamp')} for sample in samples[:50] if isinstance(sample,dict)]))
 total=result['hits']['total'];total=total.get('value',0) if isinstance(total,dict) else total
 return records,{'status':'ok','matching_index_records':total,'read_index_records':len(result['hits']['hits']),'query_limited':total>len(result['hits']['hits']),'upstream_coverage':'sampled summaries; full requests unavailable'}

def refresh(brain,address,source_cfg,at,fetcher=None):
 from source_settings import effective
 from activity import claim_activity
 cfg=effective(brain.store,source_cfg)
 if not cfg.get('index_url') or not any(cfg.get('source_agents',{}).values()) or not all(cfg.get(k) for k in ('index_user','index_password','index_ca')):return 'not_configured'
 scope=digest([cfg['index_url'],cfg.get('source_agents',{}),cfg.get('palo_location','')]);current=at.isoformat(timespec='seconds')
 with brain.connect() as db:
  prior=db.execute('SELECT * FROM history_queries WHERE ip=?',(address,)).fetchone()
  if prior and prior['scope']==scope and timestamp(prior['fetched']) and (at-timestamp(prior['fetched'])).total_seconds()<(3600 if json.loads(prior['content'])['status']=='error' else 300):return 'cached'
 key='history_query:'+scope+':'+address
 state=claim_activity(brain.store,key,'behavior_history_usage:'+at.date().isoformat(),100)
 if state!='claimed':return state
 try:
  records,meta=(fetcher or fetch)(cfg,address)
  for source,sensor,samples in records:save(brain,address,source,sensor,samples,current,scope)
  meta.update(fetched=current,coverage='partial')
  with brain.connect() as db:db.execute('INSERT OR REPLACE INTO history_queries VALUES(?,?,?,?)',(address,scope,current,json.dumps(meta)))
  return 'refreshed'
 except Exception:
  with brain.connect() as db:db.execute('INSERT OR REPLACE INTO history_queries VALUES(?,?,?,?)',(address,scope,current,json.dumps({'status':'error','fetched':current,'coverage':'partial'})))
  return 'failed'
 finally:brain.store.state('ip_activity_pending:'+key,{})

def cleanup(brain,at):
 # Bounded deletion, independent of native retention; no unbounded browser work.
 with brain.connect() as db:db.execute('DELETE FROM event_history WHERE rowid IN (SELECT rowid FROM event_history WHERE seen<? ORDER BY seen LIMIT 5000)',((at-dt.timedelta(days=30)).isoformat(timespec='seconds'),))


def collection_scope(brain,source_cfg):
 if source_cfg is None:return ''
 from source_settings import effective
 cfg=effective(brain.store,source_cfg)
 return digest([cfg.get('index_url',''),cfg.get('source_agents',{}),cfg.get('palo_location','')])

def cache_palo(brain,address,source_cfg,at):
 if source_cfg is None:return
 import hashlib
 from source_settings import effective
 cfg=effective(brain.store,source_cfg)
 if not cfg.get('index_url') or not cfg.get('palo_location'):return
 scope=hashlib.sha256((cfg['index_url']+'|'+cfg['palo_location']).encode()).hexdigest()[:16]
 saved=brain.store.state('ip_activity:'+scope+':'+address) or {}
 groups={}
 for sample in saved.get('events',[])[:1000]:groups.setdefault(sample.get('sensor',''),[]).append(sample)
 for sensor,samples in groups.items():
  for start in range(0,len(samples),500):save(brain,address,'palo',sensor,samples[start:start+500],saved.get('fetched') or at.isoformat(timespec='seconds'),collection_scope(brain,source_cfg))


def opaque_id(value):
 value=str(value or '')
 return value if re.fullmatch(r'[A-Za-z0-9_.:/+=-]{1,120}',value) else ('ref_'+digest(value)[:24] if value else '')


def active_sources(brain,source_cfg):
 if source_cfg is None:return None
 from source_settings import effective
 cfg=effective(brain.store,source_cfg)
 return {source for source,agent in cfg.get('source_agents',{}).items() if agent} if cfg.get('index_url') else set()


def representative(events,limit=40):
 """Place time endpoints first so byte truncation still retains a useful span."""
 if len(events)<2:return list(events)
 chosen=[0,len(events)-1]
 while len(chosen)<min(limit,len(events)):
  candidates=set(range(len(events)))-set(chosen)
  chosen.append(max(candidates,key=lambda i:(min(abs(i-j) for j in chosen),-i)))
 return [events[i] for i in chosen]
