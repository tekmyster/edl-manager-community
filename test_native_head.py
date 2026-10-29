"""Synthetic native documents, real Store/normal worker; no network or models."""
import copy, datetime as dt, json, sqlite3, hashlib
import pytest, requests
import native_ingestion as n
from core import Store
from worker import ingest_source
UTC=dt.timezone.utc
NOW=dt.datetime.now(UTC).replace(hour=12,minute=0,second=0,microsecond=0)-dt.timedelta(days=1)
CFG={'index_url':'https://fixture.invalid','source_agents':{'waf':'*','tpot':'Collector','wazuh':'*'},'collected_fields':[],'palo_location':''}

@pytest.fixture(autouse=True)
def deny_network(monkeypatch):
 import socket
 def denied(*a,**k):raise AssertionError('Synthetic tests forbid external connections')
 monkeypatch.setattr(socket.socket,'connect',denied)

class Memory:
 def __init__(self):self.values={}
 def state(self,key,*value):
  if value:self.values[key]=copy.deepcopy(value[0])
  return copy.deepcopy(self.values.get(key))

class Response:
 def __init__(self,value):self.value=value;self.closed=False
 def raise_for_status(self):pass
 def iter_content(self,size):yield json.dumps(self.value).encode()
 def close(self):self.closed=True

def event_id(ident):return hashlib.sha256(ident.encode()).hexdigest()

def document(ident,seen=None,stamp=None,qual='no',address='8.8.4.4',source='waf',detector='coraza-interruption',agent='Collector'):
 seen=seen or NOW-dt.timedelta(hours=16);stamp=stamp or NOW-dt.timedelta(minutes=1)
 data={'srcip':address,'edl_source':source,'edl_detector':detector,'edl_pipeline':'tekmyster-edl30-v1','edl_seen_utc':seen.isoformat(),'edl_event_id':event_id(ident),'edl_qualifying':qual,'edl_path_hashes':'a'*24,'edl_activity_json':json.dumps({'events':[{'id':ident,'seen':seen.isoformat(),'method':'POST','host':'fixture.example','path':'/form','action':'HTTP request'}]})}
 return {'_id':ident,'_source':{'data':data,'timestamp':stamp.isoformat(),'rule':{'id':'119902' if qual=='no' else '119900'},'agent':{'name':agent}}}

class Session:
 def __init__(self,documents=()):self.documents=list(documents);self.calls=[];self.head_error=None;self.old_error=None;self.saturate=False;self.responses=[]
 def post(self,url,json,**kw):
  self.calls.append((url,copy.deepcopy(json),kw))
  assert kw=={'timeout':(3,8),'stream':True} and json['timeout']=='8s'
  assert 'allow_partial_search_results=false' in url
  if json['size']:
   assert 1<=json['size']<=500 and 'aggs' not in json and 'search_after' not in json
   assert json['sort']==[{'timestamp':'desc'}]
   assert len(url.split('/_search')[0].split(','))<=2
   if self.head_error:raise self.head_error
   ranges={key:value for f in json['query']['bool']['filter'] for key,value in f.get('range',{}).items()}
   lo,hi=map(n.parse,(ranges['timestamp']['gte'],ranges['timestamp']['lte']))
   hits=[d for d in self.documents if lo<=n.parse(d['_source']['timestamp'])<=hi]
   hits=sorted(hits,key=lambda d:n.parse(d['_source']['timestamp']),reverse=True)[:json['size']]
   value={'_shards':{'total':2,'failed':0},'hits':{'hits':hits}}
  else:
   assert 1<=json['aggs']['items']['composite']['size']<=500
   if self.old_error:raise self.old_error
   value={'_shards':{'total':1,'failed':0},'aggregations':{'items':{'buckets':[]}}}
  response=Response(value);self.responses.append(response);return response

def run(store,session,at=NOW,ingest=ingest_source,cfg=CFG):
 return n.collect_partitioned(store,cfg,session,cfg['source_agents'],ingest,at,{'through':(NOW-dt.timedelta(days=3)).isoformat(),'reconciled':'2000-01-01T00:00:00+00:00'})

def seed_old(store):
 state={'through':(NOW-dt.timedelta(days=3)).isoformat(),'status':'partial','pending':{'lower':(NOW-dt.timedelta(days=3)).isoformat(),'upper':(NOW-dt.timedelta(days=2)).isoformat(),'ceiling':(NOW-dt.timedelta(hours=5)).isoformat(),'cutoff':(NOW-dt.timedelta(days=30)).isoformat(),'after':{'ip':'9.9.9.9','source':'waf','detector':'web-request'},'page_size':1},'source_debt':{'observations':7,'examples':[{'reason':'fixture unavailable day'}]},'retry_after':(NOW+dt.timedelta(days=1)).isoformat()}
 for name in ('native_live','native_history','general_live','native_rolling_waf_'+NOW.strftime('%Y%m%d')):store.state('ingest_partition_'+name,state)
 return {key:copy.deepcopy(store.state(key)) for key in ['ingest_partition_'+name for name in ('native_live','native_history','general_live','native_rolling_waf_'+NOW.strftime('%Y%m%d'))]}

def test_late_no_while_all_old_fences_exclude_it_keeps_exact_old_state_and_qualifying50(tmp_path):
 s=Store(tmp_path/'db');old=seed_old(s);yes=document('old-yes',NOW-dt.timedelta(hours=22),NOW-dt.timedelta(hours=20),qual='yes')
 d=yes['_source']['data'];ingest_source(s,{'ip':d['srcip'],'source':d['edl_source'],'detector':d['edl_detector']},d,yes['_source']['timestamp'],1,CFG)
 before=s.describe('8.8.4.4')['evidence'];session=Session([document('late-no')])
 run(s,session);run(s,session,NOW+dt.timedelta(seconds=1))
 assert s.describe('8.8.4.4')['evidence']==before and s.describe('8.8.4.4')['score']==50
 for key,value in old.items():assert s.state(key)==value
 with s.connect() as db:
  activity=json.loads(db.execute('SELECT details FROM source_activity WHERE ip=?',('8.8.4.4',)).fetchone()[0])
  assert 'late-no' in json.dumps(activity)
 assert all(r.closed for r in session.responses)

def test_yes_no_same_bucket_and_source_detector_ip_agent_isolation(tmp_path):
 s=Store(tmp_path/'db');docs=[document('yes',NOW-dt.timedelta(hours=20),qual='yes'),document('new-no'),document('other-ip',address='9.9.9.9',qual='yes'),document('other-source',source='tpot',detector='failed-login',qual='yes'),document('wrong-agent',source='tpot',agent='Wrong',address='1.1.1.1',qual='yes'),document('disabled',source='disabled',address='1.0.0.1',qual='yes')]
 session=Session(docs);run(s,session);before=s.describe('8.8.4.4')['evidence'];run(s,session,NOW+dt.timedelta(seconds=1))
 assert s.describe('8.8.4.4')['score']>=50
 assert s.describe('8.8.4.4')['evidence']==before
 waf=[e for e in before if e['source']=='waf'];assert len(waf)==1 and waf[0]['seen']==docs[0]['_source']['data']['edl_seen_utc']
 assert json.loads(waf[0]['details'])['native_record_id']==event_id('yes')
 assert s.describe('9.9.9.9')['score']==50 and not s.describe('1.1.1.1')['evidence'] and not s.describe('1.0.0.1')['evidence']

def test_saturated_head_reopens_after_restart_and_newest_arrival_is_not_behind_afterkey():
 s=Memory();session=Session([document('old-'+str(i)) for i in range(501)]);got=[]
 run(s,session,ingest=lambda store,key,data,*a:got.append(data['edl_event_id']))
 assert s.state('native_head_observation')['saturated']
 saved=copy.deepcopy(s.values);s=Memory();s.values=saved;session.documents.append(document('fresh',stamp=NOW+dt.timedelta(seconds=1)))
 run(s,session,NOW+dt.timedelta(seconds=2),ingest=lambda store,key,data,*a:got.append(data['edl_event_id']))
 assert event_id('fresh') in got and not s.state('native_head_observation').get('pending')
 assert s.state('native_ingest_coverage')['status']=='partial'

def test_head_timeout_has_no_backoff_or_frozen_fence_and_history_still_gets_three_slots():
 s=Memory();session=Session();session.head_error=requests.ReadTimeout('fixture');run(s,session,ingest=lambda *a:None)
 first=copy.deepcopy(s.state('native_head_observation'));assert first['next_page_size']==250 and len(session.calls)==4
 session.head_error=None;session.documents=[document('fresh',stamp=NOW+dt.timedelta(seconds=2))];got=[]
 run(s,session,NOW+dt.timedelta(seconds=3),ingest=lambda store,key,data,*a:got.append(data['edl_event_id']))
 assert got==[event_id('fresh')] and s.state('native_head_observation')['upper']>first['upper'] and s.state('native_head_observation')['next_page_size']==500
 assert len(session.calls)==8

def test_rotation_fairness_max_four_queries_and_bounded_state_without_archive_growth():
 s=Memory();session=Session();schedule=[]
 for i in range(40):
  before=len(session.calls);run(s,session,NOW+dt.timedelta(minutes=i),ingest=lambda *a:None)
  assert len(session.calls)-before<=4
  lanes=s.state('native_ingest_coverage')['lanes'];assert lanes[0]=='native_head';schedule.append(lanes[1:])
 for offset in range(0,40,4):
  lanes=[name for turn in schedule[offset:offset+4] for name in turn]
  assert all(lanes.count(name)==3 for name in ('native_live','native_history','general_live'))
  assert sum(name.startswith('native_rolling_') for name in lanes)==3
 assert len(json.dumps(s.state('native_head_observation')))<2000
 assert len([k for k in s.values if k.startswith('native_head')])==1

@pytest.mark.parametrize('at',[NOW.replace(hour=0,minute=1),NOW.replace(hour=23,minute=59)])
def test_midnight_two_partitions_and_scope_change_uses_fresh_domain(at):
 s=Memory();session=Session();run(s,session,at,ingest=lambda *a:None);before=s.state('native_head_observation')
 cfg={**CFG,'index_url':'https://other.invalid','source_agents':{'waf':'Other'}}
 run(s,session,at+dt.timedelta(minutes=1),ingest=lambda *a:None,cfg=cfg)
 after=s.state('native_head_observation');assert before['scope']!=after['scope'] and after['page_size']==500
 head=[(url,q) for url,q,_ in session.calls if q['size']]
 assert all(len(url.split('/_search')[0].split(','))==2 for url,_ in head)
 assert head[-1][1]['query']['bool']['filter'][0]['bool']['should']==[{'bool':{'filter':[{'term':{'data.edl_source':'waf'}},{'term':{'agent.name':'Other'}}]}}]

@pytest.mark.parametrize('shape',['empty','unavailable','timeout','partial','oversize','malformed','overitems'])
def test_head_response_admission_and_honest_partial_coverage(shape):
 s=Memory();session=Session();original=session.post
 def post(url,json,**kw):
  response=original(url,json,**kw)
  if json['size']:
   if shape=='unavailable':response.value={'_shards':{'total':0},'hits':{'hits':[]}}
   elif shape=='timeout':response.value['timed_out']=True
   elif shape=='partial':response.value['_shards']['failed']=1
   elif shape=='malformed':response.value.pop('hits')
   elif shape=='overitems':response.value['hits']['hits']=[document(str(i)) for i in range(501)]
   elif shape=='oversize':response.iter_content=lambda size:iter([b'x'*65536]*129)
  return response
 session.post=post;run(s,session,ingest=lambda *a:None)
 head=s.state('native_head_observation');assert head['status']=='partial'
 assert bool(head.get('last_success_at'))==(shape=='empty')
 assert bool(s.state('native_ingest_coverage')['errors'].get('native_head'))==(shape!='empty')
 assert all(r.closed for r in session.responses)

def test_elapsed_deadline_closes_head_response_and_preserves_prior_success(monkeypatch):
 s=Memory();session=Session();run(s,session,ingest=lambda *a:None);prior=s.state('native_head_observation')['last_success_at'];ticks=[0]
 def clock():ticks[0]+=16;return ticks[0]
 monkeypatch.setattr(n.time,'monotonic',clock);run(s,session,NOW+dt.timedelta(minutes=1),ingest=lambda *a:None)
 assert s.state('native_head_observation')['last_success_at']==prior and all(r.closed for r in session.responses)

def test_application_interruption_repeats_head_idempotently_and_busy_propagates(tmp_path):
 s=Store(tmp_path/'db');session=Session([document('yes',qual='yes'),document('no',address='9.9.9.9')]);fired=[False]
 def interrupted(store,key,*args):
  result=ingest_source(store,key,*args)
  if not fired[0]:fired[0]=True;raise sqlite3.OperationalError('fixture owner contention')
  return result
 with pytest.raises(sqlite3.OperationalError):run(s,session,ingest=interrupted)
 assert not s.state('native_head_observation').get('last_success_at')
 run(s,session);run(s,session,NOW+dt.timedelta(seconds=1))
 assert len(s.describe('8.8.4.4')['evidence'])==1 and not s.describe('9.9.9.9')['evidence']

def test_late_index_outside_head_still_uses_existing_reconciliation_lane():
 s=Memory();old_stamp=NOW-dt.timedelta(days=4);session=Session([document('old-visible-late',seen=NOW-dt.timedelta(days=5),stamp=old_stamp)]);original=session.post;got=[]
 day=old_stamp.replace(hour=0,minute=0,second=0,microsecond=0)
 s.state('ingest_partition_native_history',{'through':day.isoformat(),'pending':{'lower':day.isoformat(),'upper':(day+dt.timedelta(days=1)).isoformat(),'ceiling':NOW.isoformat(),'cutoff':(NOW-dt.timedelta(days=30)).isoformat(),'after':None,'page_size':500}})
 def post(url,json,**kw):
  response=original(url,json,**kw)
  fence=next(f['range']['timestamp'] for f in json['query']['bool']['filter'] if 'timestamp' in f.get('range',{}))
  if not json['size'] and 'rule' not in json['aggs']['items']['composite']['sources'][1] and n.parse(fence['gte'])<=old_stamp<=n.parse(fence['lte']):
   d=session.documents[0];response.value['aggregations']['items']['buckets']=[{'key':{'ip':'8.8.4.4','source':'waf','detector':'coraza-interruption'},'doc_count':1,'last':{'hits':{'hits':[d]}}}]
  return response
 session.post=post;run(s,session,ingest=lambda store,key,data,*a:got.append(data['edl_event_id']))
 assert got and not s.state('native_head_observation')['documents'] and s.state('native_ingest_coverage')['status']=='partial'

def test_retained_composite_keeps_after_shape_but_latest_no_does_not_hide_qualified_yes(tmp_path):
 s=Store(tmp_path/'db');session=Session();original=session.post
 yes=document('retained-yes',NOW-dt.timedelta(days=5),qual='yes');no=document('retained-no',NOW-dt.timedelta(days=4))
 def post(url,json,**kw):
  response=original(url,json,**kw)
  if not json['size'] and 'rule' not in json['aggs']['items']['composite']['sources'][1]:
   agg=json['aggs']['items'];assert len(agg['composite']['sources'])==3
   assert agg['aggs']['qualified']['filter']=={'term':{'data.edl_qualifying':'yes'}}
   response.value['aggregations']['items']['buckets']=[{'key':{'ip':'8.8.4.4','source':'waf','detector':'coraza-interruption'},'doc_count':2,'last':{'hits':{'hits':[no]}},'qualified':{'doc_count':1,'last':{'hits':{'hits':[yes]}}}}]
  return response
 session.post=post;run(s,session);first=s.describe('8.8.4.4')['evidence'];run(s,session,NOW+dt.timedelta(seconds=1))
 assert s.describe('8.8.4.4')['score']==50 and s.describe('8.8.4.4')['evidence']==first
 assert first[0]['seen']==yes['_source']['data']['edl_seen_utc']
 assert json.loads(first[0]['details'])['native_record_id']==event_id('retained-yes')
 with s.connect() as db:assert 'retained-no' in db.execute('SELECT details FROM source_activity WHERE ip=?',('8.8.4.4',)).fetchone()[0]

@pytest.mark.parametrize('defer_publication',[False,True])
def test_normal_worker_publication_handoff_with_head_only_no_and_original_yes(tmp_path,monkeypatch,defer_publication):
 import worker
 from test_native_owner_repair import owner
 s=Store(tmp_path/'db');owner(worker,s,tmp_path,monkeypatch,build=True)
 yes=document('old-yes',NOW-dt.timedelta(hours=22),qual='yes');data=yes['_source']['data'];ingest_source(s,{'ip':'8.8.4.4','source':'waf','detector':'coraza-interruption'},data,yes['_source']['timestamp'],1,CFG)
 before=s.describe('8.8.4.4')['evidence'];session=Session([document('late-no')])
 if defer_publication:monkeypatch.setattr(s,'build',lambda *a,**k:None)
 monkeypatch.setattr(worker,'collect',lambda store,cfg,**kw:run(store,session))
 worker.main()
 status=s.state('ingest_status');assert status['ingestion_committed']
 assert status['publication']==('pending' if defer_publication else 'published')
 assert bool(status['generation'])!=defer_publication
 assert s.describe('8.8.4.4')['evidence']==before and s.describe('8.8.4.4')['score']==50
 assert s._worker_connection is None and s.state('native_head_observation')['documents']==1
