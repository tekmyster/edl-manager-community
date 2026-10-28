import copy,datetime as dt,json
import pytest,requests
from core import Store
from worker import ingest_source
from native_ingestion import collect_partitioned
from test_native_ingestion_partitions import Response,bucket,config
UTC=dt.timezone.utc
@pytest.fixture(autouse=True)
def stable_clock(monkeypatch):
 # Keep reference metadata within its intended retention window in future CI.
 real=dt.datetime;fixed=real(2026,10,28,1,tzinfo=UTC)
 class Clock(real):
  @classmethod
  def now(cls,tz=None):return cls.fromtimestamp(fixed.timestamp(),tz)
 monkeypatch.setattr(dt,'datetime',Clock)

class Memory:
 def __init__(self):self.values={}
 def state(self,key,*value):
  if value:self.values[key]=copy.deepcopy(value[0])
  return copy.deepcopy(self.values.get(key))
class Delayed:
 def __init__(self,clock,root,seen):self.clock=clock;self.root=root;self.seen=seen;self.visible=False;self.calls=[];self.fail_old=True;self.fail_general=True
 def post(self,url,json,**kw):
  self.calls.append((url,copy.deepcopy(json),kw));assert json['timeout']=='8s' and kw=={'timeout':(3,8),'stream':True}
  filters=json['query']['bool']['filter'];rolling=any('data.edl_source' in v.get('term',{}) for v in filters);general='rule' in json['aggs']['items']['composite']['sources'][1]
  if any(v.get('term',{}).get('data.edl_source')=='tpot' for v in filters):raise requests.Timeout('unavailable noisy source')
  if general and self.fail_general or not general and not rolling and self.fail_old:raise requests.Timeout('bounded unavailable old source')
  fence=next(v['range']['timestamp'] for v in filters if 'timestamp' in v.get('range',{}));lo=dt.datetime.fromisoformat(fence['gte']);hi=dt.datetime.fromisoformat(fence['lte'])
  matches=self.visible and lo<=self.root<=hi and any(v.get('term',{}).get('data.edl_source')=='waf' for v in filters)
  rows=[bucket(self.seen.isoformat(),address='8.8.4.4')] if matches else []
  if rows:rows[0]['last']['hits']['hits'][0]['_source']['timestamp']=self.root.isoformat()
  return Response({'timed_out':False,'_shards':{'total':3,'failed':0},'aggregations':{'items':{'buckets':rows}}})

def test_alert_timestamp_can_be_indexed_hours_late_after_completed_recent_scan(tmp_path):
 # Root timestamp is alert generation, never treated as actual index arrival.
 started=dt.datetime(2026,10,28,1,tzinfo=UTC);root=dt.datetime(2026,10,27,22,0,0,100000,tzinfo=UTC);seen=dt.datetime(2026,10,27,6,26,44,tzinfo=UTC)
 s=Store(tmp_path/'db');cfg=config(True);seed={'through':'2026-10-25T00:00:00+00:00','reconciled':'2026-10-22T12:53:45+00:00'};session=Delayed(started,root,seen)
 s.state('native_ingest_cursor',seed)
 for i in range(4):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started+dt.timedelta(minutes=i),seed)
 pending=copy.deepcopy(s.state('ingest_partition_native_live')['pending']);assert not s.describe('8.8.4.4')['evidence']
 completed=s.state('ingest_partition_native_rolling_waf_20261027');assert completed['rolling_cycle_completed_at'] and completed['pending'] is None
 session.visible=True;later=started+dt.timedelta(hours=26)
 for i in range(8):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,later+dt.timedelta(minutes=i),seed)
 row=s.describe('8.8.4.4');assert row['score']==50 and not row['auto_candidate'] and len(row['evidence'])==1
 assert row['evidence'][0]['seen']=='2026-10-27T06:26:44+00:00'
 held=s.state('ingest_partition_native_live')['pending'];assert held['lower']==pending['lower'] and held['upper']==pending['upper'] and held['after']==pending['after']
 assert s.state('native_ingest_cursor')==seed and s.state('native_ingest_coverage')['status']=='partial'
 for i in range(8):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,later+dt.timedelta(hours=2,minutes=i),seed)
 assert len(s.describe('8.8.4.4')['evidence'])==1 and s.describe('8.8.4.4')['score']==50

def test_old_fixed_general_query_has_persistent_backoff_and_fresh_sources_continue():
 started=dt.datetime(2026,10,28,1,tzinfo=UTC);seed={'through':'2026-10-25T00:00:00+00:00'};s=Memory();cfg=config(True);session=Delayed(started,started-dt.timedelta(hours=2),started-dt.timedelta(hours=8))
 def general_calls():return [query for _,query,_ in session.calls if 'rule' in query['aggs']['items']['composite']['sources'][1]]
 collect_partitioned(s,cfg,session,cfg['source_agents'],lambda *a:None,started,seed);first=copy.deepcopy(s.state('ingest_partition_general_live')['pending']);assert len(general_calls())==1
 saved=copy.deepcopy(s.values);s=Memory();s.values=saved # independent worker restart
 collect_partitioned(s,cfg,session,cfg['source_agents'],lambda *a:None,started+dt.timedelta(seconds=10),seed);assert len(general_calls())==1
 assert len(session.calls)>=5 # native work still admitted while general waits
 collect_partitioned(s,cfg,session,cfg['source_agents'],lambda *a:None,started+dt.timedelta(seconds=61),seed);assert len(general_calls())==2
 held=s.state('ingest_partition_general_live')['pending'];assert (held['lower'],held['upper'],held['after'],held['ceiling'])==(first['lower'],first['upper'],first['after'],first['ceiling'])
 assert dt.datetime.fromisoformat(s.state('ingest_partition_general_live')['retry_after'])==started+dt.timedelta(seconds=181)

def test_recurring_retention_sweep_finds_late_document_outside_recent_days_without_reset():
 started=dt.datetime(2026,10,28,12,tzinfo=UTC);root=started-dt.timedelta(days=7);seen=root-dt.timedelta(hours=2);s=Memory();cfg=config();seed={'through':(started-dt.timedelta(days=12)).isoformat(),'reconciled':(started-dt.timedelta(days=20)).isoformat()};session=Delayed(started,root,seen);seen_ids=[]
 def ingest(store,key,data,*args):seen_ids.append(data['edl_event_id'])
 # Complete an entire rolling retention sweep before making the old alert visible.
 for i in range(128):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest,started+dt.timedelta(seconds=i),seed)
 assert not seen_ids;session.visible=True;later=started+dt.timedelta(hours=12)
 for i in range(128):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest,later+dt.timedelta(seconds=i),seed)
 assert seen_ids and s.state('ingest_partition_native_live')['through']==seed['through']
 assert not s.state('ingest_partition_native_history').get('completed')

def test_source_fair_recent_turns_do_not_let_tpot_timeout_starve_waf():
 started=dt.datetime(2026,10,28,12,tzinfo=UTC);s=Memory();cfg=config();cfg['source_agents']['tpot']='*';session=Delayed(started,started-dt.timedelta(hours=2),started-dt.timedelta(hours=4));session.visible=True;got=[]
 for i in range(12):
  before=len(session.calls);collect_partitioned(s,cfg,session,cfg['source_agents'],lambda store,key,data,*a:got.append(key['source']),started+dt.timedelta(minutes=i),{'through':'2026-10-25T00:00:00+00:00'});assert len(session.calls)-before<=4
 assert 'waf' in got

def test_source_and_sql_application_exceptions_propagate_in_new_rolling_lane():
 started=dt.datetime(2026,10,28,12,tzinfo=UTC);s=Memory();cfg=config();session=Delayed(started,started-dt.timedelta(days=2,hours=-1),started-dt.timedelta(days=3));session.visible=True
 def fail(*a):raise RuntimeError('application transaction failure')
 with pytest.raises(RuntimeError,match='application transaction failure'):collect_partitioned(s,cfg,session,cfg['source_agents'],fail,started,{'through':'2026-10-25T00:00:00+00:00'})

def test_zero_shard_real_shape_does_not_regress_in_rolling_pages():
 started=dt.datetime(2026,10,28,12,tzinfo=UTC);s=Memory();cfg=config()
 class Absent:
  def post(self,*a,**kw):return Response({'took':0,'timed_out':False,'_shards':{'total':0,'successful':0,'failed':0},'hits':{'total':{'value':0,'relation':'eq'},'hits':[]}})
 collect_partitioned(s,cfg,Absent(),cfg['source_agents'],lambda *a:None,started,{'through':'2026-10-25T00:00:00+00:00'})
 assert s.state('native_ingest_coverage')['status']=='partial'
 assert s.state('ingest_partition_native_rolling_waf_20261026')['source_debt']['observations']==1

def test_nonempty_rolling_after_key_and_fence_survive_restart_and_interleaving():
 started=dt.datetime(2026,10,28,12,tzinfo=UTC);s=Memory();cfg=config();seed={'through':'2026-10-25T00:00:00+00:00'};session=Delayed(started,started-dt.timedelta(days=2,hours=-1),started-dt.timedelta(days=3));session.visible=True;normal=session.post
 def paging(url,json,**kw):
  response=normal(url,json,**kw)
  if response.value['aggregations']['items']['buckets'] and not json['aggs']['items']['composite'].get('after'):response.value['aggregations']['items']['after_key']={'ip':'8.8.4.4','source':'waf','detector':'coraza-interruption'}
  return response
 session.post=paging;collect_partitioned(s,cfg,session,cfg['source_agents'],lambda *a:None,started,seed);name='ingest_partition_native_rolling_waf_20261026';before=copy.deepcopy(s.state(name)['pending']);assert before['after']
 saved=copy.deepcopy(s.values);s=Memory();s.values=saved
 for i in range(1,6):collect_partitioned(s,cfg,session,cfg['source_agents'],lambda *a:None,started+dt.timedelta(minutes=i),seed)
 requests_with_after=[q for _,q,_ in session.calls if q['aggs']['items']['composite'].get('after')==before['after']]
 assert requests_with_after
 query=requests_with_after[-1];assert next(v['range']['timestamp'] for v in query['query']['bool']['filter'] if 'timestamp' in v.get('range',{}))=={'gte':before['lower'],'lte':before['upper']}
 assert next(v['range']['data.edl_seen_utc'] for v in query['query']['bool']['filter'] if 'data.edl_seen_utc' in v.get('range',{}))=={'gte':before['cutoff'],'lte':before['ceiling']}
 assert s.state(name)['pending'] is None

def test_later_nonqualifying_context_never_renews_native_50(tmp_path):
 started=dt.datetime(2026,10,28,1,tzinfo=UTC);root=dt.datetime(2026,10,27,22,0,0,tzinfo=UTC);seen=dt.datetime(2026,10,27,6,26,44,tzinfo=UTC);s=Store(tmp_path/'db');cfg=config();session=Delayed(started,root,seen);session.visible=True;normal=session.post
 def with_activity(url,json,**kw):
  response=normal(url,json,**kw)
  if response.value['aggregations']['items']['buckets']:
   activity=bucket('2026-10-27T19:20:07+00:00',address='8.8.4.4',qualifying='no');activity['key']['detector']='web-request';data=activity['last']['hits']['hits'][0]['_source']['data'];data['edl_detector']='web-request';data['edl_event_id']='synthetic-later-No';data['edl_activity_json']=__import__('json').dumps({'events':[{'id':'synthetic-later-context','seen':'2026-10-27T19:20:07+00:00','action':'HTTP request','method':'POST','path':'/contact.php'}]});activity['last']['hits']['hits'][0]['_source']['timestamp']=root.isoformat();response.value['aggregations']['items']['buckets'].append(activity)
  return response
 session.post=with_activity
 for i in range(8):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started+dt.timedelta(minutes=i),{'through':'2026-10-25T00:00:00+00:00'})
 row=s.describe('8.8.4.4');assert row['score']==50 and not row['auto_candidate'] and len(row['evidence'])==1 and row['evidence'][0]['seen']=='2026-10-27T06:26:44+00:00'
 with s.connect() as db:activity={sensor:seen for sensor,seen in db.execute('SELECT sensor,seen FROM source_activity')}
 assert activity['web-request']=='2026-10-27T19:20:07+00:00' and activity['coraza-interruption']=='2026-10-27T06:26:44+00:00'
