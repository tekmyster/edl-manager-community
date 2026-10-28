import copy,datetime as dt,json,re
import pytest,requests
from core import Store
from worker import ingest_source
from native_ingestion import collect_partitioned,page
UTC=dt.timezone.utc

def config(general=False):return {'index_url':'https://synthetic.invalid','source_agents':{'waf':'*',**({'wazuh':'*'} if general else {})},'collected_fields':[],'palo_location':''}
def bucket(seen,address='8.8.8.8',qualifying='yes'):
    row={'edl_source':'waf','srcip':address,'edl_detector':'coraza-interruption','edl_pipeline':'tekmyster-edl30-v1','edl_seen_utc':seen,'edl_event_id':address+'-synthetic','edl_path_hashes':'a'*24,'edl_activity_json':json.dumps({'events':[{'id':'synthetic-transaction','seen':seen,'action':'WAF interrupted','method':'POST','path':'/contact.php'}]}),'edl_qualifying':qualifying}
    return {'key':{'ip':address,'source':'waf','detector':'coraza-interruption'},'doc_count':1,'last':{'hits':{'hits':[{'_source':{'data':row,'timestamp':seen,'agent':{'name':'synthetic'}}}]}}}
class Response:
    def __init__(self,value):self.value=value;self.closed=False
    def raise_for_status(self):pass
    def iter_content(self,size):yield json.dumps(self.value).encode()
    def close(self):self.closed=True
class Session:
    def __init__(self,started,buckets=None,fail_general=False):self.started=started;self.buckets=buckets or [];self.calls=[];self.fail_general=fail_general;self.fail_all=False;self.after=False;self.partial=False
    def post(self,url,json,**kw):
        self.calls.append((url,copy.deepcopy(json),kw));assert re.search(r'wazuh-alerts-\*\d{4}\.\d{2}\.\d{2}/_search',url);assert json['timeout']=='8s' and 1<=json['aggs']['items']['composite']['size']<=500 and kw=={'timeout':(3,8),'stream':True}
        general='rule' in json['aggs']['items']['composite']['sources'][1]
        if self.fail_all or general and self.fail_general:raise requests.Timeout('synthetic bounded query failure')
        today=self.started.strftime('%Y.%m.%d') in url
        values=[] if general or not today else self.buckets
        return Response({'timed_out':self.partial,'_shards':{'failed':0},'aggregations':{'items':{'buckets':values,**({'after_key':{'ip':'next'}} if self.after and values else {})}}})

def test_old_shared_cursor_catches_up_daily_without_starving_on_general_failure(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);old=(started-dt.timedelta(days=4)).isoformat();seed={'through':old,'reconciled':old,'mode':'incremental'};s.state('native_ingest_cursor',seed);cfg=config(True);session=Session(started,[bucket(started.isoformat())],True)
    for _ in range(6):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,s.state('native_ingest_cursor'))
    assert s.state('native_ingest_cursor')['through']==started.isoformat()
    assert s.state('ingest_partition_general_live')['through']==old
    assert s.state('native_ingest_cursor')['reconciled']==old
    assert s.state('native_ingest_coverage')['errors']['general_live']=='Timeout'
    with s.connect() as db:
        assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==1
        assert db.execute('SELECT max(strength) FROM evidence').fetchone()[0]==50
        assert db.execute('SELECT count(*) FROM source_activity').fetchone()[0]==1
    assert len(session.calls)<=6*4

def test_timeout_and_partial_shards_never_advance_or_create_empty_success(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);old=(started-dt.timedelta(hours=1)).isoformat();seed={'through':old,'reconciled':old};cfg=config();session=Session(started);session.fail_all=True
    collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    before=s.state('ingest_partition_native_live');assert before['through']==old
    session.fail_all=False;session.partial=True;collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    after=s.state('ingest_partition_native_live');assert after['through']==before['through']
    assert {k:after['pending'][k] for k in ('lower','upper','after')}=={k:before['pending'][k] for k in ('lower','upper','after')}
    assert s.state('native_ingest_coverage')['status']=='partial'

def test_page_application_interruption_retries_idempotently(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat()};cfg=config();session=Session(started,[bucket(started.isoformat()),bucket(started.isoformat(),'9.9.9.9')])
    def interrupted(store,key,*args):
        if key['ip']=='9.9.9.9':raise RuntimeError('synthetic per-page interruption')
        return ingest_source(store,key,*args)
    with pytest.raises(RuntimeError,match='per-page interruption'):collect_partitioned(s,cfg,session,cfg['source_agents'],interrupted,started,seed)
    assert s.state('ingest_partition_native_live')['through']==seed['through']
    collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    with s.connect() as db:
        assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==2
        assert db.execute('SELECT max(strength) FROM evidence').fetchone()[0]==50

def test_nonqualifying_waf_never_scores_and_uses_original_event_time(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seen=(started-dt.timedelta(days=1)).isoformat();seed={'through':(started-dt.timedelta(hours=1)).isoformat()};cfg=config();session=Session(started,[bucket(seen,qualifying='no')]);collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    with s.connect() as db:
        assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==0
        assert db.execute('SELECT max(seen) FROM source_activity').fetchone()[0]==dt.datetime.fromisoformat(seen).isoformat(timespec='seconds')

def test_history_reconciliation_finishes_all_days_before_claiming_reconciled(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat(),'reconciled':'2000-01-01T00:00:00+00:00'};cfg=config();session=Session(started)
    for i in range(32):
        collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,s.state('native_ingest_cursor') or seed)
        if s.state('native_ingest_cursor')['reconciled']==started.isoformat():break
        assert s.state('native_ingest_cursor')['reconciled']==seed['reconciled']
    else:pytest.fail('History partitions failed to finish')
    assert i>=29

def test_pagination_checkpoint_is_fixed_and_scope_change_preserves_prior_domain(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat()};cfg=config();session=Session(started,[bucket(started.isoformat())]);session.after=True
    collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed);before=s.state('ingest_partition_native_live');assert before['pending']['after']=={'ip':'next'}
    session.after=False;collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    queries=[query for _,query,_ in session.calls if next(f['range']['timestamp'] for f in query['query']['bool']['filter'] if 'timestamp' in f.get('range',{}))=={'gte':before['pending']['lower'],'lte':before['pending']['upper']}]
    assert queries[-1]['aggs']['items']['composite']['after']=={'ip':'next'}
    done=s.state('ingest_partition_native_live');changed={**cfg,'source_agents':{'waf':'other-agent'}}
    collect_partitioned(s,changed,session,changed['source_agents'],ingest_source,started,seed)
    assert s.state('ingest_partition_native_live_scope_'+done['scope'])==done
    assert s.state('ingest_partition_native_live')['scope']!=done['scope']
    assert dt.datetime.fromisoformat(s.state('ingest_partition_native_live')['through'])<started-dt.timedelta(days=20)

def test_response_size_guard_closes_response_and_holds_checkpoint(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);cfg=config();seed={'through':(started-dt.timedelta(hours=1)).isoformat()}
    class Large(Response):
        def iter_content(self,size):
            for _ in range(129):yield b'x'*65536
    class LargeSession:
        def post(self,*args,**kw):self.response=Large({});return self.response
    session=LargeSession();collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    assert session.response.closed and s.state('ingest_partition_native_live')['through']==seed['through']
    assert s.state('ingest_partition_native_live')['pending']['page_size']==250

def test_timeout_retries_a_smaller_page_at_same_fence_without_skipping(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat()};cfg=config();session=Session(started,[bucket(started.isoformat())]);session.fail_all=True
    collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed);pending=s.state('ingest_partition_native_live')['pending'];assert pending['page_size']==250
    session.fail_all=False;collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    query=next(query for _,query,_ in reversed(session.calls) if next(f['range']['timestamp'] for f in query['query']['bool']['filter'] if 'timestamp' in f.get('range',{}))=={'gte':pending['lower'],'lte':pending['upper']});assert query['aggs']['items']['composite']['size']==250
    assert next(f['range']['timestamp'] for f in query['query']['bool']['filter'] if 'timestamp' in f.get('range',{}))=={'gte':pending['lower'],'lte':pending['upper']}
    with s.connect() as db:assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==1

def test_disabled_sources_never_query_or_move_existing_cursor(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':started.isoformat()};s.state('native_ingest_cursor',seed);cfg=config();cfg['source_agents']={};session=Session(started)
    assert collect_partitioned(s,cfg,session,{},ingest_source,started,seed)==0
    assert not session.calls and s.state('native_ingest_cursor')==seed

def test_no_matching_index_shards_keeps_source_debt_and_cannot_certify_reconciliation(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat(),'reconciled':'2000-01-01T00:00:00+00:00'};cfg=config()
    class Missing(Session):
        def post(self,*args,**kwargs):
            response=super().post(*args,**kwargs);response.value['_shards']['total']=0;return response
    session=Missing(started)
    for _ in range(32):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,s.state('native_ingest_cursor') or seed)
    assert s.state('native_ingest_cursor')['through']==started.isoformat()
    assert s.state('native_ingest_cursor')['reconciled']==seed['reconciled']
    assert s.state('ingest_partition_native_history')['source_debt']['observations']>=30
    assert s.state('native_ingest_coverage')['status']=='partial'

def test_general_authentication_count_spans_midnight_without_blocking_native_lane(tmp_path):
    s=Store(tmp_path/'native');started=dt.datetime(2026,10,27,12,tzinfo=UTC);cfg=config(True);seed={'through':(started-dt.timedelta(hours=1)).isoformat()}
    events=[started-dt.timedelta(hours=v) for v in (1,2,13,14,15)]
    class CrossDay(Session):
        def post(self,url,json,**kw):
            response=super().post(url,json,**kw)
            if 'rule' in json['aggs']['items']['composite']['sources'][1]:
                fence=next(f['range']['timestamp'] for f in json['query']['bool']['filter'] if 'timestamp' in f.get('range',{}));lo=dt.datetime.fromisoformat(fence['gte']);hi=dt.datetime.fromisoformat(fence['lte']);matched=[v for v in events if lo<=v<=hi]
                assert len(url.split('/_search')[0].split(','))<=31
                response.value['aggregations']['items']['buckets']=[] if not matched else [{'key':{'ip':'9.9.9.9','rule':'synthetic-auth'},'doc_count':len(matched),'last':{'hits':{'hits':[{'_id':'synthetic-auth-id','_source':{'timestamp':max(matched).isoformat(),'rule':{'id':'synthetic-auth','level':8,'description':'authentication failed','groups':['authentication_fail']}}}]}}}]
            return response
    session=CrossDay(started,[bucket((started-dt.timedelta(minutes=5)).isoformat())]);collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,seed)
    auth=s.describe('9.9.9.9');assert auth['score']==55 and len(auth['evidence'])==1
    assert json.loads(auth['evidence'][0]['details'])['records']==5
    assert s.describe('8.8.8.8')['score']==50
    assert s.state('ingest_partition_general_live')['through']==started.isoformat()


def test_actual_zero_shard_shape_catches_up_without_certifying_missing_days(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);old=(started-dt.timedelta(days=3)).replace(hour=0,minute=0,second=0,microsecond=0).isoformat();seed={'through':old,'reconciled':old};cfg=config()
    class ActualMissing(Session):
        def post(self,url,json,**kw):
            response=super().post(url,json,**kw)
            if self.started.strftime('%Y.%m.%d') not in url:
                response.value={'took':0,'timed_out':False,'_shards':{'total':0,'successful':0,'skipped':0,'failed':0},'hits':{'total':{'value':0,'relation':'eq'},'hits':[]}}
            return response
    session=ActualMissing(started,[bucket(started.isoformat())])
    for _ in range(6):collect_partitioned(s,cfg,session,cfg['source_agents'],ingest_source,started,s.state('native_ingest_cursor') or seed)
    assert s.state('native_ingest_cursor')['through']==started.isoformat()
    assert s.state('native_ingest_cursor')['reconciled']==old
    assert s.state('ingest_partition_native_live')['source_debt']['observations']==3
    assert s.state('native_ingest_coverage')['status']=='partial'
    assert s.describe('8.8.8.8')['score']==50
    with s.connect() as db:assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==1

@pytest.mark.parametrize('aggregation',[None,{}, {'items':{}}, {'items':None}])
def test_existing_index_missing_aggregation_holds_checkpoint(tmp_path,aggregation):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat()};cfg=config()
    class Malformed(Session):
        def post(self,*args,**kw):
            response=super().post(*args,**kw);response.value={'_shards':{'total':3,'failed':0}}
            if aggregation is not None:response.value['aggregations']=aggregation
            return response
    collect_partitioned(s,cfg,Malformed(started),cfg['source_agents'],ingest_source,started,seed)
    lane=s.state('ingest_partition_native_live')
    assert lane['through']==seed['through'] and lane['pending']['after'] is None
    assert s.state('native_ingest_coverage')['errors']['native_live']=='PartitionUnavailable'
    assert not lane.get('source_debt')

def test_application_keyerror_is_not_masked_as_response_uncertainty(tmp_path):
    s=Store(tmp_path/'native');started=(dt.datetime.now(UTC)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0);seed={'through':(started-dt.timedelta(hours=1)).isoformat()};cfg=config()
    def broken(*args):raise KeyError('application failure')
    with pytest.raises(KeyError,match='application failure'):
        collect_partitioned(s,cfg,Session(started,[bucket(started.isoformat())]),cfg['source_agents'],broken,started,seed)
    assert s.state('ingest_partition_native_live')['pending']['after'] is None
