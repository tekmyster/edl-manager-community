import datetime as dt,json
import pytest
from core import Store,now
from behavior_ai import Brain,DEFAULTS,infer
from evidence_history import save,query,refresh,cleanup,collection_scope
@pytest.fixture
def data(tmp_path):
 s=Store(tmp_path/'manager.sqlite3');return s,Brain(s),dt.datetime.now(dt.timezone.utc)
def event(at,ident='one',**extra):return {'id':ident,'seen':at.isoformat(),'path':'/login?username=secret-user&token=secret-token','method':'POST','status':401,'destination':'10.0.0.7','port':443,'action':'HTTP request',**extra}
def config():return {'index_url':'https://index.invalid','index_user':'configured','index_password':'test-only','index_ca':'/trusted/ca.pem','source_agents':{'nginx':'*'}}
def test_persistence_duplicates_late_delivery_pagination_native_invariance(data):
 s,b,at=data;before=s.describe('8.8.8.8');first=event(at-dt.timedelta(hours=2));late=event(at-dt.timedelta(hours=3),'late')
 save(b,'8.8.8.8','nginx','request',[first,first],at.isoformat());save(b,'8.8.8.8','nginx','request',[late],(at+dt.timedelta(minutes=1)).isoformat())
 got=query(Brain(s),'8.8.8.8',at)
 assert got['total']==2 and got['coverage']=='partial' and got['events'][1]['seen']<got['events'][1]['received']
 assert s.describe('8.8.8.8')==before and query(b,'8.8.8.8',at,limit=1)['limited']
 assert query(b,'8.8.8.8',at,limit=1,offset=1)['events'][0]['id']==got['events'][1]['id']
def test_sensitive_fields_removed_before_storage(data):
 s,b,at=data;sample=event(at,authorization='private-auth',cookies='private-cookie',body='private-body',headers={'Authorization':'private-header'},http_metadata={'protocol':'HTTP/2','content_type':'application/json','Authorization':'private-header'})
 save(b,'8.8.8.8','waf','request',[sample],at.isoformat());encoded=json.dumps(query(b,'8.8.8.8',at))
 for secret in ('secret-user','secret-token','private-auth','private-cookie','private-body','private-header','10.0.0.7'):assert secret not in encoded
 assert 'application/json' in encoded and 'HTTP/2' in encoded and 'asset_' in encoded
@pytest.mark.parametrize('count',[0,1,501])
def test_query_coverage_cache_and_forwarded_ineligibility(data,count):
 s,b,at=data;cfg=config()
 def fetcher(*args):return [('nginx','request',[event(at,str(i)) for i in range(count)])],{'status':'ok','matching_index_records':count,'read_index_records':min(count,500),'query_limited':count>500}
 assert refresh(b,'8.8.8.8',cfg,at,fetcher)=='refreshed';got=query(b,'8.8.8.8',at,source_cfg=cfg)
 assert got['total']==min(count,500) and got['coverage']=='partial' and got['collection']['query_limited']==(count>500)
 assert refresh(b,'8.8.8.8',cfg,at,lambda *a:pytest.fail('Duplicate query'))=='cached'
 assert all(not e['independent_evidence'] for e in got['events'])
def test_disabled_failed_queries_and_scope_changes(data):
 s,b,at=data;cfg=config()
 assert refresh(b,'8.8.8.8',{},at,lambda *a:pytest.fail('Network'))=='not_configured'
 save(b,'8.8.8.8','nginx','request',[event(at)],at.isoformat(),collection_scope(b,cfg))
 def broken(*args):raise TimeoutError('private failure')
 assert refresh(b,'8.8.8.8',cfg,at,broken)=='failed'
 got=query(b,'8.8.8.8',at,source_cfg=cfg);assert got['total']==1 and 'private failure' not in json.dumps(got)
 assert refresh(b,'8.8.8.8',cfg,at+dt.timedelta(minutes=6),lambda *a:pytest.fail('Failure backoff'))=='cached'
 s.state('source_configuration',{'index_url':cfg['index_url'],'sources':{'nginx':'new-agent'}})
 assert query(b,'8.8.8.8',at,source_cfg=cfg)['total']==0
 s.state('source_configuration',{'index_url':'','sources':{}})
 assert query(b,'8.8.8.8',at,source_cfg={})['total']==0
def test_cleanup_and_clock_guard(data):
 s,b,at=data
 save(b,'8.8.8.8','nginx','request',[event(at-dt.timedelta(days=31),'old'),event(at+dt.timedelta(hours=1),'future'),event(at)],at.isoformat())
 assert query(b,'8.8.8.8',at)['total']==1;before=s.describe('8.8.8.8');cleanup(b,at+dt.timedelta(days=31))
 assert query(b,'8.8.8.8',at)['total']==0 and s.describe('8.8.8.8')==before
def test_actual_transport_bounded_redacted_sequence(data):
 s,b,at=data
 for source in ('nginx','waf','owapot','tpot','crowdsec','wazuh'):save(b,'8.8.8.8',source,'sensor',[event(at-dt.timedelta(seconds=i),str(i)) for i in range(100)],at.isoformat())
 packet=b.packet(s.describe('8.8.8.8'),at=at)[1]
 assert len(json.dumps(packet).encode())<12500 and packet['sequence']['partial'] and packet['sequence']['available']>=200
 assert packet['events']==sorted(packet['events'],key=lambda e:(e['seen'],e['id'])) and len({e['source'] for e in packet['events']})>=4
 captured=[]
 class Response:
  status_code=200
  def close(self):pass
  def iter_content(self,n):
   from behavior_generation import example as result
   yield json.dumps({'done':True,'model':'test','message':{'content':json.dumps(result(packet))}}).encode()
 def send(url,**kwargs):captured.append(kwargs['json']['messages'][1]['content']);return Response()
 infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'test-only-key',requester=send)
 assert json.loads(captured[0])['packet']['sequence']==packet['sequence']
 for secret in ('secret-user','secret-token','10.0.0.7'):assert secret not in captured[0]
 assert b.packet(s.describe('8.8.8.8'),at=at)[0]==packet['packet_id']
def test_portable_http_structure_ignores_sensitive_headers_and_body():
 from web_client import http_details,request_structure
 sample={**http_details({'request':{'headers':{'Authorization':'private-auth','Content-Type':'application/json'},'body':'private-body'}}),**request_structure('/login?user=private-user&password=private-pass')}
 assert sample['parameter_names'] and sample['http_metadata']['content_type']=='application/json'
 for secret in ('private-user','private-pass','private-auth','private-body'):assert secret not in json.dumps(sample)
def test_history_auth_and_reporting_token(tmp_path):
 from app import create_app
 from reporting_api import issue
 app=create_app({'database':str(tmp_path/'manager.sqlite3'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'test','hosts':['localhost']});app.testing=True;c=app.test_client()
 assert c.get('/behavior/8.8.8.8/history',base_url='https://localhost').status_code==302
 with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 with c.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 assert c.get('/behavior/8.8.8.8/history',base_url='https://localhost').status_code==200
 assert c.get('/behavior/8.8.8.8/history?offset=bad',base_url='https://localhost').status_code==400
 assert c.get('/api/v1/ips/8.8.8.8/history',base_url='https://localhost').status_code==401
 token=issue(app.store,'history test',30,'admin');response=c.get('/api/v1/ips/8.8.8.8/history',base_url='https://localhost',headers={'Authorization':'Bearer '+token})
 assert response.status_code==200 and response.json['coverage']=='partial'


def test_time_selection_keeps_both_endpoints():
 from evidence_history import representative
 values=[{'seen':i} for i in range(100)]
 result=representative(values)
 assert result[:2]==[values[0],values[-1]] and len(result)==40 and len({v['seen'] for v in result})==40

@pytest.mark.skipif(__import__('os').name!='posix',reason='native worker uses Linux flock')
def test_enlarged_source_samples_leave_native_scoring_and_retention_unchanged(tmp_path):
 from worker import ingest_source
 snapshots=[];at=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
 for size in (3,24):
  s=Store(tmp_path/str(size)/'manager.sqlite3')
  samples=[event(at-dt.timedelta(seconds=i),str(i)) for i in range(size)]
  d={'edl_activity_json':json.dumps({'events':samples}),'edl_seen_utc':at.isoformat(),'edl_qualifying':'yes','edl_native_event_count':'50','edl_native_attempt_count':'5','edl_dst_ports':'443','edl_path_hashes':'native-path'}
  assert ingest_source(s,{'ip':'8.8.8.8','source':'nginx','detector':'sensitive-path-probe'},d,at.isoformat(),50)
  before=s.describe('8.8.8.8');Brain(s).packet(before)
  after=s.describe('8.8.8.8');assert before==after
  with s.connect(commit=False) as db:snapshots.append({name:[tuple(r) for r in db.execute('SELECT * FROM '+name+' ORDER BY rowid')] for name in ('evidence','block_retention','offender_blocks','offender_returns')})
 assert snapshots[0]==snapshots[1]


def test_native_bucket_fallback_is_explicitly_a_summary(data):
 s,b,at=data;s.evidence('8.8.8.8','crowdsec','scenario',at.isoformat(),'http',25,details={'detector':'scenario'})
 packet=b.packet(s.describe('8.8.8.8'),at=at)[1]
 assert packet['events'] and all(e['provenance']['detail']=='summary' for e in packet['events'])


def test_later_index_provenance_enriches_duplicate_without_changing_first_receipt(data):
 s,b,at=data;sample=event(at);first=at.isoformat()
 save(b,'8.8.8.8','nginx','request',[sample],first)
 indexed={**sample,'_agent':'synthetic-edge','_index_id':'index-record-123456789012345678901234','_index':'wazuh-alerts-fixture','_indexed_at':at.isoformat()}
 save(b,'8.8.8.8','nginx','request',[indexed],(at+dt.timedelta(minutes=1)).isoformat())
 got=query(b,'8.8.8.8',at)
 assert got['total']==1 and got['events'][0]['received']==first
 origin=got['events'][0]['provenance']
 assert origin['collector_agent']=='synthetic-edge' and origin['record_id']==indexed['_index_id'] and origin['index']==indexed['_index']


def test_firewall_source_change_isolates_cached_scope(data):
 s,b,at=data;cfg=config()
 s.state('source_configuration',{'index_url':cfg['index_url'],'sources':{'nginx':'*'},'palo_location':'synthetic-firewall-a'})
 save(b,'8.8.8.8','palo','web',[event(at)],at.isoformat(),collection_scope(b,cfg))
 assert query(b,'8.8.8.8',at,source_cfg=cfg)['total']==1
 s.state('source_configuration',{'index_url':cfg['index_url'],'sources':{'nginx':'*'},'palo_location':'synthetic-firewall-b'})
 assert query(b,'8.8.8.8',at,source_cfg=cfg)['total']==0
