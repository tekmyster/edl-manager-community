import copy,datetime as dt,json
import pytest
from core import Store,now
from behavior_ai import Brain,DEFAULTS,VERSION,model_job,run,validate_result,validate_settings,local_endpoint

@pytest.fixture
def evidence(tmp_path):
 s=Store(tmp_path/'manager.sqlite3')
 activity={'events':[{'id':'a','seen':now(),'path':'/owa/token/private-token?password=unpublished&email=user@example.com','action':'authentication failure','method':'POST','port':'443','headers':{'Authorization':'Bearer keep-secret'},'body':'private-content','destination':'10.1.1.2'},{'id':'b','seen':now(),'path':'/owa/auth.owa','action':'authentication failure','method':'POST'}]}
 s.evidence('8.8.8.8','owapot','OWA',now(),'http',50,details={'activity':activity,'native_attempt_count':2})
 return s

def result(packet):
 return {'schema_version':VERSION,'packet_id':packet['packet_id'],'classification':'malicious','maliciousness_confidence':.9,'automation':{'classification':'credential_attack_automation','confidence':.9},'intent':{'classification':'credential_attack','confidence':.9},'findings':[{'summary':'Repeated authentication failures','evidence_ids':[packet['events'][0]['id']]}],'attack_techniques':[],'d3fend_context':[],'actor_correlation':[],'contradictory_evidence':[],'limitations':['Saved samples only'],'analysis_summary':'Authentication attempts require review.'}

def test_packet_is_redacted_deduplicated_and_cached_without_native_writes(evidence):
 b=Brain(evidence);before=evidence.describe('8.8.8.8');ident,packet,features=b.packet(before)
 encoded=json.dumps(packet)
 for secret in ('private-token','unpublished','user@example.com','keep-secret','private-content','10.1.1.2'):assert secret not in encoded
 assert len(packet['events'])==2 and packet['coverage']=='saved_samples'
 assert b.packet(before)[0]==ident
 after=evidence.describe('8.8.8.8');assert after['score']==before['score'] and after['retention']==before['retention']
 with b.connect() as d:assert d.execute('SELECT count(*) FROM packets').fetchone()[0]==1

@pytest.mark.parametrize('change',[lambda r:r.update(maliciousness_confidence=float('nan')),lambda r:r.update(maliciousness_confidence=True),lambda r:r.update(score=100),lambda r:r.update(packet_id='other'),lambda r:r['findings'][0].update(evidence_ids=['invented']),lambda r:r.update(attack_techniques=[{'technique_id':'T0000','evidence_ids':r['findings'][0]['evidence_ids'],'explanation':'invented'}])])
def test_untrusted_output_cannot_introduce_fields_scores_or_references(evidence,change):
 packet=Brain(evidence).packet(evidence.describe('8.8.8.8'))[1];r=result(packet);change(r)
 with pytest.raises(ValueError):validate_result(r,packet,[],{})

def test_model_cache_budget_failure_and_shadow_score_invariant(evidence,monkeypatch):
 import behavior_ai
 cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'endpoint':'https://10.1.1.1:11435','model':'test','daily_budget':1,'max_bump':25}
 evidence.state('behavior_settings',cfg);b=Brain(evidence);before=evidence.describe('8.8.8.8');ident,packet,features=b.packet(before);calls=[]
 def infer(*args):calls.append(1);return result(packet),{'model':'test'}
 monkeypatch.setattr(behavior_ai,'infer',infer)
 assert model_job(b,ident,packet,features,cfg)=='completed'
 assert model_job(b,ident,packet,features,cfg)=='cached' and len(calls)==1
 view=b.view('8.8.8.8');assert view['applied_bump']==0 and not view['scoring_eligible'] and view['hypothetical_score'] is not None
 after=evidence.describe('8.8.8.8');assert after['score']==before['score'] and after['retention']==before['retention']
 with b.connect() as d:d.execute("UPDATE assessments SET expires='2020-01-01T00:00:00+00:00'")
 assert model_job(b,ident,packet,features,cfg)=='budget'
 cfg['daily_budget']=2
 def fail(*args):raise TimeoutError('private diagnostic must not escape')
 monkeypatch.setattr(behavior_ai,'infer',fail)
 assert model_job(b,ident,packet,features,cfg)=='failed' and b.view('8.8.8.8')['assessment'] is None
 with b.connect() as d:assert 'private diagnostic' not in json.dumps([dict(r) for r in d.execute('SELECT * FROM assessments')])

def test_expired_success_can_refresh_after_three_analyses(evidence,monkeypatch):
 import behavior_ai
 cfg={**DEFAULTS,'model_enabled':True,'model':'test','endpoint':'https://10.1.1.1','daily_budget':10};b=Brain(evidence);ident,packet,features=b.packet(evidence.describe('8.8.8.8'))
 monkeypatch.setattr(behavior_ai,'infer',lambda *args:(result(packet),{}))
 for unused in range(5):
  assert model_job(b,ident,packet,features,cfg)=='completed'
  with b.connect() as d:d.execute("UPDATE assessments SET expires='2020-01-01T00:00:00+00:00'")

def test_similarity_is_reviewable_but_never_transfers_enforcement(evidence):
 b=Brain(evidence);first=evidence.describe('8.8.8.8');one,packet,features=b.packet(first)
 other=copy.deepcopy(first);other.update(ip='1.1.1.1',score=0);two,unused,features2=b.packet(other)
 assert b.candidates(two,features2)
 view=b.view('1.1.1.1');assert view['applied_bump']==0 and view['baseline_at_analysis']==0
 ident=view['matches'][0]['id'];b.review(ident,'rejected','Common public tool','admin');assert not b.view('1.1.1.1')['matches']

def test_provider_and_numeric_validation():
 for value in ['http://10.1.1.1','https://user:pass@10.1.1.1','https://10.1.1.1/api/chat']:
  with pytest.raises(ValueError):validate_settings({'endpoint':value})
 with pytest.raises(ValueError):validate_settings({'max_bump':'nan'})
 with pytest.raises(ValueError):local_endpoint('https://8.8.8.8')
 local_endpoint('https://127.0.0.1:11435')

def test_worker_disabled_does_not_inspect_or_publish(evidence,monkeypatch):
 monkeypatch.setattr(evidence,'all_scores',lambda:pytest.fail('Disabled worker read native scores'))
 assert run(evidence)=={'status':'disabled'}

def test_transport_pins_tls_disables_redirects_and_restricts_output(evidence):
 from behavior_ai import infer
 packet=Brain(evidence).packet(evidence.describe('8.8.8.8'))[1];cfg={**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test','ca_file':'/trusted/ca.pem'};calls=[]
 class Response:
  status_code=200
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','message':{'content':json.dumps(result(packet))}}).encode()
  def close(self):calls.append('closed')
 def send(url,**kwargs):
  assert url=='https://127.0.0.1/api/chat' and kwargs['verify']=='/trusted/ca.pem' and kwargs['allow_redirects'] is False
  schema=kwargs['json']['format']['properties'];assert schema['attack_techniques']['maxItems']==0 and schema['actor_correlation']['maxItems']==0
  assert 'tools' not in kwargs['json']
  return Response()
 assessment,metadata=infer(cfg,packet,[],{},'secret',requester=send)
 assert assessment['classification']=='malicious' and calls==['closed']

def test_transport_rejects_oversized_model_responses(evidence):
 from behavior_ai import infer
 packet=Brain(evidence).packet(evidence.describe('8.8.8.8'))[1];cfg={**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'}
 class Response:
  status_code=200
  def iter_content(self,n):yield b' '*131073
  def close(self):pass
 with pytest.raises(ValueError,match='size limit'):infer(cfg,packet,[],{},'',requester=lambda *a,**kw:Response())

def test_behavior_routes_require_auth_csrf_and_reporting_token(tmp_path):
 from app import create_app
 from reporting_api import issue
 app=create_app({'database':str(tmp_path/'manager.sqlite3'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'test','hosts':['localhost']});app.testing=True;c=app.test_client()
 assert c.get('/behavior',base_url='https://localhost').status_code==302
 assert c.get('/behavior/metrics',base_url='https://localhost').status_code==302
 with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 with c.session_transaction() as s:s.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 assert c.get('/behavior',base_url='https://localhost').status_code==200
 assert c.post('/settings/behavior',base_url='https://localhost').status_code==400
 assert c.get('/api/v1/behavior',base_url='https://localhost').status_code==401
 token=issue(app.store,'test',30,'admin');r=c.get('/api/v1/behavior',base_url='https://localhost',headers={'Authorization':'Bearer '+token})
 assert r.status_code==200 and r.json['active_scoring'] is False
 assert c.get('/behavior/metrics',base_url='https://localhost').status_code==200
 assert c.get('/api/v1/behavior/metrics',base_url='https://localhost').status_code==401
 response=c.get('/api/v1/behavior/metrics?period=7d',base_url='https://localhost',headers={'Authorization':'Bearer '+token})
 assert response.status_code==200 and len(response.json['bins'])==7
 assert c.get('/api/v1/behavior/metrics?period=all',base_url='https://localhost',headers={'Authorization':'Bearer '+token}).status_code==400


def test_small_gpu_response_is_compact_and_truncation_is_rejected(evidence):
 from behavior_ai import infer
 packet=Brain(evidence).packet(evidence.describe('8.8.8.8'))[1]
 cfg={**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'}
 class Response:
  status_code=200
  def iter_content(self,n):
   yield json.dumps({'done':True,'done_reason':'length','model':'test','message':{'content':json.dumps(result(packet))}}).encode()
  def close(self):pass
 def send(*args,**kwargs):
  schema=kwargs['json']['format']['properties']
  assert schema['findings']['maxItems']==2
  assert schema['findings']['items']['properties']['evidence_ids']['maxItems']==2
  assert schema['analysis_summary']['maxLength']==240
  return Response()
 with pytest.raises(ValueError,match='output_limit'):
  infer(cfg,packet,[],{},'',requester=send)


def test_model_failure_records_token_usage_without_storing_reply(evidence,monkeypatch):
 import behavior_ai
 b=Brain(evidence);ident,packet,features=b.packet(evidence.describe('8.8.8.8'))
 cfg={**DEFAULTS,'model_enabled':True,'model':'test','daily_budget':1}
 def fail(*args):raise behavior_ai.ModelOutputError('output_limit',{'input_tokens':200,'output_tokens':1800})
 monkeypatch.setattr(behavior_ai,'infer',fail)
 assert model_job(b,ident,packet,features,cfg)=='failed'
 with b.connect() as db:
  r=db.execute('SELECT result,error FROM assessments').fetchone()
 assert r['error']=='output_limit' and json.loads(r['result'])['metadata']['output_tokens']==1800


def test_inference_separates_current_and_historical_references(evidence):
 from behavior_ai import infer
 packet=Brain(evidence).packet(evidence.describe('8.8.8.8'))[1]
 candidate={'candidate_id':'peer','historical_events':[{'id':'remote-event'}]}
 cfg={**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'}
 class Response:
  status_code=200
  def iter_content(self,n):
   r=result(packet)
   r['actor_correlation']=[{'candidate_id':'peer','confidence':.5,'current_evidence_ids':[packet['events'][0]['id']],'historical_evidence_ids':['remote-event'],'explanation':'Similar requests','alternative_explanations':['Shared tooling']}]
   yield json.dumps({'done':True,'model':'test','message':{'content':json.dumps(r)}}).encode()
  def close(self):pass
 def send(*args,**kw):
  fields=kw['json']['format']['properties']['actor_correlation']['items']['properties']
  assert fields['historical_evidence_ids']['items']['enum']==['remote-event']
  assert 'evidence_ids' not in fields
  return Response()
 r,meta=infer(cfg,packet,[candidate],{},'',requester=send)
 assert r['actor_correlation'][0]['evidence_ids']==[packet['events'][0]['id'],'remote-event']
