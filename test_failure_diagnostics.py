"""Isolated failure mechanics and privacy; no live inference or truth labels."""
import json
from pathlib import Path
import pytest
import requests
import behavior_ai as ai
from analytics_store import Attempt,connect as ledger
from core import Store,now
from test_behavior_backend_telemetry import request_fixture


class Response:
 def __init__(self,status=503,body=b'PRIVATE-BODY https://private.invalid/?key=PRIVATE-KEY'):
  self.status_code=status;self.body=body;self.closed=False
 def iter_content(self,n):
  assert self.status_code==200,'Rejected response body must not be read'
  yield self.body
 def close(self):self.closed=True


@pytest.mark.parametrize('kind,category',[('tls','tls'),('certificate','tls'),('deadline','timeout'),('timeout','timeout'),('connection','connection'),('http','transport')])
def test_standard_library_pipeline_transport_failures_keep_fixed_categories(kind,category):
 import ssl,http.client
 from behavior_deadline import Expired
 errors={'tls':ssl.SSLError('PRIVATE-TLS'),'certificate':ssl.SSLCertVerificationError('PRIVATE-CERT'),'deadline':Expired('PRIVATE-DEADLINE'),'timeout':TimeoutError('PRIVATE-TIMEOUT'),'connection':ConnectionRefusedError('PRIVATE-CONNECTION'),'http':http.client.BadStatusLine('PRIVATE-HTTP')}
 saved=ai.failure_diagnostic(errors[kind],'dispatch')
 assert saved=={'phase':'dispatch','category':category} and 'PRIVATE' not in json.dumps(saved)


def metadata(exc):
 return exc.metadata if isinstance(exc,ai.ModelOutputError) else exc._edl_failure_metadata


@pytest.mark.parametrize('status',[400,401,403,429,500,502,503])
def test_http_rejection_keeps_actual_status_receipt_and_original_error(tmp_path,status):
 packet,_,_=request_fixture(tmp_path,{})
 store=Store(tmp_path/'native');attempt=Attempt(store,packet['packet_id']);response=Response(status)
 with pytest.raises(ValueError) as caught:
  ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'PRIVATE-KEY',requester=lambda *a,**k:response,attempt=attempt)
 assert type(caught.value) is ValueError and response.closed
 saved=metadata(caught.value)
 assert saved['failure_diagnostic']=={'phase':'http_status','category':'http_rejection','http_status':status}
 assert saved['request_id']==attempt.id and saved['request_transport_state']=='failed'
 assert saved['request_started_at']==attempt.started and saved['request_finished_at']
 assert not any(k in saved for k in ('input_tokens','output_tokens','first_content_seconds'))
 assert 'PRIVATE' not in json.dumps(saved) and 'https://' not in json.dumps(saved)
 with ledger(store) as db:
  row=dict(db.execute('SELECT * FROM requests').fetchone())
 assert row['id']==attempt.id and row['state']=='failed' and row['started']==saved['request_started_at'] and row['finished']==saved['request_finished_at']
 assert row['input_tokens'] is None and row['first_seconds'] is None


@pytest.mark.parametrize('exception,category',[
 (requests.exceptions.ConnectTimeout('PRIVATE-SECRET fullURL'),'timeout'),
 (requests.exceptions.ReadTimeout('PRIVATE-SECRET fullURL'),'timeout'),
 (requests.exceptions.SSLError('PRIVATE-SECRET fullURL'),'tls'),
 (requests.exceptions.ConnectionError('PRIVATE-SECRET fullURL'),'connection'),
 (requests.exceptions.RequestException('PRIVATE-SECRET fullURL'),'transport'),
 (RuntimeError('PRIVATE-SECRET fullURL'),'local_error')])
def test_transport_preserves_exact_exception_and_unknown_status(tmp_path,exception,category):
 packet,_,_=request_fixture(tmp_path,{})
 attempt=Attempt(Store(tmp_path/'native'),packet['packet_id'])
 def fail(*a,**k):raise exception
 with pytest.raises(type(exception)) as caught:
  ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'PRIVATE-KEY',requester=fail,attempt=attempt)
 assert caught.value is exception
 saved=metadata(caught.value)
 assert saved['failure_diagnostic']=={'phase':'request_headers','category':category}
 assert saved['request_id']==attempt.id and saved['request_transport_state']=='failed'
 assert 'PRIVATE' not in json.dumps(saved) and 'http_status' not in saved['failure_diagnostic']


@pytest.mark.parametrize('body,rejected',[
 (b'PRIVATE-NOT-JSON',False),
 (json.dumps({'model':'test','done':True,'message':{'content':'PRIVATE-NOT-JSON'},'prompt_eval_count':12,'eval_count':3}).encode(),True)])
def test_response_format_and_schema_failures_keep_observed_status_without_body(tmp_path,body,rejected):
 packet,_,_=request_fixture(tmp_path,{})
 attempt=Attempt(Store(tmp_path/'native'),packet['packet_id']);response=Response(200,body)
 with pytest.raises(ValueError) as caught:
  ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=lambda *a,**k:response,attempt=attempt)
 saved=metadata(caught.value)
 assert saved['failure_diagnostic']=={'phase':'assessment_validation' if rejected else 'response_envelope','category':'assessment_rejected' if rejected else 'response_format','http_status':200}
 assert saved['request_transport_state']==('rejected' if rejected else 'failed')
 assert saved['request_id']==attempt.id and 'PRIVATE' not in json.dumps(saved)
 assert response.closed
 if rejected:assert saved['input_tokens']==12 and caught.value.code=='invalid_assessment'
 else:assert 'input_tokens' not in saved


@pytest.fixture
def job(tmp_path):
 store=Store(tmp_path/'manager.sqlite3');store.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50)
 brain=ai.Brain(store);ident,packet,features=brain.packet(store.describe('8.8.8.8'))
 cfg={**ai.DEFAULTS,'enabled':True,'model_enabled':True,'endpoint':'https://127.0.0.1','model':'test','daily_budget':None}
 return store,brain,ident,packet,features,cfg


def test_job_failure_persists_observed_receipt_preserves_history_and_backoff(job,monkeypatch):
 store,brain,ident,packet,features,cfg=job;before=store.describe('8.8.8.8');calls=[]
 with brain.connect() as db:
  db.execute("INSERT INTO assessments VALUES('old','historic','old','2020','2021','failed','{}','ValueError',2)")
  old=tuple(db.execute("SELECT * FROM assessments WHERE id='old'").fetchone())
 def send(*a,**kw):calls.append(1);return Response(502)
 import behavior_tokens
 from behavior_pipeline_job import run
 from test_pipeline_support import SyntheticCounter
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 assert run(brain,ident,packet,features,cfg,requester=send)=='failed'
 with brain.connect() as db:
  rows=db.execute('SELECT * FROM assessments ORDER BY rowid').fetchall();assert tuple(rows[0])==old
  row=rows[-1];saved=json.loads(row['result'])['metadata'];assert row['error']=='ValueError'
  request_id=saved['generation_stages'][0]['request_id']
  assert saved['failure_diagnostic']['http_status']==502 and request_id
  guard=json.loads(db.execute("SELECT value FROM retention_state WHERE name LIKE 'provider_backoff:%'").fetchone()[0]);assert guard['failures']==1
 with ledger(store) as db:
  attempts=db.execute('SELECT * FROM requests').fetchall();assert len(attempts)==1 and attempts[0]['id']==request_id
 assert run(brain,ident,packet,features,cfg,requester=send)=='persistence_review_required' and calls==[1]
 with brain.connect() as db:db.execute("UPDATE assessments SET expires='2020' WHERE id!='old'")
 assert run(brain,ident,packet,features,cfg,requester=send)=='persistence_review_required' and calls==[1]
 after=store.describe('8.8.8.8');assert before['score']==after['score'] and before['retention']==after['retention']
 assert cfg['daily_budget'] is None and ai.DEFAULTS['daily_budget']==24
 assert ai.PROMPT_VERSION=='behavior-3.41'


def test_predispatch_failure_has_no_fabricated_receipt(job,monkeypatch):
 store,brain,ident,packet,features,cfg=job
 def no_prepare(*a,**kw):raise ValueError('PRIVATE-PREPARE')
 monkeypatch.setattr('behavior_generation.prepare',no_prepare)
 monkeypatch.setattr(requests.Session,'post',lambda *a,**kw:pytest.fail('No dispatch allowed'))
 assert ai.model_job(brain,ident,packet,features,cfg)=='input_verification_required'
 with brain.connect() as db:
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM usage').fetchone()[0]==0
 assert not (Path(store.path).parent/'analytics.sqlite3').exists()


def test_stream_timeout_keeps_only_observed_first_content_and_phase(tmp_path):
 packet,_,_=request_fixture(tmp_path,{})
 attempt=Attempt(Store(tmp_path/'native'),packet['packet_id'])
 class Interrupted(Response):
  def iter_content(self,n):
   yield json.dumps({'model':'test','done':False,'message':{'content':'PRIVATE-PARTIAL'}}).encode()+b'\n'
   raise requests.exceptions.ReadTimeout('PRIVATE-TRANSPORT-EXCEPTION')
 response=Interrupted(200)
 with pytest.raises(requests.exceptions.ReadTimeout) as caught:
  ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=lambda *a,**k:response,attempt=attempt)
 saved=metadata(caught.value)
 assert saved['failure_diagnostic']=={'phase':'response_stream','category':'timeout','http_status':200}
 assert saved['first_content_seconds']>=0 and saved['request_transport_state']=='failed'
 assert 'input_tokens' not in saved and 'output_tokens' not in saved and 'PRIVATE' not in json.dumps(saved)
 assert response.closed
