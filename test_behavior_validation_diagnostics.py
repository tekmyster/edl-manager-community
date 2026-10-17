"""Synthetic transport checks of bounded diagnostics; never measured inference."""
import json,pytest
from behavior_ai import DEFAULTS,infer,ModelOutputError
from test_behavior_backend_telemetry import request_fixture
from test_behavior_ai import result

@pytest.mark.parametrize('change,stage,reason,field',[
 (lambda r:r.update(classification='PRIVATE-REJECTED-LABEL'),'response_schema','label_or_enum','classification'),
 (lambda r:r.update(maliciousness_confidence=90),'response_schema','confidence','maliciousness_confidence'),
 (lambda r:r.update(**{'PRIVATE-UNEXPECTED-KEY':'PRIVATE-CONTENT'}),'response_schema','object_fields','$'),
 (lambda r:r['findings'][0].update(evidence_ids=['PRIVATE-CITATION']),'response_schema','label_or_enum','findings.*.evidence_ids.*'),
 (lambda r:r.update(classification='malicious',findings=[]),'response_schema','label_or_enum','classification'),
])
def test_rejections_record_only_fixed_codes_and_schema_paths(tmp_path,change,stage,reason,field):
 packet,unused,calls=request_fixture(tmp_path,{})
 value=result(packet);change(value)
 class Response:
  status_code=200
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','prompt_eval_count':123,'eval_count':45,'message':{'content':json.dumps(value)}}).encode()
  def close(self):pass
 def send(*a,**kw):calls.append(1);return Response()
 with pytest.raises(ModelOutputError) as caught:infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=send)
 assert caught.value.code=='invalid_assessment' and calls==[1]
 diagnostic=caught.value.metadata['validation_diagnostic']
 assert diagnostic=={'stage':stage,'reason':reason,**({'field':field} if field else {})}
 assert 'PRIVATE' not in json.dumps(caught.value.metadata)
 assert caught.value.metadata['input_tokens']==123

def test_invalid_json_does_not_persist_text_or_decoder_exception(tmp_path):
 packet,unused,calls=request_fixture(tmp_path,{})
 class Response:
  status_code=200
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','message':{'content':'PRIVATE-INVALID-JSON'}}).encode()
  def close(self):pass
 with pytest.raises(ModelOutputError) as caught:infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=lambda *a,**kw:Response())
 assert caught.value.code=='invalid_assessment'
 assert caught.value.metadata['validation_diagnostic']=={'stage':'json_content','reason':'json_decode'}
 assert 'PRIVATE' not in json.dumps(caught.value.metadata)

def test_model_job_persists_diagnostic_as_failure_without_verdict(tmp_path,monkeypatch):
 import behavior_ai
 from core import Store,now
 s=Store(tmp_path/'native');s.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50)
 b=behavior_ai.Brain(s);ident,packet,features=b.packet(s.describe('8.8.8.8'));before=s.describe('8.8.8.8')
 diagnostic={'stage':'response_schema','reason':'label_or_enum','field':'classification'}
 def reject(*a,**kw):raise ModelOutputError('invalid_assessment',{'validation_diagnostic':diagnostic})
 monkeypatch.setattr(behavior_ai,'infer',reject)
 assert behavior_ai.model_job(b,ident,packet,features,{**DEFAULTS,'model_enabled':True,'endpoint':'https://127.0.0.1','model':'test'})=='failed'
 with b.connect() as db:row=db.execute('SELECT status,error,result FROM assessments').fetchone()
 assert row['status']=='failed' and row['error']=='invalid_assessment'
 assert json.loads(row['result'])=={'metadata':{'validation_diagnostic':diagnostic}}
 after=s.describe('8.8.8.8');assert before['score']==after['score'] and before['retention']==after['retention']
