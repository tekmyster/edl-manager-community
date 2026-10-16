"""Mocked transport mechanics only; these are not measured inference results."""
import json,pytest
from core import Store,now
from behavior_ai import Brain,DEFAULTS,infer,ModelOutputError
from test_behavior_ai import result

def request_fixture(tmp_path,fields):
 s=Store(tmp_path/'native');s.evidence('8.8.8.8','waf','fixture',now(),'http',50,details={'activity':{'events':[{'id':'one','seen':now(),'path':'/login','method':'GET','action':'sample'}]}})
 packet=Brain(s).packet(s.describe('8.8.8.8'))[1]
 envelope={'done':True,'model':'test','prompt_eval_count':123,'eval_count':45,'message':{'content':json.dumps(result(packet))},**fields}
 class Response:
  status_code=200
  def iter_content(self,n):yield json.dumps(envelope).encode()
  def close(self):pass
 calls=[]
 def send(*args,**kwargs):calls.append(1);return Response()
 return packet,send,calls

def test_actual_backend_duration_fields_are_preserved_separately(tmp_path):
 fields={'total_duration':1000000000,'load_duration':100000000,'prompt_eval_duration':200000000,'eval_duration':700000000};packet,send,calls=request_fixture(tmp_path,fields)
 _,metadata=infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=send)
 assert metadata['backend_timings']==fields and metadata['backend_timings_unit']=='nanoseconds'
 assert metadata['input_tokens']==123 and metadata['output_tokens']==45 and calls==[1]

@pytest.mark.parametrize('value',[None,True,-1,3600000000001,'123',1.25])
def test_unknown_or_invalid_backend_duration_is_not_fabricated(tmp_path,value):
 packet,send,calls=request_fixture(tmp_path,{'total_duration':value})
 _,metadata=infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=send)
 assert all(v is None for v in metadata['backend_timings'].values()) and calls==[1]

def test_incomplete_output_keeps_only_observed_telemetry_without_verdict(tmp_path):
 packet,send,calls=request_fixture(tmp_path,{'done':False,'eval_duration':200000000})
 with pytest.raises(ModelOutputError) as exc:infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',requester=send)
 assert exc.value.metadata['backend_timings']['eval_duration']==200000000 and calls==[1]
