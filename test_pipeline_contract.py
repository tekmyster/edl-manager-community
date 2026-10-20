"""Strict two-stage composition and immutable source bindings; synthetic only."""
import copy,json,threading,time
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline import Pipeline,aggregate
from behavior_pipeline_job import run
from test_pipeline_support import SyntheticCounter,Reply,choices,setup,close
from test_source_observations import linked_packet

@pytest.fixture
def pipeline(monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00')
 return Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},linked_packet(),[],{})

def test_empty_and_selected_accounts_preserve_complete_source_data(pipeline):
 for selection in ('omit','selected'):
  receipt=pipeline.freeze(choices(pipeline.stage1,groups=selection));q,check=pipeline.second(receipt)
  a=json.loads(pipeline.stage1['messages'][1]['content']);b=json.loads(q['messages'][1]['content'])
  a.pop('generation_schema_version');b.pop('generation_schema_version');b.pop('frozen_account_choices');assert a==b
  result=pipeline.compose(choices(q),receipt)
  assert result['observable_synthesis']==receipt['accounts']
  assert bool(result['observable_synthesis'])==(selection=='selected')
  assert 'reason' not in q['format']['properties']['observations'].get('properties',{})

@pytest.mark.parametrize('change',[lambda r:r.update(binding='0'*64),lambda r:r.update(input_key='changed'),lambda r:r.update(accounts=[]),lambda r:r.update(choices={}),lambda r:r.update(extra=True)])
def test_modified_frozen_receipt_rejects(pipeline,change):
 r=pipeline.freeze(choices(pipeline.stage1,groups='selected'));change(r)
 with pytest.raises(ValueError):pipeline.second(r)

def test_duplicate_json_keys_and_unknown_stage_fields_reject(pipeline):
 from behavior_generation import parse_wire
 with pytest.raises(ValueError):parse_wire('{"accounts":{},"accounts":{}}')
 w=choices(pipeline.stage1);w['classification']='malicious'
 with pytest.raises(ValueError):pipeline.freeze(w)
 r=pipeline.freeze(choices(pipeline.stage1));q,_=pipeline.second(r);w=choices(q);w['account_binding']='changed'
 with pytest.raises(ValueError):pipeline.compose(w,r)

def test_aggregate_keeps_missing_report_unknown_and_no_phantom_attempt():
 a=aggregate([{'request_started_at':'synthetic','input_tokens':4,'output_tokens':2,'first_content_seconds':.1},{'input_tokens':None,'output_tokens':None}],1)
 assert a['request_count']==1 and a['input_tokens'] is None and a['first_content_seconds'] is None
 assert a['pipeline_usage']['input_tokens'] is None and a['generation_stages'][0]['input_tokens']==4

@pytest.mark.parametrize('seconds',[10,120,180])
def test_shared_deadline_aborts_late_first_stage_before_second(tmp_path,monkeypatch,seconds):
 from behavior_deadline import Deadline
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr('behavior_pipeline_job.Deadline',lambda value,stop:Deadline(.18,stop))
 s,b,cfg,p=setup(tmp_path/'native');cfg={**cfg,'timeout':seconds};s.state('behavior_settings',cfg);calls=[];closed=threading.Event()
 class Slow(Reply):
  def iter_content(self,n):
   while not closed.wait(.02):yield b' '
  def close(self):closed.set()
 def send(url,**kw):calls.append(kw);return Slow(kw['json'],choices(kw['json']))
 start=time.monotonic()
 try:
  status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)
  assert status in ('failed','persistence_review_required') and len(calls)==1 and time.monotonic()-start<1
  assert closed.wait(.5)
  assert calls[0]['headers'].get('X-EDL-Admission-Wait')==('15' if seconds==180 else None)
  with b.connect() as db:assert db.execute('SELECT requests FROM usage').fetchone()[0]==1
 finally:closed.set();close(s)
