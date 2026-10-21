"""Single joint immutable request/strict canonical decoding and hard deadline."""
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
 return Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},linked_packet(),[],{})

def test_joint_groups_and_observations_remain_optional(pipeline):
 for selection in ['omit','selected']:
  wire=choices(pipeline.request,groups=selection);result=pipeline.decode(wire)
  assert bool(result['observable_synthesis'])==(selection=='selected')
  assert result['findings']==[] and result['intent']=={'classification':'unknown','confidence':0}

def test_plan_copies_cannot_change_request_or_source_identity(pipeline):
 original=pipeline.request;changed=pipeline.request;changed['model']='changed';pipeline.packet['events'].clear();pipeline.identity.clear()
 assert pipeline.request==original and pipeline.packet['events'] and pipeline.identity
 with pytest.raises(AttributeError):pipeline.input_key='changed'
 assert not any(hasattr(pipeline,name) for name in ['stage1','second','freeze','compose'])

def test_decode_never_prepares_or_tokenizes_again(pipeline,monkeypatch):
 import behavior_generation as gen
 monkeypatch.setattr(gen,'prepare',lambda *a:(_ for _ in ()).throw(AssertionError('Request assembly during decode')))
 monkeypatch.setattr(gen,'offers',lambda *a:(_ for _ in ()).throw(AssertionError('Offer rebuild during decode')))
 assert pipeline.decode(choices(pipeline.request))['classification']=='inconclusive'

def test_old_and_duplicate_wire_reject(pipeline):
 from behavior_generation import parse_wire
 with pytest.raises(ValueError):parse_wire('{"observations":{},"observations":{}}')
 wire=choices(pipeline.request);wire['account_binding']='old-stage2'
 with pytest.raises(ValueError):pipeline.decode(wire)

def test_single_receipt_has_actual_counts_and_unknowns_without_phantom_sum():
 result=aggregate([{'request_started_at':'synthetic','input_tokens':4,'output_tokens':None,'first_content_seconds':.1}],1)
 assert result['planned_requests']==2 and result['request_count']==1 and result['input_tokens'] is None and result['output_tokens'] is None and result['first_content_seconds'] is None and result['generation_stages'][0]['first_content_seconds']==.1
 with pytest.raises(ValueError):aggregate([{},{},{}],1)

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
  assert status in ('failed','persistence_review_required','persistence_deferred') and len(calls)==1 and time.monotonic()-start<1
  assert closed.wait(.5)
  assert (int(calls[0]['headers']['X-EDL-Admission-Wait'])<=15 if seconds==180 else 'X-EDL-Admission-Wait' not in calls[0]['headers'])
  with b.connect() as db:assert db.execute('SELECT requests FROM usage').fetchone()[0]==1
 finally:closed.set();close(s)

@pytest.mark.parametrize('blocked',['preparation','identity','decode'])
def test_blocked_preparation_identity_or_decode_cannot_hold_controller_past_deadline(tmp_path,monkeypatch,blocked):
 from behavior_deadline import Deadline
 import behavior_pipeline_job as job
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(job,'Deadline',lambda value,stop:Deadline(.18,stop))
 s,b,cfg,p=setup(tmp_path/'native');calls=[];release=threading.Event();entered=threading.Event();exited=threading.Event()
 if blocked=='preparation':
  original=job.Pipeline
  def wait(*args,**kw):
   entered.set();release.wait(2)
   try:return original(*args,**kw)
   finally:exited.set()
  monkeypatch.setattr(job,'Pipeline',wait)
 elif blocked=='identity':
  original=job.source_identity
  def wait():
   entered.set();release.wait(2)
   try:return original()
   finally:exited.set()
  monkeypatch.setattr(job,'source_identity',wait)
 else:
  original=Pipeline.decode
  def wait(self,wire):
   entered.set();release.wait(2)
   try:return original(self,wire)
   finally:exited.set()
  monkeypatch.setattr(Pipeline,'decode',wait)
 def send(url,**kw):calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 start=time.monotonic()
 try:
  status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)
  assert entered.is_set() and status!='completed' and time.monotonic()-start<1
  assert len(calls)==(1 if blocked=='decode' else 0)
  with b.connect() as db:assert db.execute("SELECT count(*) FROM assessments WHERE status='completed'").fetchone()[0]==0
  if blocked=='decode':
   with b.connect() as db:row=db.execute('SELECT result FROM assessments').fetchone()
   if row:metadata=json.loads(row[0])['metadata']
   else:
    with b.connect() as db:metadata=json.loads(json.loads(db.execute('SELECT outcome FROM pipeline_plans').fetchone()[0])['row'][6])['metadata']
   assert metadata['request_count']==1 and metadata.get('input_tokens') in (None,10) and metadata['generation_stages'][0]['request_started_at']
 finally:release.set();assert exited.wait(1);time.sleep(.05);close(s)


def test_direct_real_transport_requires_a_verified_plan(monkeypatch):
 monkeypatch.setattr('requests.Session.post',lambda *a,**k:pytest.fail('Unverified real transport'))
 with pytest.raises(ValueError,match='Verified joint plan'):ai.infer({**ai.DEFAULTS,'model':'synthetic'},linked_packet(),[],{},'synthetic')
