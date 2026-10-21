"""Actual application tests using inert NDJSON transport, never a model endpoint."""
import copy,json,pathlib,sqlite3,threading,time
import pytest
import behavior_ai as ai,behavior_tokens
from behavior_pipeline import Pipeline,aggregate,VERSION,request_digest
from behavior_pipeline_job import run
from behavior_pipeline_store import Ledger,Refused
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())

@pytest.fixture
def sample(tmp_path):
 s,b,cfg,packets=setup(tmp_path/'fixture',count=2)
 yield s,b,cfg,packets
 close(s)

def rows(b,table):
 with b.connect() as db:return [dict(r) for r in db.execute('SELECT * FROM '+table)]

def sender(calls,mutate=lambda n,w:None):
 def send(url,**kw):
  request=kw['json'];calls.append(copy.deepcopy(request));wire=choices(request,groups='selected')
  mutate(len(calls),wire);return Reply(request,wire)
 return send

def test_two_serial_calls_two_charges_one_final_and_owned_raw_binding(sample):
 s,b,cfg,p=sample;calls=[]
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))
 assert status=='completed' and status.request_units==len(calls)==2
 assert sum(r['requests'] for r in rows(b,'usage'))==2
 assert [r['state'] for r in rows(b,'pipeline_stages')]==['accepted','accepted']
 assert len(rows(b,'assessments'))==1 and rows(b,'pipeline_reservations')[0]['held']==0
 draft=rows(b,'pipeline_drafts')[0];receipt=json.loads(draft['receipt'])
 assert receipt['parent']==rows(b,'pipeline_plans')[0]['id']
 assert receipt['draft_wire_sha256']==__import__('hashlib').sha256(draft['raw'].encode()).hexdigest()
 assert receipt['draft_canonical_sha256']==request_digest(json.loads(draft['canonical']))
 assert receipt['draft_rendering_sha256']==request_digest(json.loads(draft['rendering']))
 assert json.loads(draft['revision_request'])==calls[1]
 result=json.loads(rows(b,'assessments')[0]['result']);meta=result['metadata']
 assert meta['planned_requests']==meta['request_count']==2 and meta['input_tokens']==20
 assert [v['stage'] for v in meta['generation_stages']]==[1,2]
 assert meta['first_content_seconds'] is None
 assert not any(k in json.dumps(result) for k in ('draft_binding','provisional_answer','draft_wire_sha256'))
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2

def test_one_remaining_unit_never_dispatches_or_charges(sample):
 s,b,cfg,p=sample;calls=[]
 with b.connect() as db:db.execute('INSERT INTO usage VALUES(?,1)',(ai.now()[:10],))
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='budget'
 assert not calls and not rows(b,'pipeline_plans') and rows(b,'usage')[0]['requests']==1

@pytest.mark.parametrize('stage',[1,2])
@pytest.mark.parametrize('bad',['old','binding','authored','witness','duplicate','nonfinite'])
def test_invalid_output_never_accepted_or_refilled(sample,stage,bad):
 s,b,cfg,p=sample;calls=[]
 def send(url,**kw):
  q=kw['json'];calls.append(q);w=choices(q)
  if len(calls)==stage:
   if bad=='old':w['generation_schema_version']='joint-statement-comparison-1'
   elif bad=='binding':w['draft_binding']='0'*64
   elif bad=='authored':w['PRIVATE']='PRIVATE value'
   elif bad=='witness':w['observations'][next(iter(q['format']['properties']['observations']['properties']))]={'field':'summary','compared_account':'','purpose':'detail'}
   elif bad=='duplicate':
    r=Reply(q,w);r.body=r.body.replace(b'"content": "',b'"content": "',1)
    text=json.dumps(w)[:-1]+',"classification":"inconclusive"}'
    r.body=(json.dumps({'done':True,'model':q['model'],'message':{'content':text},'prompt_eval_count':10,'eval_count':2})+'\n').encode();return r
   else:w['maliciousness_confidence']=float('nan')
  return Reply(q,w)
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)
 assert status!='completed' and len(calls)==stage and status.request_units==stage
 assert len(rows(b,'pipeline_stages'))==2
 assert [r['state'] for r in rows(b,'pipeline_stages')][:stage-1]==['accepted']*(stage-1)
 assert not [r for r in rows(b,'assessments') if r['status']=='completed']
 assert 'PRIVATE' not in json.dumps(rows(b,'assessments'))
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='persistence_review_required' and len(calls)==stage

@pytest.mark.parametrize('phase,units,calls_expected',[('before_claim1',0,0),('after_claim1',0,0),('before_entry1',0,0),('after_entry1',1,0),('before_accept1',1,1),('after_accept1',1,1),('before_revision',1,1),('after_revision',1,1),('before_claim2',1,1),('after_claim2',1,1),('before_entry2',1,1),('after_entry2',2,1),('before_final',2,2),('after_final',2,2)])
def test_cancel_at_every_boundary_preserves_authority_no_second_or_retry(sample,phase,units,calls_expected):
 s,b,cfg,p=sample;calls=[];stop=threading.Event()
 def hook(point):
  if point==phase:stop.set()
 result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook,should_stop=stop.is_set)
 assert result!='completed' and len(calls)==calls_expected and result.request_units==units
 assert sum(r['requests'] for r in rows(b,'usage'))==units
 if phase in ('after_accept1','before_revision','after_revision','before_claim2','after_claim2','before_entry2','after_entry2','before_final','after_final'):
  assert rows(b,'pipeline_stages')[0]['state']=='accepted'
 if phase=='after_final':
  plan=rows(b,'pipeline_plans')[0]
  assert plan['state']=='final_pending' and json.loads(plan['outcome'])['row'][5]=='completed'
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls)) in ('completed','failed','cached','persistence_review_required')
 assert len(calls)==calls_expected and rows(b,'pipeline_reservations')[0]['held']==0

@pytest.mark.parametrize('phase',['after_accept1','after_final'])
def test_lost_durable_terminal_ack_keeps_accepted_authority(sample,phase):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point==phase:raise sqlite3.OperationalError('lost committed terminal ACK')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert rows(b,'pipeline_stages')[0]['state']=='accepted'
 if phase=='after_final':
  assert rows(b,'pipeline_stages')[1]['state']=='accepted'
  assert json.loads(rows(b,'pipeline_plans')[0]['outcome'])['row'][5]=='completed'
 count=len(calls)
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls)) in ('completed','failed','cached','persistence_review_required')
 assert len(calls)==count

def test_lost_second_claim_ack_never_copies_first_stage_counts_or_request_identity(sample):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point=='after_claim2':raise sqlite3.OperationalError('Synthetic lost second claim ACK')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='failed'
 stages=rows(b,'pipeline_stages');first=json.loads(stages[0]['metadata']);second=json.loads(stages[1]['metadata'])
 assert stages[0]['state']=='accepted' and stages[1]['state']=='failed'
 assert second['stage']==2 and second['request_id']==stages[1]['request_id']!=first['request_id']
 assert second.get('input_tokens') is None and second.get('output_tokens') is None
 assert not second.get('request_started_at') and second['request_transport_state']=='not_entered'
 assert len(calls)==sum(r['requests'] for r in rows(b,'usage'))==1
 metadata=json.loads(rows(b,'assessments')[0]['result'])['metadata']
 assert metadata['charged_request_units']==metadata['request_count']==1
 assert metadata['generation_stages'][1]['request_id']==stages[1]['request_id']
 assert metadata['input_tokens'] is None and metadata['generation_stages'][0]['input_tokens']==10

@pytest.mark.parametrize('stage',[1,2])
@pytest.mark.parametrize('artifact',['request.json','binding.json','choice-content.utf8','raw-response.bin','capture.json','finalization.json','outcome.json'])
def test_owned_capture_tampering_never_accepts_or_refills(sample,stage,artifact):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point==('before_accept1' if stage==1 else 'before_final'):
   root=pathlib.Path(b.path).with_suffix('.request-evidence');target=next(root.iterdir())/('stage%d'%stage)/artifact
   target.write_bytes(b'{}')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert len(calls)==stage and len(rows(b,'pipeline_drafts'))==stage-1
 assert not rows(b,'pipeline_finals')

def test_no_caller_raw_argument_on_runtime_revision(sample):
 s,b,cfg,p=sample;ledger=Ledger(b)
 with pytest.raises(TypeError):ledger.revision('parent','cfg',None,raw='historical draft')

@pytest.mark.parametrize('stage',[1,2])
def test_correlated_capture_file_rewrite_cannot_replace_exact_owned_stream(sample,stage):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point!=('before_accept1' if stage==1 else 'before_final'):return
  root=next(pathlib.Path(b.path).with_suffix('.request-evidence').iterdir())/('stage%d'%stage)
  envelope=json.loads((root/'raw-response.bin').read_bytes());envelope['message']['content']=' \n'+envelope['message']['content']
  raw=(json.dumps(envelope)+'\n').encode();(root/'raw-response.bin').write_bytes(raw)
  (root/'choice-content.utf8').write_bytes(envelope['message']['content'].encode())
  capture=json.loads((root/'capture.json').read_bytes());capture.update(bytes=len(raw),sha256=__import__('hashlib').sha256(raw).hexdigest());(root/'capture.json').write_text(json.dumps(capture))
  (root/'envelope.json').write_text(json.dumps(envelope));(root/'frames.json').write_text(json.dumps({'frames':[envelope],'invalid_lines':[]}))
  finalized=json.loads((root/'finalization.json').read_bytes());finalized['snapshot_bytes']=len(raw);(root/'finalization.json').write_text(json.dumps(finalized))
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert len(calls)==stage and not rows(b,'pipeline_finals')
 assert len(rows(b,'pipeline_drafts'))==stage-1

@pytest.mark.parametrize('stage',[1,2])
def test_request_capture_bytes_must_match_bound_hash_even_if_JSON_is_unchanged(sample,stage):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point!=('before_accept1' if stage==1 else 'before_final'):return
  path=next(pathlib.Path(b.path).with_suffix('.request-evidence').iterdir())/('stage%d'%stage)/'request.json'
  before=path.read_bytes();value=json.loads(before);after=json.dumps(value,indent=2).encode()
  assert before!=after and json.loads(before)==json.loads(after)
  path.write_bytes(after)
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert len(calls)==stage and not rows(b,'pipeline_finals')

def test_aggregate_missing_or_conflicting_stage_counts_stay_unknown():
 meta=aggregate([{'input_tokens':10,'output_tokens':2,'first_content_seconds':.2},{'input_tokens':None,'output_tokens':3,'first_content_seconds':.4}],2)
 assert meta['input_tokens'] is None and meta['output_tokens']==5 and meta['first_content_seconds'] is None
 assert meta['generation_stages'][0]['first_content_seconds']==.2
 with pytest.raises(ValueError):aggregate([{}, {}, {}],2)

def test_known_failed_revision_counts_cache_and_draft_receipt_are_preserved(sample):
 s,b,cfg,p=sample;calls=[]
 def send(url,**kw):
  q=kw['json'];calls.append(q)
  counts={'prompt_eval_count':10,'eval_count':2 if len(calls)==1 else 7,'prompt_eval_cached_count':3 if len(calls)==1 else 4}
  if len(calls)==2:counts['done_reason']='length'
  return Reply(q,choices(q),metadata=counts)
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='failed'
 meta=json.loads(rows(b,'assessments')[0]['result'])['metadata']
 assert (meta['input_tokens'],meta['output_tokens'],meta['cached_input_tokens'],meta['uncached_input_tokens'])==(20,9,7,13)
 assert [r['state'] for r in rows(b,'pipeline_stages')]==['accepted','failed']
 assert [r['request_transport_state'] for r in meta['generation_stages']]==['accepted','rejected']
 assert len(calls)==2 and sum(r['requests'] for r in rows(b,'usage'))==2
 assert not rows(b,'pipeline_finals')
 assert all('as_of' in r['request_evidence']['usage'] for r in meta['generation_stages'])

@pytest.mark.parametrize('state',['completed','partial'])
def test_database_relocation_and_day_change_do_not_reopen_owned_work(sample,tmp_path,monkeypatch,state):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if state=='partial' and point=='after_accept1':raise sqlite3.OperationalError('Synthetic lost child ACK')
 run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)
 destination=tmp_path/'relocated'/'fixture';destination.parent.mkdir()
 with sqlite3.connect(s.path) as source,sqlite3.connect(destination) as target:source.backup(target)
 with sqlite3.connect(b.path) as source,sqlite3.connect(destination.parent/pathlib.Path(b.path).name) as target:source.backup(target)
 from core import Store
 second=Store(destination);relocated=ai.Brain(second)
 try:
  monkeypatch.setattr(ai,'now',lambda:'2026-10-25T00:00:01+00:00');before=len(calls)
  result=run(relocated,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))
  assert result==('cached' if state=='completed' else 'persistence_review_required')
  assert len(calls)==before
  assert rows(relocated,'pipeline_stages')==rows(b,'pipeline_stages')
 finally:close(second)

def test_rollover_between_accepted_draft_and_revision_charges_actual_entry_days(sample,monkeypatch):
 s,b,cfg,p=sample;calls=[];clock=['2026-10-17T23:59:59+00:00'];monkeypatch.setattr(ai,'now',lambda:clock[0])
 def hook(phase):
  if phase=='after_accept1':clock[0]='2026-10-18T00:00:01+00:00'
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='completed'
 assert {r['day']:r['requests'] for r in rows(b,'usage')}=={'2026-10-17':1,'2026-10-18':1}
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2

def test_terminal_parent_cannot_be_downgraded_by_cleanup(sample):
 s,b,cfg,p=sample;calls=[]
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='completed'
 ledger=Ledger(b);parent=rows(b,'pipeline_plans')[0]['id'];before=rows(b,'pipeline_plans')
 ledger.uncertain(parent)
 with pytest.raises(Refused):ledger.recovered(parent,'failed')
 assert rows(b,'pipeline_plans')==before

def test_literal_binding_collision_preserves_source_and_binding():
 import behavior_revision as revision,behavior_generation as gen
 from behavior_representation import expand
 binding='0123456789abcdef'*4
 logical={'packet':{'one':binding,'two':binding,'three':binding},'provisional_answer':{'draft_binding':binding,'choices':{},'rendered':{}}}
 q=revision.request({},logical,'synthetic-only',gen,'synthetic')
 encoded=json.loads(q['messages'][1]['content'])
 assert encoded['input']['provisional_answer']['draft_binding']==binding
 assert expand(encoded)==logical

@pytest.mark.parametrize('phase',['before_reservation','after_reservation'])
def test_uncooperative_reservation_hook_cannot_extend_parent_deadline(sample,monkeypatch,phase):
 from behavior_deadline import Deadline
 s,b,cfg,p=sample;calls=[];gate=threading.Event();entered=threading.Event();done=threading.Event()
 monkeypatch.setattr('behavior_pipeline_job.Deadline',lambda seconds,stop:Deadline(.18,stop))
 def hook(point):
  if point==phase:
   entered.set();gate.wait(2);done.set()
 started=time.monotonic()
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
  assert entered.is_set() and not calls and time.monotonic()-started<1
  assert sum(r['requests'] for r in rows(b,'usage'))==0
  assert sum(r['held'] for r in rows(b,'pipeline_reservations'))==0
  before=rows(b,'pipeline_plans')
  gate.set();assert done.wait(1);time.sleep(.05)
  assert rows(b,'pipeline_plans')==before
 finally:gate.set()

def test_finite_cycle_does_not_start_two_children_with_only_one_cycle_unit_left(tmp_path,monkeypatch):
 from test_behavior_drain import queue
 from test_pipeline_mock import stage_mock
 s,b,cfg=queue(tmp_path,2);cfg={**cfg,'daily_budget':24};s.state('behavior_settings',cfg);calls=[]
 def reject(cfg,packet,*args):
  calls.append(packet['packet_id']);raise ai.ModelOutputError('invalid_assessment',{})
 stage_mock(monkeypatch,'behavior_ai.infer',reject)
 try:
  results,examined,reason=ai.drain_queue(b,s,cfg)
  assert results=={'failed':1} and reason=='finite_cycle_limit' and len(calls)==1
  with b.connect() as db:
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==1
   assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==1
 finally:close(s)

def test_rollover_rechecks_full_remaining_hold_before_entry(sample,monkeypatch):
 s,b,cfg,p=sample;calls=[];clock=['2026-10-17T23:59:59+00:00'];monkeypatch.setattr(ai,'now',lambda:clock[0])
 def hook(phase):
  if phase=='before_entry1':
   clock[0]='2026-10-18T00:00:01+00:00'
   with b.connect() as db:db.execute("INSERT INTO usage VALUES('2026-10-18',1)")
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert calls==[] and rows(b,'usage')==[{'day':'2026-10-18','requests':1}]
 assert rows(b,'pipeline_reservations')[0]['held']==0

@pytest.mark.parametrize('terminal',['after_accept1','after_final'])
def test_manager_terminal_ack_assertions_on_application_topology(sample,terminal):
 # Preserve the manager reproducer's essential assertions: durable acceptance,
 # matching reported acceptance and no entry into any remaining physical slot.
 s,b,cfg,p=sample;calls=[];stop=threading.Event()
 def hook(point):
  if point==terminal:
   stop.set();raise TimeoutError('Synthetic lost terminal acknowledgment at cancellation')
 run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook,should_stop=stop.is_set)
 durable=rows(b,'pipeline_stages');plan=rows(b,'pipeline_plans')[0]
 attempted=1 if terminal=='after_accept1' else 2
 assert len(calls)==attempted
 assert sum(s['state']=='planned' for s in durable)==2-attempted
 assert durable[0]['state']=='accepted'
 saved=json.loads(json.loads(plan['outcome'])['row'][6])['metadata']['generation_stages']
 assert saved[0]['request_transport_state']=='accepted'
 assert sum(s.get('request_transport_state')=='accepted' for s in saved)==sum(s['state']=='accepted' for s in durable)
 if terminal=='after_final':assert json.loads(plan['outcome'])['row'][5]=='completed'
