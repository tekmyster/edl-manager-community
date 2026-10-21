"""Partial raw evidence, durable close failure and append-only late reports."""
import json,pathlib,threading,time,hashlib,sqlite3
import pytest
import behavior_ai as ai,behavior_tokens,behavior_request_evidence as evidence
from behavior_pipeline_job import run
from behavior_deadline import Deadline
from behavior_accounting import reconcile,check_usage
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())

def request_directory(b):return next(pathlib.Path(b.path).with_suffix('.request-evidence').iterdir())

@pytest.mark.parametrize('fault',['close','raw-response.bin','envelope.json','capture.json','finalization.json','incomplete','length','invalid'])
def test_capture_or_terminal_failure_retains_raw_and_never_accepts_or_retries(tmp_path,monkeypatch,fault):
 s,b,cfg,p=setup(tmp_path/'native');calls=[];put=evidence.put
 def inject(path,value):
  if pathlib.Path(path).name==fault:raise OSError('Synthetic evidence write failure')
  return put(path,value)
 monkeypatch.setattr(evidence,'put',inject)
 class Broken(Reply):
  def close(self):
   if fault=='close':raise OSError('PRIVATE close detail')
  def iter_content(self,n):
   if fault=='incomplete':yield b'{"model":"synthetic","done":false,"message":{"content":"PRIVATE"}}\n'
   elif fault=='length':yield self.body.replace(b'"done": true',b'"done": true, "done_reason":"length"')
   else:yield self.body
 def send(url,**kw):
  calls.append(1);wire=choices(kw['json'])
  if fault=='invalid':wire['PRIVATE']='not a legal field'
  return Broken(kw['json'],wire)
 try:
  result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)
  assert result!='completed' and result.request_units==1 and calls==[1]
  with b.connect() as db:
   assert not db.execute("SELECT 1 FROM assessments WHERE status='completed'").fetchone()
   for row in db.execute('SELECT result FROM assessments'):assert 'PRIVATE' not in row[0]
  directory=request_directory(b)
  assert (directory/'raw-response.bin').exists() or fault=='raw-response.bin'
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='persistence_review_required' and calls==[1]
 finally:close(s)

def test_rejected_raw_counter_string_remains_private_not_public_diagnostic(tmp_path):
 s,b,cfg,p=setup(tmp_path/'native')
 def send(url,**kw):return Reply(kw['json'],choices(kw['json']),metadata={'prompt_eval_count':'PRIVATE_BAD_COUNT','eval_count':2,'prompt_eval_cached_count':0})
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='completed'
  directory=request_directory(b);private=(directory/'outcome.json').read_text();assert 'PRIVATE_BAD_COUNT' in private
  with b.connect() as db:
   result=db.execute('SELECT result FROM assessments').fetchone()[0];assert 'PRIVATE_BAD_COUNT' not in result
   meta=json.loads(result)['metadata'];assert meta['input_tokens'] is None and meta['request_evidence']['usage']['invalid_report_count']>0
 finally:close(s)

def test_delayed_snapshot_late_metadata_never_extends_request_or_changes_outcome(tmp_path,monkeypatch):
 s,b,cfg,p=setup(tmp_path/'native');gate=threading.Event();done=threading.Event();calls=[];old=evidence.put
 monkeypatch.setattr('behavior_pipeline_job.Deadline',lambda value,stop:Deadline(.2,stop))
 def delayed(path,value):
  if pathlib.Path(path).name=='envelope.json':gate.wait(3)
  result=old(path,value)
  if pathlib.Path(path).name.startswith('accounting-metadata-'):done.set()
  return result
 monkeypatch.setattr(evidence,'put',delayed)
 monkeypatch.setattr('behavior_accounting.put',delayed)
 def send(url,**kw):calls.append(1);return Reply(kw['json'],choices(kw['json']),metadata={'prompt_eval_count':10,'eval_count':2,'prompt_eval_cached_count':0})
 started=time.monotonic()
 try:
  result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)
  assert result!='completed' and time.monotonic()-started<1 and calls==[1]
  directory=request_directory(b);original=(directory/'outcome.json').read_bytes();u=json.loads(original)['usage'];assert u['input_tokens']==10 and u['output_tokens']==2
  with b.connect() as db:before=[tuple(x) for x in db.execute('SELECT * FROM pipeline_plans')]
  gate.set();assert done.wait(2)
  _,late=reconcile(directory,'synthetic');assert check_usage(late['usage']) and late['attempts_added']==late['accepted_outputs_added']==0 and not late['request_deadline_extended']
  assert original==(directory/'outcome.json').read_bytes() and calls==[1]
  with b.connect() as db:assert before==[tuple(x) for x in db.execute('SELECT * FROM pipeline_plans')]
 finally:gate.set();close(s)

def test_busy_final_commit_keeps_validated_review_and_no_redispatch(tmp_path):
 s,b,cfg,p=setup(tmp_path/'native');locks=[];calls=[]
 def send(url,**kw):calls.append(1);return Reply(kw['json'],choices(kw['json']))
 def hook(point):
  if point=='before_final' and not locks:
   db=sqlite3.connect(str(b.path),timeout=.01);db.execute('BEGIN IMMEDIATE');locks.append(db)
 try:
  status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send,hook=hook)
  assert status=='persistence_review_required' and status.request_units==1 and calls==[1]
  assert len(list(pathlib.Path(b.path).with_suffix('.pipeline-review').glob('*.json')))==1
 finally:
  for db in locks:db.rollback();db.close()
 with b.connect() as db:db.execute('UPDATE pipeline_plans SET deadline=0')
 try:assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='persistence_review_required' and calls==[1]
 finally:close(s)

def test_evidence_follows_existing_compaction_and_never_prunes_pending_or_uncertain(tmp_path):
 from behavior_pipeline_store import compact
 s,b,cfg,p=setup(tmp_path/'native')
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=lambda url,**kw:Reply(kw['json'],choices(kw['json'])))=='completed'
  directory=request_directory(b);assert evidence.prune(b)==0 and directory.exists()
  with b.connect() as db:
   db.execute('DELETE FROM assessments');db.execute("UPDATE pipeline_plans SET created='2000'");assert compact(db,10,'2020')['compacted']==1
  assert evidence.prune(b)==1 and not directory.exists()
  with b.connect() as db:assert db.execute('SELECT count(*) FROM pipeline_plans').fetchone()[0]==1
 finally:close(s)


def test_blocked_outcome_publication_cannot_extend_deadline_or_accept_late(tmp_path,monkeypatch):
 s,b,cfg,p=setup(tmp_path/'native');gate=threading.Event();published=threading.Event();old=evidence.put;calls=[]
 monkeypatch.setattr('behavior_pipeline_job.Deadline',lambda value,stop:Deadline(.18,stop))
 def blocked(path,value):
  if pathlib.Path(path).name=='outcome.json':gate.wait(3)
  result=old(path,value)
  if pathlib.Path(path).name=='outcome.json':published.set()
  return result
 monkeypatch.setattr(evidence,'put',blocked)
 def send(url,**kw):calls.append(1);return Reply(kw['json'],choices(kw['json']))
 start=time.monotonic()
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)!='completed' and time.monotonic()-start<1 and calls==[1]
  with b.connect() as db:
   assert not db.execute("SELECT 1 FROM assessments WHERE status='completed'").fetchone()
   before=[tuple(x) for x in db.execute('SELECT * FROM pipeline_plans')]
  gate.set();assert published.wait(2);time.sleep(.05)
  with b.connect() as db:assert before==[tuple(x) for x in db.execute('SELECT * FROM pipeline_plans')]
  assert calls==[1]
 finally:gate.set();close(s)


def test_blocked_pending_journal_defers_already_durable_result_without_redispatch(tmp_path,monkeypatch):
 import behavior_persistence as pending
 s,b,cfg,p=setup(tmp_path/'native');gate=threading.Event();released=threading.Event();old=pending.stage;calls=[]
 monkeypatch.setattr('behavior_pipeline_job.Deadline',lambda value,stop:Deadline(.2,stop))
 def blocked(*a,**k):
  gate.wait(3)
  try:return old(*a,**k)
  finally:released.set()
 monkeypatch.setattr(pending,'stage',blocked)
 def send(url,**kw):calls.append(1);return Reply(kw['json'],choices(kw['json']))
 start=time.monotonic()
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='persistence_deferred' and time.monotonic()-start<1 and calls==[1]
  with b.connect() as db:
   plan=dict(db.execute('SELECT * FROM pipeline_plans').fetchone());assert plan['state']=='final_pending' and json.loads(plan['outcome'])['row'][5]=='completed'
  gate.set();assert released.wait(2)
  # Only persistence of that already committed result may finish later.
  end=time.monotonic()+2
  while time.monotonic()<end:
   with b.connect() as db:
    if db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='completed':break
   time.sleep(.01)
  with b.connect() as db:assert db.execute('SELECT count(*) FROM pipeline_stages').fetchone()[0]==1 and db.execute('SELECT requests FROM usage').fetchone()[0]==1
  assert calls==[1]
 finally:gate.set();close(s)
