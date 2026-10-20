"""Actual isolated SQLite, subprocess crash/restart and concurrency contracts."""
import copy,json,pathlib,sqlite3,subprocess,sys,threading,time
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline import Pipeline
from behavior_pipeline_job import run
from behavior_pipeline_store import Ledger,Refused,process_token
from test_pipeline_support import SyntheticCounter,Reply,choices,setup,close

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00');monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())

@pytest.fixture
def sample(tmp_path):
 store,b,cfg,p=setup(tmp_path/'native-test.sqlite3',count=2)
 yield store,b,cfg,p
 close(store)

def rows(b,table):
 with b.connect() as db:return [dict(r) for r in db.execute('SELECT * FROM '+table)]

def sender(calls,mutate=None):
 def send(url,**kw):
  q=kw['json'];calls.append(copy.deepcopy(q));w=choices(q,groups='selected')
  if mutate:mutate(len(calls),w,q)
  return Reply(q,w)
 return send

def test_two_calls_one_assessment_and_cached_no_charge(sample):
 s,b,cfg,p=sample;calls=[];status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))
 assert status=='completed' and status.request_units==2 and len(calls)==2
 assert rows(b,'usage')[0]['requests']==2 and len(rows(b,'assessments'))==1
 assert [x['state'] for x in rows(b,'pipeline_stages')]==['accepted','accepted'] and rows(b,'pipeline_reservations')[0]['held']==0
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2
 assert run(b,p[1]['packet_id'],p[1],set(),cfg,requester=sender(calls))=='budget'
 metadata=json.loads(rows(b,'assessments')[0]['result'])['metadata'];assert len(metadata['generation_stages'])==2 and metadata['pipeline_usage']['input_tokens']==20 and metadata['input_tokens'] is None

def test_finite_one_refuses_before_first_call_and_unlimited_keeps_history(sample):
 s,b,cfg,p=sample;calls=[]
 s.state('behavior_settings',{**cfg,'daily_budget':1})
 assert run(b,p[0]['packet_id'],p[0],set(),{**cfg,'daily_budget':1},requester=sender(calls))=='budget' and calls==[] and rows(b,'usage')==[]
 s.state('behavior_settings',{**cfg,'daily_budget':None})
 with b.connect() as db:db.execute("INSERT INTO usage VALUES('2000-01-01',24)")
 assert run(b,p[0]['packet_id'],p[0],set(),{**cfg,'daily_budget':None},requester=sender(calls))=='completed'
 assert {r['day']:r['requests'] for r in rows(b,'usage')}=={'2000-01-01':24,'2026-10-17':2}

@pytest.mark.parametrize('change',[lambda w:w.update(accounts={}),lambda w:w['accounts'].update({'unknown':'omit'}),lambda w:w.update(contract='wrong'),lambda w:w.update(packet_id='wrong')])
def test_invalid_first_stage_aborts_without_second_or_replay(sample,change):
 s,b,cfg,p=sample;calls=[]
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls,lambda n,w,q:change(w) if n==1 else None))=='failed'
 assert len(calls)==1 and rows(b,'usage')[0]['requests']==1 and rows(b,'pipeline_reservations')[0]['held']==0
 assert rows(b,'assessments')[0]['status']=='failed'
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_review_required' and len(calls)==1
 assert rows(b,'pipeline_plans')[0]['state']=='failed'

def test_stage2_cannot_rewrite_frozen_accounts(sample):
 s,b,cfg,p=sample;calls=[]
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls,lambda n,w,q:w.update(observable_synthesis={}) if n==2 else None))
 assert status=='failed' and len(calls)==2 and rows(b,'usage')[0]['requests']==2
 assert rows(b,'pipeline_stages')[0]['receipt'] and rows(b,'assessments')[0]['status']=='failed'

def test_cut_quota_after_stage1_releases_second_reservation(sample):
 s,b,cfg,p=sample;calls=[]
 def hook(phase):
  if phase=='after_freeze':s.state('behavior_settings',{**cfg,'daily_budget':1})
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='failed'
 assert len(calls)==1 and rows(b,'usage')[0]['requests']==1 and rows(b,'pipeline_reservations')[0]['held']==0

def test_midnight_charges_dispatch_days_not_assessment_count(sample,monkeypatch):
 s,b,cfg,p=sample;calls=[]
 def hook(phase):
  if phase=='after_freeze':monkeypatch.setattr(ai,'now',lambda:'2026-10-18T00:00:01+00:00')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='completed'
 assert {r['day']:r['requests'] for r in rows(b,'usage')}=={'2026-10-17':1,'2026-10-18':1}

@pytest.mark.parametrize('phase',['before_reservation','after_reservation','before_claim1','after_claim1','before_entry1','after_entry1','before_freeze','after_freeze','before_claim2','after_claim2','before_entry2','after_entry2','before_final','after_final','before_persist','after_persist'])
def test_actual_process_crash_boundary_never_resumes_inference(tmp_path,phase):
 directory=tmp_path/phase;directory.mkdir();helper=pathlib.Path(__file__).with_name('test_pipeline_support.py')
 done=subprocess.run([sys.executable,str(helper),str(directory),phase],cwd=helper.parent,capture_output=True,text=True,timeout=20)
 assert done.returncode==71,done.stdout+done.stderr
 from core import Store
 s=Store(directory/'native-test.sqlite3');b=ai.Brain(s);cfg=ai.settings(s)
 with b.connect() as db:packet=json.loads(db.execute('SELECT content FROM packets ORDER BY id LIMIT 1').fetchone()[0])
 count=lambda:len((directory/'mock-transport.log').read_text().splitlines()) if (directory/'mock-transport.log').exists() else 0
 before=count();calls=[]
 try:
  status=run(b,packet['packet_id'],packet,set(),cfg,requester=sender(calls))
  if phase=='before_reservation':assert status=='completed' and len(calls)==2
  elif phase in ('after_final','before_persist','after_persist'):
   assert status=='completed' and calls==[] and status.request_units==0 and len(rows(b,'assessments'))==1
   assert run(b,packet['packet_id'],packet,set(),cfg,requester=sender(calls))=='cached'
  else:
   assert status=='persistence_review_required' and calls==[] and not rows(b,'assessments')
   assert rows(b,'pipeline_plans')[0]['state']=='uncertain'
   assert run(b,packet['packet_id'],packet,set(),{**cfg,'timeout':121},requester=sender(calls))=='persistence_review_required'
  assert count()==before
 finally:close(s)

def test_actual_held_writer_rolls_back_claim_and_never_dispatches(sample):
 s,b,cfg,p=sample;ledger=Ledger(b);parent=ledger.begin(p[0]['packet_id'],'fixture-config','fixture-input',cfg,time.time()+120,[p[0]['packet_id']])
 lock=sqlite3.connect(str(b.path),timeout=.01);lock.execute('BEGIN IMMEDIATE')
 try:
  with pytest.raises(sqlite3.OperationalError):ledger.claim(parent,1,'fixture-config','hash',2)
 finally:lock.rollback();lock.close()
 assert rows(b,'usage')==[] and rows(b,'pipeline_stages')[0]['state']=='planned' and rows(b,'pipeline_reservations')[0]['held']==2

def test_duplicate_claim_entry_and_changed_input_guard(sample):
 s,b,cfg,p=sample;ledger=Ledger(b);parent=ledger.begin(p[0]['packet_id'],'cfg','input',cfg,time.time()+120,[p[0]['packet_id']])
 ledger.claim(parent,1,'cfg','exact-hash',2)
 with pytest.raises(Refused):ledger.claim(parent,1,'cfg','exact-hash',2)
 with pytest.raises(Refused):ledger.entry(parent,1,'cfg','changed')
 ledger.entry(parent,1,'cfg','exact-hash')
 with pytest.raises(Refused):ledger.entry(parent,1,'cfg','exact-hash')
 with pytest.raises(Refused):ledger.claim(parent,2,'cfg','second',2)
 assert rows(b,'usage')[0]['requests']==1

def test_missing_input_metadata_stops_before_transport_and_reservation(sample,monkeypatch):
 s,b,cfg,p=sample;calls=[]
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:(_ for _ in ()).throw(ValueError('not configured')))
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='input_verification_required'
 assert calls==[] and rows(b,'pipeline_stages')==[] and rows(b,'usage')==[]

@pytest.mark.parametrize('change',['packet','config','lease','receipt','source','cancel'])
def test_mutation_after_freeze_never_dispatches_stage2(sample,monkeypatch,change):
 s,b,cfg,p=sample;calls=[];stop=threading.Event()
 def hook(phase):
  if phase!='after_freeze':return
  if change=='config':s.state('behavior_settings',{**cfg,'model':'changed'})
  elif change=='cancel':stop.set()
  elif change=='source':monkeypatch.setattr('behavior_pipeline_job.source_identity',lambda:{})
  else:
   with b.connect() as db:
    if change=='lease':db.execute('UPDATE jobs SET lease=0')
    elif change=='packet':db.execute("UPDATE packets SET content='{}' WHERE id=?",(p[0]['packet_id'],))
    else:db.execute("UPDATE pipeline_stages SET receipt='{}' WHERE ordinal=1")
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook,should_stop=stop.is_set)
 assert status in ('failed','persistence_review_required') and len(calls)==1
 assert rows(b,'usage')[0]['requests']==1 and rows(b,'pipeline_reservations')[0]['held']==0

def test_concurrent_workers_cannot_take_second_permit_or_budget(sample):
 s,b,cfg,p=sample;entered=threading.Event();release=threading.Event();calls=[];results=[]
 def send(url,**kw):
  calls.append(kw['json']);entered.set();assert release.wait(3);return Reply(kw['json'],choices(kw['json']))
 thread=threading.Thread(target=lambda:results.append(run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)))
 thread.start()
 try:
  assert entered.wait(3)
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender([]))=='leased_or_exhausted'
  assert run(b,p[1]['packet_id'],p[1],set(),cfg,requester=sender([]))=='leased_or_exhausted'
  assert rows(b,'usage')[0]['requests']==1 and rows(b,'pipeline_reservations')[0]['held']==1
 finally:release.set();thread.join(5)
 assert results==['completed'] and len(calls)==2 and rows(b,'usage')[0]['requests']==2

def test_actual_process_race_reserves_only_two_total_units(tmp_path):
 s,b,cfg,p=setup(tmp_path/'native-test.sqlite3',count=2);helper=pathlib.Path(__file__).with_name('test_pipeline_support.py');children=[]
 try:
  children=[subprocess.Popen([sys.executable,str(helper),str(tmp_path),'race:'+str(i)],cwd=helper.parent,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for i in range(2)]
  (tmp_path/'race-start').touch();limit=time.monotonic()+8
  while not all((tmp_path/('race-'+str(i)+'.json')).exists() for i in range(2)):
   assert time.monotonic()<limit;time.sleep(.02)
  outcomes=sorted(json.loads((tmp_path/('race-'+str(i)+'.json')).read_text())['status'] for i in range(2))
  assert outcomes==['leased_or_exhausted','reserved']
  assert sum(r['held'] for r in rows(b,'pipeline_reservations'))==2 and rows(b,'usage')==[] and len(rows(b,'pipeline_plans'))==1
 finally:
  (tmp_path/'race-release').touch()
  for process in children:
   stdout,stderr=process.communicate(timeout=10);assert process.returncode==0,stdout+stderr
  close(s)

def test_busy_final_commit_retains_private_validated_result_without_replay(sample):
 s,b,cfg,p=sample;calls=[];held=[]
 def hook(phase):
  if phase=='before_final' and not held:
   db=sqlite3.connect(str(b.path),timeout=.01);db.execute('BEGIN IMMEDIATE');held.append(db)
 try:
  status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)
  assert status=='persistence_review_required' and status.request_units==2 and len(calls)==2
  assert not rows(b,'assessments')
  review=list(pathlib.Path(b.path).with_suffix('.pipeline-review').glob('*.json'));assert len(review)==1
  assert json.loads(review[0].read_bytes())['row'][5]=='completed'
 finally:
  for db in held:db.rollback();db.close()
 # Simulate the elapsed whole-assessment deadline after the failed writer.
 with b.connect() as db:db.execute('UPDATE pipeline_plans SET deadline=0')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_review_required' and len(calls)==2
 assert rows(b,'pipeline_plans')[0]['state']=='uncertain' and rows(b,'pipeline_reservations')[0]['held']==0

def test_bounded_compaction_preserves_failed_tombstone_and_uncertain_receipt(sample):
 from behavior_pipeline_store import compact
 s,b,cfg,p=sample;cfg={**cfg,'daily_budget':None};s.state('behavior_settings',cfg);calls=[]
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='completed'
 assert run(b,p[1]['packet_id'],p[1],set(),cfg,requester=sender([],lambda n,w,q:w.update(contract='invalid') if n==1 else None))=='failed'
 with b.connect() as db:db.execute("UPDATE assessments SET expires='2000'")
 def crash(phase):
  if phase=='after_freeze':raise KeyboardInterrupt()
 with pytest.raises(KeyboardInterrupt):run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=crash)
 plans=rows(b,'pipeline_plans');uncertain=next(x for x in plans if x['state']=='uncertain');receipt=next(x['receipt'] for x in rows(b,'pipeline_stages') if x['parent']==uncertain['id'] and x['ordinal']==1)
 assert receipt
 with b.connect() as db:
  db.execute('DELETE FROM assessments');db.execute("UPDATE pipeline_plans SET created='2000'")
  results=[compact(db,1,'2020') for _ in range(6)]
 assert all(x['scanned']<=1 for x in results) and sum(x['compacted'] for x in results)==2
 after=rows(b,'pipeline_plans');assert len(after)==3 and all(x['outcome'] is None for x in after)
 assert next(x['receipt'] for x in rows(b,'pipeline_stages') if x['parent']==uncertain['id'] and x['ordinal']==1)==receipt
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_review_required'
 assert run(b,p[1]['packet_id'],p[1],set(),{**cfg,'timeout':121},requester=sender(calls))=='persistence_review_required'

@pytest.mark.parametrize('phase,actual',[('before_claim1',0),('before_entry1',0),('before_freeze',1),('before_claim2',1),('before_entry2',1),('before_final',2)])
@pytest.mark.parametrize('change',['config','source','packet','cancel'])
def test_boundary_mutations_are_rechecked_after_hook_before_transaction(sample,monkeypatch,phase,actual,change):
 s,b,cfg,p=sample;calls=[];stop=threading.Event();changed=[]
 def hook(point):
  if point!=phase or changed:return
  changed.append(1)
  if change=='config':s.state('behavior_settings',{**cfg,'model':'changed'})
  elif change=='source':monkeypatch.setattr('behavior_pipeline_job.source_identity',lambda:{})
  elif change=='cancel':stop.set()
  else:
   with b.connect() as db:db.execute("UPDATE packets SET content='{}' WHERE id=?",(p[0]['packet_id'],))
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook,should_stop=stop.is_set)
 assert changed and status in ('failed','persistence_review_required') and len(calls)==actual
 assert not [r for r in rows(b,'assessments') if r['status']=='completed']
 assert rows(b,'pipeline_reservations')[0]['held']==0

@pytest.mark.parametrize('phase,actual',[('before_claim2',1),('before_entry2',1),('before_final',2)])
def test_frozen_receipt_is_rechecked_at_claim_entry_and_commit(sample,phase,actual):
 s,b,cfg,p=sample;calls=[];changed=[]
 def hook(point):
  if point==phase and not changed:
   changed.append(1)
   with b.connect() as db:db.execute("UPDATE pipeline_stages SET receipt='{}' WHERE ordinal=1")
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)
 assert changed and status in ('failed','persistence_review_required') and len(calls)==actual
 assert not [r for r in rows(b,'assessments') if r['status']=='completed']

@pytest.mark.parametrize('phase,actual,charges',[('before_claim1',0,0),('before_entry1',0,1),('before_claim2',1,1),('before_entry2',1,2)])
def test_quota_cut_at_irreducible_boundaries_never_posts_after_cut(sample,phase,actual,charges):
 s,b,cfg,p=sample;calls=[];changed=[]
 def hook(point):
  if point==phase and not changed:changed.append(1);s.state('behavior_settings',{**cfg,'daily_budget':1})
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='failed'
 assert changed and len(calls)==actual and sum(r['requests'] for r in rows(b,'usage'))==charges
 assert rows(b,'pipeline_reservations')[0]['held']==0
 assert not [r for r in rows(b,'retention_state') if r['name'].startswith('provider_backoff:')]

def test_midnight_between_claim_and_entry_consumes_claim_without_dispatch(sample,monkeypatch):
 s,b,cfg,p=sample;calls=[]
 def hook(phase):
  if phase=='before_entry1':monkeypatch.setattr(ai,'now',lambda:'2026-10-18T00:00:01+00:00')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='failed'
 assert calls==[] and {r['day']:r['requests'] for r in rows(b,'usage')}=={'2026-10-17':1}
 assert rows(b,'pipeline_reservations')[0]['held']==0
