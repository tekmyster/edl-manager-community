"""Two-request SQLite, process crash, lost acknowledgements and budget races."""
import copy,json,pathlib,sqlite3,subprocess,sys,threading,time
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline_job import run
from behavior_pipeline_store import Ledger,Refused
from test_pipeline_support import SyntheticCounter,Reply,choices,setup,close

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00');monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())

@pytest.fixture
def sample(tmp_path):
 s,b,cfg,p=setup(tmp_path/'native-test.sqlite3',count=2)
 yield s,b,cfg,p
 close(s)

def rows(b,table):
 with b.connect() as db:return [dict(r) for r in db.execute('SELECT * FROM '+table)]

def sender(calls,mutate=None):
 def send(url,**kw):
  q=kw['json'];calls.append(copy.deepcopy(q));wire=choices(q,groups='selected')
  if mutate:mutate(wire)
  return Reply(q,wire)
 return send

def test_two_calls_two_charges_one_assessment_and_cached_no_charge(sample):
 s,b,cfg,p=sample;calls=[];cfg={**cfg,'daily_budget':2};s.state('behavior_settings',cfg)
 status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))
 assert status=='completed' and status.request_units==len(calls)==2
 assert rows(b,'usage')[0]['requests']==2 and len(rows(b,'assessments'))==1
 assert [r['state'] for r in rows(b,'pipeline_stages')]==['accepted','accepted'] and rows(b,'pipeline_reservations')[0]['held']==0
 assert rows(b,'pipeline_plans')[0]['topology']=='full-joint-draft-revision-1'
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2
 assert run(b,p[1]['packet_id'],p[1],set(),cfg,requester=sender(calls))=='budget'
 meta=json.loads(rows(b,'assessments')[0]['result'])['metadata'];assert meta['planned_requests']==meta['request_count']==2 and meta['input_tokens']==20

def test_unlimited_preserves_all_existing_usage(sample):
 s,b,cfg,p=sample;cfg={**cfg,'daily_budget':None};s.state('behavior_settings',cfg)
 with b.connect() as db:db.execute("INSERT INTO usage VALUES('2000-01-01',24)")
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender([]))=='completed'
 assert {r['day']:r['requests'] for r in rows(b,'usage')}=={'2000-01-01':24,'2026-10-17':2}

@pytest.mark.parametrize('change',[lambda w:w.update(observable_synthesis={}),lambda w:w['observable_synthesis'].update({'unknown':'omit'}),lambda w:w.update(generation_schema_version='old'),lambda w:w.update(packet_id='wrong'),lambda w:w.update(account_binding='old-stage2')])
def test_invalid_joint_output_cannot_retry_or_refill(sample,change):
 s,b,cfg,p=sample;calls=[]
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls,change))=='failed'
 assert len(calls)==rows(b,'usage')[0]['requests']==1
 assert rows(b,'assessments')[0]['status']=='failed'
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_review_required' and len(calls)==1

@pytest.mark.parametrize('phase',['before_reservation','after_reservation','before_claim1','after_claim1','before_entry1','after_entry1','before_dispatch1','before_accept1','after_accept1','before_revision','after_revision','before_claim2','after_claim2','before_entry2','after_entry2','before_dispatch2','before_final','after_final','before_persist','after_persist'])
def test_real_subprocess_crash_recovery_never_resumes_generation(tmp_path,phase):
 directory=tmp_path/phase;directory.mkdir();helper=pathlib.Path(__file__).with_name('test_pipeline_support.py')
 proc=subprocess.run([sys.executable,str(helper),str(directory),phase],cwd=helper.parent,capture_output=True,text=True,timeout=25)
 assert proc.returncode==71,proc.stdout+proc.stderr
 from core import Store
 s=Store(directory/'native-test.sqlite3');b=ai.Brain(s);cfg=ai.settings(s)
 with b.connect() as db:packet=json.loads(db.execute('SELECT content FROM packets LIMIT 1').fetchone()[0])
 calls=[]
 try:
  result=run(b,packet['packet_id'],packet,set(),cfg,requester=sender(calls))
  if phase=='before_reservation':assert result=='completed' and len(calls)==2
  elif phase in ['after_final','before_persist','after_persist']:
   assert result=='completed' and calls==[] and result.request_units==0
   assert run(b,packet['packet_id'],packet,set(),cfg,requester=sender(calls))=='cached'
  else:
   assert result=='persistence_review_required' and calls==[] and not rows(b,'assessments')
   assert rows(b,'pipeline_plans')[0]['state']=='uncertain'
 finally:close(s)

@pytest.mark.parametrize('phase,actual',[('before_claim1',0),('before_entry1',0),('before_dispatch1',0),('before_claim2',1),('before_entry2',1),('before_dispatch2',1),('before_final',2)])
@pytest.mark.parametrize('change',['config','source','packet','tokenizer','cancel','master','model'])
def test_live_input_fences_after_hooks_before_commit_or_dispatch(sample,monkeypatch,phase,actual,change):
 s,b,cfg,p=sample;calls=[];stop=threading.Event();changed=[]
 def hook(point):
  if point!=phase or changed:return
  changed.append(1)
  if change in ['config','master','model']:s.state('behavior_settings',{**cfg,**{'config':{'model':'changed'},'master':{'enabled':False},'model':{'model_enabled':False}}[change]})
  elif change=='source':monkeypatch.setattr('behavior_pipeline_job.source_identity',lambda:{})
  elif change=='tokenizer':monkeypatch.setattr(behavior_tokens,'load',lambda cfg:(_ for _ in ()).throw(ValueError('changed pin')))
  elif change=='cancel':stop.set()
  else:
   with b.connect() as db:db.execute("UPDATE packets SET content='{}'")
 result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook,should_stop=stop.is_set)
 assert changed and result!='completed' and len(calls)==actual
 assert not [r for r in rows(b,'assessments') if r['status']=='completed']
 assert rows(b,'pipeline_reservations')[0]['held']==0

@pytest.mark.parametrize('phase',['before_entry1','before_dispatch1','before_accept1','after_accept1','before_revision','after_revision','before_claim2','after_claim2','before_entry2','after_entry2','before_dispatch2','before_final'])
def test_durable_exact_request_receipt_tampering_rejects(sample,phase):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point==phase:
   with b.connect() as db:db.execute("UPDATE pipeline_stages SET receipt='{}'")
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert len(calls)==(2 if phase=='before_final' else 0 if phase in ('before_entry1','before_dispatch1') else 1)

@pytest.mark.parametrize('phase',['before_claim1','before_entry1','before_dispatch1'])
def test_valid_quota_cut_does_not_reclaim_charged_units(sample,phase):
 s,b,cfg,p=sample;calls=[];cfg={**cfg,'daily_budget':3};s.state('behavior_settings',cfg)
 with b.connect() as db:db.execute('INSERT INTO usage VALUES(?,1)',(ai.now()[:10],))
 def hook(point):
  if point==phase:s.state('behavior_settings',{**cfg,'daily_budget':1})
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert calls==[] and rows(b,'usage')[0]['requests']==(2 if phase=='before_dispatch1' else 1)

def test_short_writer_claim_rollback_and_duplicate_no_second_stage(sample):
 s,b,cfg,p=sample;l=Ledger(b);parent=l.begin(p[0]['packet_id'],'cfg','input',cfg,time.time()+120,[p[0]['packet_id']])
 lock=sqlite3.connect(str(b.path),timeout=.01);lock.execute('BEGIN IMMEDIATE')
 try:
  with pytest.raises(sqlite3.OperationalError):l.claim(parent,1,'cfg','hash',2)
 finally:lock.rollback();lock.close()
 assert rows(b,'usage')==[] and rows(b,'pipeline_reservations')[0]['held']==2
 l.claim(parent,1,'cfg','hash',2)
 with pytest.raises(Refused):l.claim(parent,1,'cfg','hash',2)
 with pytest.raises(Refused):l.claim(parent,2,'cfg','hash',2)
 l.entry(parent,1,'cfg','hash')
 with pytest.raises(Refused):l.entry(parent,1,'cfg','hash')
 with b.connect() as db:
  with pytest.raises(sqlite3.IntegrityError):db.execute("INSERT INTO pipeline_stages VALUES(?,2,'another',NULL,'planned',NULL,NULL,NULL,NULL)",(parent,))
 assert rows(b,'usage')[0]['requests']==1

@pytest.mark.parametrize('phase',['after_claim1','after_entry1','after_final'])
def test_lost_committed_ack_is_not_a_retry_token(sample,phase):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point==phase:raise sqlite3.OperationalError('Synthetic lost commit acknowledgement')
 result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)
 assert result!='completed' and result.request_units=={'after_claim1':0,'after_entry1':1,'after_final':2}[phase]
 count=len(calls);again=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))
 assert len(calls)==count and again in ['completed','failed','persistence_review_required','cached']
 assert sum(r['requests'] for r in rows(b,'usage'))=={'after_claim1':0,'after_entry1':1,'after_final':2}[phase]

def test_no_writer_lock_across_generation_and_single_active_permit(sample):
 s,b,cfg,p=sample;entered=threading.Event();release=threading.Event();calls=[];result=[]
 def send(url,**kw):
  with b.connect() as db:db.execute('BEGIN IMMEDIATE');db.rollback()
  calls.append(kw['json']);entered.set();release.wait(3);return Reply(kw['json'],choices(kw['json']))
 worker=threading.Thread(target=lambda:result.append(run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)));worker.start()
 try:
  assert entered.wait(2)
  assert run(b,p[1]['packet_id'],p[1],set(),cfg,requester=sender([]))=='leased_or_exhausted'
  assert rows(b,'usage')[0]['requests']==1 and rows(b,'pipeline_reservations')[0]['held']==1
 finally:release.set();worker.join(4)
 assert result==['completed'] and len(calls)==2

def test_actual_process_race_reserves_one_unit(tmp_path):
 s,b,cfg,p=setup(tmp_path/'native-test.sqlite3',count=2);helper=pathlib.Path(__file__).with_name('test_pipeline_support.py');children=[]
 try:
  Ledger(b)
  children=[subprocess.Popen([sys.executable,str(helper),str(tmp_path),'race:'+str(i)],cwd=helper.parent,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True) for i in range(2)]
  (tmp_path/'race-start').touch();end=time.monotonic()+10
  while not all((tmp_path/f'race-{i}.json').exists() for i in range(2)):assert time.monotonic()<end;time.sleep(.02)
  assert sorted(json.loads((tmp_path/f'race-{i}.json').read_text())['status'] for i in range(2))==['leased_or_exhausted','reserved']
  assert sum(r['held'] for r in rows(b,'pipeline_reservations'))==2 and rows(b,'usage')==[]
 finally:
  (tmp_path/'race-release').touch()
  for child in children:
   out,err=child.communicate(timeout=12);assert child.returncode==0,out+err
  close(s)

def test_midnight_between_claim_entry_never_refills(sample,monkeypatch):
 s,b,cfg,p=sample;calls=[]
 def hook(point):
  if point=='after_entry1':monkeypatch.setattr(ai,'now',lambda:'2026-10-18T00:00:01+00:00')
 assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)!='completed'
 assert calls==[] and rows(b,'usage')==[{'day':'2026-10-17','requests':1}]
