"""Historical version1 topology fixtures; no production database is opened."""
import json,pathlib,time,sqlite3
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline_store import Ledger,Refused,process_token
from behavior_pipeline_job import run
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())

def old_fixture(tmp_path,state):
 s,b,cfg,p=setup(tmp_path/'native',budget=4,count=2)
 schema=pathlib.Path(__file__).with_name('testdata')/'pipeline-schema-v1.sql'
 with b.connect() as db:
  db.executescript(schema.read_text())
  packet=p[0]['packet_id'];row=['legacy-assessment',packet,'legacy-config',ai.now(),'2099','completed',json.dumps({'schema_version':'behavior-3','metadata':{'prompt_version':'behavior-3.29','generation_schema_version':'account-then-selection-1'},'classification':'inconclusive'}),'',.1]
  outcome={'version':1,'row':row,'owner':'legacy-owner','backoff_key':'legacy-backoff','backoff_previous':None,'backoff_at':time.time()}
  raw=json.dumps(outcome)
  db.execute('INSERT INTO pipeline_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',('legacy-plan',packet,'legacy-config','legacy-input','legacy-owner',process_token(),state,ai.now(),time.time()+120,'legacy-assessment',raw if state=='final_pending' else None,'legacy-provider'))
  for ordinal in [1,2]:db.execute('INSERT INTO pipeline_stages VALUES(?,?,?,?,?,?,?,?,?)',('legacy-plan',ordinal,'legacy-request-'+str(ordinal),'old-body-hash','entered' if ordinal==2 else 'accepted',ai.now()[:10],ai.now(),'{"binding":"legacy-frozen"}','{"input_tokens":11}'))
  db.execute('INSERT INTO pipeline_reservations VALUES(?,?,1)',('legacy-plan',ai.now()[:10]));db.execute("INSERT INTO pipeline_active VALUES(1,'legacy-plan')")
  db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',('legacy-owner',packet,'legacy-config','running',time.time()+150,1,ai.now()));db.execute('INSERT INTO usage VALUES(?,2)',(ai.now()[:10],))
 return s,b,cfg,p,raw,row

@pytest.mark.parametrize('state',['stage1_ready','stage1_entered','stage1_validated','stage2_claimed','stage2_entered','uncertain','review'])
def test_old_topology_fenced_with_charges_and_receipts_preserved(tmp_path,state):
 s,b,cfg,p,raw,row=old_fixture(tmp_path,state)
 try:
  with b.connect() as db:before=[tuple(r) for r in db.execute('SELECT * FROM pipeline_stages')]
  ledger=Ledger(b)
  with b.connect() as db:
   assert db.execute('SELECT version FROM pipeline_schema').fetchone()[0]==3
   plan=dict(db.execute('SELECT * FROM pipeline_plans').fetchone());assert plan['topology']=='account-then-selection-1' and plan['state'] in ['uncertain','review']
   assert before==[tuple(r) for r in db.execute('SELECT * FROM pipeline_stages')]
   assert db.execute('SELECT requests FROM usage').fetchone()[0]==2 and db.execute('SELECT held FROM pipeline_reservations').fetchone()[0]==0
   with pytest.raises(sqlite3.IntegrityError):db.execute("UPDATE pipeline_plans SET topology='joint-keyed-purpose-1'")
  with pytest.raises(Refused):ledger.claim('legacy-plan',2,'legacy-config','new',3)
  calls=[]
  result=run(b,p[1]['packet_id'],p[1],set(),cfg,requester=lambda *a,**k:calls.append(1))
  assert result=='persistence_review_required' and calls==[]
 finally:close(s)

def test_old_final_pending_recovery_saves_original_bytes_without_new_inference(tmp_path):
 s,b,cfg,p,raw,row=old_fixture(tmp_path,'final_pending');calls=[]
 try:
  result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=lambda *a,**k:calls.append(1))
  assert result=='completed' and result.request_units==0 and calls==[]
  with b.connect() as db:
   saved=db.execute('SELECT result,config_id FROM assessments').fetchone();assert saved[0]==row[6] and saved[1]=='legacy-config'
   plan=dict(db.execute('SELECT * FROM pipeline_plans').fetchone());assert plan['outcome']==raw and plan['topology']=='account-then-selection-1' and plan['state']=='completed'
   assert db.execute('SELECT requests FROM usage').fetchone()[0]==2
  # A distinct new prompt identity must not reinterpret/cache the old result.
  def send(url,**kw):calls.append(1);return Reply(kw['json'],choices(kw['json']))
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='persistence_review_required' and calls==[]
  with b.connect() as db:assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==1 and db.execute('SELECT requests FROM usage').fetchone()[0]==2
 finally:close(s)

def test_migration_transaction_rolls_back_schema_and_fences_on_interruption(tmp_path,monkeypatch):
 s,b,cfg,p,raw,row=old_fixture(tmp_path,'stage2_entered');original=Ledger.tx
 def fail(self,fn,live=True,**kwargs):
  def wrapped(db):fn(db);raise OSError('Synthetic interruption before migration commit')
  return original(self,wrapped,live,**kwargs)
 try:
  with monkeypatch.context() as patch:
   patch.setattr(Ledger,'tx',fail)
   with pytest.raises(OSError):Ledger(b)
  with b.connect() as db:
   assert db.execute('SELECT version FROM pipeline_schema').fetchone()[0]==1
   assert 'topology' not in [r[1] for r in db.execute('PRAGMA table_info(pipeline_plans)')]
   assert db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='stage2_entered'
  Ledger(b)
  with b.connect() as db:assert db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='uncertain'
 finally:close(s)

def test_unknown_schema_is_review_only_and_never_auto_reinitialized(tmp_path):
 s,b,cfg,p,raw,row=old_fixture(tmp_path,'stage2_entered')
 try:
  with b.connect() as db:db.execute('UPDATE pipeline_schema SET version=999')
  with pytest.raises(Refused):Ledger(b)
  with b.connect() as db:assert db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='stage2_entered'
 finally:close(s)
