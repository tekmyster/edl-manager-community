"""Installed3.17 and schema2 preservation; disposable SQLite only."""
import contextlib,json,pathlib,sqlite3,time
from types import SimpleNamespace
import pytest
from behavior_pipeline_store import Ledger,Refused,process_token

class FixtureBrain:
 def __init__(self,path):self.path=path;self.store=SimpleNamespace(path=path)
 @contextlib.contextmanager
 def connect(self):
  db=sqlite3.connect(self.path);db.row_factory=sqlite3.Row
  try:
   with db:yield db
  finally:db.close()

@pytest.mark.parametrize('legacy',[False,True])
@pytest.mark.parametrize('state',['running','failed','completed'])
def test_installed_schema_migration_preserves_consumed_authority_and_private_journals(tmp_path,legacy,state):
 b=FixtureBrain(tmp_path/'fixture');fixtures=pathlib.Path(__file__).with_name('testdata')
 with b.connect() as db:
  db.executescript((fixtures/'installed-behavior-3.17.sql').read_text())
  db.execute('INSERT INTO usage VALUES(?,?)',('2000-01-01',24))
  db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',('old-owner','packet','old-config',state,0,1,'2000'))
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('saved','packet','old-config','2000','2001',state,'{"metadata":{"prompt_version":"behavior-3.17"}}','',.5))
  if legacy:
   db.executescript((fixtures/'pipeline-schema-v2.sql').read_text())
   db.execute('INSERT INTO pipeline_plans VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',('old-plan','packet','old-config','old-input','old-owner',process_token(),'stage1_entered','2000',time.time()+120,'old-final',None,'old-provider','joint-keyed-purpose-1'))
   db.execute('INSERT INTO pipeline_stages VALUES(?,?,?,?,?,?,?,?,?)',('old-plan',1,'old-request','old-request-hash','entered','2000-01-01','2000','{"old":"receipt"}','{"input_tokens":42}'))
   db.execute('INSERT INTO pipeline_reservations VALUES(?,?,?)',('old-plan','2000-01-01',1))
   db.execute('INSERT INTO pipeline_active VALUES(1,?)',('old-plan',))
  tables=['jobs','usage','assessments']+(['pipeline_stages'] if legacy else [])
  before={t:[tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in tables}
 journal=tmp_path/'fixture.pending';journal.mkdir();(journal/'closed.inflight').write_bytes(b'{"request":"entered-not-resumable"}')
 old_bytes=(journal/'closed.inflight').read_bytes()
 ledger=Ledger(b)
 with b.connect() as db:
  assert db.execute('SELECT version FROM pipeline_schema').fetchone()[0]==3
  assert before=={t:[tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in tables}
  if legacy:
   assert db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='uncertain'
   assert db.execute('SELECT held FROM pipeline_reservations').fetchone()[0]==0
 assert (journal/'closed.inflight').read_bytes()==old_bytes
 if legacy:assert ledger.inspect('packet','old-config')['state']=='uncertain'
 else:
  with pytest.raises(Refused):ledger.inspect('packet','old-config')
 # Date/process/lease expiration never erases the consumed ownership barrier.
 ledger.recover_active()
 if legacy:assert ledger.inspect('packet','old-config')['state']=='uncertain'
 else:
  with pytest.raises(Refused):ledger.inspect('packet','old-config')
 if legacy:assert ledger.inspect('packet','new-topology-config')['state']=='uncertain'
 else:
  # A changed prompt must not reopen any consumed legacy packet, including
  # a completed result. It is review-only, never a new cache/model request.
  with pytest.raises(Refused):ledger.inspect('packet','new-topology-config')

def test_expired_old_config_owners_fence_consumed_packet_without_global_starvation(tmp_path):
 b=FixtureBrain(tmp_path/'fixture');fixtures=pathlib.Path(__file__).with_name('testdata')
 with b.connect() as db:
  db.executescript((fixtures/'installed-behavior-3.17.sql').read_text())
  for cid,state in [('old-complete','completed'),('old-unresolved','running')]:
   db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(cid,'old-packet',cid,state,0,1,'2000'))
  db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',('new-packet','8.8.8.8','2000','{}','[]',0))
  db.execute('INSERT INTO current_packets VALUES(?,?)',('8.8.8.8','new-packet'))
 ledger=Ledger(b)
 with b.connect() as db:assert db.execute('SELECT count(*) FROM pipeline_legacy_barriers').fetchone()[0]==2
 with pytest.raises(Refused,match='persistence_review_required'):ledger.inspect('old-packet','new-config')
 # No live lease or private journal exists here. Historical running state
 # still fences its packet, but is not proof of an outstanding global request.
 parent=ledger.begin('new-packet','new-config','new-input',{'endpoint':'synthetic','model':'synthetic','daily_budget':24},time.time()+120,['new-packet'])
 with b.connect() as db:
  assert dict(db.execute('SELECT config,state FROM pipeline_legacy_barriers'))=={'old-complete':'completed','old-unresolved':'running'}
  assert [tuple(r) for r in db.execute("SELECT id,state,lease FROM jobs WHERE packet_id='old-packet' ORDER BY id")]==[('old-complete','completed',0),('old-unresolved','running',0)]
  assert db.execute('SELECT state FROM pipeline_plans WHERE id=?',(parent,)).fetchone()[0]=='stage1_ready'
  assert db.execute('SELECT count(*) FROM pipeline_stages WHERE parent=?',(parent,)).fetchone()[0]==2
  assert db.execute('SELECT coalesce(sum(requests),0) FROM usage').fetchone()[0]==0

@pytest.mark.parametrize('finished',[False,True])
def test_actual_installed_journal_writer_is_preserved_and_never_reissued(tmp_path,monkeypatch,finished):
 import behavior_ai as ai,behavior_tokens,behavior_persistence as current
 from behavior_pipeline_job import run
 from test_pipeline_support import setup,close,SyntheticCounter
 from test_behavior_ai import result
 source=pathlib.Path(__file__).with_name('testdata')/'installed-behavior-persistence-3.17.py.source'
 legacy={'__name__':'offline_installed_317_journal_fixture','__file__':str(source)}
 exec(compile(source.read_bytes(),str(source),'exec'),legacy)
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 s,b,cfg,packets=setup(tmp_path/'native');packet=packets[0];ident=packet['packet_id'];cid='installed-3.17-config';owner='installed-owner';assessment='installed-final'
 try:
  with b.connect() as db:
   db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(owner,ident,cid,'running',0,1,ai.now()))
   db.execute('INSERT INTO usage VALUES(?,1)',(ai.now()[:10],))
  marker=legacy['reserve'](b,ident,cid,owner,assessment,'a'*32);original=marker.read_bytes()
  if finished:
   canonical=result(packet);canonical['metadata']={'prompt_version':'behavior-3.17','generation_schema_version':'grounded-groups-8'}
   row=[assessment,ident,cid,ai.now(),'2099','completed',json.dumps(canonical),'',.1]
   outcome={'version':1,'row':row,'owner':owner,'backoff_key':'legacy-guard','backoff_previous':None,'backoff_at':time.time()}
   journal=legacy['stage'](b,outcome);saved=journal.read_bytes()
  Ledger(b)
  assert marker.read_bytes()==original
  if finished:
   assert journal.read_bytes()==saved and current.read(journal)==outcome
   assert current.recover(b)['saved']==1
   with b.connect() as db:assert tuple(db.execute('SELECT * FROM assessments').fetchone())==tuple(row)
  calls=[]
  assert run(b,ident,packet,set(),cfg,requester=lambda *a,**k:calls.append(1))=='persistence_review_required'
  assert not calls
  with b.connect() as db:assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==1
  if not finished:assert marker.read_bytes()==original
 finally:close(s)
