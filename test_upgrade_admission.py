"""Offline 3.17 state upgrade, outstanding ownership and optional refresh recovery."""
import contextlib,datetime as dt,json,pathlib,sqlite3,time
import pytest
import behavior_ai as ai,behavior_tokens,behavior_context as ctx
from behavior_pipeline_store import Ledger,Refused,process_token
from behavior_pipeline_job import run
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 import socket
 def deny(*a,**k):raise AssertionError('Offline fixture denies all real network')
 monkeypatch.setattr(socket.socket,'connect',deny)
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda _:SyntheticCounter())

def snapshot(b):
 with b.connect() as db:return {t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in ('jobs','assessments','usage')}

def legacy(tmp_path,counts=None,lease=None):
 s,b,cfg,packets=setup(tmp_path/'native',budget=None,count=2)
 # setup creates the exact legacy base schema, without any pipeline tables.
 old=pathlib.Path(__file__).with_name('testdata')/'behavior-schema-3.17.sql'
 with b.connect() as db:
  for statement in old.read_text().split(';'):
   if statement.strip():db.execute(statement)
  assert not db.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'pipeline_%'").fetchone()
  for state,n in (counts or {'completed':3,'failed':2,'superseded':2,'running':1}).items():
   for i in range(n):
    ident=state+'-'+str(i);packet='legacy-'+ident;owner='owner-'+ident
    db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(owner,packet,'old-config',state,lease if lease is not None and state=='running' else time.time()-3600,1,ai.now()))
    if state!='running':db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('assessment-'+ident,packet,'old-config',ai.now(),'2099',state,json.dumps({'immutable':ident}),'',.1))
  db.execute('INSERT INTO usage VALUES(?,?)',(ai.now()[:10],sum((counts or {'completed':3,'failed':2,'superseded':2,'running':1}).values())))
 return s,b,cfg,packets

def sender(calls):
 def send(url,**kw):
  calls.append(kw['json']);return Reply(kw['json'],choices(kw['json'],groups='selected'))
 return send

@pytest.mark.parametrize('counts',[{'completed':9208,'failed':275,'superseded':26,'running':1},{'superseded':1},{'running':1},{'completed':1,'failed':1}])
def test_actual_317_mixed_upgrade_fresh_two_stages_and_cache(tmp_path,counts):
 s,b,cfg,p=legacy(tmp_path,counts);calls=[]
 try:
  before=snapshot(b);Ledger(b)
  assert snapshot(b)==before
  with b.connect() as db:
   barriers=[tuple(r) for r in db.execute('SELECT state,count(*) FROM pipeline_legacy_barriers GROUP BY state')]
   assert dict(barriers)==counts and db.execute('SELECT count(*) FROM pipeline_plans').fetchone()[0]==0
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='completed'
  assert len(calls)==2
  with b.connect() as db:
   assert db.execute('SELECT count(*) FROM pipeline_stages').fetchone()[0]==2
   assert db.execute('SELECT count(*) FROM pipeline_finals').fetchone()[0]==1
   assert db.execute('SELECT sum(held) FROM pipeline_reservations').fetchone()[0]==0
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==sum(counts.values())+2
   assert dict(db.execute('SELECT state,count(*) FROM pipeline_legacy_barriers GROUP BY state'))==counts
   for t in ('jobs','assessments'):
    assert [r for r in snapshot(b)[t] if str(r[0]).startswith(('owner-','assessment-'))]==before[t]
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2
 finally:close(s)

@pytest.mark.parametrize('state',['completed','failed','superseded','running'])
def test_consumed_packet_is_fenced_across_new_prompt_identity(tmp_path,state):
 s,b,cfg,p=legacy(tmp_path,{state:1});calls=[]
 try:
  with b.connect() as db:
   db.execute('UPDATE jobs SET packet_id=?',(p[0]['packet_id'],));db.execute('UPDATE assessments SET packet_id=?',(p[0]['packet_id'],))
  before=snapshot(b)
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_review_required'
  assert not calls and snapshot(b)==before
 finally:close(s)

def test_live_legacy_lease_blocks_fresh_until_expiry_without_reopening_old(tmp_path):
 s,b,cfg,p=legacy(tmp_path,{'running':1},lease=time.time()+90);calls=[]
 try:
  before=snapshot(b)
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='leased_or_exhausted'
  assert not calls and snapshot(b)==before
  with b.connect() as db:db.execute('UPDATE jobs SET lease=?',(time.time()-1,))
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='completed' and len(calls)==2
  with b.connect() as db:assert db.execute("SELECT state FROM pipeline_legacy_barriers WHERE packet='legacy-running-0'").fetchone()[0]=='running'
 finally:close(s)

@pytest.mark.parametrize('owner',['alive','dead','unknown'])
def test_new_protocol_outstanding_owner_never_replayed(tmp_path,owner):
 s,b,cfg,p=setup(tmp_path/'native',budget=None,count=2);calls=[]
 try:
  l=Ledger(b);parent=l.begin(p[0]['packet_id'],'config','input',cfg,time.time()+120,[])
  with b.connect() as db:db.execute('UPDATE pipeline_plans SET process=? WHERE id=?',({'alive':process_token(),'dead':'999999999:1','unknown':'unknown'}[owner],parent))
  result=run(b,p[1]['packet_id'],p[1],set(),cfg,requester=sender(calls))
  if owner in ('alive','unknown'):assert result=='leased_or_exhausted' and calls==[]
  else:
   assert result=='completed' and len(calls)==2
   with b.connect() as db:assert db.execute('SELECT state FROM pipeline_plans WHERE id=?',(parent,)).fetchone()[0]=='uncertain'
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls)) in ('leased_or_exhausted','persistence_review_required')
  assert len(calls)==(2 if owner=='dead' else 0)
 finally:close(s)

@pytest.mark.parametrize('kind',['inflight','review','pending'])
def test_private_unknown_dispatch_or_pending_result_keeps_global_protection(tmp_path,kind):
 import behavior_persistence as pending
 s,b,cfg,p=legacy(tmp_path,{'running':1});calls=[]
 try:
  if kind=='inflight':pending.reserve(b,'legacy-running-0','old-config','owner-running-0','missing-assessment','old-request')
  elif kind=='review':(pending.review_directory(b,True)/'attention').write_text('Retained review')
  else:
   with b.connect() as db:db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',('legacy-running-0','7.7.7.7',ai.now(),json.dumps(p[1]),'[]',0))
   row=['old-final','legacy-running-0','old-config',ai.now(),'2099','completed',json.dumps({'immutable':'old-final'}),'',.1]
   pending.stage(b,{'version':1,'row':row,'owner':'different-owner','backoff_key':'unused','backoff_previous':None,'backoff_at':time.time()})
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_review_required' and not calls
  with b.connect() as db:assert db.execute('SELECT count(*) FROM pipeline_plans').fetchone()[0]==0
 finally:close(s)

def test_legacy_pending_final_recovers_original_bytes_before_fresh_work(tmp_path):
 import behavior_persistence as pending
 s,b,cfg,p=legacy(tmp_path,{'running':1});calls=[]
 try:
  with b.connect() as db:
   db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',('legacy-running-0','7.7.7.7',ai.now(),json.dumps(p[1]),'[]',0))
   db.execute('INSERT INTO current_packets VALUES(?,?)',('7.7.7.7','legacy-running-0'))
  raw=json.dumps({'immutable':'original legacy response','metadata':{'prompt_version':'behavior-3.17'}})
  row=['old-final','legacy-running-0','old-config',ai.now(),'2099','completed',raw,'',.1]
  path=pending.stage(b,{'version':1,'row':row,'owner':'owner-running-0','backoff_key':'unused','backoff_previous':None,'backoff_at':time.time()})
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='completed' and len(calls)==2
  with b.connect() as db:
   assert tuple(db.execute("SELECT * FROM assessments WHERE id='old-final'").fetchone())==tuple(row)
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==3
  assert not path.exists()
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2
 finally:close(s)

def test_held_derived_writer_has_safe_phase_diagnostic_then_recovers(tmp_path,caplog):
 s,b,cfg,p=legacy(tmp_path,{'running':1});calls=[];Ledger(b)
 try:
  holder=sqlite3.connect(b.path);holder.execute('BEGIN IMMEDIATE')
  try:
   for _ in range(3):
    started=time.monotonic();assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='persistence_deferred';assert time.monotonic()-started<2
   assert not calls and 'phase=owner_recovery' in caplog.text and 'sqlite_code=5' in caplog.text
  finally:holder.rollback();holder.close()
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='completed' and len(calls)==2
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2
 finally:close(s)

def test_optional_palo_busy_repeated_passes_still_finish_analysis_and_recover(tmp_path,monkeypatch):
 import evidence_history,activity
 from core import now
 from test_delivery_contention import palo_fixture
 from behavior_pipeline_job import run as pipeline_run
 s,b,cfg,p=setup(tmp_path/'native',budget=None);calls=[];fetches=[];holders=[];blocked=[True]
 source=palo_fixture(s);cfg.update(palo_context_enabled=True);s.state('behavior_settings',cfg)
 s.evidence('9.9.9.9','nginx','sensitive-path-probe',now(),'http',50)
 monkeypatch.setattr(evidence_history,'refresh',lambda *a,**k:'cached')
 original=ctx.refresh_palo
 def refresh(*a,**kw):
  if blocked[0]:
   holder=sqlite3.connect(s.path);holder.execute('BEGIN IMMEDIATE');holders.append(holder)
  return original(*a,**kw,fetcher=lambda *a:fetches.append(1) or {'status':'ok','fetched':now(),'events':[]})
 monkeypatch.setattr(ctx,'refresh_palo',refresh)
 monkeypatch.setattr(ai,'model_job',lambda *a,**kw:pipeline_run(*a,**kw,requester=sender(calls)))
 def queue():
  with b.connect() as db:db.execute('INSERT OR REPLACE INTO analysis_queue VALUES(?,?,?)',('8.8.8.1',p[0]['packet_id'],now()))
 def release():
  for holder in holders:holder.rollback();holder.close()
  holders.clear()
 try:
  for attempt in range(3):
   queue();started=time.monotonic()
   result=ai.run(s,source_cfg=source)
   assert time.monotonic()-started<5 and result['palo_context']=={'busy_retry_next_pass':1}
   assert result['indexed']>=1 and result['analysis']==({'completed':1} if attempt==0 else {'cached':1})
   assert len(calls)==2 and not fetches and result['cursor_persistence']['status']=='deferred'
   assert s.state('behavior_palo_usage:'+dt.datetime.now(dt.timezone.utc).date().isoformat()) is None
   assert result['phase']=='status_persistence' and not result['status_persisted']
   release()
  blocked[0]=False;queue();result=ai.run(s,source_cfg=source)
  assert result.get('status')!='deferred' and len(calls)==2 and len(fetches)==1
  with b.connect() as db:
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==2
   assert db.execute('SELECT count(*) FROM pipeline_finals').fetchone()[0]==1
   assert db.execute('SELECT sum(held) FROM pipeline_reservations').fetchone()[0]==0
 finally:release();close(s)
