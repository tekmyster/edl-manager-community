"""Held SQLite writers, cooperative native boundaries and normal-pass recovery."""
import contextlib,datetime as dt,hashlib,json,sqlite3,time
import pytest
import core,behavior_ai as ai,behavior_context as ctx
from core import Store,now
from test_pipeline_support import close
from test_native_owner_repair import w,owner,inputs
EVENT_AT=now()

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 import socket
 def forbidden(*a,**k):raise AssertionError('No real network/model allowed')
 monkeypatch.setattr(socket.socket,'connect',forbidden)

def count(path,table):
 with contextlib.closing(sqlite3.connect(path)) as db:return db.execute('SELECT count(*) FROM '+table).fetchone()[0]

def unit(s,i,kind):
 address='11.0.0.'+str(i+1)
 if kind=='activity':s.source_activity(address,'nginx','web-request',EVENT_AT,{'activity':{'events':[{'id':str(i),'seen':EVENT_AT,'action':'HTTP request','method':'GET','path':'/example'}]}})
 else:s.evidence(address,'nginx','sensitive-path-probe',EVENT_AT,'http',50)

@pytest.mark.parametrize('kind',['activity','evidence'])
def test_real_elapsed_checkpoint_releases_sub100_batch_and_replay(tmp_path,kind):
 s=Store(tmp_path/'native');anchor=sqlite3.connect(s.path);s._worker_connection=anchor;s._batch_evidence=True
 table='source_activity' if kind=='activity' else 'evidence'
 try:
  started=time.monotonic()
  for i in range(12):unit(s,i,kind);time.sleep(.1)
  assert time.monotonic()-started>=core.WORKER_WRITE_SECONDS
  visible=count(s.path,table);assert 0<visible<=12 and s._worker_last_direct_commit=='elapsed_write_budget'
  # Finish the remaining complete unit, then another writer can acquire.
  anchor.commit()
  with contextlib.closing(sqlite3.connect(s.path,timeout=.025)) as rival:rival.execute('BEGIN IMMEDIATE');rival.rollback()
  assert count(s.path,table)==12
  for i in range(12):unit(s,i,kind)
  anchor.commit();assert count(s.path,table)==12
  if kind=='activity':assert count(s.path,'source_sample_handoff')==12 and count(s.path,'evidence')==0
 finally:s._worker_connection=None;anchor.rollback();anchor.close();close(s)

def test_slow_capture_is_not_split_and_failed_unit_rolls_back(tmp_path,monkeypatch):
 import source_handoff
 s=Store(tmp_path/'native');anchor=sqlite3.connect(s.path);s._worker_connection=anchor;s._batch_evidence=True
 original=source_handoff.capture;inside=[]
 monkeypatch.setattr(core,'WORKER_WRITE_SECONDS',.02)
 def capture(*a,**kw):
  original(*a,**kw);time.sleep(.03)
  # The source row and handoff are both uncommitted while this unit runs.
  inside.append((count(s.path,'source_activity'),count(s.path,'source_sample_handoff')))
  if len(inside)==2:raise TypeError('isolated capture failure after writes')
 monkeypatch.setattr(source_handoff,'capture',capture)
 try:
  unit(s,0,'activity');assert inside==[(0,0)] and count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==1
  with pytest.raises(TypeError,match='capture failure'):unit(s,1,'activity')
  assert inside[-1]==(1,1) and not anchor.in_transaction
  assert count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==1
  monkeypatch.setattr(source_handoff,'capture',original);unit(s,1,'activity');anchor.commit()
  assert count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==2
 finally:s._worker_connection=None;anchor.rollback();anchor.close();close(s)

def test_short_scoped_wait_restores_shared_handle_and_rolls_back(tmp_path):
 s=Store(tmp_path/'native');anchor=sqlite3.connect(s.path);s._worker_connection=anchor
 try:
  with pytest.raises(TypeError):
   with s.connect(busy_timeout_ms=10) as db:
    assert db.execute('PRAGMA busy_timeout').fetchone()[0]==10
    db.execute("INSERT INTO state VALUES('partial_fixture','1')");raise TypeError('rollback')
  assert not anchor.in_transaction and anchor.execute('PRAGMA busy_timeout').fetchone()[0]==30000
  assert count(s.path,'state') and s.state('partial_fixture') is None
  for invalid in [30001,-1,True,.25]:
   with pytest.raises(ValueError):
    with s.connect(busy_timeout_ms=invalid):pass
 finally:s._worker_connection=None;anchor.close();close(s)

def test_actual_ingest_elapsed_commits_keep_failed_unit_atomic_and_cursor_unadvanced(w,tmp_path,monkeypatch):
 import source_handoff
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);inputs(w,s,monkeypatch,n=8,activity=True)
 monkeypatch.setattr(core,'WORKER_WRITE_SECONDS',.01)
 capture=source_handoff.capture;ingest=w.ingest_source;calls=[]
 def slow(*a,**kw):
  value=ingest(*a,**kw);time.sleep(.02);return value
 def failed(*a,**kw):
  capture(*a,**kw);calls.append(1)
  if len(calls)==4:raise TypeError('atomic unit interrupted')
 monkeypatch.setattr(w,'ingest_source',slow);monkeypatch.setattr(source_handoff,'capture',failed)
 with pytest.raises(TypeError,match='atomic unit'):w.main()
 assert count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==3
 assert s.state('native_ingest_cursor') is None and not s._worker_connection
 assert s.state('ingest_status')['status']=='error' and 'evidence_buckets' not in s.state('ingest_status')
 monkeypatch.setattr(source_handoff,'capture',capture);w.main()
 assert count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==8
 assert s.state('native_ingest_cursor') and s.state('ingest_status')['status']=='ok'
 close(s)

def test_elapsed_direct_commit_failure_is_owned_rolled_back_and_replayable(w,tmp_path,monkeypatch):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);inputs(w,s,monkeypatch,n=1,activity=True)
 monkeypatch.setattr(core,'WORKER_WRITE_SECONDS',0);original=sqlite3.connect;fired=[]
 class Failing(sqlite3.Connection):
  def commit(self):
   if getattr(s,'_worker_last_direct_commit',None)=='elapsed_write_budget' and not fired:
    fired.append(1);raise OSError('isolated elapsed commit failure')
   return super().commit()
 def connect(*a,**kw):kw['factory']=Failing;return original(*a,**kw)
 monkeypatch.setattr(sqlite3,'connect',connect)
 with pytest.raises(OSError,match='elapsed commit'):w.main()
 assert count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==0 and s.state('native_ingest_cursor') is None
 assert s.state('ingest_status')['pending_transaction']=='rolled_back' and s.state('ingest_status')['last_direct_commit_boundary']=='elapsed_write_budget'
 monkeypatch.setattr(sqlite3,'connect',original);w.main()
 assert count(s.path,'source_activity')==count(s.path,'source_sample_handoff')==1 and s.state('native_ingest_cursor')
 close(s)

def palo_fixture(s):
 s.state('source_configuration',{'index_url':'https://fixture.invalid','palo_location':'fixture'})
 return {'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture'}

def test_palo_claim_busy_has_no_charge_or_fetch_and_next_pass_fetches_once(tmp_path):
 s=Store(tmp_path/'native');cfg=palo_fixture(s);calls=[];holder=sqlite3.connect(s.path);holder.execute('BEGIN IMMEDIATE')
 def fetcher(*a):calls.append(1);return {'status':'ok','fetched':now(),'events':[]}
 try:
  started=time.monotonic()
  assert ctx.refresh_palo(s,cfg,'8.8.8.8',2,fetcher)=='busy_retry_next_pass'
  assert time.monotonic()-started<1.5 and not calls
  assert s.state('behavior_palo_usage:'+dt.datetime.now(dt.timezone.utc).date().isoformat()) is None
 finally:holder.rollback();holder.close()
 try:
  assert ctx.refresh_palo(s,cfg,'8.8.8.8',2,fetcher)=='refreshed'
  assert ctx.refresh_palo(s,cfg,'8.8.8.8',2,fetcher)=='cached' and calls==[1]
  assert s.state('behavior_palo_usage:'+dt.datetime.now(dt.timezone.utc).date().isoformat())==1
 finally:close(s)

def test_actual_pass_palo_busy_indexes_with_stored_context_and_keeps_unsaved_cursor(tmp_path,monkeypatch):
 import evidence_history,packet_indexing
 s=Store(tmp_path/'native');cfg=palo_fixture(s);s.evidence('8.8.8.8','nginx','sensitive-path-probe',now(),'http',50)
 s.state('behavior_settings',{**ai.DEFAULTS,'enabled':True,'model_enabled':False,'palo_context_enabled':True});previous={'completed':'previous'};s.state('behavior_worker',previous);cursor={'offset':0};s.state('behavior_cursor',cursor)
 monkeypatch.setattr(evidence_history,'refresh',lambda *a,**kw:'cached')
 original=ctx.refresh_palo;holders=[];fetches=[]
 def blocked(*a,**kw):
  db=sqlite3.connect(s.path);db.execute('BEGIN IMMEDIATE');holders.append(db)
  return original(*a,**kw,fetcher=lambda *a:fetches.append(1))
 monkeypatch.setattr(ctx,'refresh_palo',blocked)
 try:
  result=ai.run(s,index_only=True,source_cfg=cfg)
  assert result['status']=='deferred' and result['phase']=='status_persistence' and result['status_persisted'] is False
  assert result['indexed']==1 and result['palo_context']=={'busy_retry_next_pass':1} and result['cursor_persistence']['status']=='deferred'
  assert not fetches and s.state('behavior_cursor')==cursor and s.state('behavior_worker')==previous
 finally:
  for db in holders:db.rollback();db.close()
 def fetcher(*a):fetches.append(1);return {'status':'ok','fetched':now(),'events':[]}
 monkeypatch.setattr(ctx,'refresh_palo',lambda *a,**kw:original(*a,**kw,fetcher=fetcher))
 try:
  recovered=ai.run(s,index_only=True,source_cfg=cfg)
  assert recovered.get('status')!='deferred' and s.state('behavior_worker')==recovered and fetches==[1]
  ai.run(s,index_only=True,source_cfg=cfg);assert fetches==[1]
 finally:close(s)

def test_final_status_busy_retains_two_stage_final_and_next_pass_never_reissues(tmp_path,monkeypatch):
 from test_pipeline_support import setup,Reply,choices,SyntheticCounter
 import behavior_tokens,behavior_pipeline_job as job
 s,b,cfg,packets=setup(tmp_path/'native',budget=100);packet=packets[0]
 monkeypatch.setattr(ai,'local_endpoint',lambda *a:None);monkeypatch.setattr(behavior_tokens,'load',lambda *a:SyntheticCounter())
 calls=[]
 def send(url,**kw):calls.append(kw['json']);return Reply(kw['json'],choices(kw['json'],groups='selected'))
 monkeypatch.setattr(ai,'model_job',lambda *a,**kw:job.run(*a,**kw,requester=send))
 def queue():
  with b.connect() as db:db.execute('INSERT OR REPLACE INTO analysis_queue VALUES(?,?,?)',('8.8.8.1',packet['packet_id'],now()))
 queue();s.state('behavior_worker',{'completed':'previous'});state=s.state;holders=[];block=[True]
 def blocked_state(key,value=None,**kw):
  if key=='behavior_worker' and value is not None and block[0]:
   db=sqlite3.connect(s.path);db.execute('BEGIN IMMEDIATE');holders.append(db)
  return state(key,value,**kw)
 monkeypatch.setattr(s,'state',blocked_state)
 try:
  result=ai.run(s)
  assert result['status']=='deferred' and result['phase']=='status_persistence' and not result['status_persisted'] and 'completed' not in result
  assert result['analysis']=={'completed':1} and len(calls)==2 and state('behavior_worker')=={'completed':'previous'}
  with b.connect() as db:
   assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==db.execute('SELECT count(*) FROM pipeline_finals').fetchone()[0]==1
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==2 and db.execute('SELECT sum(held) FROM pipeline_reservations').fetchone()[0]==0
 finally:
  for db in holders:db.rollback();db.close()
 block[0]=False;queue()
 try:
  next_pass=ai.run(s);assert next_pass['analysis']=={'cached':1} and len(calls)==2 and state('behavior_worker')==next_pass
  with b.connect() as db:
   assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==db.execute('SELECT count(*) FROM pipeline_finals').fetchone()[0]==1
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==2 and db.execute('SELECT sum(held) FROM pipeline_reservations').fetchone()[0]==0
 finally:close(s)

@pytest.mark.parametrize('boundary',['claim','status'])
def test_non_contention_sql_errors_are_not_reported_as_deferral(tmp_path,monkeypatch,boundary):
 s=Store(tmp_path/'native')
 if boundary=='claim':
  import activity
  cfg=palo_fixture(s)
  def broken(*a,**kw):raise sqlite3.OperationalError('no such table: fixture')
  monkeypatch.setattr(activity,'claim_activity',broken)
  with pytest.raises(sqlite3.OperationalError,match='no such table'):ctx.refresh_palo(s,cfg,'8.8.8.8',2)
 else:
  s.state('behavior_settings',{**ai.DEFAULTS,'enabled':True,'model_enabled':False});state=s.state
  def broken(key,value=None,**kw):
   if key=='behavior_worker' and value is not None:raise sqlite3.OperationalError('no such table: fixture')
   return state(key,value,**kw)
  monkeypatch.setattr(s,'state',broken)
  with pytest.raises(sqlite3.OperationalError,match='no such table'):ai.run(s,index_only=True)
 close(s)
