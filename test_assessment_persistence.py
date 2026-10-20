"""Isolated real SQLite result-save contention; no network or production writes."""
from test_pipeline_mock import stage_mock
import contextlib,json,os,pathlib,sqlite3,threading,time,subprocess,sys
import pytest
import behavior_ai as ai
import behavior_persistence as pending
import analytics_store as ledger
from behavior_grounding import example
from test_behavior_drain import queue


class Holder:
 def __init__(self,path,sql,uri=False):
  self.ready=threading.Event();self.release=threading.Event();self.errors=[]
  def hold():
   try:
    with contextlib.closing(sqlite3.connect(path,timeout=1,uri=uri)) as db:
     for statement in sql:db.execute(statement).fetchall()
     self.ready.set();assert self.release.wait(10);db.rollback()
   except BaseException as exc:self.errors.append(exc);self.ready.set()
  self.thread=threading.Thread(target=hold);self.thread.start();assert self.ready.wait(3);assert not self.errors
 def close(self):
  self.release.set();self.thread.join(3);assert not self.thread.is_alive() and not self.errors


def packet(b):
 with b.connect() as db:return json.loads(db.execute("SELECT content FROM packets WHERE id='packet0'").fetchone()[0])


def records(b):
 with b.connect() as db:return {t:[tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in ('assessments','jobs','usage','retention_state')}


def fake(monkeypatch,b,after=None):
 calls=[]
 def infer(cfg,p,candidates,allowed,key,requester,attempt):
  calls.append(1);assert len(calls)==1,'Persistence redispatched inference'
  assert attempt.start();meta={'request_id':attempt.id,'input_tokens':23,'output_tokens':7,'request_seconds':.4,'first_content_seconds':.1};assert attempt.finish('accepted',meta)
  return example(p),meta
 def journal_ready():
  # Explicitly retain coverage for a legacy dispatch marker alongside the new
  # SQLite journal. New production dispatches never create this marker.
  with b.connect() as db:
   plan=db.execute('SELECT * FROM pipeline_plans ORDER BY rowid DESC LIMIT 1').fetchone();request=db.execute('SELECT request_id FROM pipeline_stages WHERE parent=? AND ordinal=2',(plan['id'],)).fetchone()[0]
  pending.reserve(b,plan['packet'],plan['config'],plan['owner'],plan['assessment'],request)
  if after:after()
 stage_mock(monkeypatch,ai,infer,before_persist=journal_ready)
 return calls


def files(b):return list(pending.directory(b).glob('*.json'))


def test_consumed_legacy_marker_cleanup_race_and_owner_guard(tmp_path,monkeypatch):
 from concurrent.futures import ThreadPoolExecutor
 s,b,cfg=queue(tmp_path,1);owner='synthetic-race-owner';p=pending.location(b,'packet0','cfg')
 pending.reserve(b,'packet0','cfg',owner,'assessment','a'*32)
 barrier=threading.Barrier(2);original=json.loads;thread=threading.local()
 def parsed(value,*args,**kw):
  result=original(value,*args,**kw)
  if isinstance(result,dict) and result.get('owner')==owner and not getattr(thread,'checked',False):thread.checked=True;barrier.wait(3)
  return result
 with monkeypatch.context() as patch:
  patch.setattr(json,'loads',parsed)
  with ThreadPoolExecutor(max_workers=2) as pool:
   futures=[pool.submit(pending.clear_reservation,p,owner) for _ in range(2)]
   for future in futures:future.result(timeout=5)
 assert not p.with_suffix('.inflight').exists()
 pending.reserve(b,'packet0','cfg','new-owner','next-assessment','b'*32)
 pending.clear_reservation(p,owner)
 assert json.loads(p.with_suffix('.inflight').read_bytes())['owner']=='new-owner'


def test_consumed_result_cleanup_race_preserves_different_result(tmp_path,monkeypatch):
 from concurrent.futures import ThreadPoolExecutor
 s,b,cfg=queue(tmp_path,1);value={'version':1,'row':['id','packet0','cfg',ai.now(),'2099','completed','{}','',.1],'owner':'result-owner','backoff_key':'backoff','backoff_previous':None,'backoff_at':time.time()};p=pending.stage(b,value)
 barrier=threading.Barrier(2);original=json.loads;thread=threading.local()
 def parsed(body,*args,**kw):
  result=original(body,*args,**kw)
  if result==value and not getattr(thread,'checked',False):thread.checked=True;barrier.wait(3)
  return result
 with monkeypatch.context() as patch:
  patch.setattr(json,'loads',parsed)
  with ThreadPoolExecutor(max_workers=2) as pool:
   futures=[pool.submit(pending.discard_saved,p,value) for _ in range(2)]
   for future in futures:future.result(timeout=5)
 assert not p.exists()
 different={**value,'owner':'next-owner'};pending.stage(b,different)
 with pytest.raises(ValueError,match='Conflicting consumed'):pending.discard_saved(p,value)
 assert pending.read(p)==different


@pytest.mark.parametrize('blocked',[1,3])
def test_marker_read_retry_is_bounded_and_preserves_another_owner(tmp_path,monkeypatch,blocked):
 s,b,cfg=queue(tmp_path,1);p=pending.location(b,'packet0','cfg');pending.reserve(b,'packet0','cfg','next-owner','assessment','a'*32);marker=p.with_suffix('.inflight');original=pathlib.Path.open;calls=[]
 def open_file(self,*args,**kw):
  if self==marker and len(calls)<blocked:calls.append(1);raise PermissionError('Synthetic transient sharing failure')
  return original(self,*args,**kw)
 with monkeypatch.context() as patch:
  patch.setattr(pathlib.Path,'open',open_file)
  if blocked==3:
   with pytest.raises(PermissionError):pending.clear_reservation(p,'prior-owner')
  else:pending.clear_reservation(p,'prior-owner')
 assert len(calls)==blocked and json.loads(marker.read_bytes())['owner']=='next-owner'


def verify_once(b,calls):
 rows=records(b);assert len(rows['assessments'])==1 and rows['assessments'][0][5]=='completed'
 assert rows['jobs'][0][3]=='completed' and rows['jobs'][0][4]==0 and rows['jobs'][0][5]==1
 assert rows['usage'][0][1]==2 and calls==[1]
 with ledger.connect(b.store) as db:
  actual=list(db.execute('SELECT * FROM requests'));assert len(actual)==2 and all(r['state']=='accepted' for r in actual)
  meta=json.loads(rows['assessments'][0][6])['metadata']['generation_stages'][1];assert actual[1]['id']==meta['request_id'] and actual[1]['input_tokens']==23 and actual[1]['output_tokens']==7
 return rows


def test_held_writer_preserves_result_and_fresh_process_saves_without_inference(tmp_path,monkeypatch,caplog):
 s,b,cfg=queue(tmp_path,1);held=[];calls=fake(monkeypatch,b,lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 try:
  start=time.monotonic();assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred';assert time.monotonic()-start<1.2
  saved=pending.read(files(b)[0]);assert records(b)['assessments']==[] and records(b)['usage'][0][1]==2 and records(b)['jobs'][0][3]=='running'
  assert 'sqlite_code=5' in caplog.text and saved['row'][0] not in caplog.text
  if os.name=='posix':assert files(b)[0].stat().st_mode&0o777==0o600 and pending.directory(b).stat().st_mode&0o777==0o700
 finally:
  for h in held:h.close()
 code="from core import Store;from behavior_ai import Brain;from behavior_persistence import recover;import sys,json;print(json.dumps(recover(Brain(Store(sys.argv[1])))))"
 r=subprocess.run([sys.executable,'-c',code,str(s.path)],cwd=pathlib.Path(ai.__file__).parent,capture_output=True,text=True,timeout=20);assert r.returncode==0,r.stderr;assert json.loads(r.stdout)['saved']==1
 rows=verify_once(b,calls);assert list(rows['assessments'][0])==saved['row'] and not files(b)


def test_short_writer_retry_completes_same_result(tmp_path,monkeypatch,caplog):
 s,b,cfg=queue(tmp_path,1);held=[]
 def after():
  h=Holder(b.path,['BEGIN IMMEDIATE']);held.append(h);threading.Timer(.08,h.release.set).start()
 calls=fake(monkeypatch,b,after)
 try:assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='completed'
 finally:
  for h in held:h.close()
 verify_once(b,calls);assert not files(b) and not caplog.records


def test_real_commit_busy_rolls_back_assessment_job_and_backoff(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1)
 with b.connect() as db:assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
 original=sqlite3.connect;held=[];partial=[]
 class Connection(sqlite3.Connection):
  def execute(self,sql,*args,**kw):
   out=super().execute(sql,*args,**kw)
   if sql.startswith('INSERT OR REPLACE INTO retention_state') and not held:
    partial.append(super().execute('SELECT count(*) FROM assessments').fetchone()[0]);held.append(Holder(b.path,['BEGIN','SELECT * FROM assessments']))
   return out
 def connect(*args,**kw):
  if str(args[0])==str(b.path) and kw.get('timeout')==.025:kw['factory']=Connection
  return original(*args,**kw)
 calls=fake(monkeypatch,b)
 with monkeypatch.context() as patch:
  patch.setattr(sqlite3,'connect',connect)
  try:
   assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
   rows=records(b);assert rows['assessments']==[] and rows['jobs'][0][3]=='running' and rows['jobs'][0][4]>0 and rows['retention_state']==[]
  finally:
   for h in held:h.close()
 assert partial==[1] and len(files(b))==1
 assert pending.recover(b)['saved']==1;verify_once(b,calls)


def test_real_shared_cache_locked_after_partial_writes_rolls_back(tmp_path,monkeypatch,caplog):
 s,b,cfg=queue(tmp_path,1);original=sqlite3.connect;held=[];partial=[];uri=b.path.resolve().as_uri()+'?cache=shared'
 class Connection(sqlite3.Connection):
  def execute(self,sql,*args,**kw):
   if sql.startswith('INSERT OR REPLACE INTO retention_state'):partial.append(super().execute('SELECT count(*) FROM assessments').fetchone()[0])
   return super().execute(sql,*args,**kw)
 def connect(*args,**kw):
  if str(args[0])==str(b.path) and kw.get('timeout')==.025:args=(uri,*args[1:]);kw.update(uri=True,factory=Connection)
  return original(*args,**kw)
 calls=fake(monkeypatch,b,lambda:held.append(Holder(uri,['BEGIN','SELECT * FROM retention_state'],True)))
 with monkeypatch.context() as patch:
  patch.setattr(sqlite3,'connect',connect)
  try:
   assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
   assert records(b)['assessments']==[] and records(b)['jobs'][0][3]=='running'
  finally:
   for h in held:h.close()
 assert partial and all(n==1 for n in partial) and 'sqlite_code=262' in caplog.text
 assert pending.recover(b)['saved']==1;verify_once(b,calls)


def test_permanent_partial_save_failure_visible_and_replayable(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1)
 with b.connect() as db:db.execute("CREATE TRIGGER isolated_save_failure AFTER INSERT ON assessments BEGIN SELECT RAISE(ABORT,'private canary'); END")
 calls=fake(monkeypatch,b)
 assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_review_required'
 assert records(b)['assessments']==[] and records(b)['jobs'][0][3]=='running' and len(files(b))==1
 with b.connect() as db:db.execute('DROP TRIGGER isolated_save_failure')
 assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='completed';verify_once(b,calls)


def test_crash_after_commit_before_unlink_replays_identical_id_once(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);calls=fake(monkeypatch,b);original=pathlib.Path.unlink
 def unlink(self,*args,**kw):
  if self.suffix=='.json' and self.parent==pending.directory(b):raise OSError('isolated unlink failure')
  return original(self,*args,**kw)
 with monkeypatch.context() as patch:
  patch.setattr(pathlib.Path,'unlink',unlink)
  assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_review_required'
 before=verify_once(b,calls);assert len(files(b))==1
 assert pending.recover(b)['saved']==1 and records(b)==before and not files(b)


def test_cancelled_busy_save_keeps_response_and_queue_without_redispatch(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);held=[];cancel=[False]
 def after():held.append(Holder(b.path,['BEGIN IMMEDIATE']));cancel[0]=True
 calls=fake(monkeypatch,b,after)
 try:
  result=ai.drain_queue(b,s,cfg,should_stop=lambda:cancel[0]);assert result[2]=='persistence_deferred'
  with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==1
 finally:
  for h in held:h.close()
 cancel[0]=False;assert pending.recover(b)['saved']==1;verify_once(b,calls)


def test_lost_lease_keeps_private_result_without_publishing_or_clearing_successor(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1)
 def after():
  with b.connect() as db:db.execute("UPDATE jobs SET id='successor',lease=9999999999")
 calls=fake(monkeypatch,b,after);assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='lease_lost'
 assert len(list(pending.review_directory(b).glob('*/*.json')))==1 and not files(b) and not records(b)['assessments'] and records(b)['jobs'][0][0]=='successor' and records(b)['jobs'][0][4]==9999999999
 result=pending.recover(b);assert result['review_retained'] and not result['deferred'] and calls==[1] and not records(b)['assessments']


def test_superseded_packet_saves_history_and_releases_only_own_lease(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,2)
 def after():
  with b.connect() as db:db.execute("UPDATE current_packets SET packet_id='packet1' WHERE packet_id='packet0'")
 calls=fake(monkeypatch,b,after);assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='superseded'
 rows=records(b);assert rows['assessments'][0][5]=='superseded' and rows['jobs'][0][3]=='superseded' and rows['jobs'][0][4]==0 and calls==[1]


@pytest.mark.parametrize('code',[None,1,8,10,11,26,-251,True])
def test_only_actual_nonnegative_numeric_busy_or_locked_retry(code):
 exc=sqlite3.OperationalError('database is locked; private body');calls=[]
 if code is not None:exc.sqlite_errorcode=code
 def operation():calls.append(1);raise exc
 with pytest.raises(sqlite3.OperationalError):pending.retry_busy(operation)
 assert calls==[1]


def test_frozen_backoff_does_not_overwrite_newer_guard(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);held=[];calls=fake(monkeypatch,b,lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 try:assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
 finally:
  for h in held:h.close()
 v=pending.read(files(b)[0]);newer=json.dumps({'failures':5,'until':9999999999})
 with b.connect() as db:db.execute('INSERT OR REPLACE INTO retention_state VALUES(?,?)',(v['backoff_key'],newer))
 assert pending.recover(b)['saved']==1;verify_once(b,calls)
 with b.connect() as db:assert db.execute('SELECT value FROM retention_state WHERE name=?',(v['backoff_key'],)).fetchone()[0]==newer


def test_corrupt_pending_result_stays_visible_without_new_request(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);held=[];calls=fake(monkeypatch,b,lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 try:assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
 finally:
  for h in held:h.close()
 files(b)[0].write_text('{incomplete')
 assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='failed'
 assert calls==[1] and records(b)['assessments']==[] and records(b)['usage'][0][1]==2


def test_journal_recovery_page_is_bounded(tmp_path):
 s,b,cfg=queue(tmp_path,51)
 with b.connect() as db:
  for i in range(51):db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',('owner'+str(i),'packet'+str(i),'cfg','running',9999999999,1,ai.now()))
 for i in range(51):pending.stage(b,{'version':1,'row':['id'+str(i),'packet'+str(i),'cfg',ai.now(),'2099-01-01T00:00:00+00:00','completed','{}','',.1],'owner':'owner'+str(i),'backoff_key':'backoff','backoff_previous':None,'backoff_at':time.time()})
 result=pending.recover(b);assert result['scanned']==result['saved']==50 and len(files(b))==1
 assert pending.recover(b)['saved']==1 and not files(b)


def test_cursor_commit_busy_keeps_committed_ledger_count_and_replays_once(tmp_path,monkeypatch):
 from test_telemetry_contention import fixture,cursor,requests
 import behavior_telemetry as telemetry
 b,meta=fixture(tmp_path)
 with b.connect() as db:assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
 original=sqlite3.connect;held=[];partial=[]
 class Connection(sqlite3.Connection):
  def execute(self,sql,*args,**kw):
   out=super().execute(sql,*args,**kw)
   if sql.startswith("INSERT INTO retention_state VALUES('telemetry_cursor'") and not held:
    partial.append(super().execute("SELECT count(*) FROM retention_state WHERE name='telemetry_cursor'").fetchone()[0]);held.append(Holder(b.path,['BEGIN','SELECT * FROM retention_state']))
   return out
 def connect(*args,**kw):
  if str(args[0])==str(b.path) and kw.get('timeout')==.025:kw['factory']=Connection
  return original(*args,**kw)
 with monkeypatch.context() as patch:
  patch.setattr(sqlite3,'connect',connect)
  try:
   result=telemetry.recover(b);assert result['status']=='retry' and result['phase']=='cursor_write' and result['sqlite_code']==5
   assert result['recovered']==result['ledger_recovered']==1 and result['cursor_advanced'] is False and cursor(b) is None
   before=requests(b);assert len(before)==1
  finally:
   for h in held:h.close()
 assert partial==[1];assert telemetry.recover(b)['cursor_advanced'] and requests(b)==before
 with ledger.connect(b.store) as db:assert db.execute('SELECT count(*) FROM request_recovery').fetchone()[0]==1


def test_actual_readonly_database_keeps_result_and_does_not_redispatch(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);original=sqlite3.connect
 def connect(*args,**kw):
  if str(args[0])==str(b.path) and kw.get('timeout')==.025:args=(b.path.resolve().as_uri()+'?mode=ro',*args[1:]);kw['uri']=True
  return original(*args,**kw)
 with monkeypatch.context() as patch:
  calls=fake(monkeypatch,b,lambda:patch.setattr(sqlite3,'connect',connect))
  assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_review_required'
 assert len(files(b))==1 and not records(b)['assessments']
 assert pending.recover(b)['saved']==1;verify_once(b,calls)


def test_busy_logging_never_includes_validated_assessment_text(tmp_path,monkeypatch,caplog):
 s,b,cfg=queue(tmp_path,1);held=[]
 def infer(cfg,p,*args):return example(p),{'safe_fixture_marker':'private assessment canary'}
 stage_mock(monkeypatch,ai,infer,before_persist=lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 try:assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
 finally:
  for h in held:h.close()
 assert 'private assessment canary' not in caplog.text and pending.read(files(b)[0])['row'][6].find('private assessment canary')>=0
 assert pending.recover(b)['saved']==1


def test_missing_packet_is_visible_and_retains_pending_result(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);held=[];calls=fake(monkeypatch,b,lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 try:assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
 finally:
  for h in held:h.close()
 with b.connect() as db:db.execute("DELETE FROM packets WHERE id='packet0'")
 with pytest.raises(ValueError,match='packet unavailable'):pending.recover(b)
 assert len(files(b))==1 and not records(b)['assessments'] and calls==[1]


def test_result_journal_disk_failure_retains_dispatch_intent_without_repeat(tmp_path,monkeypatch,caplog):
 s,b,cfg=queue(tmp_path,1);calls=fake(monkeypatch,b)
 def fail(*args):raise OSError('isolated disk failure')
 with monkeypatch.context() as patch:
  patch.setattr(pending,'stage',fail)
  assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_review_required'
 assert not files(b)
 with b.connect() as db:assert db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='final_pending'
 assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='completed' and calls==[1]
 assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='cached' and calls==[1]
 verify_once(b,calls)


def test_commit_surviving_dispatch_marker_resolves_without_repeat(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1);saved=[]
 def after():
  p=next(pending.directory(b).glob('*.inflight'));saved.append((p,p.read_bytes()))
 calls=fake(monkeypatch,b,after);assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='completed';before=verify_once(b,calls)
 saved[0][0].write_bytes(saved[0][1])
 assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='cached' and records(b)==before
 assert pending.recover(b)['dispatch_markers_scanned']==1 and not saved[0][0].exists()


def test_uncertain_dispatch_skips_only_its_packet_and_keeps_other_work(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,2);calls=[]
 def infer(cfg,p,candidates,allowed,key,requester,attempt):
  calls.append(p['packet_id']);attempt.start()
  if p['packet_id']=='packet0':raise KeyboardInterrupt()
  meta={'request_id':attempt.id};attempt.finish('accepted',meta);return example(p),meta
 stage_mock(monkeypatch,ai,infer)
 with pytest.raises(KeyboardInterrupt):ai.model_job(b,'packet0',packet(b),set(),cfg)
 with b.connect() as db:db.execute('UPDATE jobs SET lease=0')
 with b.connect() as db:assert db.execute('SELECT state FROM pipeline_plans').fetchone()[0]=='uncertain'
 results,examined,reason=ai.drain_queue(b,s,cfg)
 assert reason=='idle' and results=={'persistence_review_required':1,'completed':1} and calls==['packet0','packet1']
 with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==1


def test_cursor_real_locked_preserves_committed_receipt_then_replays_once(tmp_path,monkeypatch,caplog):
 from test_telemetry_contention import fixture,cursor,requests
 import behavior_telemetry as telemetry
 b,meta=fixture(tmp_path);uri=b.path.resolve().as_uri()+'?cache=shared';original=sqlite3.connect
 held=Holder(uri,['BEGIN','SELECT * FROM retention_state'],True)
 def connect(*args,**kw):
  if str(args[0])==str(b.path) and kw.get('timeout')==.025:args=(uri,*args[1:]);kw['uri']=True
  return original(*args,**kw)
 try:
  with monkeypatch.context() as patch:
   patch.setattr(sqlite3,'connect',connect);result=telemetry.recover(b)
  assert result['status']=='retry' and result['phase']=='cursor_write' and result['sqlite_code']==262
  assert result['ledger_recovered']==result['recovered']==1 and result['cursor_advanced'] is False
  before=requests(b);assert len(before)==1 and cursor(b) is None and 'sqlite_code=262' in caplog.text
 finally:held.close()
 assert telemetry.recover(b)['cursor_advanced'] and requests(b)==before


def test_concurrent_result_replayers_commit_exactly_once(tmp_path,monkeypatch):
 from concurrent.futures import ThreadPoolExecutor
 s,b,cfg=queue(tmp_path,1);held=[];calls=fake(monkeypatch,b,lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 try:assert ai.model_job(b,'packet0',packet(b),set(),cfg)=='persistence_deferred'
 finally:
  for h in held:h.close()
 p=files(b)[0];barrier=threading.Barrier(2);original=pending.read
 def read(path):
  value=original(path);barrier.wait(3);return value
 with monkeypatch.context() as patch:
  patch.setattr(pending,'read',read)
  with ThreadPoolExecutor(max_workers=2) as pool:
   futures=[pool.submit(pending.persist,b,p) for _ in range(2)];assert [f.result(timeout=5) for f in futures]==['completed','completed']
 verify_once(b,calls);assert not files(b) and not list(pending.directory(b).glob('*.inflight'))
