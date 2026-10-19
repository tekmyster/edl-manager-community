"""Real isolated SQLite contention; no production connections or model calls."""
import contextlib,json,sqlite3,threading
import pytest
from core import Store
from behavior_ai import Brain
import behavior_scheduling as scheduling


class ConnectionScope:
 """Same commit/rollback/close contract, with a short isolated test timeout."""
 def __init__(self,brain,shared=False,begin=False,after_read=None,readonly=False):
  self.path=brain.path;self.store=brain.store;self.shared=shared;self.begin=begin;self.after_read=after_read;self.readonly=readonly;self.events=[]
 @contextlib.contextmanager
 def connect(self):
  owner=self
  class Connection(sqlite3.Connection):
   def execute(self,sql,args=()):
    result=super().execute(sql,args)
    if owner.after_read and sql.startswith('SELECT value FROM retention_state'):
     callback=owner.after_read;owner.after_read=None;callback()
    return result
  uri=self.path.as_uri()+'?mode='+('ro' if self.readonly else 'rw')+('&cache=shared' if self.shared else '')
  db=sqlite3.connect(uri,uri=True,timeout=.03,factory=Connection);db.row_factory=sqlite3.Row
  try:
   if self.begin:db.execute('BEGIN')
   yield db;db.commit();self.events.append(('commit',db.total_changes))
  except BaseException:
   changed=db.total_changes;db.rollback();self.events.append(('rollback',changed));raise
  finally:db.close();self.events.append(('closed',None))


def fixture(tmp_path,count=5,cursor=True):
 b=Brain(Store(tmp_path/'native.sqlite3'))
 with b.connect() as db:
  for i in range(count):
   ident='packet'+str(i);address='198.18.'+str(i//250)+'.'+str(i%250+1);seen='2026-10-17T12:00:00+00:00'
   p={'packet_id':ident,'events':[{'id':'event'+str(i),'seen':seen,'source':'synthetic','sensor':'fixture','action':'HTTP request','path':'/path/'+str(i),'method':'GET'}]}
   db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,address,seen,json.dumps(p),'[]',0))
   db.execute('INSERT INTO current_packets VALUES(?,?)',(address,ident));db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',(address,ident,seen))
  if cursor:db.execute("INSERT INTO retention_state VALUES('schedule_cursor_v2',?)",(str(count+1),))
 return b


def snapshot(b):
 with b.connect() as db:
  result={t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in ('packets','current_packets','analysis_queue','queue_priority','packet_scheduling','packet_scheduling_v2_ready','jobs','usage')}
  row=db.execute("SELECT value FROM retention_state WHERE name='schedule_cursor_v2'").fetchone();result['cursor']=row[0] if row else None
  return result


def deferred(result,scope,primary):
 assert result['status']=='deferred' and result['sqlite_code']&255==primary
 assert result['scanned']==0 and result['partial'] is True and result['bound']==200 and result['version']==2
 assert result['retry']=='next_normal_pass' and scope.events[-2][0]=='rollback' and scope.events[-1][0]=='closed'


def complete_next_pass(b,count):
 result=scheduling.backfill(ConnectionScope(b));assert result=={'scanned':count,'bound':200,'partial':False,'version':2}
 state=snapshot(b);assert len(state['packet_scheduling'])==len(state['packet_scheduling_v2_ready'])==count and state['cursor']=='1'
 assert {r[0] for r in state['packet_scheduling']}=={'packet'+str(i) for i in range(count)}
 assert all(r[2]=='2026-10-17T12:00:00+00:00' for r in state['packet_scheduling'])
 return state


class BackgroundWriter:
 def __init__(self,b):
  self.ready=threading.Event();self.release=threading.Event();self.errors=[]
  def work():
   try:
    with contextlib.closing(sqlite3.connect(b.path,timeout=.1)) as db:
     db.execute('BEGIN IMMEDIATE');db.execute("INSERT INTO retention_state VALUES('other_background_work','1')");self.ready.set()
     assert self.release.wait(5);db.commit()
   except BaseException as exc:self.errors.append(exc);self.ready.set()
  self.thread=threading.Thread(target=work);self.thread.start();assert self.ready.wait(3) and not self.errors
 def close(self):
  self.release.set();self.thread.join(3);assert not self.thread.is_alive() and not self.errors


@pytest.mark.parametrize('cursor',[False,True])
def test_background_held_writer_defers_without_initializing_or_advancing_cursor(tmp_path,cursor):
 b=fixture(tmp_path,cursor=cursor);before=snapshot(b);scope=ConnectionScope(b);writer=BackgroundWriter(b)
 try:
  result=scheduling.backfill(scope);deferred(result,scope,sqlite3.SQLITE_BUSY)
  assert result['sqlite_code']==sqlite3.SQLITE_BUSY and snapshot(b)==before
 finally:writer.close()
 after=complete_next_pass(b,5)
 assert after['packets']==before['packets'] and after['analysis_queue']==before['analysis_queue']


def test_real_read_to_write_upgrade_extended_busy_preserves_snapshot_and_resumes(tmp_path):
 b=fixture(tmp_path);before=snapshot(b)
 def concurrent_commit():
  with sqlite3.connect(b.path,timeout=.1) as db:db.execute("INSERT INTO retention_state VALUES('concurrent_commit','1')")
 scope=ConnectionScope(b,begin=True,after_read=concurrent_commit)
 result=scheduling.backfill(scope);deferred(result,scope,sqlite3.SQLITE_BUSY)
 assert result['sqlite_code']==sqlite3.SQLITE_BUSY_SNAPSHOT and snapshot(b)==before
 complete_next_pass(b,5)


@pytest.mark.parametrize('locked_table',['packet_scheduling_v2_ready','retention_state'])
def test_real_shared_cache_lock_after_partial_indexing_rolls_back_every_table(tmp_path,locked_table):
 b=fixture(tmp_path)
 with b.connect() as db:scheduling.index(db,'packet0')
 before=snapshot(b);scope=ConnectionScope(b,shared=True)
 reader=sqlite3.connect(b.path.as_uri()+'?mode=rw&cache=shared',uri=True,timeout=.1)
 try:
  reader.execute('BEGIN');reader.execute('SELECT * FROM '+locked_table).fetchall()
  result=scheduling.backfill(scope);deferred(result,scope,sqlite3.SQLITE_LOCKED)
  assert result['sqlite_code']==sqlite3.SQLITE_LOCKED_SHAREDCACHE
  assert scope.events[-2][1]>0,'No partial index writes actually occurred'
  assert snapshot(b)==before
 finally:reader.rollback();reader.close()
 complete_next_pass(b,5)


def test_real_commit_busy_rolls_back_index_readiness_priorities_and_cursor(tmp_path):
 b=fixture(tmp_path)
 with b.connect() as db:assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
 before=snapshot(b);scope=ConnectionScope(b);reader=sqlite3.connect(b.path,timeout=.1)
 try:
  reader.execute('BEGIN');reader.execute('SELECT * FROM packets').fetchall()
  result=scheduling.backfill(scope);deferred(result,scope,sqlite3.SQLITE_BUSY)
  assert scope.events[-2][1]>0 and snapshot(b)==before
 finally:reader.rollback();reader.close()
 complete_next_pass(b,5)


def test_deferred_then_bounded_normal_passes_visit_all405_packets_exactly(tmp_path):
 b=fixture(tmp_path,405);before=snapshot(b);scope=ConnectionScope(b);writer=BackgroundWriter(b)
 try:deferred(scheduling.backfill(scope,100000),scope,sqlite3.SQLITE_BUSY);assert snapshot(b)==before
 finally:writer.close()
 seen=set()
 for expected,partial in [(200,True),(200,True),(5,False)]:
  result=scheduling.backfill(ConnectionScope(b),100000);assert result['scanned']==expected and result['partial']==partial
  state=snapshot(b);ready={r[0] for r in state['packet_scheduling_v2_ready']}
  assert len(ready-seen)==expected and seen<=ready;seen=ready
 assert seen=={'packet'+str(i) for i in range(405)} and state['cursor']=='1'
 assert scheduling.backfill(ConnectionScope(b))=={'scanned':0,'bound':200,'partial':False,'version':2}


@pytest.mark.parametrize('table',['packet_scheduling_v2_ready','retention_state'])
def test_real_noncontention_cursor_or_readiness_failure_is_not_hidden_and_all_work_rolls_back(tmp_path,table):
 b=fixture(tmp_path);before=snapshot(b)
 with b.connect() as db:db.execute("CREATE TRIGGER fail_fixture BEFORE INSERT ON "+table+" BEGIN SELECT RAISE(ABORT,'database is locked'); END")
 scope=ConnectionScope(b)
 with pytest.raises(sqlite3.IntegrityError) as caught:scheduling.backfill(scope)
 assert caught.value.sqlite_errorcode==sqlite3.SQLITE_CONSTRAINT_TRIGGER and snapshot(b)==before
 assert scope.events[-2][0]=='rollback' and scope.events[-2][1]>0
 with b.connect() as db:db.execute('DROP TRIGGER fail_fixture')
 complete_next_pass(b,5)


def test_real_readonly_database_error_is_propagated(tmp_path):
 b=fixture(tmp_path);before=snapshot(b);scope=ConnectionScope(b,readonly=True)
 with pytest.raises(sqlite3.OperationalError) as caught:scheduling.backfill(scope)
 assert caught.value.sqlite_errorcode==sqlite3.SQLITE_READONLY and snapshot(b)==before


@pytest.mark.parametrize('error',[OSError('fixture IO failure'),ValueError('fixture programming failure'),sqlite3.OperationalError('database is locked')])
def test_io_programming_and_uncoded_lock_message_errors_propagate_after_rollback(tmp_path,monkeypatch,error):
 b=fixture(tmp_path);before=snapshot(b);original=scheduling.index;scope=ConnectionScope(b)
 def fail_after_index(db,ident):original(db,ident);raise error
 monkeypatch.setattr(scheduling,'index',fail_after_index)
 with pytest.raises(type(error)) as caught:scheduling.backfill(scope)
 assert caught.value is error and snapshot(b)==before and scope.events[-2][1]>0


def test_foreground_run_reports_background_table_lock_and_next_normal_pass_indexes_without_inference(tmp_path,monkeypatch):
 import behavior_ai as ai
 b=fixture(tmp_path);scope=ConnectionScope(b,shared=True);scope.backfill_features=lambda:0
 # Use the actual foreground run and backfill. Other background consumers are
 # represented by their normal worker flags; no source collection is invoked.
 b.store._source_handoff_background=True;b.store._packet_index_background=True
 b.store.state('behavior_settings',{**ai.DEFAULTS,'enabled':True,'model_enabled':False})
 monkeypatch.setattr(ai,'Brain',lambda store:scope)
 monkeypatch.setattr(ai,'infer',lambda *a,**kw:pytest.fail('Offline contention test attempted inference'))
 ready=threading.Event();release=threading.Event();errors=[]
 def background_reader():
  try:
   with contextlib.closing(sqlite3.connect(b.path.as_uri()+'?mode=rw&cache=shared',uri=True,timeout=.1)) as db:
    db.execute('BEGIN');db.execute('SELECT * FROM packet_scheduling_v2_ready').fetchall();ready.set()
    assert release.wait(10);db.rollback()
  except BaseException as exc:errors.append(exc);ready.set()
 thread=threading.Thread(target=background_reader);thread.start();assert ready.wait(3) and not errors
 try:
  status=ai.run(b.store,index_only=True)
  assert status['scheduling_index']['status']=='deferred' and status['scheduling_index']['sqlite_code']==sqlite3.SQLITE_LOCKED_SHAREDCACHE
  assert status['analysis_stop']=='index_only' and b.store.state('behavior_worker')['scheduling_index']==status['scheduling_index']
  state=snapshot(b);assert state['cursor']=='6' and state['packet_scheduling']==state['packet_scheduling_v2_ready']==[]
 finally:release.set();thread.join(3);assert not thread.is_alive() and not errors
 status=ai.run(b.store,index_only=True)
 assert status['scheduling_index']=={'scanned':5,'bound':200,'partial':False,'version':2}
 assert {r[0] for r in snapshot(b)['packet_scheduling_v2_ready']}=={'packet'+str(i) for i in range(5)}
