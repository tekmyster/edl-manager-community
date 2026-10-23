"""Real SQLite writer interleavings; only inert, owned NDJSON fake requests."""
import contextlib,datetime as dt,json,sqlite3,threading,time
import pytest
import behavior_ai as ai,behavior_tokens
from behavior_pipeline_job import run
from behavior_pipeline_store import Ledger,local_retry
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.fixture(autouse=True)
def offline(monkeypatch):
 import socket
 def deny(*a,**kw):raise AssertionError('No real network or model')
 monkeypatch.setattr(socket.socket,'connect',deny)
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda _:SyntheticCounter())

class Writers:
 def __init__(self):self.timers=[];self.errors=[]
 def hold(self,path,seconds=.4,after=None):
  db=sqlite3.connect(path,check_same_thread=False);db.execute('BEGIN IMMEDIATE')
  def release():
   try:
    db.rollback();db.close()
    if after:after()
   except BaseException as exc:self.errors.append(exc)
  t=threading.Timer(seconds,release);t.start();self.timers.append(t)
 def finish(self):
  for t in self.timers:t.join()
  assert not self.errors,self.errors

def sender(calls):
 def send(url,**kw):calls.append(kw['json']);return Reply(kw['json'],choices(kw['json'],groups='selected'))
 return send

def facts(b):
 with b.connect() as db:
  return {'parents':db.execute('SELECT count(*) FROM pipeline_plans').fetchone()[0],
   'stages':[tuple(r) for r in db.execute('SELECT ordinal,state,charged_day IS NOT NULL FROM pipeline_stages ORDER BY ordinal')],
   'charges':db.execute('SELECT coalesce(sum(requests),0) FROM usage').fetchone()[0],
   'held':db.execute('SELECT coalesce(sum(held),0) FROM pipeline_reservations').fetchone()[0],
   'drafts':db.execute('SELECT count(*) FROM pipeline_drafts').fetchone()[0],
   'finals':db.execute('SELECT count(*) FROM pipeline_finals').fetchone()[0]}

@pytest.mark.parametrize('phase',['owner_recovery','before_claim1','before_entry1','before_accept1','before_revision','before_claim2','before_entry2','before_final','multiple'])
def test_released_writer_completes_same_parent_without_reissuing_draft(tmp_path,monkeypatch,caplog,phase):
 s,b,cfg,p=setup(tmp_path/'native',budget=None);Ledger(b);calls=[];writers=Writers();seen=set()
 original=Ledger.recover_active
 def recover(self):
  if phase=='owner_recovery' and 'owner' not in seen:seen.add('owner');writers.hold(b.path)
  return original(self)
 monkeypatch.setattr(Ledger,'recover_active',recover)
 def hook(at):
  if (at==phase or phase=='multiple' and at in ('before_entry1','before_accept1','before_revision','before_entry2','before_final')) and at not in seen:
   seen.add(at);writers.hold(b.path)
 try:
  result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook);writers.finish()
  assert result=='completed' and result.request_units==len(calls)==2
  f=facts(b);assert f=={'parents':1,'stages':[(1,'accepted',1),(2,'accepted',1)],'charges':2,'held':0,'drafts':1,'finals':1}
  assert 'sqlite_code=5' in caplog.text
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='cached' and len(calls)==2
  assert facts(b)==f
  print(json.dumps({'boundary':phase,'result':str(result),'physical_fake_POSTs':len(calls),**f}))
 finally:writers.finish();close(s)

@pytest.mark.parametrize('stop',['deadline','cancel'])
def test_held_revision_writer_terminates_without_late_stage2(tmp_path,stop,caplog):
 s,b,cfg,p=setup(tmp_path/'native',budget=None);cfg['timeout']=.7;s.state('behavior_settings',cfg);writers=Writers();calls=[];cancel=threading.Event()
 def hook(phase):
  if phase=='before_revision':
   writers.hold(b.path,.9)
   if stop=='cancel':
    t=threading.Timer(.12,cancel.set);t.start();writers.timers.append(t)
 try:
  started=time.monotonic();result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook,should_stop=cancel.is_set)
  assert time.monotonic()-started<1.7 and len(calls)<=1
  writers.finish();time.sleep(.05)
  assert len(calls)==1 and facts(b)['charges']==1 and facts(b)['finals']==0
  with b.connect() as db:
   assert db.execute('SELECT revision_request FROM pipeline_drafts').fetchone()[0] is None
   assert db.execute('SELECT entered FROM pipeline_stages WHERE ordinal=2').fetchone()[0] is None
  assert 'phase=revision_bind' in caplog.text and 'sqlite_code=5' in caplog.text
 finally:writers.finish();close(s)

@pytest.mark.parametrize('change',['owner','input','configuration'])
def test_retry_rechecks_owner_input_and_configuration_before_more_dispatch(tmp_path,change):
 s,b,cfg,p=setup(tmp_path/'native',budget=None);writers=Writers();calls=[]
 def hook(phase):
  if phase=='before_revision':
   # Change through the competing writer itself before releasing its lock.
   db=sqlite3.connect(b.path,check_same_thread=False);db.execute('BEGIN IMMEDIATE')
   def release():
    if change=='configuration':s.state('behavior_settings',{**cfg,'model':'changed'})
    if change=='owner':db.execute("UPDATE pipeline_plans SET owner='other-owner'")
    if change=='input':db.execute("UPDATE current_packets SET packet_id='new-logical-packet'")
    db.commit();db.close()
   t=threading.Timer(.4,release);t.start();writers.timers.append(t)
 try:
  result=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook);writers.finish()
  assert result!='completed' and len(calls)==1 and facts(b)['charges']==1 and facts(b)['finals']==0
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls)) in ('persistence_review_required','pipeline_review_required') and len(calls)==1
 finally:writers.finish();close(s)

def test_noncontention_revision_error_is_not_retried_and_has_safe_durable_code(tmp_path,monkeypatch,caplog):
 s,b,cfg,p=setup(tmp_path/'native',budget=None);calls=[];original=Ledger.tx;attempts=[]
 def tx(self,fn,*a,**kw):
  if kw.get('phase')=='revision_bind':
   def broken(db):attempts.append(1);db.execute('SELECT private_fixture_sql_text FROM missing_private_fixture_table')
   return original(self,broken,*a,**kw)
  return original(self,fn,*a,**kw)
 monkeypatch.setattr(Ledger,'tx',tx)
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls))=='failed'
  assert len(calls)==len(attempts)==1
  with b.connect() as db:
   value=json.loads(db.execute('SELECT result FROM assessments').fetchone()[0])['metadata']['persistence_diagnostic']
   assert value=={'phase':'revision_bind','sqlite_code':1,'contention':False}
  assert 'phase=revision_bind' in caplog.text and 'sqlite_code=1' in caplog.text
  assert 'private_fixture_sql_text' not in caplog.text and 'missing_private_fixture_table' not in caplog.text
 finally:close(s)

def test_actual_busy_after_partial_sql_rolls_back_before_retry(tmp_path):
 s,b,cfg,p=setup(tmp_path/'native',budget=None);ledger=Ledger(b,retry_seconds=1);rival=tmp_path/'rival';writers=Writers();attempts=[];traces=[]
 with b.connect() as db:db.execute('CREATE TABLE fixture_counter(n)');db.execute('INSERT INTO fixture_counter VALUES(0)')
 with contextlib.closing(sqlite3.connect(rival)) as db:db.execute('CREATE TABLE fixture_once(n)');db.commit()
 writers.hold(rival)
 def unit(db):
  attempts.append(1);db.set_trace_callback(lambda sql:traces.append(sql) if sql in ('ROLLBACK','COMMIT') else None)
  db.execute('ATTACH DATABASE ? AS rival',(str(rival),));db.execute('UPDATE fixture_counter SET n=n+1');db.execute('INSERT INTO rival.fixture_once VALUES(1)')
 try:
  ledger.tx(unit,phase='revision_bind');writers.finish()
  with b.connect() as db:assert db.execute('SELECT n FROM fixture_counter').fetchone()[0]==1
  with contextlib.closing(sqlite3.connect(rival)) as db:assert db.execute('SELECT count(*) FROM fixture_once').fetchone()[0]==1
  assert len(attempts)>1 and 'ROLLBACK' in traces and 'COMMIT' in traces
  print(json.dumps({'actual_busy_rollback_count':traces.count('ROLLBACK'),'successful_commits':traces.count('COMMIT'),'attempts':len(attempts),'committed_counter':1}))
 finally:writers.finish();close(s)

def test_analytics_busy_does_not_repeat_transport_or_charge(tmp_path,caplog):
 import analytics_store
 s,b,cfg,p=setup(tmp_path/'native',budget=None);calls=[];writers=Writers();first=[True]
 analytics_store.event(s,'ai','fixture')
 def hook(phase):
  if phase=='before_entry1' and first[0]:first[0]=False;writers.hold(analytics_store.path(s))
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=sender(calls),hook=hook)=='completed';writers.finish()
  assert len(calls)==facts(b)['charges']==2 and facts(b)['finals']==1
  with analytics_store.connect(s) as db:assert db.execute('SELECT count(*) FROM requests').fetchone()[0]==2
 finally:writers.finish();close(s)

def test_exclusive_writer_read_guard_reopens_short_connection(tmp_path,caplog):
 from behavior_deadline import Deadline
 s,b,cfg,p=setup(tmp_path/'native',budget=None);deadline=Deadline(2);ledger=Ledger(b,check=deadline.check);ledger.retry_until=deadline.end;timers=[]
 with b.connect() as db:assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete'
 holder=sqlite3.connect(b.path,check_same_thread=False);holder.execute('BEGIN EXCLUSIVE')
 t=threading.Timer(.4,lambda:(holder.rollback(),holder.close()));t.start();timers.append(t)
 try:
  row=ledger.read(lambda db:db.execute('SELECT id FROM packets WHERE id=?',(p[0]['packet_id'],)).fetchone(),phase='packet_read')
  assert row[0]==p[0]['packet_id'] and 'phase=packet_read' in caplog.text and 'sqlite_code=5' in caplog.text
 finally:
  for t in timers:t.join()
  deadline.finish();close(s)

def test_error_after_commit_observation_never_repeats_committed_sql(tmp_path,monkeypatch):
 s,b,cfg,p=setup(tmp_path/'native',budget=None);ledger=Ledger(b,retry_seconds=1);connect=ledger.connection;calls=[]
 with b.connect() as db:db.execute('CREATE TABLE fixture_counter(n)');db.execute('INSERT INTO fixture_counter VALUES(0)')
 @contextlib.contextmanager
 def uncertain(live=True):
  with connect(live) as db:yield db
  error=sqlite3.OperationalError('injected close observation after commit');error.sqlite_errorcode=sqlite3.SQLITE_BUSY;raise error
 monkeypatch.setattr(ledger,'connection',uncertain)
 def unit(db):calls.append(1);db.execute('UPDATE fixture_counter SET n=n+1')
 try:
  with pytest.raises(sqlite3.OperationalError) as error:ledger.tx(unit,phase='entry1')
  assert error.value._edl_no_sql_retry and calls==[1]
  with b.connect() as db:assert db.execute('SELECT n FROM fixture_counter').fetchone()[0]==1
 finally:close(s)
