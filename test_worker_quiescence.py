"""Deterministic offline consumer quiescence; no inference or production data."""
import json,sqlite3,threading,time,signal
import pytest
from core import Store
from behavior_ai import Brain,settings
import source_handoff as handoff
import packet_indexing as indexing
from test_handoff_delivery_throughput import enabled,load
from test_source_handoff import counts
from test_packet_readiness import fixture


def join(thread):
 thread.join(8);assert not thread.is_alive()


def test_delivery_quiescence_finishes_active_derived_commit_and_native_ack_then_resumes(tmp_path,monkeypatch):
 import evidence_history
 s=Store(tmp_path/'native');enabled(s);b=Brain(s);load(s,0,1100);before=counts(s);entered=threading.Event();release=threading.Event();q=threading.Event();stop=threading.Event();done=threading.Event();save=evidence_history.save_events;calls=[]
 def held(*args,**kwargs):
  save(*args,**kwargs)
  if not entered.is_set():entered.set();assert release.wait(5)
 monkeypatch.setattr(evidence_history,'save_events',held)
 deliver=handoff.deliver
 def counted(*args,**kwargs):r=deliver(*args,**kwargs);calls.append(r);return r
 monkeypatch.setattr(handoff,'deliver',counted)
 thread=threading.Thread(target=handoff.consume,args=(s,stop,done,q));thread.start()
 try:assert entered.wait(5);q.set()
 finally:release.set();join(thread)
 after=counts(s);assert sum(r[-1] for r in after)==500 and len(calls)==1 and not stop.is_set()
 assert [r[:3] for r in after]==[r[:3] for r in before]
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==500
  assert db.execute('SELECT count(*) FROM source_sample_applied').fetchone()[0]==500
 assert s._source_handoff_status['totals']['applied']==500
 done.set();handoff.consume(s,stop,done)
 assert all(r[-1] for r in counts(s)) and [r[:3] for r in counts(s)]==[r[:3] for r in before]
 with b.connect() as db:assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==1100
 assert handoff.deliver(b)['read']==0


def test_readiness_quiescence_commits_active_packet_queue_and_revision_ack_then_resumes(tmp_path,monkeypatch):
 s,b,addresses=fixture(tmp_path,3);s.state('behavior_settings',{'enabled':True,'model_enabled':True,'correlation_enabled':False});before=counts(s);entered=threading.Event();release=threading.Event();q=threading.Event();stop=threading.Event();done=threading.Event();packet=Brain.packet
 def held(*args,**kwargs):
  result=packet(*args,**kwargs)
  if not entered.is_set():entered.set();assert release.wait(5)
  return result
 monkeypatch.setattr(Brain,'packet',held)
 thread=threading.Thread(target=indexing.consume,args=(s,None,stop,done,q));thread.start()
 try:assert entered.wait(5);q.set()
 finally:release.set();join(thread)
 assert not stop.is_set() and len(handoff.ready(b))==2 and counts(s)==before
 with b.connect() as db:
  original=tuple(db.execute('SELECT * FROM packets').fetchone())
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==1
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0
 assert s._packet_index_status['status']=='yielded' and s._packet_index_status['totals']['indexed']==1
 done.set();indexing.consume(s,None,stop,done)
 assert not handoff.ready(b) and counts(s)==before
 with b.connect() as db:
  assert tuple(db.execute('SELECT * FROM packets WHERE id=?',(original[0],)).fetchone())==original
  assert db.execute('SELECT count(*) FROM current_packets').fetchone()[0]==3
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==3
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0


def test_readiness_waiting_for_lock_yields_without_starting_a_transaction(tmp_path,monkeypatch):
 s,b,_=fixture(tmp_path,2);q=threading.Event();stop=threading.Event();done=threading.Event();entered=threading.Event();ready=handoff.ready
 def observed(*args,**kwargs):r=ready(*args,**kwargs);entered.set();return r
 monkeypatch.setattr(handoff,'ready',observed)
 def forbidden(*args,**kwargs):raise AssertionError('Quiesced consumer started a transaction')
 monkeypatch.setattr(indexing,'index_packet',forbidden)
 with s._behavior_index_lock:
  thread=threading.Thread(target=indexing.consume,args=(s,None,stop,done,q));thread.start();assert entered.wait(5);q.set()
 join(thread);assert len(ready(b))==2 and s._packet_index_status['status']=='yielded' and not stop.is_set()


@pytest.mark.parametrize('consumer',['delivery','readiness'])
def test_quiesced_consumer_never_initializes_or_hides_active_failure(tmp_path,monkeypatch,consumer):
 s=Store(tmp_path/'native');enabled(s);q=threading.Event();q.set();stop=threading.Event();done=threading.Event()
 def forbidden(*a,**kw):raise AssertionError('Initialization after quiescence')
 monkeypatch.setattr('behavior_ai.Brain',forbidden)
 if consumer=='delivery':handoff.consume(s,stop,done,q)
 else:indexing.consume(s,None,stop,done,q)
 assert not stop.is_set()


@pytest.mark.parametrize('consumer',['delivery','readiness'])
def test_quiescence_does_not_suppress_an_unexpected_active_operation_failure(tmp_path,monkeypatch,consumer):
 s=Store(tmp_path/'native');enabled(s);q=threading.Event();stop=threading.Event();done=threading.Event()
 def failed(*a,**kw):q.set();raise ValueError('isolated active operation fault')
 if consumer=='delivery':
  monkeypatch.setattr(handoff,'deliver',failed);handoff.consume(s,stop,done,q);status=s._source_handoff_status
 else:
  monkeypatch.setattr(indexing,'page',failed);indexing.consume(s,None,stop,done,q);status=s._packet_index_status
 assert stop.is_set() and status=={'status':'failed','error':'ValueError'}


def worker_fixture(tmp_path,monkeypatch):
 pytest.importorskip('fcntl');import behavior_worker as worker
 s=Store(tmp_path/'native');enabled(s);cfg=tmp_path/'config.json';cfg.write_text(json.dumps({'database':s.path}));monkeypatch.setenv('EDL_CONFIG',str(cfg));monkeypatch.setattr('sys.argv',['behavior_worker.py']);monkeypatch.setattr(worker,'Store',lambda path:s)
 return worker,s


@pytest.mark.parametrize('outcome',['persistence_deferred','exception','shutdown'])
def test_worker_signals_both_consumers_before_join_and_waits_for_atomic_completion(tmp_path,monkeypatch,outcome):
 worker,s=worker_fixture(tmp_path,monkeypatch);entered=[threading.Event(),threading.Event()];finished_seen=[threading.Event(),threading.Event()];committed=[];errors=[];signals={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
 def consume(number,stop,finished,q):
  try:
   with sqlite3.connect(tmp_path/('atomic-'+str(number))) as db:
    db.execute('CREATE TABLE commits(n INTEGER)');db.execute('BEGIN IMMEDIATE');db.execute('INSERT INTO commits VALUES(1)');entered[number].set();assert q.wait(5);assert finished.is_set();finished_seen[number].set();assert finished_seen[1-number].wait(5)
   committed.append(number)
  except BaseException as exc:errors.append(exc)
 def delivery(store,stop,finished,q):consume(0,stop,finished,q)
 def readiness(store,cfg,stop,finished,q):consume(1,stop,finished,q)
 monkeypatch.setattr(handoff,'consume',delivery);monkeypatch.setattr(indexing,'consume',readiness)
 def foreground(store,**kwargs):
  assert all(event.wait(5) for event in entered)
  if outcome=='exception':raise ValueError('isolated foreground failure')
  if outcome=='shutdown':kwargs['should_stop'].__self__.set()
  return {'analysis_stop':outcome}
 monkeypatch.setattr(worker,'run',foreground)
 if outcome=='exception':
  with pytest.raises(ValueError,match='isolated foreground failure'):worker.main()
 else:worker.main()
 assert not errors and sorted(committed)==[0,1] and not s._source_handoff_background and not s._packet_index_background
 assert all(signal.getsignal(sig)==value for sig,value in signals.items())
 assert not any(t.name in ('source-sample-delivery','packet-readiness') for t in threading.enumerate())
 for n in (0,1):
  with sqlite3.connect(tmp_path/('atomic-'+str(n))) as db:assert db.execute('SELECT count(*) FROM commits').fetchone()[0]==1


def test_worker_partial_thread_start_failure_joins_started_consumer_and_restores_signals(tmp_path,monkeypatch):
 worker,s=worker_fixture(tmp_path,monkeypatch);ended=threading.Event();original=threading.Thread.start;signals={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
 def delivery(store,stop,finished,q):assert q.wait(5);ended.set()
 def start(thread):
  if thread.name=='packet-readiness':raise RuntimeError('isolated thread startup failure')
  return original(thread)
 monkeypatch.setattr(handoff,'consume',delivery);monkeypatch.setattr(threading.Thread,'start',start)
 with pytest.raises(RuntimeError,match='isolated thread startup failure'):worker.main()
 assert ended.is_set() and not s._source_handoff_background and not s._packet_index_background
 assert all(signal.getsignal(sig)==value for sig,value in signals.items())
 assert not any(t.name=='source-sample-delivery' for t in threading.enumerate())


def test_foreground_real_sqlite_save_deferral_survives_quiescence_and_recovers_without_redispatch(tmp_path,monkeypatch):
 pytest.importorskip('fcntl');import behavior_worker as worker
 import behavior_ai as ai
 import behavior_persistence as pending
 from test_behavior_drain import queue
 from test_assessment_persistence import fake,Holder,packet,files,verify_once
 s,b,cfg=queue(tmp_path,1);held=[];calls=fake(monkeypatch,b,lambda:held.append(Holder(b.path,['BEGIN IMMEDIATE'])))
 path=tmp_path/'config.json';path.write_text(json.dumps({'database':s.path}));monkeypatch.setenv('EDL_CONFIG',str(path));monkeypatch.setattr('sys.argv',['behavior_worker.py']);monkeypatch.setattr(worker,'Store',lambda path:s);seen=[]
 def delivery(store,stop,done,q):assert q.wait(5);assert done.is_set();seen.append('delivery')
 def readiness(store,cfg,stop,done,q):assert q.wait(5);assert done.is_set();seen.append('readiness')
 monkeypatch.setattr(handoff,'consume',delivery);monkeypatch.setattr(indexing,'consume',readiness)
 def foreground(store,**kwargs):
  status=ai.model_job(b,'packet0',packet(b),set(),cfg);assert status=='persistence_deferred'
  return {'analysis_stop':status}
 monkeypatch.setattr(worker,'run',foreground)
 try:
  worker.main();assert sorted(seen)==['delivery','readiness'];saved=pending.read(files(b)[0]);assert calls==[1]
 finally:
  for holder in held:holder.close()
 assert pending.recover(b)['saved']==1 and not files(b)
 rows=verify_once(b,calls);assert list(rows['assessments'][0])==saved['row']
