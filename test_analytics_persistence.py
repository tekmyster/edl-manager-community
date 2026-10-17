"""Real SQLite failure/recovery fixtures; no live model or production writes."""
import concurrent.futures
import datetime as dt
import multiprocessing as mp
import os
import sqlite3
import threading


import pytest
import analytics_store as ledger
from core import Store
from behavior_ai import Brain, DEFAULTS, infer, ModelOutputError
from production_analytics import summary
from test_behavior_backend_telemetry import request_fixture

class LedgerStore:
    def __init__(self,path):self.path=path


META={'first_content_seconds':1.25,'request_seconds':3.5,'input_tokens':11,'output_tokens':7}


def writer(database, ready, release):
    db=sqlite3.connect(database)
    db.execute('BEGIN IMMEDIATE')
    ready.set()
    try:
        if not release.wait(20):raise RuntimeError('test writer release timeout')
    finally:db.rollback();db.close()


def initializer(native, start_gate, pipe):
    store=LedgerStore(path=native)
    a=ledger.Attempt(store,'packet')
    try:
        assert start_gate.wait(20)
        started=a.start()
        pipe.send((a.id,a.started,started))
        assert pipe.recv()=='finish'
        pipe.send(a.finish('accepted',META))
    finally:pipe.close()


def rows(store):
    with ledger.connect(store) as db:return [dict(r) for r in db.execute('SELECT * FROM requests')]


def dump(db):
    with db.connect() as connection:return list(connection.iterdump())


def test_crossprocess_failed_start_and_finish_recover_actual_times_once(tmp_path,caplog):
    b=Brain(Store(tmp_path/'manager'))
    native,behavior=dump(b.store),dump(b)
    with ledger.connect(b.store,True) as db:
        assert db.execute('PRAGMA busy_timeout').fetchone()[0]==25
    ctx=mp.get_context('spawn');ready=ctx.Event();release=ctx.Event()
    p=ctx.Process(target=writer,args=(str(ledger.path(b.store)),ready,release));p.start()
    a=ledger.Attempt(b.store,'actual-packet')
    try:
        assert ready.wait(20)
        assert a.start() is False
        start=a.started
        assert a.finish('rejected',META) is False
        completion=a._outcome[0]
        # A failed pruning transaction must not mark maintenance committed.
        assert rows(b.store)==[]
    finally:release.set();p.join(20)
    assert p.exitcode==0
    assert a.finish('accepted',{'input_tokens':999}) is True
    first=rows(b.store)[0]
    assert first=={'id':a.id,'packet':'actual-packet','started':start,'finished':completion,
                   'state':'rejected','first_seconds':1.25,'input_tokens':11,'output_tokens':7,'total_seconds':3.5}
    assert a.start() and a.finish('failed',{})
    assert rows(b.store)==[first]
    assert 'operation=ai_start sqlite_code=5' in caplog.text
    assert 'operation=ai_finish sqlite_code=5' in caplog.text
    assert str(tmp_path) not in caplog.text
    # New store/process-style read: persisted final state and deduped tokens.
    with b.connect() as db:
        import json
        db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('linked','p','cfg',completion,completion,'failed',json.dumps({'metadata':{**META,'request_id':a.id}}),'fixture',1))
    report=summary(Brain(Store(b.store.path)),at=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=1))
    assert report['requests']==report['hour_requests']==1
    assert report['outcomes']=={'rejected':1}
    assert report['first_samples']==1 and report['first_seconds']==1.25
    assert report['day_tokens']==18 and report['day_known']==1 and report['historical_completions']==0
    assert dump(b.store)==native
    # Only the explicit fixture assessment above may change the behavior DB.
    with b.connect() as db:db.execute("DELETE FROM assessments WHERE id='linked'")
    assert dump(b)==behavior


def test_fresh_schema_initialization_from_concurrent_processes(tmp_path):
    store=LedgerStore(path=str(tmp_path/'native'))
    ctx=mp.get_context('spawn');gate=ctx.Event();workers=[]
    try:
        for _ in range(4):
            parent,child=ctx.Pipe()
            p=ctx.Process(target=initializer,args=(store.path,gate,child));p.start();child.close();workers.append((p,parent))
        gate.set()
        identities=[]
        for p,pipe in workers:
            assert pipe.poll(30);identities.append(pipe.recv())
        # A bounded failure during concurrent startup is allowed; each actual
        # completion must recover when its writer turn is available.
        for p,pipe in workers:
            pipe.send('finish');assert pipe.poll(30);assert pipe.recv() is True
        for p,pipe in workers:p.join(20);assert p.exitcode==0
        saved=rows(store)
        assert {r['id'] for r in saved}=={r[0] for r in identities}
        assert {r['started'] for r in saved}=={r[1] for r in identities}
        with ledger.connect(store) as db:
            assert db.execute("SELECT started FROM coverage WHERE name='ai'").fetchone()[0]==min(r[1] for r in identities)
            assert db.execute('PRAGMA journal_mode').fetchone()[0]=='wal'
            assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
    finally:
        gate.set()
        for p,pipe in workers:
            pipe.close();p.join(1)
            if p.is_alive():p.terminate();p.join(5)


def test_same_store_concurrent_threads_reuse_one_handle_each(tmp_path):
    store=LedgerStore(path=str(tmp_path/'native'));barrier=threading.Barrier(4)
    # Initialize once, then exercise the actual shared-store handle ownership.
    with ledger.connect(LedgerStore(store.path),True):pass
    def work(i):
        a=ledger.Attempt(store,str(i));barrier.wait(timeout=10)
        a.start()
        return a.finish('accepted',META)
    with concurrent.futures.ThreadPoolExecutor(4) as pool:assert all(pool.map(work,range(4)))
    assert len(rows(store))==4
    assert len(store._analytics_handles)==4


def test_failed_transaction_does_not_skip_retention_retry(tmp_path):
    store=LedgerStore(path=str(tmp_path/'native'))
    with ledger.connect(store,True) as db:
        db.execute("INSERT INTO requests(id,packet,started,state) VALUES('old','p','2000-01-01T00:00:00+00:00','pending')")
    ledger._pruned.pop(str(ledger.path(store)))
    with pytest.raises(ValueError):
        with ledger.connect(store,True):raise ValueError('rollback fixture')
    assert str(ledger.path(store)) not in ledger._pruned
    assert len(rows(store))==1
    with ledger.connect(store,True):pass
    assert rows(store)==[]


@pytest.mark.skipif(os.name=='nt' or getattr(os,'geteuid',lambda:0)()==0,reason='requires unprivileged POSIX permissions')
def test_real_readonly_ledger_fails_safely_and_recovers_without_acl_workaround(tmp_path,caplog):
    directory=tmp_path/'isolated';directory.mkdir()
    store=LedgerStore(path=str(directory/'native'))
    with ledger.connect(store,True):pass
    for db in store._analytics_handles.values():db.close()
    store._analytics_handles.clear()
    database=ledger.path(store);database.chmod(0o444);directory.chmod(0o555)
    a=ledger.Attempt(store,'private-packet')
    try:
        assert a.start() is False
        assert a.finish('rejected',META) is False
        ledger.event(store,'misp','hit','8.8.8.8')
        codes=[r.args[1] for r in caplog.records if r.msg.startswith('Analytics persistence failed')]
        assert codes and all(type(c) is int and c & 255 == sqlite3.SQLITE_READONLY for c in codes)
        assert str(tmp_path) not in caplog.text and 'private-packet' not in caplog.text and '8.8.8.8' not in caplog.text
    finally:directory.chmod(0o755);database.chmod(0o644)
    assert a.finish('rejected',META)
    assert len(rows(store))==1


def test_os_diagnostics_never_log_exception_content(tmp_path,monkeypatch,caplog):
    store=LedgerStore(path=str(tmp_path/'native'))
    def denied(*a,**kw):raise PermissionError(13,'SECRET CREDENTIAL AND PATH')
    monkeypatch.setattr(ledger.sqlite3,'connect',denied)
    a=ledger.Attempt(store,'secret-packet');assert not a.start();assert not a.finish('failed',{})
    assert 'os_errno=13' in caplog.text and 'SECRET' not in caplog.text and str(tmp_path) not in caplog.text


def test_finish_without_known_dispatch_does_not_invent_history(tmp_path):
    store=LedgerStore(path=str(tmp_path/'native'))
    assert not ledger.Attempt(store,'p').finish('accepted',META)
    assert not ledger.path(store).exists()


@pytest.mark.parametrize('terminator',[b'\n',b''])
@pytest.mark.parametrize('streaming',[True,False])
@pytest.mark.parametrize('rejected',[True,False])
def test_inference_recovers_failed_start_with_final_validation_and_ttfr(tmp_path,terminator,streaming,rejected):
    import json
    from test_behavior_ai import result
    packet,_,_=request_fixture(tmp_path,{})
    b=Brain(Store(tmp_path/'manager'));native,behavior=dump(b.store),dump(b)
    with ledger.connect(b.store,True):pass
    lock=sqlite3.connect(ledger.path(b.store));lock.execute('BEGIN IMMEDIATE')
    value=result(packet)
    if rejected:value['packet_id']='not-the-supplied-packet'
    text=json.dumps(value)
    frames=([{'model':'test','done':False,'message':{'content':text}}] if streaming else [])
    frames.append({'model':'test','done':True,'message':{'content':'' if streaming else text},'prompt_eval_count':11,'eval_count':7})
    calls=[]
    class Response:
        status_code=200
        def iter_content(self,n):
            for i,frame in enumerate(frames):yield json.dumps(frame).encode()+(b'\n' if i<len(frames)-1 else terminator)
        def close(self):pass
    def request(*a,**kw):
        calls.append(1);lock.rollback();return Response()
    a=ledger.Attempt(b.store,packet['packet_id'])
    try:
        if rejected:
            with pytest.raises(ModelOutputError):infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',request,a)
        else:infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',request,a)
    finally:lock.close()
    assert calls==[1]
    row=rows(b.store)[0]
    assert row['state']==('rejected' if rejected else 'accepted')
    assert (row['first_seconds'] is not None)==streaming
    assert row['input_tokens']==11 and row['output_tokens']==7
    assert dump(b.store)==native and dump(b)==behavior
