"""Real two-database contention fixtures; no provider or production calls."""
import contextlib,datetime as dt,json,sqlite3,threading,time
import pytest
import analytics_store as ledger
import behavior_telemetry as telemetry
from behavior_ai import Brain
from core import Store

def fixture(tmp_path):
    b=Brain(Store(tmp_path/'native'));when=dt.datetime.now(dt.timezone.utc).isoformat()
    meta={'request_id':'a'*32,'request_started_at':when,'request_finished_at':when,
          'request_transport_state':'accepted','input_tokens':123,'output_tokens':7,'first_content_seconds':.1,'request_seconds':.2}
    with b.connect() as db:
        db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('saved','packet','fixture',when,when,'completed',json.dumps({'metadata':meta}),'',.2))
    with ledger.connect(b.store,True):pass
    return b,meta

@contextlib.contextmanager
def lock_at(monkeypatch,target,needle,seconds):
    original=sqlite3.connect;begin=threading.Event();held=threading.Event();release=threading.Event();errors=[]
    def holder():
        try:
            assert begin.wait(3)
            with contextlib.closing(original(target,timeout=1)) as db:
                db.execute('BEGIN IMMEDIATE');held.set();release.wait(seconds);db.rollback()
        except BaseException as exc:errors.append(exc);held.set()
    class Connection(sqlite3.Connection):
        def execute(self,sql,*args,**kw):
            if needle in sql and not begin.is_set():begin.set();assert held.wait(3)
            return super().execute(sql,*args,**kw)
    def connect(*args,**kw):kw['factory']=Connection;return original(*args,**kw)
    thread=threading.Thread(target=holder);thread.start()
    with monkeypatch.context() as patch:
        patch.setattr(sqlite3,'connect',connect)
        try:yield
        finally:release.set();thread.join(3)
    assert not thread.is_alive() and not errors

def requests(b):
    with ledger.connect(b.store) as db:return [tuple(r) for r in db.execute('SELECT * FROM requests')]

def cursor(b):
    with b.connect() as db:
        row=db.execute("SELECT value FROM retention_state WHERE name='telemetry_cursor'").fetchone()
        return json.loads(row[0]) if row else None

def test_short_behavior_cursor_lock_retries_without_repeating_ledger_receipt(tmp_path,monkeypatch,caplog):
    b,meta=fixture(tmp_path)
    with lock_at(monkeypatch,b.path,"INSERT INTO retention_state VALUES('telemetry_cursor'",.08):
        result=telemetry.recover(b)
    assert result['recovered']==result['ledger_recovered']==1 and result['cursor_advanced']
    row=requests(b)[0];assert row[0]==meta['request_id'] and row[2]==meta['request_started_at'] and row[3]==meta['request_finished_at']
    assert len(requests(b))==1 and cursor(b)['id']=='saved' and not caplog.records

@pytest.mark.parametrize('phase',['cursor_write','ledger_write'])
def test_exhausted_lock_identifies_database_and_restart_replays_once(tmp_path,monkeypatch,caplog,phase):
    b,meta=fixture(tmp_path);target=b.path if phase=='cursor_write' else ledger.path(b.store)
    if phase=='ledger_write':
        for connection in b.store._analytics_handles.values():connection.close()
        b.store._analytics_handles.clear()
    sql="INSERT INTO retention_state VALUES('telemetry_cursor'" if phase=='cursor_write' else 'INSERT INTO requests VALUES'
    with lock_at(monkeypatch,target,sql,2):
        start=time.monotonic();result=telemetry.recover(b);elapsed=time.monotonic()-start
        assert result['status']=='retry' and result['phase']==phase and elapsed<.7
        assert cursor(b) is None
        assert len(requests(b))==(phase=='cursor_write')
    before=requests(b);result=telemetry.recover(Brain(Store(b.store.path)))
    assert result['cursor_advanced'] and result['recovered']==(phase=='ledger_write')
    assert len(requests(b))==1 and (not before or requests(b)==before)
    assert f'operation=ai_recover sqlite_code=5 os_errno=None phase={phase}' in caplog.text
    assert meta['request_id'] not in caplog.text and 'packet' not in caplog.text

def test_permanent_cursor_failure_stays_visible_and_keeps_committed_ledger(tmp_path,caplog):
    b,_=fixture(tmp_path)
    with b.connect() as db:db.execute("CREATE TRIGGER isolated_denial BEFORE INSERT ON retention_state WHEN NEW.name='telemetry_cursor' BEGIN SELECT RAISE(ABORT,'isolated permanent denial'); END")
    result=telemetry.recover(b)
    assert result['status']=='failed' and result['phase']=='cursor_write' and result['ledger_recovered']==1
    assert cursor(b) is None and len(requests(b))==1 and 'phase=cursor_write' in caplog.text
    with b.connect() as db:db.execute('DROP TRIGGER isolated_denial')
    assert telemetry.recover(b)['cursor_advanced'] and len(requests(b))==1

def test_cursor_compare_and_swap_never_overwrites_concurrent_advance(tmp_path,monkeypatch):
    b,_=fixture(tmp_path)
    with b.connect() as db:
        db.execute("INSERT INTO assessments SELECT 'later',packet_id,config_id,created,expires,status,result,error,latency FROM assessments")
        row=db.execute("SELECT rowid,id FROM assessments WHERE id='later'").fetchone();marker=json.dumps(dict(row),sort_keys=True)
    original=telemetry.retry_busy
    def concurrent_advance(fn):
        with b.connect() as db:db.execute("INSERT INTO retention_state VALUES('telemetry_cursor',?)",(marker,))
        return original(fn)
    monkeypatch.setattr(telemetry,'retry_busy',concurrent_advance)
    result=telemetry.recover(b,1)
    assert not result['cursor_advanced'] and cursor(b)['id']=='later'
