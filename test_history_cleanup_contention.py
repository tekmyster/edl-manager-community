"""File-backed mechanics only; no live locks, inference or truth labels."""
import contextlib,datetime as dt,sqlite3,threading
import pytest
from core import Store,now
import behavior_ai as ai
import evidence_history as history

@contextlib.contextmanager
def connection(brain,shared=False,after_first=None,readonly=False):
 uri=brain.path.resolve().as_uri()+('?mode=ro' if readonly else '?cache=shared' if shared else '')
 db=sqlite3.connect(uri,uri=True,timeout=.05);db.row_factory=sqlite3.Row
 if after_first:
  def trace(sql):
   if sql.startswith('DELETE FROM source_binding_receipts'):after_first(db)
  db.set_trace_callback(trace)
 try:yield db;db.commit()
 except Exception:db.rollback();raise
 finally:db.close()

@contextlib.contextmanager
def held(brain,reader=False):
 ready=threading.Event();release=threading.Event();errors=[]
 def work():
  try:
   db=sqlite3.connect(brain.path.resolve().as_uri()+('?cache=shared' if reader else ''),uri=True,timeout=1)
   try:
    db.execute('BEGIN' if reader else 'BEGIN IMMEDIATE')
    if reader:db.execute('SELECT * FROM source_binding_receipts').fetchall()
    else:db.execute("INSERT OR REPLACE INTO history_queries VALUES('fixture-lock','scope','now','{}')")
    ready.set();assert release.wait(5)
   finally:db.rollback();db.close()
  except BaseException as exc:errors.append(exc);ready.set()
 worker=threading.Thread(target=work);worker.start();assert ready.wait(5)
 try:assert not errors;yield
 finally:release.set();worker.join(5);assert not worker.is_alive();assert not errors

@pytest.fixture
def data(tmp_path):
 store=Store(tmp_path/'manager.sqlite3');brain=ai.Brain(store);at=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
 with brain.connect() as db:
  for ident,scope,when in [('old','scope',at-dt.timedelta(days=31)),('keep','scope',at),('boundary','scope',at-dt.timedelta(days=30)),('same','other-scope',at)]:
   db.execute('INSERT INTO event_history VALUES(?,?,?,?,?,?,?,?)',(ident,'9.9.9.9','fixture','fixture',when.isoformat(),at.isoformat(),scope,'{}'))
  for ident,scope in [('old','scope'),('keep','scope'),('same','wrong-scope')]:db.execute('INSERT INTO source_binding_receipts VALUES(?,?,?,?)',(ident,scope,at.isoformat(),'{}'))
  for ident,event,scope in [('old-audit','old','scope'),('keep-audit','keep','scope'),('orphan-audit','none','scope'),('wrong-scope-audit','same','wrong-scope')]:db.execute('INSERT INTO source_binding_audit VALUES(?,?,?,?,?,?,?,?)',(ident,event,scope,at.isoformat(),'fixture','0'*64,'1'*64,'{}'))
 return store,brain,at

def rows(brain):
 with brain.connect() as db:return {t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in ('event_history','source_binding_receipts','source_binding_audit')}

def test_real_busy_defers_and_next_pass_succeeds(data,monkeypatch,caplog):
 _,brain,at=data;before=rows(brain);monkeypatch.setattr(brain,'connect',lambda:connection(brain))
 with held(brain):result=history.cleanup(brain,at)
 assert result=={'status':'deferred','reason':'sqlite_contention','sqlite_code':sqlite3.SQLITE_BUSY,'retry':'next_normal_pass','batch_bound_per_table':5000}
 assert rows(brain)==before and 'Behavior history cleanup deferred sqlite_code=5' in caplog.text
 result=history.cleanup(brain,at)
 assert result['status']=='completed' and result['scope']=='bounded_pass'
 assert result['deleted']=={'events':1,'receipts':2,'audit':3}
 remaining=rows(brain);assert {r[0] for r in remaining['event_history']}=={'keep','boundary','same'}
 assert remaining['source_binding_audit']==[before['source_binding_audit'][1]]

def test_real_locked_second_table_rolls_back_first_delete(data,monkeypatch):
 _,brain,at=data;before=rows(brain);first=[]
 def observed(db):first.append(db.execute("SELECT count(*) FROM event_history WHERE id='old'").fetchone()[0])
 monkeypatch.setattr(brain,'connect',lambda:connection(brain,shared=True,after_first=observed))
 with held(brain,reader=True):result=history.cleanup(brain,at)
 assert result['status']=='deferred' and result['sqlite_code']&255==sqlite3.SQLITE_LOCKED
 assert first==[0] and rows(brain)==before
 assert history.cleanup(brain,at)['deleted']['events']==1

def test_schema_error_after_first_delete_propagates_and_rolls_back(data,monkeypatch,caplog):
 _,brain,at=data
 with brain.connect() as db:db.execute('DROP TABLE source_binding_receipts')
 monkeypatch.setattr(brain,'connect',lambda:connection(brain))
 with pytest.raises(sqlite3.OperationalError) as caught:history.cleanup(brain,at)
 assert caught.value.sqlite_errorcode==sqlite3.SQLITE_ERROR
 with brain.connect() as db:assert db.execute("SELECT count(*) FROM event_history WHERE id='old'").fetchone()[0]==1
 assert 'deferred' not in caplog.text

def test_real_readonly_is_not_busy(data,monkeypatch,caplog):
 _,brain,at=data;monkeypatch.setattr(brain,'connect',lambda:connection(brain,readonly=True))
 with pytest.raises(sqlite3.OperationalError) as caught:history.cleanup(brain,at)
 assert caught.value.sqlite_errorcode&255==sqlite3.SQLITE_READONLY and 'deferred' not in caplog.text

@pytest.mark.parametrize('code',[None,sqlite3.SQLITE_IOERR,sqlite3.SQLITE_CORRUPT,sqlite3.SQLITE_ERROR])
def test_nonbusy_codes_and_message_only_lock_are_not_suppressed(data,monkeypatch,code,caplog):
 _,brain,at=data
 @contextlib.contextmanager
 def failed():
  exc=sqlite3.OperationalError('database is locked')
  if code is not None:exc.sqlite_errorcode=code
  raise exc
  yield
 monkeypatch.setattr(brain,'connect',failed)
 with pytest.raises(sqlite3.OperationalError):history.cleanup(brain,at)
 assert 'deferred' not in caplog.text

def test_batch_bounds_and_receipt_protected_audit(data):
 _,brain,at=data
 with brain.connect() as db:
  db.execute('DELETE FROM source_binding_receipts');db.execute('DELETE FROM event_history');db.execute('DELETE FROM source_binding_audit')
  db.executemany('INSERT INTO event_history VALUES(?,?,?,?,?,?,?,?)',[(str(i),'9.9.9.9','fixture','fixture',(at-dt.timedelta(days=31)).isoformat(),at.isoformat(),'scope','{}') for i in range(5001)])
  db.executemany('INSERT INTO source_binding_receipts VALUES(?,?,?,?)',[(str(i),'scope',at.isoformat(),'{}') for i in range(5001)])
  db.executemany('INSERT INTO source_binding_audit VALUES(?,?,?,?,?,?,?,?)',[(str(i),str(i),'scope',at.isoformat(),'fixture','0'*64,'1'*64,'{}') for i in range(5001)])
  db.execute("INSERT INTO source_binding_receipts VALUES('extra','scope',?,'{}')",(at.isoformat(),));db.execute("INSERT INTO source_binding_audit VALUES('extra','extra','scope',?,'fixture',?,?,'{}')",(at.isoformat(),'0'*64,'1'*64))
 result=history.cleanup(brain,at);assert result['deleted']=={'events':5000,'receipts':5000,'audit':5000}
 with brain.connect() as db:
  assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==1
  assert db.execute('SELECT count(*) FROM source_binding_audit a JOIN source_binding_receipts r ON r.event_id=a.event_id AND r.scope=a.scope WHERE NOT EXISTS(SELECT 1 FROM event_history h WHERE h.id=a.event_id AND h.scope=a.scope)').fetchone()[0]>=1
 assert history.cleanup(brain,at)['deleted']=={'events':1,'receipts':2,'audit':2}

def test_cycle_continuity_and_visible_status(data,monkeypatch):
 store,brain,at=data;store.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50);store.state('behavior_settings',{**ai.DEFAULTS,'enabled':True,'model_enabled':True,'daily_budget':None})
 monkeypatch.setattr(brain,'connect',lambda:connection(brain));monkeypatch.setattr(ai,'Brain',lambda unused:brain);original=history.cleanup
 def contended(b,clock):
  with held(b):return original(b,clock)
 monkeypatch.setattr(history,'cleanup',contended);analysis=[]
 def drain(*a,**kw):analysis.append(1);return {'fixture_continued':1},1,'idle'
 monkeypatch.setattr(ai,'drain_queue',drain);result=ai.run(store)
 assert result['history_cleanup']['status']=='deferred' and 'deleted' not in result['history_cleanup']
 assert result['indexed']==1 and analysis==[1] and result['analysis']=={'fixture_continued':1}
 assert store.state('behavior_worker')['history_cleanup']==result['history_cleanup']
 assert ai.run(store,should_stop=lambda:True)=={'status':'cancelled'}


def test_real_invalid_database_is_not_deferred(tmp_path,caplog):
 brain=ai.Brain.__new__(ai.Brain);brain.path=tmp_path/'invalid.sqlite3';brain.path.write_bytes(b'not a SQLite database')
 with pytest.raises(sqlite3.DatabaseError) as caught:history.cleanup(brain,dt.datetime.now(dt.timezone.utc))
 assert caught.value.sqlite_errorcode==sqlite3.SQLITE_NOTADB
 assert 'deferred' not in caplog.text
