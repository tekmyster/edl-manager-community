"""Actual SQLite ownership and replay contracts; no providers/production data."""
import contextlib,copy,datetime as dt,json,pathlib,sqlite3,threading
import pytest
from test_native_owner_repair import w,owner
from core import Store
from behavior_ai import Brain,DEFAULTS,settings
import source_handoff as handoff,evidence_history as history,packet_indexing as indexing
from test_binding_receipts import proven
from test_source_observation_cache import AT,ADDRESS
from test_source_handoff import counts
from test_assessment_persistence import Holder

@pytest.fixture(autouse=True)
def fixed_receipts(monkeypatch):
 import core
 monkeypatch.setattr(core,'now',lambda:AT.isoformat())

def values(count):return [{'id':'writer-fixture-'+str(i),'seen':AT.isoformat(),'action':'HTTP request','path':'/example/'+str(i),'method':'GET'} for i in range(count)]
def fixture(tmp_path,count=35):
 s=Store(tmp_path/'native');b=Brain(s);s.source_activity(ADDRESS,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':values(count)}});return s,b
def short_connections(monkeypatch):
 original=sqlite3.connect
 class Short(sqlite3.Connection):
  def execute(self,sql,*a,**kw):
   if str(sql).upper().startswith('PRAGMA BUSY_TIMEOUT='):sql='PRAGMA busy_timeout=25'
   return super().execute(sql,*a,**kw)
 def connect(*a,**kw):kw['timeout']=.025;kw['factory']=Short;return original(*a,**kw)
 monkeypatch.setattr(sqlite3,'connect',connect)

def test_initialized_constructor_reads_under_held_writer_and_does_not_maintain(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');statements=[];original=sqlite3.connect
 def traced(*a,**kw):
  db=original(*a,**kw);db.set_trace_callback(statements.append);return db
 short_connections(monkeypatch);short=sqlite3.connect
 def wrapped(*a,**kw):db=short(*a,**kw);db.set_trace_callback(statements.append);return db
 holder=Holder(s.path,['BEGIN IMMEDIATE'])
 try:
  monkeypatch.setattr(sqlite3,'connect',wrapped);Store(s.path)
 finally:holder.close()
 assert not [q for q in statements if q.strip().upper().startswith(('INSERT','UPDATE','DELETE','BEGIN'))]

@pytest.mark.parametrize('kind',['index','handoff_columns','arrival_marker','policy_missing','arrival_missing','index_shape','primary_key'])
def test_real_schema_or_marker_failure_is_never_hidden(tmp_path,monkeypatch,kind):
 s=Store(tmp_path/'native')
 with s.connect() as db:
  if kind=='index':db.execute('DROP INDEX source_sample_expiry')
  elif kind=='handoff_columns':db.execute('ALTER TABLE source_sample_handoff RENAME COLUMN delivered TO incompatible')
  elif kind=='arrival_marker':db.execute("UPDATE state SET value='{}' WHERE key='new_ip_tracking'")
  elif kind=='policy_missing':db.execute('DROP TABLE policy_events')
  elif kind=='arrival_missing':db.execute('DROP TABLE ip_observations')
  elif kind=='index_shape':db.execute('DROP INDEX source_sample_expiry');db.execute('CREATE INDEX source_sample_expiry ON source_sample_handoff(ip)')
  else:db.execute('DROP TABLE ip_observations');db.execute('CREATE TABLE ip_observations(ip TEXT,seen TEXT)')
 if kind=='index':
  short_connections(monkeypatch);holder=Holder(s.path,['BEGIN IMMEDIATE'])
  try:
   with pytest.raises(sqlite3.OperationalError):Store(s.path)
  finally:holder.close()
  Store(s.path)
  with s.connect() as db:assert db.execute("SELECT 1 FROM sqlite_master WHERE name='source_sample_expiry'").fetchone()
 else:
  with pytest.raises((sqlite3.Error,ValueError)):Store(s.path)

def test_concurrent_legacy_initializer_preserves_rows_and_tracking(tmp_path):
 s=Store(tmp_path/'native')
 with s.connect() as db:
  db.execute("DELETE FROM state WHERE key='new_ip_tracking'");db.execute('INSERT INTO ips VALUES(?,?,?,?)',('9.9.9.9',AT.isoformat(),AT.isoformat(),'{}'))
 gate=threading.Barrier(2);errors=[]
 def initialize():
  try:gate.wait();Store(s.path)
  except BaseException as exc:errors.append(exc)
 threads=[threading.Thread(target=initialize) for _ in range(2)]
 for t in threads:t.start()
 for t in threads:t.join(10);assert not t.is_alive()
 assert not errors
 with s.connect() as db:assert db.execute("SELECT count(*) FROM ip_observations WHERE ip='9.9.9.9'").fetchone()[0]==1

def test_scheduled_maintenance_bounded_restart_and_eligibility(tmp_path):
 from new_ips import maintain as arrivals
 s=Store(tmp_path/'native');now=dt.datetime.now(dt.timezone.utc);old=(now-dt.timedelta(days=367)).isoformat();boundary=(now-dt.timedelta(days=366)).isoformat();expired=(now-dt.timedelta(days=31)).isoformat()
 with s.connect() as db:
  db.executemany('INSERT INTO ip_observations VALUES(?,?)',[('11.0.'+str(i//250)+'.'+str(i%250+1),old) for i in range(5003)])
  db.execute('INSERT INTO ip_observations VALUES(?,?)',('9.9.9.9',boundary))
  db.executemany('INSERT INTO source_sample_handoff(id,ip,source,sensor,scope,seen,received,content) VALUES(?,?,?,?,?,?,?,?)',[(str(i),ADDRESS,'tpot','fixture','',expired,expired,'{}') for i in range(5003)])
 Store(s.path)
 with s.connect() as db:assert db.execute('SELECT count(*) FROM ip_observations').fetchone()[0]==5004
 assert arrivals(s,now)=={'deleted':5000,'partial':True,'bound':5000};assert handoff.maintain(s,now)=={'deleted':5000,'partial':True,'bound':5000}
 Store(s.path)
 assert arrivals(s,now)['deleted']==3 and not arrivals(s,now)['partial'];assert handoff.maintain(s,now)['deleted']==3
 with s.connect() as db:assert db.execute('SELECT * FROM ip_observations').fetchone()['seen']==boundary

def test_audit_maintenance_partial_restart_and_rollback(tmp_path,monkeypatch):
 import event_history as events
 s=Store(tmp_path/'native')
 with s.connect() as db:
  for i in range(3):db.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(AT.isoformat(),'fixture','rule.add',json.dumps({'action':'block','value':'9.9.9.9','id':str(i),'reason':'fixture'})))
 Store(s.path)
 with s.connect() as db:assert db.execute('SELECT count(*) FROM policy_events').fetchone()[0]==0
 original=events.audit_event
 def fail(db,ident,*a):
  if ident==2:raise sqlite3.OperationalError('isolated failure')
  return original(db,ident,*a)
 monkeypatch.setattr(events,'audit_event',fail)
 with pytest.raises(sqlite3.OperationalError):events.recover_audit(s,limit=2)
 with s.connect() as db:assert db.execute('SELECT count(*) FROM policy_events').fetchone()[0]==0
 monkeypatch.setattr(events,'audit_event',original);first=events.recover_audit(s,limit=1);assert first['processed']==1 and first['partial']
 Store(s.path);last=events.recover_audit(s,limit=2);assert last['processed']==2 and not last['partial']
 with s.connect() as db:assert db.execute('SELECT count(*) FROM policy_events').fetchone()[0]==3

def test_foreground_short_commits_partial_failure_never_marks_query_success(tmp_path,monkeypatch):
 s,b=fixture(tmp_path,0);calls=[0];apply=history.apply_events
 def fail(db,*a):
  calls[0]+=1
  if calls[0]==2:raise ValueError('isolated second chunk')
  return apply(db,*a)
 monkeypatch.setattr(history,'apply_events',fail)
 cfg={'index_url':'https://index.example.test','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'tpot':'*'}}
 fetch=lambda *a:([('tpot','Cowrie',values(40))],{'status':'ok'})
 with pytest.raises(ValueError):history.refresh(b,ADDRESS,cfg,AT,fetcher=fetch)
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==history.HISTORY_COMMIT_EVENTS
  assert db.execute('SELECT count(*) FROM history_queries').fetchone()[0]==0
 monkeypatch.setattr(history,'apply_events',apply);assert history.refresh(b,ADDRESS,cfg,AT,fetcher=fetch)=='refreshed'
 with b.connect() as db:assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==40

def test_nested_history_never_begins_commits_or_closes_owner(tmp_path):
 s,b=fixture(tmp_path,0);events=[history.normalize(ADDRESS,'tpot','Cowrie',v,AT.isoformat()) for v in values(40)];statements=[]
 with b.connect() as db:
  db.execute('BEGIN IMMEDIATE');db.set_trace_callback(statements.append)
  class Borrowed:
   def connect(self):return contextlib.nullcontext(db)
  history.save_events(Borrowed(),ADDRESS,events,AT.isoformat());assert db.in_transaction
  assert not any(q.upper().startswith(('BEGIN','COMMIT','ROLLBACK')) for q in statements)
  db.rollback()
 with b.connect() as db:assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==0
 with b.connect() as db:
  with pytest.raises(RuntimeError):history.apply_events(db,ADDRESS,events,AT.isoformat())

def test_delivery_preserves_public_read_bound_and_nonempty_binding_audits(tmp_path,monkeypatch):
 results=[]
 for size in (16,64):
  monkeypatch.setattr(handoff,'DELIVERY_COMMIT_EVENTS',size);s,b=fixture(tmp_path/str(size),35)
  for data in (proven(),proven(count=2,at=AT+dt.timedelta(minutes=1))):s.source_activity(ADDRESS,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':data}})
  result=handoff.deliver(b,at=AT);assert result['read']==41 and result['acknowledged']==41
  with b.connect() as db:
   state={t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in ('event_history','source_binding_receipts','source_binding_audit','source_sample_applied','source_sample_ready')};assert len(state['source_binding_audit'])>0
  results.append(state)
 assert results[0]==results[1]

def test_partial_delivery_busy_counts_only_committed_chunks(tmp_path,monkeypatch):
 s,b=fixture(tmp_path);original=b.connect;calls=[0];holders=[]
 @contextlib.contextmanager
 def connect():
  calls[0]+=1
  if calls[0]==2:holders.append(Holder(b.path,['BEGIN IMMEDIATE']))
  with original() as db:yield db
 monkeypatch.setattr(b,'connect',connect)
 try:result=handoff.deliver(b,at=AT)
 finally:
  for holder in holders:holder.close()
 assert result['status']=='busy_retry_next_pass' and result['read']==result['applied']==result['acknowledged']==16
 assert sum(r[-1] for r in counts(s))==16
 monkeypatch.setattr(b,'connect',original);assert handoff.deliver(b,at=AT)['applied']==19

@pytest.mark.parametrize('change',['revision','native_scope','native_config','caller_config'])
def test_stale_preparation_never_publishes_or_acks_successor(tmp_path,monkeypatch,change):
 s,b=fixture(tmp_path,3);handoff.deliver(b,at=AT);revision=handoff.ready(b)[ADDRESS];cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':False};describe=Store.describe
 def changed(reader,address):
  row=describe(reader,address)
  if change=='revision':
   with b.connect() as db:db.execute('UPDATE source_sample_ready SET revision=revision+100')
  elif change=='native_scope':s.state('source_configuration',{'index_url':'https://changed.example.test'})
  elif change=='native_config':s.state('behavior_settings',{'enabled':False})
  else:cfg['model_enabled']=False
  return row
 monkeypatch.setattr(Store,'describe',changed);assert indexing.index_packet(b,s,ADDRESS,cfg,revision=revision,at=AT)==(None,[])
 with b.connect() as db:assert db.execute('SELECT count(*) FROM packets').fetchone()[0]==0 and db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==0
 assert handoff.ready(b)

def test_native_preparation_does_not_hold_derived_writer(tmp_path,monkeypatch):
 s,b=fixture(tmp_path,3);handoff.deliver(b,at=AT);revision=handoff.ready(b)[ADDRESS];describe=Store.describe;checks=[]
 def probe(reader,address):
  with sqlite3.connect(b.path,timeout=.025) as db:db.execute('BEGIN IMMEDIATE');db.rollback();checks.append(True)
  return describe(reader,address)
 monkeypatch.setattr(Store,'describe',probe);cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':False}
 assert indexing.index_packet(b,s,ADDRESS,cfg,revision=revision,at=AT)[0] and checks==[True]


def test_after_commit_native_ack_busy_replay_preserves_ledger(tmp_path,monkeypatch):
 s,b=fixture(tmp_path,35);original=s.connect;calls=[0];holders=[];short_connections(monkeypatch)
 @contextlib.contextmanager
 def connect(*a,**kw):
  calls[0]+=1
  if calls[0]==2:holders.append(Holder(s.path,['BEGIN IMMEDIATE']))
  with original(*a,**kw) as db:yield db
 monkeypatch.setattr(s,'connect',connect)
 try:result=handoff.deliver(b,at=AT)
 finally:
  for holder in holders:holder.close()
 assert result['status']=='busy_retry_next_pass' and result['applied']==16 and result['acknowledged']==0
 assert not any(r[-1] for r in counts(s))
 monkeypatch.setattr(s,'connect',original);result=handoff.deliver(b,at=AT)
 assert result['applied']==19 and result['acknowledged']==35
 with b.connect() as db:assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==35


def test_cancel_later_chunk_rolls_back_only_that_chunk(tmp_path,monkeypatch):
 s,b=fixture(tmp_path,35);original=history.save_events;calls=[0];stop=threading.Event()
 def cancelling(*a,**kw):
  calls[0]+=1;original(*a,**kw)
  if calls[0]==18:stop.set()
 monkeypatch.setattr(history,'save_events',cancelling);result=handoff.deliver(b,at=AT,should_stop=stop.is_set)
 assert result['status']=='cancelled' and result['applied']==result['read']==result['acknowledged']==16
 with b.connect() as db:assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==16
 monkeypatch.setattr(history,'save_events',original);assert handoff.deliver(b,at=AT)['applied']==19


def test_first_receipt_select_is_already_serialized(tmp_path,monkeypatch):
 s,b=fixture(tmp_path,0);old=proven()[-1:];new=proven(count=2,at=AT+dt.timedelta(minutes=1))[-1:]
 history.save(b,ADDRESS,'tpot','Cowrie',old,AT.isoformat());original=sqlite3.connect;attempts=[]
 class Interleaved(sqlite3.Connection):
  def execute(self,sql,*a,**kw):
   result=super().execute(sql,*a,**kw)
   if str(sql).upper().startswith('SELECT CONTENT,CHECKED_AT FROM SOURCE_BINDING_RECEIPTS') and not attempts:
    assert self.in_transaction
    with contextlib.closing(original(b.path,timeout=.025)) as rival:
     try:rival.execute('BEGIN IMMEDIATE')
     except sqlite3.OperationalError as exc:attempts.append(exc.sqlite_errorcode)
     else:pytest.fail('Receipt SELECT left a competing writer free to overwrite')
   return result
 def connect(*a,**kw):kw['factory']=Interleaved;return original(*a,**kw)
 monkeypatch.setattr(sqlite3,'connect',connect);history.save(b,ADDRESS,'tpot','Cowrie',old,(AT+dt.timedelta(minutes=2)).isoformat())
 assert attempts==[sqlite3.SQLITE_BUSY]
 history.save(b,ADDRESS,'tpot','Cowrie',new,(AT+dt.timedelta(minutes=1)).isoformat());history.save(b,ADDRESS,'tpot','Cowrie',old,(AT+dt.timedelta(minutes=3)).isoformat())
 with b.connect() as db:
  receipt=db.execute('SELECT content FROM source_binding_receipts').fetchone();assert json.loads(receipt[0])['source_observation']['connection_count']==2
  assert db.execute('SELECT count(*) FROM source_binding_audit').fetchone()[0]>0


def test_scheduled_owner_reports_partial_maintenance_and_resumes(w,tmp_path,monkeypatch):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);monkeypatch.setattr(w,'collect',lambda *a,**kw:0)
 old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=367)).isoformat()
 with s.connect() as db:db.executemany('INSERT INTO ip_observations VALUES(?,?)',[('11.0.'+str(i//250)+'.'+str(i%250+1),old) for i in range(5003)])
 w.main();first=s.state('ingest_status');assert first['status']=='ok' and first['maintenance']['arrivals']=={'deleted':5000,'partial':True,'bound':5000}
 w.main();last=s.state('ingest_status');assert last['maintenance']['arrivals']=={'deleted':3,'partial':False,'bound':5000}


def test_native_context_preparation_uses_same_snapshot_as_description(tmp_path,monkeypatch):
 s,b=rich_fixture(tmp_path);handoff.deliver(b,at=AT);revision=handoff.ready(b)[ADDRESS];describe=Store.describe
 def changing(reader,address):
  result=describe(reader,address)
  s.cache(ADDRESS,'misp',{'matches':0,'attribute_ids':[],'snapshot_generation':'newer-native'})
  return result
 monkeypatch.setattr(Store,'describe',changing)
 ident,_=indexing.index_packet(b,s,ADDRESS,{**DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':True},revision=revision,at=AT)
 with b.connect() as db:packet=json.loads(db.execute('SELECT content FROM packets WHERE id=?',(ident,)).fetchone()[0])
 misp=next(v for v in packet['context'] if v.get('provider')=='misp');assert misp['snapshot_generation']=='frozen-fixture' and misp['indicators']
 assert json.loads(s.cached(ADDRESS,'misp')['payload'])['snapshot_generation']=='newer-native'


def rich_fixture(path,count=192):
 s=Store(path/'native');b=Brain(s);events=values(count)
 for i,event in enumerate(events):event['path']=('/owa/auth.owa','/wordpress/wp-admin.php')[i%2]
 s.source_activity(ADDRESS,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':events}})
 for data in (proven(),proven(count=2,at=AT+dt.timedelta(minutes=1))):s.source_activity(ADDRESS,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':data}})
 expires=(AT+dt.timedelta(days=1)).isoformat();attributes=[{'id':str(i),'event_id':'fixture-event','source':'Redacted fixture feed','to_ids':True,'timestamp':int(AT.timestamp())} for i in range(1500)]
 s.state('misp_snapshot',{'generation':'frozen-fixture','expires':expires,'attributes':attributes})
 s.cache(ADDRESS,'misp',{'matches':1,'attribute_ids':['101'],'sources':['Redacted fixture feed'],'snapshot_generation':'frozen-fixture','fresh_to_ids_and_warninglists_enforced':True})
 with s.connect() as db:db.execute('UPDATE cache SET fetched=?,expires=?',(AT.isoformat(),expires))
 # Same uncommon paths create an actual persisted correlation candidate.
 from test_behavior_correlation import packet
 packet(b,'frozen-peer','1.1.1.1',['/owa/auth.owa','/wordpress/wp-admin.php'])
 return s,b


def test_frozen_packet_matches_prior_atomic_path_with_misp_and_correlation(tmp_path,monkeypatch):
 results=[]
 class Frozen(dt.datetime):
  @classmethod
  def now(cls,tz=None):return AT
 monkeypatch.setattr(dt,'datetime',Frozen)
 for mode in ('prior','prepared','old_loaded_brain'):
  s,b=rich_fixture(tmp_path/mode);handoff.deliver(b,at=AT);revision=handoff.ready(b)[ADDRESS]
  cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':True}
  if mode=='old_loaded_brain':
   original=Brain.packet;b.prepared_native_context=False
   monkeypatch.setattr(Brain,'packet',lambda self,row,cfg=None,at=None,source_cfg=None:original(self,row,cfg,at,source_cfg))
  target=prior_index_packet if mode=='prior' else indexing.index_packet
  ident,candidates=target(b,s,ADDRESS,cfg,revision=revision)
  assert ident and candidates and not handoff.ready(b)
  with b.connect() as db:
   packet=json.loads(db.execute('SELECT content FROM packets WHERE id=?',(ident,)).fetchone()[0]);misp=next(v for v in packet['context'] if v.get('provider')=='misp');assert misp['indicators'] and misp['snapshot_current']
   tables=('packets','current_packets','analysis_queue','correlation_features','correlation_ready','links','intelligence_alerts','event_history','source_binding_receipts','source_binding_audit','source_sample_ready')
   results.append({t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY rowid')] for t in tables})
   assert results[-1]['source_binding_audit']
 assert results[0]==results[1]==results[2]


# Frozen pre-repair owner from Private9bfa34f / Community23565a3.
def prior_index_packet(brain,store,address,cfg,source_cfg=None,revision=None,should_stop=None):
 """One bounded derived commit; native access remains strictly read-only."""
 from core import now
 stopped=should_stop or (lambda:False)
 # Copies bind existing methods to these transaction-local handles. Never
 # replace a connection on the Store/Brain shared by another worker thread.
 local=copy.copy(brain);reader=copy.copy(store);local.store=reader
 try:
  with contextlib.closing(sqlite3.connect(pathlib.Path(store.path).resolve().as_uri()+'?mode=ro',uri=True,timeout=30)) as native,brain.connect() as db:
   native.row_factory=sqlite3.Row;native.execute('PRAGMA query_only=ON')
   reader.connect=lambda *a,**kw:contextlib.nullcontext(native)
   local.connect=lambda:contextlib.nullcontext(db)
   db.execute('BEGIN IMMEDIATE')
   if stopped():raise indexing.Cancelled
   if revision is not None:
    from evidence_history import collection_scope
    current=db.execute('SELECT revision FROM source_sample_ready WHERE ip=? AND scope=?',(address,collection_scope(local,source_cfg))).fetchone()
    if current is None or current['revision']!=revision:return None,[]
   detailed=reader.describe(address)
   ident,packet,features=local.packet(detailed,cfg,source_cfg=source_cfg)
   candidates=local.candidates(ident,features) if cfg['correlation_enabled'] else []
   if cfg['correlation_enabled']:
    from behavior_intelligence import inspect,load_catalog
    inspect(local,ident,candidates,load_catalog(pathlib.Path(store.path).parent/'behavior-references.json'))
   if cfg['model_enabled'] and packet['events']:
    db.execute('INSERT INTO analysis_queue SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM analysis_queue WHERE ip=?) OR (SELECT count(*) FROM analysis_queue)<10000 ON CONFLICT(ip) DO UPDATE SET packet_id=excluded.packet_id',(address,ident,now(),address))
   if revision is not None:
    from source_handoff import indexed
    indexed(local,address,revision,source_cfg)
   if stopped():raise indexing.Cancelled
   assert native.total_changes==0
 finally:
  # The existing 60-second snapshot cache survives per-packet handle reuse.
  for name in ('_behavior_misp_snapshot','_behavior_misp_snapshot_at','_behavior_misp_lookup'):
   if hasattr(reader,name):setattr(store,name,getattr(reader,name))
 return ident,candidates
