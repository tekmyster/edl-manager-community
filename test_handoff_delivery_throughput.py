"""Offline persistence/concurrency load fixtures; no activity labels or requests."""
import contextlib,copy,datetime as dt,hashlib,json,sqlite3,threading,time
import pytest
import source_handoff as handoff
from core import Store
from behavior_ai import Brain
from evidence_history import normalize
from test_source_handoff import ingest,counts
from test_binding_receipts import proven
from test_source_observation_cache import AT,ADDRESS,history

def load(store,start,count):
 values=[{'id':'isolated-load-'+str(i),'seen':AT.isoformat(),'action':'HTTP request','path':'/'} for i in range(start,start+count)]
 for i in range(0,len(values),500):ingest(store,values[i:i+500])

def enabled(store):store.state('behavior_settings',{'enabled':True,'model_enabled':False})

def test_capture_status_alias_preserves_actual_first_body_and_receipt(tmp_path):
 s=Store(tmp_path/'native');values=proven();ingest(s,values);before=counts(s)
 other=copy.deepcopy(values)
 for value in other:value['source_observation']['lookup_status']='not_selected'
 ingest(s,other);assert counts(s)==before
 with s.connect() as db:
  assert all(json.loads(r[0])['source_observation']['lookup_status']=='complete' for r in db.execute('SELECT content FROM source_sample_handoff'))
 assert all(v['source_observation']['lookup_status']=='not_selected' for v in other)

def test_old_pending_status_aliases_ack_without_double_merge_or_new_revision(tmp_path):
 s=Store(tmp_path/'native');b=Brain(s);values=proven();values.append(copy.deepcopy(values[-1]));values[-1]['source_observation']['lookup_status']='not_selected'
 with s.connect() as db:
  for i,value in enumerate(values):
   e=normalize(ADDRESS,'tpot','Cowrie',value,AT.isoformat());raw=json.dumps(e,sort_keys=True,separators=(',',':'));ident=hashlib.sha256(json.dumps([ADDRESS,'',e],sort_keys=True,separators=(',',':')).encode()).hexdigest()
   db.execute('INSERT INTO source_sample_handoff(id,ip,source,sensor,scope,seen,received,content) VALUES(?,?,?,?,?,?,?,?)',(ident,ADDRESS,'tpot','Cowrie','',e['seen'],(AT+dt.timedelta(seconds=i)).isoformat(),raw))
  originals=[tuple(r) for r in db.execute('SELECT id,received,content FROM source_sample_handoff ORDER BY revision')]
 result=handoff.deliver(b);assert result['read']==result['applied']==4 and result['merged']==3 and result['equivalent']==1
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM source_sample_applied').fetchone()[0]==4
  assert db.execute('SELECT count(*) FROM source_sample_equivalence').fetchone()[0]==3
  assert db.execute('SELECT revision FROM source_sample_ready').fetchone()[0]==3
 with s.connect() as db:assert [tuple(r) for r in db.execute('SELECT id,received,content FROM source_sample_handoff ORDER BY revision')]==originals
 ingest(s,values);assert len(counts(s))==4
 assert handoff.deliver(Brain(Store(s.path)))['applied']==0

@pytest.mark.parametrize('change',['checked','window','count0','count2','record_sha','scope','target','partial','error','no_proof'])
def test_equivalence_retains_real_changes_and_uncertainty(change):
 from source_observations import proof_scope
 a=normalize(ADDRESS,'tpot','Cowrie',proven()[-1],AT.isoformat());b=copy.deepcopy(a);collection=''
 o=b['source_observation'];p=o['binding_proof']
 if change=='checked':p['checked_at']=(AT+dt.timedelta(minutes=1)).isoformat()
 if change=='window':
  p['window_start']=(AT-dt.timedelta(days=30,minutes=1)).isoformat();p['window_end']=(AT-dt.timedelta(minutes=1)).isoformat();p['scope_ref']=proof_scope(o,p['window_start'],p['window_end'])
 if change.startswith('count'):
  count=int(change[-1]);p.update(connection_count=count,connection_id=None,connection_sha256=None);o.update(connection_count=count);o.pop('connection_id',None)
 if change=='record_sha':p['record_sha256']='f'*64
 if change=='scope':collection='different-configured-scope'
 if change=='target':b['destination']={'scope':'internal','asset_id':'different_asset'}
 if change in ('partial','error'):o['lookup_status']=change
 if change=='no_proof':o.pop('binding_proof')
 assert handoff.identity(ADDRESS,'',a)[0]!=handoff.identity(ADDRESS,collection,b)[0]
 # Nonunique reports stay distinct even for current-selection status changes.
 if change.startswith('count'):
  c=copy.deepcopy(b);c['source_observation']['lookup_status']='not_selected'
  assert handoff.identity(ADDRESS,'',c)[0]!=handoff.identity(ADDRESS,'',b)[0]

def test_cancelled_batch_rolls_back_history_semantic_ledger_and_ready(tmp_path,monkeypatch):
 import evidence_history
 s=Store(tmp_path/'native');b=Brain(s);ingest(s,proven());stop=threading.Event();save=evidence_history.save_events
 def interrupted(*a,**kw):save(*a,**kw);stop.set()
 monkeypatch.setattr(evidence_history,'save_events',interrupted)
 assert handoff.deliver(b,should_stop=stop.is_set)['status']=='cancelled'
 with b.connect() as db:
  for t in ('event_history','source_binding_receipts','source_sample_applied','source_sample_equivalence','source_sample_ready'):assert db.execute('SELECT count(*) FROM '+t).fetchone()[0]==0
 assert all(not r[-1] for r in counts(s))
 monkeypatch.setattr(evidence_history,'save_events',save);stop.clear()
 assert handoff.deliver(b)['applied']==len(proven())

def test_successive_batches_with_continuing_arrivals_have_no_cycle_quota(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');enabled(s);load(s,0,1500);stop=threading.Event();finished=threading.Event();finished.set();deliver=handoff.deliver;calls=0
 def arriving(*a,**kw):
  nonlocal calls
  r=deliver(*a,**kw);calls+=1
  if calls<=3:load(s,1500+(calls-1)*10,10)
  return r
 monkeypatch.setattr(handoff,'deliver',arriving)
 handoff.consume(s,stop,finished)
 assert all(r[-1] for r in counts(s)) and len(counts(s))==1530
 assert s._source_handoff_status['totals']['transactions']>=4
 assert s._source_handoff_status['totals']['applied']==1530

def test_native_writes_continue_during_derived_outage_then_restart_drains(tmp_path):
 s=Store(tmp_path/'native');enabled(s);b=Brain(s);load(s,0,20);lock=sqlite3.connect(b.path);lock.execute('BEGIN IMMEDIATE');stop=threading.Event();thread=threading.Thread(target=handoff.consume,args=(s,stop));thread.start()
 try:
  deadline=time.monotonic()+5
  while not hasattr(s,'_source_handoff_status') and time.monotonic()<deadline:time.sleep(.01)
  load(s,20,20);assert len(counts(s))==40 and all(not r[-1] for r in counts(s))
 finally:stop.set();thread.join(5);lock.rollback();lock.close()
 assert not thread.is_alive()
 finished=threading.Event();finished.set();handoff.consume(Store(s.path),threading.Event(),finished)
 assert all(r[-1] for r in counts(s))

def test_unexpected_delivery_failure_signals_stop_without_ack(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');enabled(s);load(s,0,2);stop=threading.Event()
 def fail(*a,**kw):raise ValueError('isolated fault')
 monkeypatch.setattr(handoff,'deliver',fail);handoff.consume(s,stop)
 assert stop.is_set() and s._source_handoff_status=={'status':'failed','error':'ValueError'}
 assert all(not r[-1] for r in counts(s))

def test_existing_behavior_process_delivers_while_serial_work_waits_and_finishes(tmp_path,monkeypatch):
 pytest.importorskip('fcntl');import behavior_worker
 s=Store(tmp_path/'native');enabled(s);load(s,0,1500);cfg=tmp_path/'config.json';cfg.write_text(json.dumps({'database':s.path}));monkeypatch.setenv('EDL_CONFIG',str(cfg));monkeypatch.setattr('sys.argv',['behavior_worker.py']);observed={}
 def serial_wait(store,**kw):
  assert store._source_handoff_background
  deadline=time.monotonic()+15
  while time.monotonic()<deadline:
   done=sum(r[-1] for r in counts(store))
   if done>=500:observed['during_serial_wait']=done;break
   time.sleep(.01)
  assert observed.get('during_serial_wait',0)>=500
  return {'status':'isolated_serial_work_no_model_request'}
 monkeypatch.setattr(behavior_worker,'run',serial_wait)
 behavior_worker.main()
 assert all(r[-1] for r in counts(s))
 assert not any(t.name=='source-sample-delivery' for t in threading.enumerate())
