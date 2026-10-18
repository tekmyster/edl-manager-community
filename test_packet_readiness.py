"""Isolated readiness/concurrency mechanics; no provider or quality evidence."""
import datetime as dt
import json
import sqlite3
import threading
import time
import pytest
from core import Store
from behavior_ai import Brain
from source_handoff import deliver,ready
import packet_indexing as indexing
from test_binding_receipts import proven
from test_source_observation_cache import AT


def fixture(tmp_path,count=1,source_cfg=None):
 s=Store(tmp_path/'native');b=Brain(s)
 s.state('behavior_settings',{'enabled':True,'model_enabled':False,'correlation_enabled':False})
 addresses=('8.8.8.8',)+tuple('11.0.'+str(i//250)+'.'+str(i%250+1) for i in range(1,count))
 if source_cfg is not None:
  from source_settings import effective
  source_cfg=effective(s,source_cfg)
 for address in addresses:
  s.evidence(address,'tpot','Cowrie',AT.isoformat(),'ssh',50,'',{})
  s.source_activity(address,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':proven()},'native_event_count':17,'native_attempt_count':3},source_cfg=source_cfg)
 while deliver(b)['read']:pass
 s._behavior_index_addresses=addresses;s._behavior_index_lock=threading.RLock()
 return s,b,addresses


def test_ready_drain_exceeds_model_batch_and_page_without_model_calls(tmp_path):
 s,b,addresses=fixture(tmp_path,205);stop=threading.Event();done=threading.Event();done.set()
 indexing.consume(s,None,stop,done)
 assert not ready(b) and not stop.is_set()
 assert s._packet_index_status['totals']['indexed']==205
 assert s._packet_index_status['totals']['pages']==3
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM current_packets').fetchone()[0]==205
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==0


def test_arriving_revision_survives_ack_and_old_packet_is_immutable(tmp_path,monkeypatch):
 s,b,addresses=fixture(tmp_path);address=addresses[0];original=indexing.index_packet;packets=[]
 def arriving(*a,**kw):
  result=original(*a,**kw)
  with b.connect() as db:packets.extend([tuple(r) for r in db.execute('SELECT * FROM packets')])
  s.source_activity(address,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':proven(at=AT+dt.timedelta(minutes=1))}})
  deliver(b);return result
 monkeypatch.setattr(indexing,'index_packet',arriving)
 assert indexing.page(b,s,None)['indexed']==1 and address in ready(b)
 monkeypatch.setattr(indexing,'index_packet',original)
 assert indexing.page(b,s,None)['indexed']==1 and address not in ready(b)
 with b.connect() as db:
  for r in packets:assert tuple(db.execute('SELECT * FROM packets WHERE id=?',(r[0],)).fetchone())==r


def test_restart_after_packet_commit_before_ack_and_cancel(tmp_path,monkeypatch):
 import source_handoff
 s,b,addresses=fixture(tmp_path);original=source_handoff.indexed
 def interrupted(*a,**kw):raise RuntimeError('isolated interruption after packet commit')
 monkeypatch.setattr(source_handoff,'indexed',interrupted)
 with pytest.raises(RuntimeError):indexing.page(b,s,None)
 with b.connect() as db:before=[tuple(r) for r in db.execute('SELECT * FROM packets')]
 assert addresses[0] in ready(b)
 monkeypatch.setattr(source_handoff,'indexed',original)
 assert indexing.page(b,s,None,lambda:True)['status']=='cancelled'
 assert addresses[0] in ready(b)
 restarted=Store(s.path);restarted._behavior_index_addresses=addresses
 assert indexing.page(Brain(restarted),restarted,None)['indexed']==1
 assert not ready(b)
 with b.connect() as db:
  for r in before:assert tuple(db.execute('SELECT * FROM packets WHERE id=?',(r[0],)).fetchone())==r


def test_readiness_runs_while_existing_worker_serial_work_waits(tmp_path,monkeypatch):
 pytest.importorskip('fcntl');import behavior_worker
 cfg={'database':str(tmp_path/'native'),'index_url':'https://index.invalid','source_agents':{'tpot':'collector'}}
 s,b,addresses=fixture(tmp_path,30,source_cfg=cfg);config=tmp_path/'config.json';config.write_text(json.dumps(cfg))
 assert len(ready(b,cfg))==30
 monkeypatch.setenv('EDL_CONFIG',str(config));monkeypatch.setattr('sys.argv',['behavior_worker.py'])
 def waiting(store,**kw):
  store._behavior_index_addresses=addresses
  until=time.monotonic()+20
  while ready(b,cfg) and time.monotonic()<until:time.sleep(.02)
  assert not ready(b,cfg);return {'status':'simulated_serial_model_work_no_request'}
 monkeypatch.setattr(behavior_worker,'run',waiting);behavior_worker.main()
 with b.connect() as db:assert db.execute('SELECT count(*) FROM current_packets').fetchone()[0]==30
 assert not any(t.name in ('packet-readiness','source-sample-delivery') for t in threading.enumerate())


def test_configured_scope_and_native_eligibility_are_preserved(tmp_path):
 s,b,addresses=fixture(tmp_path)
 s._behavior_index_addresses=('9.9.9.9',)
 assert indexing.page(b,s,None)['status']=='idle' and addresses[0] in ready(b)
 s._behavior_index_addresses=addresses
 assert indexing.page(b,s,{'index_url':'https://different.invalid','source_agents':{'tpot':'other'}})['status']=='idle'
 assert addresses[0] in ready(b)
