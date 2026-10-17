"""Queue lifecycle mechanics with mock inference, never production traffic."""
import datetime as dt,json,sys,signal,os
import pytest
from core import Store,now
from behavior_ai import Brain,DEFAULTS,drain_queue,model_job,run
from behavior_grounding import example
from behavior_scheduling import schedule

def queue(tmp_path,count):
 s=Store(tmp_path/'native');b=Brain(s);cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':False,'daily_budget':None,'model':'synthetic','endpoint':'https://127.0.0.1'};s.state('behavior_settings',cfg)
 with b.connect() as db:
  for i in range(count):
   ident='packet'+str(i);address='8.8.'+str(i//250)+'.'+str(i%250+1);p={'packet_id':ident,'events':[{'id':'e'+str(i),'seen':now(),'source':'synthetic','sensor':'fixture','action':'HTTP request','method':'GET','path':'/example'}]}
   db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,address,now(),json.dumps(p),'[]',0))
   db.execute('INSERT INTO current_packets VALUES(?,?)',(address,ident))
   db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',(address,ident,'2026-01-01T00:00:00+00:00'))
 return s,b,cfg

def test_unlimited_drains_beyond_scheduler_pages_without_sleep(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,250);calls=[]
 def job(brain,ident,*args,**kw):calls.append(ident);return 'completed'
 monkeypatch.setattr('behavior_ai.model_job',job)
 monkeypatch.setattr('behavior_ai.time.sleep',lambda *_:pytest.fail('Unlimited work was paced'))
 results,examined,reason=drain_queue(b,s,cfg)
 assert results=={'completed':250} and examined==250 and reason=='idle' and len(set(calls))==250
 with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==0

def test_leased_prefix_does_not_hide_later_work_or_spin(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,180);calls=[]
 def job(brain,ident,*args,**kw):calls.append(ident);return 'leased_or_exhausted' if int(ident[6:])<145 else 'completed'
 monkeypatch.setattr('behavior_ai.model_job',job)
 results,examined,reason=drain_queue(b,s,cfg)
 assert results=={'leased_or_exhausted':145,'completed':35} and reason=='idle'
 assert examined==180 and len(set(calls))==len(calls)==180
 with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==145

def test_new_window_of_skipped_ip_is_not_excluded(tmp_path):
 s,b,cfg=queue(tmp_path,1)
 with b.connect() as db:
  address=db.execute('SELECT ip FROM analysis_queue').fetchone()[0]
  row=db.execute("SELECT * FROM packets WHERE id='packet0'").fetchone();values=list(row);values[0]='new-window';db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',values)
  db.execute('UPDATE current_packets SET packet_id=? WHERE ip=?',('new-window',address))
  rows=schedule(db,excluded={(address,'packet0')})
 assert len(rows)==1 and rows[0]['packet_id']=='new-window'

def test_cancellation_between_requests_preserves_unclaimed_queue(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,5);calls=[]
 def infer(cfg,p,*args):calls.append(p['packet_id']);return example(p),{}
 monkeypatch.setattr('behavior_ai.infer',infer)
 results,examined,reason=drain_queue(b,s,cfg,should_stop=lambda:len(calls)>=3)
 assert reason=='cancelled' and results=={'completed':3}
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==2
  assert db.execute('SELECT requests FROM usage').fetchone()[0]==3
  assert db.execute("SELECT count(*) FROM jobs WHERE state='running'").fetchone()[0]==0

def test_cancellation_before_claim_does_not_consume_usage_or_lease(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1)
 with b.connect() as db:p=json.loads(db.execute('SELECT content FROM packets').fetchone()[0])
 monkeypatch.setattr('behavior_ai.infer',lambda *a:pytest.fail('Cancelled job dispatched'))
 assert model_job(b,'packet0',p,set(),cfg,should_stop=lambda:True)=='cancelled'
 assert run(s,should_stop=lambda:True)=={'status':'cancelled'}
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM usage').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM jobs').fetchone()[0]==0

def test_stop_on_real_provider_failure_backoff_not_request_quota(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,5)
 def fail(*args):raise TimeoutError('synthetic')
 monkeypatch.setattr('behavior_ai.infer',fail)
 results,examined,reason=drain_queue(b,s,cfg)
 assert reason=='backoff' and results=={'failed':1,'backoff':1}
 with b.connect() as db:
  assert db.execute('SELECT requests FROM usage').fetchone()[0]==1
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==4

def test_disabling_inspection_is_observed_before_next_request(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,5)
 def infer(cfg,p,*args):s.state('behavior_settings',{**cfg,'model_enabled':False});return example(p),{}
 monkeypatch.setattr('behavior_ai.infer',infer)
 assert drain_queue(b,s,cfg)[2]=='disabled'
 with b.connect() as db:assert db.execute('SELECT requests FROM usage').fetchone()[0]==1

def test_changing_to_finite_mode_honors_consumed_count(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,5);calls=[]
 def infer(cfg,p,*args):
  calls.append(1)
  if len(calls)==2:s.state('behavior_settings',{**cfg,'daily_budget':24})
  return example(p),{}
 monkeypatch.setattr('behavior_ai.infer',infer)
 assert drain_queue(b,s,cfg)[2]=='finite_cycle_limit' and len(calls)==2

def test_periodic_indexing_interleaves_without_draining_request_cap(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,7);clock=[0];refresh=[]
 def tick():clock[0]+=61;return clock[0]
 monkeypatch.setattr('behavior_ai.time.monotonic',tick)
 monkeypatch.setattr('behavior_ai.model_job',lambda *a,**kw:'completed')
 results,_,reason=drain_queue(b,s,cfg,refresh_index=lambda:refresh.append(1))
 assert results=={'completed':7} and reason=='idle' and len(refresh)>1

def test_lost_owner_cannot_publish_result_or_clear_successor_lease(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1)
 with b.connect() as db:p=json.loads(db.execute('SELECT content FROM packets').fetchone()[0])
 def infer(cfg,p,*args):
  with b.connect() as db:db.execute("UPDATE jobs SET id='successor-owner',lease=9999999999")
  return example(p),{}
 monkeypatch.setattr('behavior_ai.infer',infer)
 assert model_job(b,'packet0',p,set(),cfg)=='lease_lost'
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0
  row=db.execute('SELECT id,state,lease FROM jobs').fetchone();assert tuple(row)==('successor-owner','running',9999999999)
  assert db.execute('SELECT requests FROM usage').fetchone()[0]==1

@pytest.mark.skipif(os.name!='posix',reason='Native worker uses Linux flock')
def test_worker_signal_is_cooperative_and_handlers_restored(tmp_path,monkeypatch):
 import behavior_worker
 cfg=tmp_path/'cfg.json';cfg.write_text(json.dumps({'database':str(tmp_path/'native')}));monkeypatch.setenv('EDL_CONFIG',str(cfg));monkeypatch.setattr(sys,'argv',['behavior_worker.py','--continuous']);calls=[];previous=signal.getsignal(signal.SIGTERM)
 def work(store,**kwargs):
  assert not kwargs['should_stop']();signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None);assert kwargs['should_stop']();calls.append(1);return {'status':'cancelled'}
 monkeypatch.setattr(behavior_worker,'run',work);behavior_worker.main()
 assert calls==[1] and signal.getsignal(signal.SIGTERM)==previous
