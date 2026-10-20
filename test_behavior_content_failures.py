"""Isolated rejection/outage lifecycle tests; no real provider calls."""
from test_pipeline_mock import stage_mock
import json,time
import pytest
from behavior_ai import drain_queue,model_job,ModelOutputError,digest
from behavior_grounding import example
from test_behavior_drain import queue


@pytest.mark.parametrize('code',['invalid_assessment','output_limit'])
def test_rejected_content_continues_unrelated_work_and_caches_same_packet(tmp_path,monkeypatch,code):
 s,b,cfg=queue(tmp_path,4);calls=[]
 def infer(cfg,p,*args):
  calls.append(p['packet_id'])
  if len(calls)==1:raise ModelOutputError(code,{'validation_diagnostic':{'stage':'generation_choices','reason':'validation_rejected'}})
  return example(p),{}
 stage_mock(monkeypatch,'behavior_ai.infer',infer)
 results,examined,reason=drain_queue(b,s,cfg)
 assert results=={'failed':1,'completed':3} and examined==4 and reason=='idle'
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==0
  assert db.execute('SELECT requests FROM usage').fetchone()[0]==8
  failed=db.execute("SELECT * FROM assessments WHERE status='failed'").fetchone()
  assert failed['error']==code and json.loads(failed['result'])['metadata']['validation_diagnostic']['stage']=='generation_choices'
  p=json.loads(db.execute('SELECT content FROM packets WHERE id=?',(calls[0],)).fetchone()[0])
 assert model_job(b,calls[0],p,set(),cfg)=='persistence_review_required'
 assert len(calls)==4


@pytest.mark.parametrize('failure',[TimeoutError(),ConnectionError(),ValueError('HTTP rejected'),ModelOutputError('incomplete_response',{})])
def test_transport_and_provider_failures_keep_global_backoff(tmp_path,monkeypatch,failure):
 s,b,cfg=queue(tmp_path,3);calls=[]
 def infer(*args):calls.append(1);raise failure
 stage_mock(monkeypatch,'behavior_ai.infer',infer)
 results,_,reason=drain_queue(b,s,cfg)
 assert reason=='backoff' and results=={'failed':1,'backoff':1} and len(calls)==1
 with b.connect() as db:
  guard=json.loads(db.execute("SELECT value FROM retention_state WHERE name LIKE 'provider_backoff:%'").fetchone()[0])
  assert guard['failures']==1 and guard['until']>time.time()
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==2


def test_content_rejection_preserves_existing_guard_bytes_and_retry_exhaustion(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,1)
 key='provider_backoff:'+digest([cfg['endpoint'],cfg['model']]);saved=json.dumps({'failures':4,'until':0},indent=2)
 with b.connect() as db:
  db.execute('INSERT INTO retention_state VALUES(?,?)',(key,saved))
  p=json.loads(db.execute('SELECT content FROM packets').fetchone()[0])
 calls=[]
 def infer(*args):calls.append(1);raise ModelOutputError('invalid_assessment',{})
 stage_mock(monkeypatch,'behavior_ai.infer',infer)
 assert model_job(b,'packet0',p,set(),cfg)=='failed'
 with b.connect() as db:
  assert db.execute('SELECT value FROM retention_state WHERE name=?',(key,)).fetchone()[0]==saved
  db.execute("UPDATE assessments SET expires='2000-01-01T00:00:00+00:00'")
 assert model_job(b,'packet0',p,set(),cfg)=='persistence_review_required' and len(calls)==1


def test_existing_active_global_backoff_is_not_cleared_or_bypassed(tmp_path,monkeypatch):
 s,b,cfg=queue(tmp_path,2);saved=json.dumps({'failures':3,'until':time.time()+600})
 key='provider_backoff:'+digest([cfg['endpoint'],cfg['model']])
 with b.connect() as db:db.execute('INSERT INTO retention_state VALUES(?,?)',(key,saved))
 stage_mock(monkeypatch,'behavior_ai.infer',lambda *a:pytest.fail('Active guard bypassed'))
 assert drain_queue(b,s,cfg)[2]=='backoff'
 with b.connect() as db:
  assert db.execute('SELECT value FROM retention_state WHERE name=?',(key,)).fetchone()[0]==saved
  assert db.execute('SELECT count(*) FROM usage').fetchone()[0]==0


def test_real_rejection_then_valid_response_survives_busy_receipts_and_restart(tmp_path,monkeypatch):
 import sqlite3
 import analytics_store as ledger
 import behavior_ai as ai
 from behavior_generation import example as wire_example
 from behavior_telemetry import recover
 s,b,cfg=queue(tmp_path,2);real_infer=ai.infer;calls=[]
 with ledger.connect(s,True):pass
 lock=sqlite3.connect(ledger.path(s));lock.execute('BEGIN IMMEDIATE')
 def infer(cfg,p,candidates,allowed,key,requester,attempt):
  p={**p,'coverage':'saved_samples'};wire=wire_example(p);calls.append(p['packet_id'])
  if len(calls)==1:wire['packet_id']='foreign'
  class Response:
   status_code=200
   def close(self):pass
   def iter_content(self,n):yield json.dumps({'model':cfg['model'],'done':True,'message':{'content':json.dumps(wire)},'prompt_eval_count':11,'eval_count':7}).encode()
  return real_infer(cfg,p,candidates,allowed,key,lambda *a,**kw:Response(),attempt)
 stage_mock(monkeypatch,ai,infer)
 try:
  results,_,reason=drain_queue(b,s,cfg)
  assert results=={'failed':1,'completed':1} and reason=='idle' and len(calls)==2
  with b.connect() as db:
   receipts=[stage for r in db.execute('SELECT result FROM assessments ORDER BY rowid') for stage in json.loads(r[0])['metadata']['generation_stages']]
   assert all(r['request_started_at'] and r['request_finished_at'] for r in receipts)
 finally:lock.rollback();lock.close()
 assert recover(ai.Brain(s))['recovered']==4
 with ledger.connect(s) as db:
  rows=list(db.execute('SELECT * FROM requests ORDER BY rowid'))
  assert [r['state'] for r in rows]==['accepted','rejected','accepted','accepted']
  for row,meta in zip(rows,receipts):
   assert row['started']==meta['request_started_at'] and row['finished']==meta['request_finished_at']
   assert row['id']==meta['request_id'] and (row['input_tokens'],row['output_tokens']) in ((10,2),(11,7))
