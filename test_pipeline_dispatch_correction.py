"""Offline post-entry dispatch/disable regressions and authenticated UTF-8 states."""
import json,threading
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline_job import run
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.mark.parametrize('stage',[1,2])
@pytest.mark.parametrize('change',['config','source','packet','receipt','lease','quota','day','cancel','master','model'])
def test_after_entry_change_prevents_post_and_keeps_claim(tmp_path,monkeypatch,stage,change):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());clock=['2026-10-17T10:01:00+00:00'];monkeypatch.setattr(ai,'now',lambda:clock[0])
 s,b,cfg,p=setup(tmp_path/'native-test.sqlite3',budget=3);calls=[];stop=threading.Event()
 if change=='quota':
  with b.connect() as db:db.execute('INSERT INTO usage VALUES(?,1)',(ai.now()[:10],))
 def hook(phase):
  if phase!='after_entry'+str(stage):return
  if change in ('config','quota','master','model'):
   key,value={'config':('model','changed'),'quota':('daily_budget',stage-1 or 1),'master':('enabled',False),'model':('model_enabled',False)}[change];s.state('behavior_settings',{**cfg,key:value})
  elif change=='source':monkeypatch.setattr('behavior_pipeline_job.source_identity',lambda:{})
  elif change=='day':clock[0]='2026-10-18T00:00:01+00:00'
  elif change=='cancel':stop.set()
  else:
   with b.connect() as db:
    if change=='packet':db.execute("UPDATE packets SET content='{}'")
    elif change=='receipt':db.execute("UPDATE pipeline_stages SET receipt='{}' WHERE ordinal=1")
    else:db.execute("UPDATE jobs SET id='successor',lease=9999999999")
 def send(url,**kw):calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 try:
  status=run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send,hook=hook,should_stop=stop.is_set)
  assert len(calls)==stage-1 and status!='completed' and status.request_units==stage
  with b.connect() as db:
   assert db.execute('SELECT sum(requests) FROM usage').fetchone()[0]==stage+(1 if change=='quota' else 0)
   assert not db.execute("SELECT 1 FROM assessments WHERE status='completed'").fetchone()
   assert db.execute('SELECT sum(held) FROM pipeline_reservations').fetchone()[0]==0
   if change in ('master','model','quota'):assert not db.execute("SELECT 1 FROM retention_state WHERE name LIKE 'provider_backoff:%'").fetchone()
 finally:close(s)

@pytest.mark.parametrize('stage',[1,2])
@pytest.mark.parametrize('key',['enabled','model_enabled'])
def test_disable_before_entry_prevents_stage(tmp_path,monkeypatch,stage,key):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());s,b,cfg,p=setup(tmp_path/'native-test.sqlite3');calls=[]
 def hook(phase):
  if phase=='before_entry'+str(stage):s.state('behavior_settings',{**cfg,key:False})
 def send(url,**kw):calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send,hook=hook)!='completed' and len(calls)==stage-1
 finally:close(s)

@pytest.mark.parametrize('populated',[False,True])
def test_authenticated_utf8_settings_and_metrics_states(tmp_path,populated):
 from test_ui_settings import ui
 app,c,_=ui.__wrapped__(tmp_path)
 if populated:
  b=ai.Brain(app.store)
  with b.connect() as db:db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('utf8','p','cfg',ai.now(),'2099','completed',json.dumps({'classification':'inconclusive','metadata':{'input_tokens':11,'output_tokens':7}}),'',1.2))
 try:
  for path in ('/behavior','/behavior/metrics'):
   response=c.get(path,base_url='https://localhost');assert response.status_code==200;text=response.data.decode('utf-8','strict')
   assert '\u00c2' not in text and '\u00e2\u20ac' not in text and '\ufffd' not in text
   assert '\u00b7' in text
   if path.endswith('metrics'):assert '\u2013' in text and '\u2014' in text
 finally:close(app.store)
