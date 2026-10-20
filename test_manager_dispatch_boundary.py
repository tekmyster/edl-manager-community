import copy,json,sys,threading
from pathlib import Path
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline_job import run
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices
@pytest.mark.parametrize('stage',[1,2])
@pytest.mark.parametrize('change',['config','packet'])
def test_changes_after_entry_do_not_send_stale_request(tmp_path,monkeypatch,stage,change):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 store,brain,cfg,packets=setup(tmp_path/'native-test.sqlite3');p=packets[0];calls=[];changed=[]
 def hook(phase):
  if phase!='after_entry'+str(stage):return
  changed.append(phase)
  if change=='config':store.state('behavior_settings',{**cfg,'model':'changed'})
  else:
   with brain.connect() as db:db.execute("UPDATE packets SET content='{}' WHERE id=?",(p['packet_id'],))
 def send(url,**kw):
  calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 try:
  status=run(brain,p['packet_id'],p,set(),cfg,requester=send,hook=hook)
  with brain.connect() as db:state={'status':str(status),'charges':list(map(list,db.execute('SELECT * FROM usage'))),'stages':list(map(list,db.execute('SELECT ordinal,state,charged_day,entered FROM pipeline_stages')))}
  state.update(change=change,stage=stage,observed_posts=len(calls),maximum_expected_posts=stage-1)
  print(json.dumps(state))
  assert changed and len(calls)==stage-1
 finally:close(store)

def test_disable_after_stage1_prevents_second_request(tmp_path,monkeypatch):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 store,brain,cfg,packets=setup(tmp_path/'native-test.sqlite3');p=packets[0];calls=[]
 def hook(phase):
  if phase=='after_freeze':store.state('behavior_settings',{**cfg,'enabled':False})
 def send(url,**kw):
  calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 try:
  status=run(brain,p['packet_id'],p,set(),cfg,requester=send,hook=hook)
  print(json.dumps({'change':'disable_analysis_after_stage1','status':str(status),'posts':len(calls)}))
  assert len(calls)==1 and status!='completed'
 finally:close(store)
