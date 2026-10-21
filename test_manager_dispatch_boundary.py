import copy,json,sys,threading
from pathlib import Path
import pytest
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline_job import run
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices
@pytest.mark.parametrize('boundary,actual',[('after_entry1',0),('before_final',1)])
@pytest.mark.parametrize('change',['config','packet'])
def test_changes_after_entry_do_not_send_stale_request(tmp_path,monkeypatch,boundary,actual,change):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 store,brain,cfg,packets=setup(tmp_path/'native-test.sqlite3');p=packets[0];calls=[];changed=[]
 def hook(phase):
  if phase!=boundary:return
  changed.append(phase)
  if change=='config':store.state('behavior_settings',{**cfg,'model':'changed'})
  else:
   with brain.connect() as db:db.execute("UPDATE packets SET content='{}' WHERE id=?",(p['packet_id'],))
 def send(url,**kw):
  calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 try:
  status=run(brain,p['packet_id'],p,set(),cfg,requester=send,hook=hook)
  with brain.connect() as db:state={'status':str(status),'charges':list(map(list,db.execute('SELECT * FROM usage'))),'stages':list(map(list,db.execute('SELECT ordinal,state,charged_day,entered FROM pipeline_stages')))}
  state.update(change=change,boundary=boundary,observed_posts=len(calls),maximum_expected_posts=actual)
  print(json.dumps(state))
  assert changed and len(calls)==actual and status!='completed'
 finally:close(store)

def test_disable_after_response_prevents_final_acceptance(tmp_path,monkeypatch):
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 store,brain,cfg,packets=setup(tmp_path/'native-test.sqlite3');p=packets[0];calls=[]
 def hook(phase):
  if phase=='before_final':store.state('behavior_settings',{**cfg,'enabled':False})
 def send(url,**kw):
  calls.append(kw['json']);return Reply(kw['json'],choices(kw['json']))
 try:
  status=run(brain,p['packet_id'],p,set(),cfg,requester=send,hook=hook)
  print(json.dumps({'change':'disable_analysis_after_stage1','status':str(status),'posts':len(calls)}))
  assert len(calls)==1 and status!='completed'
 finally:close(store)
