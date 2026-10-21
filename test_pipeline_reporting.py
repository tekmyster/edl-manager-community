"""Two real isolated telemetry receipts, missingness and idempotent recovery."""
import datetime as dt,json
import pytest
import analytics_store as analytics
import behavior_ai as ai
import behavior_tokens
from behavior_pipeline_job import run
from behavior_telemetry import recover
from production_analytics import summary
from test_pipeline_support import SyntheticCounter,Reply,choices,setup,close

def test_two_stage_metrics_are_two_attempts_and_missing_tokens_stay_unknown(tmp_path,monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 s,b,cfg,p=setup(tmp_path/'native',count=2,budget=4);calls=[]
 def send(url,**kw):
  request=kw['json'];calls.append(request)
  return Reply(request,choices(request),metadata={} if len(calls)==2 else None)
 try:
  for packet in p:assert run(b,packet['packet_id'],packet,set(),cfg,requester=send)=='completed'
  with analytics.connect(s) as db:
   rows=list(db.execute('SELECT * FROM requests'));assert len(rows)==4 and all(r['state']=='accepted' for r in rows)
   assert sorted((r['input_tokens'] is None) for r in rows)==[False,False,False,True]
  now=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=1);report=summary(b,at=now)
  assert report['requests']==4 and report['day_tokens']==36 and report['day_known']==3 and report['day_unknown']==1 and report['first_samples']==0
  with b.connect() as db:
   values=[json.loads(r[0])['metadata'] for r in db.execute('SELECT result FROM assessments')];assert all(v['request_count']==v['planned_requests']==2 for v in values) and sorted(v['input_tokens'] is None for v in values)==[False,True]
  # Remove only synthetic analytics receipts; assessment evidence restores both.
  with analytics.connect(s,True) as db:db.execute('DELETE FROM requests')
  assert recover(b)['recovered']==4 and recover(b)['recovered']==0
  assert summary(b,at=now)['requests']==4 and summary(b,at=now)['day_tokens']==36
 finally:close(s)
