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
 s,b,cfg,p=setup(tmp_path/'native');calls=[]
 def send(url,**kw):
  request=kw['json'];calls.append(request)
  return Reply(request,choices(request),metadata={} if len(calls)==2 else None)
 try:
  assert run(b,p[0]['packet_id'],p[0],set(),cfg,requester=send)=='completed'
  with analytics.connect(s) as db:
   rows=list(db.execute('SELECT * FROM requests'));assert len(rows)==2 and all(r['state']=='accepted' for r in rows)
   assert sorted((r['input_tokens'] is None) for r in rows)==[False,True]
  now=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=1);report=summary(b,at=now)
  assert report['requests']==2 and report['day_tokens']==12 and report['day_known']==1 and report['day_unknown']==1 and report['first_samples']==0
  with b.connect() as db:
   v=json.loads(db.execute('SELECT result FROM assessments').fetchone()[0])['metadata'];assert v['request_count']==2 and v['pipeline_usage']['input_tokens'] is None and v['input_tokens'] is None
  # Remove only synthetic analytics receipts; assessment evidence restores both.
  with analytics.connect(s,True) as db:db.execute('DELETE FROM requests')
  assert recover(b)['recovered']==2 and recover(b)['recovered']==0
  assert summary(b,at=now)['requests']==2 and summary(b,at=now)['day_tokens']==12
 finally:close(s)
