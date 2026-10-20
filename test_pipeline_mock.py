"""Upgrade canonical-result mocks to the current two-stage unit boundary.

This adapter is test-only. Current transport/strict-output coverage uses actual
NDJSON mocks in test_pipeline_contract/durable/https, not this adapter. A legacy
test callback runs once, at stage two; each stage still claims, enters, validates
and records its own attempt. No runtime fallback accepts old wire payloads.
"""
import copy
import behavior_ai as ai
import behavior_pipeline_job as job
import behavior_tokens
from test_pipeline_support import SyntheticCounter,choices
from test_generation_fixtures import wire_from_storage

def stage_mock(monkeypatch,target,value,*,before_persist=None):
 if target not in ('behavior_ai.infer',ai):raise ValueError('Expected the inference unit boundary')
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 previous=job.run
 if not getattr(previous,'stage_fixture',False):
  def fixture_run(*args,**kw):
   kw.setdefault('requester',lambda *a,**k:None)
   if before_persist:
    prior=kw.get('hook',lambda phase:None)
    def hook(phase):
     prior(phase)
     if phase=='before_persist':before_persist()
    kw['hook']=hook
   return previous(*args,**kw)
  fixture_run.stage_fixture=True;monkeypatch.setattr(job,'run',fixture_run)
 def infer(cfg,packet,candidates,allowed,key,requester=None,attempt=None,*,_wire=None,_deadline=None,_before_call=None,_before_post=None):
  if _wire is None:return value(cfg,packet,candidates,allowed,key,requester,attempt)
  if _before_call:_before_call()
  if _before_post:_before_post()
  if attempt:attempt.start()
  meta={}
  try:
   request=_wire['request']
   if 'contract' in request['format']['properties']:
    result=_wire['decode'](choices(request));meta={'input_tokens':10,'output_tokens':2,'request_seconds':.01}
   else:
    canonical,meta=value(cfg,packet,candidates,allowed,key,requester,attempt)
    w=wire_from_storage(packet,canonical,candidates,allowed);w.pop('observable_synthesis');w['generation_schema_version']=request['format']['properties']['generation_schema_version']['enum'][0]
    w['account_binding']=request['format']['properties']['account_binding']['enum'][0]
    w['observations']={k:v['purpose'] for k,v in w['observations'].items()};result=_wire['decode'](w)
   meta=copy.deepcopy(meta);meta.update(request_id=attempt.id if attempt else None,**_wire['preparation'])
   if attempt:attempt.finish('accepted',meta)
   return result,meta
  except Exception as exc:
   meta=exc.metadata if isinstance(exc,ai.ModelOutputError) else getattr(exc,'_edl_failure_metadata',{})
   meta.update(request_id=attempt.id if attempt else None)
   if attempt:attempt.finish('rejected' if isinstance(exc,ai.ModelOutputError) else 'failed',meta)
   if not isinstance(exc,ai.ModelOutputError):exc._edl_failure_metadata=meta
   raise
 monkeypatch.setattr(ai,'infer',infer)
