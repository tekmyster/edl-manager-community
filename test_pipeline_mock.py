"""Upgrade canonical-result mocks to the current single-request unit boundary.

This adapter is test-only. Current single-request transport/strict-output coverage uses actual
NDJSON mocks in test_pipeline_contract/durable/https, not this adapter. A legacy
test callback runs once; the request still claims, enters, validates
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
 cached={}
 def infer(cfg,packet,candidates,allowed,key,requester=None,attempt=None,*,_wire=None,_deadline=None,_before_call=None,_before_post=None):
  if _wire is None:return value(cfg,packet,candidates,allowed,key,requester,attempt)
  if _before_call:_before_call()
  if _before_post:_before_post()
  if attempt:attempt.start()
  meta={}
  try:
   request=_wire['request']
   stage=_wire['preparation']['stage']
   if stage==1:
    canonical,meta=value(cfg,packet,candidates,allowed,key,requester,attempt);cached[packet['packet_id']]=(copy.deepcopy(canonical),copy.deepcopy(meta))
   else:canonical,meta=copy.deepcopy(cached[packet['packet_id']])
   w=wire_from_storage(packet,canonical,candidates,allowed)
   w['generation_schema_version']=request['format']['properties']['generation_schema_version']['enum'][0]
   if stage==2:
    w['draft_binding']=request['format']['properties']['draft_binding']['enum'][0]
    w['observations']={k:{'comparison':'unresolved','purpose':purpose} for k,purpose in w['observations'].items()}
   result=_wire['decode'](w)
   from test_pipeline_support import Reply
   counts={target:meta[source] for source,target in [('input_tokens','prompt_eval_count'),('output_tokens','eval_count'),('cached_input_tokens','prompt_eval_cached_count')] if source in meta}
   capture=_wire['capture'](Reply(request,w,metadata=counts))
   for _ in capture.iter_content(1):pass
   capture.close()
   meta=copy.deepcopy(meta);meta.update(request_id=attempt.id if attempt else None,**_wire['preparation'])
   if attempt:attempt.finish('accepted',meta)
   _wire['metadata_report'](meta)
   return result,meta
  except Exception as exc:
   meta=exc.metadata if isinstance(exc,ai.ModelOutputError) else getattr(exc,'_edl_failure_metadata',{})
   meta.update(request_id=attempt.id if attempt else None)
   if attempt:attempt.finish('rejected' if isinstance(exc,ai.ModelOutputError) else 'failed',meta)
   if not isinstance(exc,ai.ModelOutputError):exc._edl_failure_metadata=meta
   _wire['metadata_report'](meta)
   raise
 monkeypatch.setattr(ai,'infer',infer)
