"""Actual SQLite post-claim interleavings; inert fetches only."""
import datetime as dt,hashlib,json,sqlite3,time
import pytest
import activity,behavior_context as ctx
from core import Store,now
from test_delivery_contention import palo_fixture,offline
from test_pipeline_support import close

@pytest.mark.parametrize('outcome',['success','error'])
@pytest.mark.parametrize('boundary',['cache_save','lease_clear'])
def test_postclaim_writer_release_preserves_cache_or_pending(tmp_path,monkeypatch,outcome,boundary):
 s=Store(tmp_path/'native');cfg=palo_fixture(s)
 scope=hashlib.sha256(b'https://fixture.invalid|fixture').hexdigest()[:16]
 key='ip_activity:'+scope+':8.8.8.8';lease='ip_activity_pending:'+key
 old={'status':'ok','fetched':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=2)).isoformat(),'events':[{'seen':'2026-01-01T00:00:00+00:00'}]}
 s.state(key,old);state=s.state;calls=[];writes=[];blocked=[];claims=[]
 claim=activity.claim_activity
 def claiming(*a,**kw):
  result=claim(*a,**kw);claims.append(state(lease));return result
 monkeypatch.setattr(activity,'claim_activity',claiming)
 def fetch(*a):
  calls.append(1)
  if outcome=='error':raise OSError('inert provider failure')
  return {'status':'ok','fetched':now(),'events':[]}
 def saving(name,value=None,**kw):
  if value is not None:
   writes.append(name)
   if name==(key if boundary=='cache_save' else lease) and not blocked:
    holder=sqlite3.connect(s.path);holder.execute('BEGIN IMMEDIATE');started=time.monotonic()
    try:
     with pytest.raises(sqlite3.OperationalError) as failure:state(name,value,**kw)
     assert failure.value.sqlite_errorcode==sqlite3.SQLITE_BUSY
     assert kw['busy_timeout_ms']==250 and time.monotonic()-started<1.5
     blocked.append(failure.value)
    finally:holder.rollback();holder.close()
    # The writer is gone BEFORE refresh_palo gets the BUSY and enters cleanup.
    raise blocked[0]
  return state(name,value,**kw)
 monkeypatch.setattr(s,'state',saving)
 try:
  first=ctx.refresh_palo(s,cfg,'8.8.8.8',100,fetch)
  assert first=='busy_retry_next_pass' and len(blocked)==1 and len(claims)==1
  assert state(lease)==claims[0] and state(lease).get('started')
  if boundary=='cache_save':
   assert state(key)==old and writes==[key]
   expected='pending'
  else:
   assert state(key)['status']==('ok' if outcome=='success' else 'error')
   assert state(key)['fetched']!=old['fetched'] and writes==[key,lease]
   expected='cached'
  for _ in range(3):assert ctx.refresh_palo(s,cfg,'8.8.8.8',100,fetch)==expected
  quota='behavior_palo_usage:'+dt.datetime.now(dt.timezone.utc).date().isoformat()
  assert len(calls)==1 and state(quota)==1
  witness={'outcome':outcome,'boundary':boundary,'first':first,'immediate_retry':expected,'fetches':len(calls),'charged':state(quota),'pending':state(lease),'cache':state(key)}
  # Existing 90-second lease expiry permits one normal retry after a lost save.
  # A saved cache still wins, even if lease clearing failed and its lease expires.
  state(lease,{**claims[0],'started':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=91)).isoformat()})
  retry=ctx.refresh_palo(s,cfg,'8.8.8.8',100,fetch)
  if boundary=='cache_save':
   assert retry==('refreshed' if outcome=='success' else 'failed')
   assert state(lease)=={} and len(calls)==2 and state(quota)==2
  else:assert retry=='cached' and len(calls)==1 and state(quota)==1
  assert ctx.refresh_palo(s,cfg,'8.8.8.8',100,fetch)=='cached'
  witness.update(after_expiry=retry,final_fetches=len(calls),final_charged=state(quota))
  print(json.dumps(witness,sort_keys=True))
 finally:close(s)

def test_unexpected_cache_write_error_retains_claim_and_propagates(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');cfg=palo_fixture(s);state=s.state;calls=[]
 scope=hashlib.sha256(b'https://fixture.invalid|fixture').hexdigest()[:16]
 key='ip_activity:'+scope+':8.8.8.8'
 def saving(name,value=None,**kw):
  if name==key and value is not None:raise sqlite3.OperationalError('no such table: fixture')
  return state(name,value,**kw)
 def fetch(*a):calls.append(1);return {'status':'ok','fetched':now(),'events':[]}
 monkeypatch.setattr(s,'state',saving)
 try:
  with pytest.raises(sqlite3.OperationalError,match='no such table'):ctx.refresh_palo(s,cfg,'8.8.8.8',100,fetch)
  assert state('ip_activity_pending:'+key).get('started')
  assert ctx.refresh_palo(s,cfg,'8.8.8.8',100,fetch)=='pending' and len(calls)==1
  assert state('behavior_palo_usage:'+dt.datetime.now(dt.timezone.utc).date().isoformat())==1
 finally:close(s)
