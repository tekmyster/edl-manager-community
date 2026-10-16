"""Isolated diagnostic mechanics; no production timing or detector claims."""
import ipaddress,os,pathlib,sqlite3,time,pytest
from core import Store,now
pytestmark=pytest.mark.skipif(os.name=='nt',reason='Native worker imports Linux single-flight locking')

def test_only_changed_native_inputs_count_replays_and_palo_do_not(tmp_path):
 s=Store(tmp_path/'native');s._pipeline_receipts={};seen=now()
 s.evidence('8.8.8.8','waf','fixture',seen,'http',75,details={'records':1})
 first=s._pipeline_receipts['first'];assert s._pipeline_receipts['changed_rows']==1
 s.evidence('8.8.8.8','waf','fixture',seen,'http',75,details={'records':1})
 assert s._pipeline_receipts['changed_rows']==1
 s.evidence('8.8.8.8','palo','fixture',seen,'http',0)
 assert s._pipeline_receipts['changed_rows']==1
 s.evidence('8.8.8.8','waf','fixture',seen,'http',75,details={'records':2})
 assert s._pipeline_receipts['changed_rows']==2 and s._pipeline_receipts['first']==first
 assert s.describe('8.8.8.8')['score']==75
 with s.connect() as db:
  assert db.execute('SELECT count(*) FROM block_retention').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM permanent_event_ids').fetchone()[0]==0

def test_local_publication_bounds_are_monotonic_and_explicit(tmp_path):
 from worker import pipeline_timing
 s=Store(tmp_path/'native');s._pipeline_receipts={'first':('2026-10-16T12:00:00+00:00',10),'last':('2026-10-16T12:00:01+00:00',11),'changed_rows':2}
 result=pipeline_timing(s,12,14,{'created':'2026-10-16T12:00:02+00:00'})
 assert result['first_input_to_publication_seconds']=={'lower':2,'upper':4}
 assert result['last_input_to_publication_seconds']=={'lower':1,'upper':3}
 assert result['build_seconds']==2 and 'not individual block' in result['boundary']
 assert not any(key in result for key in ('ip','paths','evidence_ids'))

def test_deferred_or_empty_cycle_never_fabricates_latency(tmp_path):
 from worker import pipeline_timing
 s=Store(tmp_path/'native');assert pipeline_timing(s,10,12,None)=={'status':'no_changed_native_evidence'}
 s._pipeline_receipts={'first':('2026-10-16T12:00:00+00:00',10),'last':('2026-10-16T12:00:00+00:00',10),'changed_rows':1}
 result=pipeline_timing(s,11,12,None)
 assert result['status']=='publication_pending' and 'first_input_to_publication_seconds' not in result

def successful_build_after_invalidation(s,output):
 from worker import pipeline_timing
 # A caught failure must not prevent genuine later native ingestion/publication.
 s.evidence('1.1.1.1','waf','fixture',now(),'http',75)
 assert s._pipeline_receipts=={'invalidated':True}
 start=time.monotonic();manifest=s.build(output);end=time.monotonic()
 timing=pipeline_timing(s,start,end,manifest)
 assert timing=={'status':'unmeasurable','reason':'transaction_rollback'}
 assert pipeline_timing(s,start,end,None)==timing
 nets=[ipaddress.ip_network(line) for line in (pathlib.Path(output)/'current'/'combined-block.txt').read_text().splitlines()]
 assert any(ipaddress.ip_address('1.1.1.1') in net for net in nets)
 assert not any(ipaddress.ip_address('9.9.9.9') in net for net in nets)
 assert s.describe('1.1.1.1')['score']==75

def test_caught_standalone_rollback_cannot_publish_phantom_timing(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');s._pipeline_receipts={}
 def fail(*args,**kwargs):raise ValueError('Isolated failure after upsert')
 with monkeypatch.context() as patch:
  patch.setattr('permanent_policy.observe',fail)
  with pytest.raises(ValueError):s.evidence('9.9.9.9','waf','fixture',now(),'http',75)
 with s.connect() as db:assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==0
 assert s._pipeline_receipts=={'invalidated':True}
 successful_build_after_invalidation(s,tmp_path/'out')

@pytest.mark.parametrize('commit_earlier',[False,True])
def test_caught_shared_batch_rollback_invalidates_earlier_receipts(tmp_path,monkeypatch,commit_earlier):
 s=Store(tmp_path/'native');s._pipeline_receipts={};anchor=sqlite3.connect(s.path);s._worker_connection=anchor;s._batch_evidence=True
 try:
  s.evidence('8.8.8.8','waf','fixture',now(),'http',75)
  assert s._pipeline_receipts['changed_rows']==1
  if commit_earlier:anchor.commit()
  def fail(*args,**kwargs):raise ValueError('Isolated shared transaction failure')
  with monkeypatch.context() as patch:
   patch.setattr('permanent_policy.observe',fail)
   with pytest.raises(ValueError):s.evidence('9.9.9.9','waf','fixture',now(),'http',75)
  assert anchor.execute('SELECT count(*) FROM evidence').fetchone()[0]==int(commit_earlier)
  assert s._pipeline_receipts=={'invalidated':True}
  successful_build_after_invalidation(s,tmp_path/'out')
 finally:s._worker_connection=None;anchor.close()

def test_rollback_elsewhere_in_shared_transaction_also_invalidates_cycle(tmp_path):
 s=Store(tmp_path/'native');s._pipeline_receipts={};anchor=sqlite3.connect(s.path);s._worker_connection=anchor;s._batch_evidence=True
 try:
  s.evidence('8.8.8.8','waf','fixture',now(),'http',75)
  with pytest.raises(ValueError):
   with s.connect(commit=False) as db:
    db.execute('INSERT INTO state VALUES(?,?)',('isolated-rollback-fixture','{}'))
    raise ValueError('Caught failure outside evidence method')
  assert anchor.execute('SELECT count(*) FROM evidence').fetchone()[0]==0
  assert s._pipeline_receipts=={'invalidated':True}
  successful_build_after_invalidation(s,tmp_path/'out')
 finally:s._worker_connection=None;anchor.close()

def test_untracked_rollback_preserves_existing_failure_behavior(tmp_path,monkeypatch):
 s=Store(tmp_path/'native')
 def fail(*args,**kwargs):raise ValueError('Original failure')
 monkeypatch.setattr('permanent_policy.observe',fail)
 with pytest.raises(ValueError,match='Original failure'):s.evidence('9.9.9.9','waf','fixture',now(),'http',75)
 assert not hasattr(s,'_pipeline_receipts')
 with s.connect() as db:assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==0
