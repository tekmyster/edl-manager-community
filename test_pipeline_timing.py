"""Isolated diagnostic mechanics; no production timing or detector claims."""
import os,pytest
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
