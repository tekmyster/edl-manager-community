"""Regression: fresh large current files must fit every existing commit recheck."""
import copy,dataclasses,json,pathlib
import pytest
import receipt_pages as pages
import source_log_reader as r
from test_generation_recovery import state_for

def pair(tmp_path,index=0,large=True):
 folder=tmp_path/str(index);folder.mkdir();a=folder/'audit.log';b=folder/'audit.log.1';scale=1024**2 if large else 1
 def fill(p,n,value):
  with p.open('wb') as f:
   block=value*min(1024**2,n)
   while n:
    size=min(n,len(block));f.write(block[:size]);n-=size
 fill(a,50*scale,b'A');fill(b,3*scale,b'B');old={str(p):state_for(p,p.read_bytes()) for p in (a,b)}
 with a.open('rb') as source,b.open('wb') as dest:
  for data in iter(lambda:source.read(1024**2),b''):dest.write(data)
 fill(a,40*scale,b'C');return a,b,old

@pytest.mark.parametrize('pairs',[1,2])
@pytest.mark.parametrize('commit',[False,True])
def test_large_current_capture_fits_rechecks_even_with_growth_at_each_stage(tmp_path,monkeypatch,pairs,commit):
 groups=[pair(tmp_path,i) for i in range(pairs)];paths=[p for a,b,old in groups for p in (a,b)];files={k:v for a,b,old in groups for k,v in old.items()};before=copy.deepcopy(files);bound=r.InputLimits(seconds=20,records=16384);guard=r.GenerationCommitGuard() if commit else None;original=r._rotation_stable;calls=0;seen=[]
 def growing(plans,admission):
  nonlocal calls
  calls+=1
  for a,b,old in groups:
   with a.open('ab') as f:f.write(b'\n')
  return original(plans,admission)
 monkeypatch.setattr(r,'_rotation_stable',growing)
 result=r.collect_log_inputs(paths,files,lambda *a:seen.append(a),cutoff=0,limits=bound,rotation_pairs=tuple(r.RotationPair(a,b) for a,b,old in groups),commit_guard=guard)
 assert result.get('generation_transitions') and result['input_bytes']<=bound.input_bytes
 if guard is not None:guard.validate()
 expected_checks=2 if commit else 1
 assert calls==expected_checks and not seen
 for a,b,old in groups:
  for p in (a,b):assert files[str(p)]['prior_generations']==[before[str(p)]]
  assert files[str(a)]['offset']==files[str(b)]['offset']==0
  assert 'delivery_offset' not in files[str(a)] and 'delivery_offset' not in files[str(b)]
 if commit:
  assert guard.receipt['final_rotation_capture_recheck_bytes']<=bound.input_bytes
  assert guard.receipt['final_validation_bytes']<=bound.validation_bytes
  assert guard.receipt['final_rotation_capture_recheck_bytes']==0
 lineage=[files[str(p)]['generation_origin']['lineage'] for p in paths];files=json.loads(json.dumps(files));monkeypatch.setattr(r,'_rotation_stable',original)
 next_guard=r.GenerationCommitGuard()
 progress=r.collect_log_inputs(paths,files,lambda *a:None,cutoff=0,limits=bound,rotation_pairs=tuple(r.RotationPair(a,b) for a,b,old in groups),commit_guard=next_guard)
 next_guard.validate()
 assert any(row.get('delivery_offset',row['offset'])>0 for row in files.values())
 assert progress['input_bytes']<=bound.input_bytes and next_guard.receipt['final_rotation_capture_recheck_bytes']<=bound.input_bytes
 assert [files[str(p)]['generation_origin']['lineage'] for p in paths]==lineage


def test_zero_record_association_does_not_spend_record_capture_budget(tmp_path):
 from test_generation_recovery import pair_fixture
 a,b,files,data=pair_fixture(tmp_path);before=copy.deepcopy(files);seen=[];guard=r.GenerationCommitGuard()
 result=r.collect_log_inputs([a,b],files,lambda *a:seen.append(a),cutoff=0,limits=dataclasses.replace(r.InputLimits(),input_bytes=2),rotation_pairs=(r.RotationPair(a,b),),commit_guard=guard)
 assert not seen and result['input_bytes']==result['records']==0
 guard.validate()
 for p in (a,b):
  assert files[str(p)]['offset']==0 and files[str(p)]['prior_generations']==[before[str(p)]]


def test_new_capture_bound_does_not_make_growing_callback_rewrite_acceptable(tmp_path,monkeypatch):
 from test_generation_recovery import pair_fixture
 a,b,files,data=pair_fixture(tmp_path);a.write_bytes(b'{"id":"new"}\n'*600)
 r.collect_log_inputs([a,b],files,lambda *_:pytest.fail('Association callback'),cutoff=0,limits=r.InputLimits(),rotation_pairs=(r.RotationPair(a,b),),commit_guard=r.GenerationCommitGuard())
 before=copy.deepcopy(files);changed=False
 def mutate(path,line):
  nonlocal changed
  if changed:return
  changed=True;body=a.read_bytes();a.write_bytes(body[:6000]+body[6000:].replace(b'new',b'BAD',1)+b'tail\n')
 with pytest.raises(pages.ReceiptPageError):r.collect_log_inputs([a,b],files,mutate,cutoff=0,limits=r.InputLimits(),rotation_pairs=(r.RotationPair(a,b),),commit_guard=r.GenerationCommitGuard())
 assert files==before
