import pathlib
from unittest import mock
import pytest
import source_log_reader as r
from test_generation_recovery import pair_fixture

@pytest.mark.parametrize('rewrite',[False,True])
def test_actual_stat_open_growth_revalidates_captured_bytes_without_callbacks(tmp_path,monkeypatch,rewrite):
 a,b,files,data=pair_fixture(tmp_path);seen=[];pair=(r.RotationPair(a,b),)
 r.collect_log_inputs([a,b],files,lambda *row:seen.append(row),cutoff=0,limits=r.InputLimits(seconds=20,records=16384),rotation_pairs=pair)
 guard=r.GenerationCommitGuard()
 r.collect_log_inputs([a,b],files,lambda *row:seen.append(row),cutoff=0,limits=r.InputLimits(seconds=20,records=16384),rotation_pairs=pair,commit_guard=guard)
 calls=len(seen);offset=files[str(a)]['offset'];original_anchor=r._rotation_anchor;original_open=pathlib.Path.open;injected=[]
 def anchor(path,length,admission):
  if str(path)!=str(a) or injected:return original_anchor(path,length,admission)
  def race_open(p,*args,**kwargs):
   if str(p)==str(a) and not injected:
    injected.append(True)
    if rewrite:
     with original_open(a,'r+b') as saved:saved.write(b'X')
    with original_open(a,'ab') as saved:saved.write(b'\n')
   return original_open(p,*args,**kwargs)
  with mock.patch.object(pathlib.Path,'open',race_open):return original_anchor(path,length,admission)
 monkeypatch.setattr(r,'_rotation_anchor',anchor)
 if rewrite:
  with pytest.raises(r.DeferredInput,match='captured range changed'):guard.validate()
 else:guard.validate()
 assert injected and guard.admission.rotation_stable_retry_count==1
 assert len(seen)==calls and files[str(a)]['offset']==offset
 assert guard.admission.rotation_recheck_bytes<=guard.admission.limits.input_bytes
 assert guard.admission.validation_bytes<=guard.admission.limits.validation_bytes
