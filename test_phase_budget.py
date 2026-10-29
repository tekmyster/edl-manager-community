"""Source closure, one checkpoint deadline, carried admissions and actual entry."""
import json,os,pathlib
import pytest
import source_log_reader as r
import edge_transaction as tx
from test_fast_checkpoint import setup


def armed(monkeypatch):
 clock=[1000.];monkeypatch.setattr(r.time,'monotonic',lambda:clock[0])
 admission=r._Admission(r.InputLimits(seconds=20,records=16384));guard=r.GenerationCommitGuard();guard.arm([],admission)
 return clock,guard,admission

@pytest.mark.parametrize('late',[20,21,180])
def test_expired_source_never_enters_checkpoint(monkeypatch,late):
 clock,guard,a=armed(monkeypatch);clock[0]+=late
 with pytest.raises(r.DeferredInput):guard.begin_checkpoint()
 assert a.phase=='input' and a.checkpoint_deadline is None

def test_separate_clock_carries_all_admissions_and_never_renews(monkeypatch):
 clock,guard,a=armed(monkeypatch);a.validation_bytes=123;a.validation_error_reserved_bytes=17;a.rotation_recheck_bytes=456;a.rotation_captures=[{'keep':'capture'}]
 original_limits=a.limits;original_deadline=a.deadline;work=a.work_deadline;captures=a.rotation_captures
 clock[0]=1019;guard.begin_checkpoint();deadline=a.checkpoint_deadline
 assert deadline==1064 and a.deadline==original_deadline and a.work_deadline==work
 clock[0]=1030;guard.begin_checkpoint();guard.validate()
 assert a.checkpoint_deadline==deadline and a.limits is original_limits and a.validation_bytes==123 and a.validation_error_reserved_bytes==17 and a.rotation_recheck_bytes==456 and a.rotation_captures is captures
 with pytest.raises(r.DeferredInput,match='closed'):a.check_input()
 clock[0]=1064
 with pytest.raises(r.DeferredInput,match='Checkpoint'):guard.begin_checkpoint()
 assert a.checkpoint_deadline==deadline

def test_checkpoint_can_cross_original_source_deadline(monkeypatch,tmp_path):
 clock,guard,a=armed(monkeypatch);transaction,saved,out,payload=setup(tmp_path,{'files':{}});transaction.guard=guard
 clock[0]=1019;guard.begin_checkpoint();original=tx.json.dumps
 def encode(value,*args,**kw):
  text=original(value,*args,**kw);clock[0]=1040;return text
 monkeypatch.setattr(tx.json,'dumps',encode);transaction.commit({'files':{},'unknown':None})
 assert json.loads(saved.read_text())=={'files':{},'unknown':None} and out.read_bytes().endswith(payload)
 assert guard.receipt['phase_budgets']['checkpoint_deadline']==1064

def test_whole_budget_caps_checkpoint_and_cannot_be_renewed(monkeypatch):
 clock,guard,a=armed(monkeypatch);guard.whole_deadline=1025;a.whole_deadline=1025
 clock[0]=1019;guard.begin_checkpoint();assert a.checkpoint_deadline==1025
 clock[0]=1025
 with pytest.raises(r.DeferredInput,match='Whole'):guard.check()

def test_loading_is_charged_to_whole_budget_before_source_arm(monkeypatch):
 clock=[1000.];monkeypatch.setattr(r.time,'monotonic',lambda:clock[0]);guard=r.GenerationCommitGuard()
 clock[0]=1180
 with pytest.raises(r.DeferredInput,match='Whole'):guard.check()

def test_recovery_uses_single_45s_from_recovery_start(monkeypatch,tmp_path):
 clock=[1000.];monkeypatch.setattr(r.time,'monotonic',lambda:clock[0]);transaction,saved,out,payload=setup(tmp_path,{'files':{}})
 finish=tx.EdgeTransaction.finish
 with monkeypatch.context() as patch:
  patch.setattr(tx.EdgeTransaction,'finish',lambda *_:(_ for _ in ()).throw(OSError('crash ready')))
  with pytest.raises(OSError):transaction.commit({'files':{}})
 read=pathlib.Path.read_text
 def slow(path,*args,**kw):
  value=read(path,*args,**kw)
  if path==transaction.ready:clock[0]+=46
  return value
 monkeypatch.setattr(pathlib.Path,'read_text',slow)
 prior=out.read_bytes()
 with pytest.raises(r.DeferredInput,match='Checkpoint'):tx.recover_edge_transaction(saved,out)
 assert transaction.ready.exists() and out.read_bytes()==prior


def test_late_cleanup_return_is_not_acknowledged(tmp_path,monkeypatch):
 clock,guard,a=armed(monkeypatch);transaction,saved,out,payload=setup(tmp_path,{'files':{}});transaction.guard=guard
 unlink=pathlib.Path.unlink
 def late(path,*args,**kw):
  result=unlink(path,*args,**kw)
  if path==transaction.stage:clock[0]=1046
  return result
 monkeypatch.setattr(pathlib.Path,'unlink',late)
 with pytest.raises(r.DeferredInput,match='Checkpoint'):transaction.commit({'files':{}})
 assert json.loads(saved.read_text())=={'files':{}} and out.read_bytes().endswith(payload)
