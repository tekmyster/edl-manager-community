import copy
import types,unittest
from unittest import mock
import source_log_reader as reader

class Admission:
 def __init__(self):self.checks=0;self.deadline=123;self.rotation_recheck_bytes=0;self.records=44
 def check(self):self.checks+=1

class RetryTests(unittest.TestCase):
 def setup_case(self):
  admission=Admission();state={'device':1,'inode':2,'size':100};plans=[{'snapshots':[{'path':'/current','device':1,'inode':2}]}]
  class P:
   def __init__(self,value):self.value=str(value)
   def __str__(self):return self.value
   def stat(self):return types.SimpleNamespace(st_dev=state['device'],st_ino=state['inode'],st_size=state['size'])
  return admission,state,plans,P
 def test_proven_growth_repeats_all_validation_without_resetting_counters(self):
  a,s,p,P=self.setup_case();old=copy.deepcopy(p);calls=[]
  def validate(plans,admission):
   calls.append(True);admission.rotation_recheck_bytes+=10
   if len(calls)==1:s['size']+=1;raise reader.DeferredInput('/current','Rotation source changed while opening.')
  with mock.patch.object(reader.pathlib,'Path',P),mock.patch.object(reader,'_rotation_stable_once',side_effect=validate):reader._rotation_stable(p,a)
  self.assertEqual(len(calls),2);self.assertEqual(a.rotation_recheck_bytes,20);self.assertEqual(a.records,44);self.assertEqual(a.deadline,123);self.assertEqual(p,old)
 def test_rewrite_plus_growth_is_rechecked_and_rejected(self):
  a,s,p,P=self.setup_case();calls=[]
  def validate(*_):
   calls.append(True)
   if len(calls)==1:s['size']+=1;raise reader.DeferredInput('/current','Rotation source changed while opening.')
   raise reader.DeferredInput('/current','Rotation captured range changed; hold pair.')
  with mock.patch.object(reader.pathlib,'Path',P),mock.patch.object(reader,'_rotation_stable_once',side_effect=validate),self.assertRaisesRegex(reader.DeferredInput,'captured range changed'):reader._rotation_stable(p,a)
  self.assertEqual(len(calls),2)
 def test_growth_retry_is_at_most_two_for_whole_admission(self):
  a,s,p,P=self.setup_case();calls=[]
  def validate(*_):calls.append(True);s['size']+=1;raise reader.DeferredInput('/current','Rotation source changed while opening.')
  with mock.patch.object(reader.pathlib,'Path',P),mock.patch.object(reader,'_rotation_stable_once',side_effect=validate),self.assertRaises(reader.DeferredInput):reader._rotation_stable(p,a)
  self.assertEqual(len(calls),3);self.assertEqual(a.rotation_stable_retry_count,2)
  with mock.patch.object(reader.pathlib,'Path',P),mock.patch.object(reader,'_rotation_stable_once',side_effect=validate),self.assertRaises(reader.DeferredInput):reader._rotation_stable(p,a)
  self.assertEqual(len(calls),4)
 def test_same_size_rewrite_has_no_retry(self):self.assert_not_retried('same')
 def test_truncation_has_no_retry(self):self.assert_not_retried('shrink')
 def test_replaced_inode_has_no_retry(self):self.assert_not_retried('replace')
 def test_retained_file_has_no_retry(self):self.assert_not_retried('retained')
 def test_capture_budget_error_is_not_retried(self):self.assert_not_retried('budget')
 def assert_not_retried(self,kind):
  a,s,p,P=self.setup_case();calls=[]
  def validate(*_):
   calls.append(True)
   if kind=='shrink':s['size']-=1
   if kind in ('replace','retained','budget'):s['size']+=1
   if kind=='replace':s['inode']=3
   raise reader.DeferredInput('/retained' if kind=='retained' else '/current','Rotation capture revalidation admission exhausted; hold pair.' if kind=='budget' else 'Rotation source changed while opening.')
  with mock.patch.object(reader.pathlib,'Path',P),mock.patch.object(reader,'_rotation_stable_once',side_effect=validate),self.assertRaises(reader.DeferredInput):reader._rotation_stable(p,a)
  self.assertEqual(len(calls),1);self.assertFalse(hasattr(a,'rotation_stable_retry_count'))
 def test_expired_deadline_between_attempts_is_not_renewed(self):
  a,s,p,P=self.setup_case();calls=[]
  def check():
   a.checks+=1
   if a.checks==2:raise TimeoutError('Original checkpoint deadline')
  a.check=check
  def validate(*_):calls.append(True);s['size']+=1;raise reader.DeferredInput('/current','Rotation source changed while opening.')
  with mock.patch.object(reader.pathlib,'Path',P),mock.patch.object(reader,'_rotation_stable_once',side_effect=validate),self.assertRaises(TimeoutError):reader._rotation_stable(p,a)
  self.assertEqual(len(calls),1);self.assertEqual(a.deadline,123)

if __name__=='__main__':unittest.main(verbosity=2)
