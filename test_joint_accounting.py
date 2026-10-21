"""Deterministic measurement/capture regressions; no model or operative authority."""
from pathlib import Path
import copy,json,math,sys,tempfile,threading,time,types,unittest
from unittest import mock
sys.dont_write_bytecode=True
H=Path(__file__).resolve().parent
import behavior_accounting as a
import behavior_request_evidence as evidence
from types import SimpleNamespace
e=SimpleNamespace(put=evidence.put,read=evidence.read,compact=evidence.compact,sha=evidence.sha,usage=a.usage)
class Accounting(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory(dir=H);self.root=Path(self.tmp.name)
 def tearDown(self):self.tmp.cleanup()
 def envelope(self,**values):
  value={'done':True,'model':'qwen2.5:3b','prompt_eval_count':23,'eval_count':11,'prompt_eval_cached_count':5};value.update(values);e.put(self.root/'envelope.json',value)
 def test_metadata_counts_and_deep_snapshot(self):
  meta={'input_tokens':23,'output_tokens':11,'cached_input_tokens':5,'backend_timings':{'eval_duration':41}}
  u=e.usage(self.root,meta,True);meta['input_tokens']=99;meta['backend_timings']['eval_duration']=77
  self.assertEqual((u['input_tokens'],u['output_tokens'],u['cached_input_tokens'],u['uncached_input_tokens']),(23,11,5,18));self.assertEqual(u['metadata']['backend_timings']['eval_duration'],41);self.assertTrue(a.check_usage(u))
 def test_preparation_estimates_never_become_reports(self):
  u=e.usage(self.root,{'input_verification':{'input_tokens':8192},'input_preparation':{'user_prompt_bytes':1000}},True);self.assertIsNone(u['input_tokens']);self.assertFalse(u['count_provenance']['input_tokens'])
 def test_unknown_stays_unknown(self):
  u=e.usage(self.root,{},True);self.assertTrue(all(u[k] is None for k in a.FIELDS));self.assertIsNone(u['dollar_cost'])
 def test_zero_and_integer_boundaries(self):
  u=e.usage(self.root,{'input_tokens':10000000,'output_tokens':0,'cached_input_tokens':0},True);self.assertEqual(u['input_tokens'],10000000);self.assertEqual(u['output_tokens'],0);self.assertEqual(u['uncached_input_tokens'],10000000)
 def test_invalid_boolean_negative_nonfinite_fraction_and_bound(self):
  for raw in [True,-1,float('nan'),float('inf'),1.0,10000001,'23']:
   with self.subTest(raw=repr(raw)):
    u=e.usage(self.root,{'input_tokens':raw},True);self.assertIsNone(u['input_tokens']);self.assertTrue(u['invalid_reports']);json.dumps(u,allow_nan=False);self.assertTrue(a.check_usage(u))
 def test_conflicting_valid_reports_are_not_silently_selected(self):
  self.envelope(prompt_eval_count=24);u=e.usage(self.root,{'input_tokens':23,'output_tokens':11,'cached_input_tokens':5},True,model='qwen2.5:3b');self.assertIsNone(u['input_tokens']);self.assertEqual(u['output_tokens'],11);self.assertIn('input_tokens',u['count_conflicts']);self.assertEqual(u['cache_accounting'],'conflict');self.assertTrue(a.check_usage(u))
 def test_invalid_envelope_preserved_with_valid_metadata(self):
  self.envelope(prompt_eval_count=True);u=e.usage(self.root,{'input_tokens':23},True,model='qwen2.5:3b');self.assertEqual(u['input_tokens'],23);self.assertEqual(u['invalid_reports'][0]['raw'],True)
 def test_wrong_model_reports_not_approved_counts(self):
  self.envelope(model='other');u=e.usage(self.root,{},True,model='qwen2.5:3b');self.assertIsNone(u['input_tokens']);self.assertTrue(u['invalid_reports']);self.assertTrue(a.check_usage(u))
 def test_cache_inconsistency_not_coerced(self):
  u=e.usage(self.root,{'input_tokens':23,'cached_input_tokens':25},True);self.assertEqual(u['cached_input_tokens'],25);self.assertEqual(u['cache_accounting'],'inconsistent');self.assertIsNone(u['uncached_input_tokens'])
 def test_received_terminal_before_file_available(self):
  raw=e.compact({'done':True,'model':'qwen2.5:3b','prompt_eval_count':23,'eval_count':11,'prompt_eval_cached_count':5})+b'\n'
  cap=types.SimpleNamespace(lock=threading.Lock(),data=bytearray(raw),complete=False,error=None)
  u=e.usage(self.root,{},True,capture=cap,model='qwen2.5:3b');self.assertEqual(u['input_tokens'],23);self.assertEqual(u['output_tokens'],11);self.assertEqual(u['reports'][-1]['evidence']['raw_sha256'],e.sha(raw));self.assertFalse((self.root/'envelope.json').exists())
 def test_published_metadata_is_deep_and_immutable_to_producer(self):
  box=a.MetadataReports(self.root);meta={'input_tokens':23,'backend_timings':{'eval_duration':41}};box.publish(meta);meta['backend_timings']['eval_duration']=99
  self.assertEqual(box.snapshot()['backend_timings']['eval_duration'],41);self.assertEqual(e.read(self.root/'accounting-metadata-0001.json')['metadata']['backend_timings']['eval_duration'],41)
 def test_late_metadata_append_does_not_rewrite_outcome(self):
  u=e.usage(self.root,{},True);out={'status':'uncertain','dispatch_entered':True,'usage':u};e.put(self.root/'outcome.json',out);original=(self.root/'outcome.json').read_bytes()
  box=a.MetadataReports(self.root);box.publish({'input_tokens':23,'output_tokens':11,'cached_input_tokens':5});p,v=a.reconcile(self.root,'qwen2.5:3b')
  self.assertEqual(v['usage']['input_tokens'],23);self.assertEqual((self.root/'outcome.json').read_bytes(),original);self.assertEqual(v['original_status'],'uncertain');self.assertEqual(v['attempts_added'],0);self.assertFalse(v['request_deadline_extended']);self.assertTrue(e.read(self.root/'accounting-metadata-0001.json')['after_outcome'])
  q,_=a.reconcile(self.root,'qwen2.5:3b');self.assertNotEqual(p,q)
 def test_late_envelope_reconciles_missing_original_report(self):
  u=e.usage(self.root,{},True);e.put(self.root/'outcome.json',{'status':'uncertain','dispatch_entered':True,'usage':u});original=(self.root/'outcome.json').read_bytes();self.envelope();_,v=a.reconcile(self.root,'qwen2.5:3b')
  self.assertIsNone(u['input_tokens']);self.assertEqual(v['usage']['input_tokens'],23);self.assertTrue(a.check_usage(v['usage']));self.assertEqual((self.root/'outcome.json').read_bytes(),original)
 def test_late_conflict_preserves_both_reports(self):
  u=e.usage(self.root,{'input_tokens':23},True);e.put(self.root/'outcome.json',{'status':'uncertain','dispatch_entered':True,'usage':u});self.envelope(prompt_eval_count=24);_,v=a.reconcile(self.root,'qwen2.5:3b');self.assertIsNone(v['usage']['input_tokens']);self.assertIn('input_tokens',v['usage']['count_conflicts'])

def test_multiple_terminal_counter_conflicts_are_preserved_and_asof_is_last_observation(tmp_path):
 raw=b'\n'.join(e.compact({'done':True,'model':'synthetic','prompt_eval_count':n,'eval_count':2}) for n in [10,20])
 cap=types.SimpleNamespace(lock=threading.Lock(),data=bytearray(raw),complete=True,error=None)
 usage=a.usage(tmp_path,{},True,capture=cap,model='synthetic',read_artifacts=False)
 assert usage['input_tokens'] is None and usage['count_conflicts']['input_tokens'] and a.check_usage(usage)
 assert {x['value'] for x in usage['count_provenance']['input_tokens']}=={10,20}
 assert all(x.get('observed',usage['as_of'])['monotonic']<=usage['as_of']['monotonic'] for x in usage['reports'])

if __name__=='__main__':unittest.main(verbosity=2)
