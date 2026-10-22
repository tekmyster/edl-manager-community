"""Comparison witnesses are model decisions, never a utility oracle/filter."""
import copy,json,itertools
import pytest
import behavior_ai as ai,behavior_generation as gen,behavior_revision as rev,behavior_synthesis as sy,behavior_tokens
from behavior_pipeline import Pipeline
from test_pipeline_support import SyntheticCounter,choices
from test_source_observations import linked_packet

def plan_and_revision(monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 plan=Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},linked_packet(),[],{})
 draft=choices(plan.request,groups='selected',purpose='detail');canonical=plan.decode(draft)
 return plan,plan._revision('synthetic-parent',json.dumps(draft),canonical,sy.presentation(canonical,plan.packet['events']))

def test_comparison_precedes_purpose_and_cannot_force_or_filter_any_choice(monkeypatch):
 plan,final=plan_and_revision(monkeypatch);before=copy.deepcopy(final.request)
 facts=gen.offers(plan.packet,[],{})[0]['facts']
 specs=final.request['format']['properties']['observations']['properties']
 for key,fact in facts.items():
  assert list(specs[key]['properties'])==['comparison','purpose']
  for comparison,purpose in itertools.product(rev.COMPARISONS,specs[key]['properties']['purpose']['enum']):
   wire=choices(final.request,groups='omit');wire['observations']={key:{'comparison':comparison,'purpose':purpose}}
   result=final.decode(wire)
   assert result['findings']==([] if purpose=='omit' else [fact])
   assert 'comparison' not in result and result['observable_synthesis']==[]
 # Optional absence, explicit all-omit, and generic selection remain legal.
 for purpose in (None,'omit'):
  assert final.decode(choices(final.request,purpose=purpose))['findings']==[]
 assert final.request==before
 assert plan.request['format']['properties']['observations']['properties'][next(iter(facts))]['type']=='string'

@pytest.mark.parametrize('bad',['detail',{'purpose':'detail'}, {'comparison':'invented','purpose':'detail'}, {'comparison':'unresolved','purpose':'detail','reason':'PRIVATE'}, {'comparison':'unresolved','purpose':'finding'}])
def test_malformed_final_rejected_without_repair(monkeypatch,bad):
 plan,final=plan_and_revision(monkeypatch);wire=choices(final.request);wire['observations']={next(iter(gen.offers(plan.packet,[],{})[0]['facts'])):bad};saved=copy.deepcopy(wire)
 with pytest.raises(ValueError):final.decode(wire)
 assert wire==saved

def test_counterevidence_roles_preserved_without_witness_authority():
 original={'properties':{'observations':{'type':'object','properties':{'a':{'type':'string','enum':['omit','detail','support','counterevidence']}},'required':[]}}}
 new=rev.selection_schema(original)
 assert new['properties']['observations']['properties']['a']['properties']['purpose']==original['properties']['observations']['properties']['a']
 assert original['properties']['observations']['properties']['a']['type']=='string'

def test_raw_source_and_provisional_data_cannot_set_comparison_choices(monkeypatch):
 plan,final=plan_and_revision(monkeypatch)
 assert final.request['format']['properties']['generation_schema_version']['enum']==['joint-answer-revision-3']
 wrong=choices(final.request,purpose='detail');wrong['draft_binding']='0'*64
 with pytest.raises(ValueError):final.decode(wrong)
 assert final.receipt['draft_wire_sha256']
