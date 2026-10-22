"""Scalar draft choices and immutable replacement binding; no comparison oracle."""
import copy,json
import pytest
import behavior_ai as ai,behavior_generation as gen,behavior_tokens
from behavior_pipeline import Pipeline,VERSION as TOPOLOGY
from test_source_observations import linked_packet
from test_generation_choices import transport
from test_pipeline_support import SyntheticCounter,choices


def test_original_statement_choices_remain_scalar_lossless_and_optional():
 packet=linked_packet();schema,logical=gen.prepare(packet,[],{});wire=gen.example(packet)
 for key,fact in gen.offers(packet,[],{})[0]['facts'].items():
  spec=schema['properties']['observations']['properties'][key]
  assert spec['enum']==['omit','detail','support']
  for purpose in spec['enum']:
   wire['observations']={key:purpose};result=gen.decode(wire,packet,[],{});ai.validate_result(result,packet,[],{})
   assert result['findings']==([] if purpose=='omit' else [fact])
   assert not result['contradictory_evidence']
 assert logical['offered']['facts'] and logical['summary_fields_definition']

@pytest.mark.parametrize('bad',[{'purpose':'detail'},{'reason':'PRIVATE','purpose':'detail'},['detail','support'],{'field':'source','compared_account':'','purpose':'detail'},None,True])
def test_old_witness_and_authored_values_fail_without_leak(bad):
 packet=linked_packet();wire=gen.example(packet);wire['observations']={next(iter(wire['observations'])):bad};before=copy.deepcopy(wire)
 with pytest.raises(ai.ModelOutputError) as error:transport(packet,wire)
 assert error.value.code=='invalid_assessment' and 'PRIVATE' not in json.dumps(error.value.metadata) and before==wire


def test_immutable_final_decoder_and_private_binding_without_expensive_decode(monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());packet=linked_packet();cfg={**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64}
 plan=Pipeline(cfg,packet,[],{});draft=choices(plan.request,groups='selected',purpose='detail');raw=json.dumps(draft);canonical=plan.decode(draft)
 import behavior_synthesis as sy
 revision=plan._revision('synthetic-proof-parent',raw,canonical,sy.presentation(canonical,packet['events']))
 final=choices(revision.request,groups='omit',purpose='detail');expected=revision.decode(final)
 assert expected['findings']==canonical['findings'] and expected['observable_synthesis']==[]
 assert plan.identity['topology']==TOPOLOGY=='full-joint-draft-revision-1'
 assert plan.identity['prompt_version']=='behavior-3.40' and plan.generation_version==gen.FINAL_VERSION==ai.GENERATION_SCHEMA_VERSION
 assert gen.VERSION!=gen.FINAL_VERSION
 for name in ['prepare','prepare_bounded','offers','annotated_facts','statement_fields']:
  monkeypatch.setattr(gen,name,lambda *a,**kw:pytest.fail('No request/schema reconstruction during decode'))
 monkeypatch.setattr(behavior_tokens,'load',lambda *a:pytest.fail('No tokenization during final decode'))
 changed=revision.request;changed['format']['properties'].clear();revision.receipt.clear()
 assert revision.decode(final)==expected
 with pytest.raises(AttributeError):revision.request_hash='PRIVATE'
 final['draft_binding']='0'*64
 with pytest.raises(ValueError):revision.decode(final)


def test_exact_raw_bytes_change_binding_and_old_final_rejects(monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());packet=linked_packet();plan=Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},packet,[],{})
 import behavior_synthesis as sy
 wire=choices(plan.request);canonical=plan.decode(wire);render=sy.presentation(canonical,packet['events'])
 a=plan._revision('parent',json.dumps(wire),canonical,render);b=plan._revision('parent',json.dumps(wire,indent=2),canonical,render)
 assert a.input_key!=b.input_key and a.receipt['draft_wire_sha256']!=b.receipt['draft_wire_sha256']
 with pytest.raises(ValueError):b.decode(choices(a.request))
 for changed in (dict(canonical,classification='benign'),):
  with pytest.raises(ValueError):plan._revision('parent',json.dumps(wire),changed,render)
 with pytest.raises(ValueError):plan._revision('parent',json.dumps(wire),canonical,{'PRIVATE':'altered rendering'})
