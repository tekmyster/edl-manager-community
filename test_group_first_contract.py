"""Requester order is intentional; omission and output member order remain legal."""
from test_generation_fixtures import decision
import copy,json
import pytest,requests
import behavior_ai as ai
import behavior_generation as gen
import behavior_synthesis as synth
from test_source_observations import linked_packet
from test_generation_choices import transport

PRIOR_ORDER=['generation_schema_version','packet_id','classification','maliciousness_confidence','automation','intent','observations','attack_techniques','d3fend_context','actor_correlation','observable_synthesis']

def omitted(packet):
 wire=gen.example(packet);wire.update(maliciousness_confidence=0)
 wire['observations']={key:decision('omit', packet=packet, key=key) for key in wire['observations']}
 return wire

def prepared(body):
 request=requests.Request('POST','https://offline.invalid/api/chat',json=body).prepare()
 assert 'Authorization' not in request.headers
 return request.body

def test_nonempty_groups_are_first_at_infer_requester_and_prepared_body_boundary():
 p=linked_packet();original=copy.deepcopy(p)
 (value,metadata),calls=transport(p,omitted(p));body=calls[0]
 wanted=['observable_synthesis',*PRIOR_ORDER[:-1]]
 assert list(body['format']['properties'])==body['format']['required']==wanted
 assert list(json.loads(prepared(body))['format']['properties'])==wanted
 assert body['messages'][0]['content']==gen.INSTRUCTION
 assert body['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}
 assert p==original and value['observable_synthesis']==value['findings']==[]
 assert metadata['prompt_version']=='behavior-3.32' and metadata['generation_schema_version']=='joint-answer-draft-1'

def test_empty_groups_keep_old_schema_property_and_required_order():
 p={'packet_id':'empty','events':[],'context':[],'coverage':'saved_samples'}
 (value,_),calls=transport(p,omitted(p));body=calls[0]
 assert list(body['format']['properties'])==body['format']['required']==PRIOR_ORDER
 assert not body['format']['properties']['observable_synthesis']['properties']
 assert not value['observable_synthesis'] and value['classification']=='inconclusive'

@pytest.mark.parametrize('select',[False,True])
@pytest.mark.parametrize('member_order',['prior','group_first','reverse'])
def test_output_member_order_is_not_an_acceptance_requirement(select,member_order):
 p=linked_packet();wire=omitted(p);groups=synth.offers(p)
 if select:wire['observable_synthesis'][next(iter(groups))]='reported_session_sequence'
 order=PRIOR_ORDER if member_order=='prior' else ['observable_synthesis',*PRIOR_ORDER[:-1]] if member_order=='group_first' else PRIOR_ORDER[::-1]
 wire={key:wire[key] for key in order}
 (value,_),calls=transport(p,wire)
 ai.validate_result(value,p,[],{})
 assert value['intent']==value['automation']=={'classification':'unknown','confidence':0}
 assert value['classification']=='inconclusive' and value['maliciousness_confidence']==0
 assert bool(value['observable_synthesis'])==select
 if select:
  group=next(iter(groups.values()))
  assert value['observable_synthesis'][0]['source_tuples']==group['source_tuples']
  assert value['observable_synthesis'][0]['evidence_ids']==group['evidence_ids']
  assert 'execution' in value['analysis_summary']

def test_canonical_loader_dict_equality_cannot_prove_property_order():
 p=linked_packet();_,calls=transport(p,omitted(p));body=calls[0]
 canonical=json.loads(json.dumps(body,sort_keys=True))
 assert body==canonical
 assert list(body['format']['properties'])[0]=='observable_synthesis'
 assert list(canonical['format']['properties'])[0]!='observable_synthesis'
 assert prepared(body)!=prepared(canonical)
 # Arrays retain order through canonicalization; this does not restore the
 # properties-object order or prove how a provider builds its grammar.
 assert body['format']['required']==canonical['format']['required']
