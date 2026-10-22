"""Choice protocol mechanics only, with no model calls or correctness labels."""
from test_generation_fixtures import decision
import copy,json
import pytest
from behavior_generation import VERSION,offers,prepare,decode,example,ChoiceError
from behavior_ai import infer,DEFAULTS,validate_result,ModelOutputError
from behavior_grounding import contract,mapping_text
from test_generation_fixtures import observation_roles
from test_source_observations import linked_packet
from test_behavior_taxonomy import catalog,event

def transport(packet,wire,candidates=None,registry=None):
 calls=[]
 class Response:
  status_code=200
  def close(self):pass
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','message':{'content':json.dumps(wire)}}).encode()
 def send(*args,**kw):calls.append(kw['json']);return Response()
 result=infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,candidates or [],registry or {},'',requester=send)
 return result,calls

def test_conservative_choice_round_trip_has_exact_bound_facts_and_zero_unknowns():
 p=linked_packet();wire=example(p);(value,metadata),calls=transport(p,wire)
 assert value['findings'][0] in contract(p,{})['facts'] and value['automation']==value['intent']=={'classification':'unknown','confidence':0}
 assert metadata['generation_schema_version']==VERSION and metadata['prompt_version']=='behavior-3.41'
 assert calls[0]['stream'] is True and calls[0]['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}
 assert set(calls[0]['format']['properties'])==set(wire)
 assert not {'analysis_summary','limitations','evidence_ids','explanation'}&set(wire)

def test_complete_pair_optional_malicious_class_still_requires_full_cited_support():
 p=linked_packet();table,coverage=offers(p,[],{})
 wire=example(p);wire['classification']='malicious';pair=coverage['malicious_support_pairs'][0];observation_roles(wire,pair)
 accepted=transport(p,wire)[0][0];validate_result(accepted,p,[],{})
 assert {e for f in accepted['findings'] for e in f['evidence_ids']}>=set(contract(p,{})['malicious_support'][0]['evidence_ids'])
 observation_roles(wire,pair[:1])
 with pytest.raises(ModelOutputError):transport(p,wire)
 observation_roles(wire)
 with pytest.raises(ModelOutputError):transport(p,wire)

@pytest.mark.parametrize('mutation',[
 lambda w:w.update(observations=list(w['observations'])),
 lambda w:w.update(contradictory_evidence=list(w['observations'])),
 lambda w:w['observations'].update({'PRIVATE-UNKNOWN-CHOICE':'detail'}),
 lambda w:w.update(packet_id='other-packet'),
 lambda w:w.update(generation_schema_version='grounded-observations-3'),
 lambda w:w.update(analysis_summary='PRIVATE-TEXT'),
 lambda w:w.update(automation={'classification':'unknown','confidence':.9}),
 lambda w:w.update(automation=[{'choice_id':'unknown','confidence':.9}]),
 lambda w:w.update(maliciousness_confidence=90),
 lambda w:w.update(maliciousness_confidence=True),
])
def test_invalid_choice_rejects_whole_output_and_retains_no_private_value(mutation):
 p=linked_packet();wire=example(p);mutation(wire)
 with pytest.raises(ModelOutputError) as caught:transport(p,wire)
 assert caught.value.code=='invalid_assessment' and 'PRIVATE' not in json.dumps(caught.value.metadata)

def test_fact_choice_cannot_be_reused_across_packets_or_bind_new_citations():
 p=linked_packet();other=copy.deepcopy(p);other['packet_id']='other';wire=example(p)
 assert set(offers(p,[],{})[0]['facts']).isdisjoint(offers(other,[],{})[0]['facts'])
 with pytest.raises(ModelOutputError):transport(other,{**wire,'packet_id':'other'})
 wire['observations'][next(iter(wire['observations']))]={'evidence_ids':['PRIVATE']}
 with pytest.raises(ModelOutputError):transport(p,wire)

def test_mapping_choice_renders_exact_explanation_and_complete_technique_refs(catalog):
 p={'packet_id':'mappings','coverage':'saved_samples','events':[event('a','powershell execution'),event('b','authentication failure'),event('c','authentication failure')],'context':[]}
 table,_=offers(p,[],catalog);wire=example(p,registry=catalog)
 ident=next(k for k,v in table['attack'].items() if v['technique_id']=='T1110');wire['attack_techniques'][ident]='include'
 d3=next(k for k,v in table['d3fend'].items() if v['technique_id']=='D3-ANET');wire['d3fend_context'][d3]='include'
 value=transport(p,wire,registry=catalog)[0][0]
 assert value['attack_techniques'][0]['evidence_ids']==['b','c']
 assert value['d3fend_context'][0]['explanation']==mapping_text('d3fend','D3-ANET',catalog['d3fend']['D3-ANET'])
 for wrong in ([ident,ident],[d3],[{'choice_id':ident,'explanation':'PRIVATE'}]):
  wire['attack_techniques']=wrong
  with pytest.raises(ModelOutputError):transport(p,wire,registry=catalog)

def test_known_hypotheses_require_offered_scoped_choice_and_bounded_confidence(catalog):
 p={'packet_id':'hypotheses','events':[event('a','authentication failure'),event('b','authentication failure')],'context':[],'coverage':'saved_samples'}
 table,_=offers(p,[],catalog);wire=example(p,registry=catalog)
 wire['automation']=[{'choice_id':next(iter(table['automation'])),'confidence':.9}]
 assert transport(p,wire,registry=catalog)[0][0]['automation']['classification']=='credential_attack_automation'
 wire['automation'][0]['confidence']=1.2
 with pytest.raises(ModelOutputError):transport(p,wire,registry=catalog)

def test_relation_choice_requires_both_real_sides_and_candidate_scope():
 p=linked_packet();p['events'][1].update(path='/distinctive/request',method='POST');e=p['events'][1]
 candidate={'candidate_id':'candidate-one','current_events':[e],'historical_events':[{**e,'id':'historical'}]}
 table,coverage=offers(p,[candidate],{});assert coverage['relation_pairs_examined']==1
 wire=example(p,[candidate]);wire['actor_correlation']=[{'choice_id':next(iter(table['relations'])),'confidence':.4}]
 value=transport(p,wire,[candidate])[0][0]
 assert value['actor_correlation'][0]['evidence_ids']==[e['id'],'historical']
 other={**candidate,'candidate_id':'candidate-two'}
 with pytest.raises(ModelOutputError):transport(p,wire,[other])
 unrelated=copy.deepcopy(candidate);unrelated['historical_events'][0]['path']='/different'
 with pytest.raises(ModelOutputError):transport(p,wire,[unrelated])
 wire['actor_correlation'][0]['current_evidence_ids']=['PRIVATE']
 with pytest.raises(ModelOutputError):transport(p,wire,[candidate])

def test_relation_choices_and_comparisons_are_bounded():
 p=linked_packet();p['events']=[{**p['events'][1],'id':str(i),'client_claim':{'label':'curl'}} for i in range(12)]
 c={'candidate_id':'peer','current_events':p['events'],'historical_events':[{**e,'id':'historical-'+e['id']} for e in p['events']]}
 table,coverage=offers(p,[c],{})
 assert len(table['relations'])==8 and coverage['relation_pairs_examined']==64 and coverage['available_relations']==64

def test_valid_new_wire_never_salvages_or_changes_legacy_invalid_assessment():
 from behavior_grounding import example as stored
 p=linked_packet();legacy=stored(p);legacy['automation']['confidence']=.9;before=copy.deepcopy(legacy)
 with pytest.raises(ValueError):validate_result(legacy,p,[],{})
 with pytest.raises(ModelOutputError):transport(p,legacy)
 assert legacy==before

def test_even_valid_legacy_result_is_not_a_valid_new_generation_payload():
 from behavior_grounding import example as stored
 p=linked_packet();legacy=stored(p);validate_result(legacy,p,[],{})
 with pytest.raises(ModelOutputError):transport(p,legacy)

def test_new_renderer_does_not_mutate_packet_wire_or_offers_and_canonical_guard_is_mandatory(monkeypatch):
 import behavior_ai
 p=linked_packet();wire=example(p);before=copy.deepcopy((p,wire));rendered=decode(wire,p,[],{})
 assert rendered['findings'][0] in contract(p,{})['facts'] and (p,wire)==before
 calls=[]
 def guard(*args):calls.append(1);raise ValueError('Canonical guard rejected')
 monkeypatch.setattr(behavior_ai,'validate_result',guard)
 with pytest.raises(ModelOutputError):transport(p,wire)
 assert calls==[1] and (p,wire)==before

def test_benign_requires_actual_cited_positive_context_and_malicious_cannot_borrow_contradictions():
 p=linked_packet();p['context']=[{'id':'ctx-positive','kind':'intelligence','provider':'crawler','status':'ok','verified':True,'cache_fresh':True,'expires':'2099-01-01T00:00:00+00:00'}]
 table,c=offers(p,[],{});wire=example(p);wire['classification']='benign'
 assert transport(p,wire)[0][0]['classification']=='benign'
 observation_roles(wire,[k for k,v in table['facts'].items() if 'ctx-positive' not in v['evidence_ids']][:1])
 with pytest.raises(ModelOutputError):transport(p,wire)
 wire['classification']='malicious';pair=c['malicious_support_pairs'][0];observation_roles(wire,pair[:1]);wire['observations'][pair[1]]=decision('counterevidence', packet=p, key=pair[1])
 with pytest.raises(ModelOutputError):transport(p,wire)

def test_repeated_current_record_cannot_be_its_own_historical_relationship():
 p=linked_packet();e=p['events'][1];e['client_claim']={'label':'curl'}
 candidate={'candidate_id':'same-copy','current_events':[e],'historical_events':[e]}
 assert offers(p,[candidate],{})[0]['relations']=={}
