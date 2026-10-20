"""Sparse observation contract: legal omission without filtering any offered role."""
import copy,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
from test_source_observations import linked_packet
from test_generation_slots import positive
from test_generation_choices import transport

@pytest.fixture(autouse=True)
def fixed_time(monkeypatch):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00')

def sparse(packet):
 wire=gen.example(packet);wire.update(maliciousness_confidence=0);wire['observations']={}
 return wire

def test_sparse_empty_and_dense_explicit_omit_are_identical_without_forced_selections():
 p=positive();wire=sparse(p);before=copy.deepcopy(wire);value,calls=transport(p,wire);dense=copy.deepcopy(wire)
 tables,_=gen.offers(p,[],{});dense['observations']={k:'omit' for k in tables['facts']}
 assert value[0]==transport(p,dense)[0][0] and wire==before
 assert value[0]['findings']==value[0]['contradictory_evidence']==[]
 assert value[0]['intent']==value[0]['automation']=={'classification':'unknown','confidence':0}
 spec=calls[0]['format']['properties']['observations']
 assert spec['required']==[] and spec['additionalProperties'] is False
 assert list(spec['properties'])==list(tables['facts'])
 assert 'observations' in calls[0]['format']['required']
 assert list(calls[0]['format']['properties'])[0]=='observable_synthesis'


def test_sparse_one_detail_retains_exact_statement_and_citations_with_group():
 p=linked_packet();tables,_=gen.offers(p,[],{});wire=sparse(p)
 wire['observable_synthesis'][next(iter(wire['observable_synthesis']))]='reported_session_sequence'
 for key,fact in tables['facts'].items():
  if len(fact['evidence_ids'])!=2:continue
  wire['observations']={key:'finding'};value=transport(p,wire)[0][0]
  assert value['findings']==[fact] and len(value['observable_synthesis'])==1
  assert 'after its cited connection' in fact['summary']
  assert ('execution is unverified' in fact['summary']) or ('network transfer is unverified' in fact['summary'])
  assert 'permission change' in fact['summary'] if 'shell input' in fact['summary'] else True
  ai.validate_result(value,p,[],{})


def test_sparse_each_legal_role_is_available_and_one_identity_cannot_take_two_roles():
 p=positive();tables,_=gen.offers(p,[],{});schema,prompt=gen.prepare(p,[],{})
 for key,fact in tables['facts'].items():
  assert {k:v for k,v in prompt['offered']['facts'][key].items() if k not in ('record_fields','record_provenance')}=={**fact,'allowed_roles':schema['properties']['observations']['properties'][key]['enum']}
  for role in schema['properties']['observations']['properties'][key]['enum']:
   wire=sparse(p);wire['observations']={key:role};value=transport(p,wire)[0][0]
   assert value['findings']==([fact] if role=='finding' else [])
   assert value['contradictory_evidence']==([fact] if role=='counterevidence' else [])
 key=next(iter(tables['facts']));wire=sparse(p);wire['observations']={key:['finding','counterevidence']}
 with pytest.raises(ai.ModelOutputError):transport(p,wire)
 with pytest.raises(gen.ChoiceError):gen.parse_wire('{"observations":{"'+key+'":"finding","'+key+'":"counterevidence"}}')


def test_sparse_generic_label_selection_is_not_postfiltered_or_withheld():
 p={'packet_id':'generic-source','coverage':'saved_samples','events':[{'id':'event','source':'sensor-source','sensor':'detector','action':'detector','seen':'2026-10-17T10:00:00+00:00'}],'context':[]}
 tables,_=gen.offers(p,[],{});assert len(tables['facts'])==1;key=next(iter(tables['facts']))
 wire=sparse(p);wire['observations']={key:'finding'}
 assert transport(p,wire)[0][0]['findings']==[tables['facts'][key]]


def test_sparse_malicious_support_cannot_be_evaded_by_omitting_a_support_key():
 p=linked_packet();tables,coverage=gen.offers(p,[],{});wire=sparse(p);wire.update(classification='malicious',maliciousness_confidence=.5)
 pair=coverage['malicious_support_pairs'][0];wire['observations']={key:'finding' for key in pair}
 assert transport(p,wire)[0][0]['classification']=='malicious'
 del wire['observations'][pair[1]]
 with pytest.raises(ai.ModelOutputError):transport(p,wire)
 wire['observations']={}
 with pytest.raises(ai.ModelOutputError):transport(p,wire)


def test_sparse_positive_context_can_support_benign_or_remain_opposing_context():
 p=positive();tables,_=gen.offers(p,[],{});key=next(iter(tables['counterevidence']));wire=sparse(p)
 wire['observations']={key:'counterevidence'};value=transport(p,wire)[0][0]
 assert value['classification']=='inconclusive' and value['contradictory_evidence']==[tables['facts'][key]]
 wire['observations']={key:'finding'};wire['classification']='benign'
 assert transport(p,wire)[0][0]['classification']=='benign'
 wire['observations']={}
 with pytest.raises(ai.ModelOutputError):transport(p,wire)

@pytest.mark.parametrize('mutation',[
 lambda w:w.pop('observations'),
 lambda w:w['observations'].update({'unoffered':'finding'}),
 lambda w:w['observations'].update({next(iter(gen.offers(linked_packet(),[],{})[0]['facts'])):'counterevidence'}),
 lambda w:w.update(generation_schema_version='grounded-groups-8'),
 lambda w:w.pop('d3fend_context'),
 lambda w:w.update(extra='invented'),
])
def test_sparse_does_not_relax_other_required_fields_offers_or_role_whitelists(mutation):
 p=linked_packet();wire=sparse(p);mutation(wire)
 with pytest.raises(ai.ModelOutputError):transport(p,wire)


def test_optional_object_validation_keeps_canonical_result_fields_required():
 p=linked_packet();value=transport(p,sparse(p))[0][0]
 for key in ai.RESPONSE_SCHEMA['required']:
  bad=copy.deepcopy(value);del bad[key]
  with pytest.raises(ValueError):ai.validate_result(bad,p,[],{})
 bad=copy.deepcopy(value);bad['invented']=[]
 with pytest.raises(ValueError):ai.validate_result(bad,p,[],{})


def test_sparse_does_not_make_mapping_member_slots_optional():
 p=linked_packet();registry={'attack':{'T1059':'Command and Scripting Interpreter'},'d3fend':{}}
 wire=gen.example(p,registry=registry);wire['observations']={}
 assert wire['attack_techniques']
 wire['attack_techniques'].pop(next(iter(wire['attack_techniques'])))
 with pytest.raises(ai.ModelOutputError):transport(p,wire,registry=registry)
