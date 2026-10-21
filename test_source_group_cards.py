"""Input representation and admission checks; no model utility claims."""
import copy,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
import behavior_synthesis as synth
from test_source_observations import linked_packet
from test_historical_prompt import expand


def test_cards_bind_sanitized_source_accounts_meanings_and_caveats_without_output_changes():
 p=linked_packet();before=copy.deepcopy(p);schema,prompt=gen.prepare(p,[],{})
 for key,group in synth.offers(p).items():
  card=prompt['synthesis_options'][key]
  assert card=={'kind':group['kind'],'evidence_ids':group['evidence_ids'],'interpretations':group['interpretations'],
               'reported_account':synth.describe(group),'interpretation_meanings':{m:synth.MEANINGS[m] for m in group['interpretations']},'uncertainty':synth.LIMITS[group['kind']]}
  assert schema['properties']['observable_synthesis']['properties'][key]['enum']==['omit',*group['interpretations']]
  assert 'reported_account' not in schema['properties'] and 'source_tuples' not in card
 assert p==before and expand(prompt)['packet']==p


def test_cards_do_not_copy_raw_secret_fields_or_turn_source_instructions_into_accounts():
 p=linked_packet()
 for event in p['events']:
  event.update(input='PRIVATE-COMMAND',password='PRIVATE-PASSWORD',body='PRIVATE-BODY')
  event['source_observation']['input']='PRIVATE-SOURCE-INSTRUCTION'
 _,prompt=gen.prepare(p,[],{})
 cards=json.dumps(prompt['synthesis_options'])
 assert 'PRIVATE' not in cards and 'permission change' in cards
 # Packet privacy is owned by the upstream sanitizer; the card adds no raw fields.


def test_card_fields_are_input_only_and_cannot_be_authored_in_choices_or_saved_tuples():
 p=linked_packet();wire=gen.example(p);key=next(iter(wire['observable_synthesis']))
 wire['observable_synthesis'][key]='reported_session_sequence'
 value=gen.decode(wire,p,[],{});ai.validate_result(value,p,[],{})
 bad=copy.deepcopy(wire);bad['reported_account']='invented'
 with pytest.raises(ValueError):gen.decode(bad,p,[],{})
 bad=copy.deepcopy(wire);bad['observable_synthesis'][key]={'reported_account':'invented'}
 with pytest.raises(ValueError):gen.decode(bad,p,[],{})
 bad=copy.deepcopy(value);bad['observable_synthesis'][0]['source_tuples'][0]['reported_account']='invented'
 with pytest.raises(ValueError):ai.validate_result(bad,p,[],{})


def test_no_group_input_is_unchanged_and_no_context_is_fabricated():
 p={'packet_id':'empty','events':[],'context':[],'coverage':'saved_samples'}
 schema,prompt=gen.prepare(p,[],{})
 assert prompt['synthesis_options']=={} and schema['properties']['observable_synthesis']['properties']=={}
 wire=gen.example(p);value=gen.decode(wire,p,[],{})
 assert value['observable_synthesis']==[] and value['intent']==value['automation']=={'classification':'unknown','confidence':0}


def test_base_card_bytes_are_admitted_exactly_or_rejected_without_clipping(monkeypatch):
 p=linked_packet();p['context']=[{'note':'é漢🙂"\\'}]
 monkeypatch.setattr(ai,'now',lambda:'2026-10-19T00:00:00+00:00')
 _,prompt=gen.prepare(p,[],{});p['context'][0]['padding']=''
 _,prompt=gen.prepare(p,[],{});p['context'][0]['padding']='x'*(18000-len(gen.prompt_json(__import__('behavior_representation').factor(prompt)).encode()))
 before=copy.deepcopy(p);_,exact,selected,meta=gen.prepare_bounded(p,[],{})
 assert len(gen.prompt_json(exact).encode())==18000 and p==before and not selected
 assert '\\ud83d\\ude42' in gen.prompt_json(exact)
 p['context'][0]['padding']+='x'
 with pytest.raises(ValueError) as caught:gen.prepare_bounded(p,[],{})
 saved=caught.value._edl_failure_metadata
 assert saved['input_preparation']['user_prompt_bytes'] is None and saved['wire_packet_ids']==[]
 assert saved['input_preparation']['base_prompt_bytes']==18001 and p['context'][0]['padding']==before['context'][0]['padding']+'x'
