"""Lossless wire input, byte boundaries and persisted provenance; no model calls."""
from test_pipeline_mock import stage_mock
import copy,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
from behavior_grounding import RELATION,ALTERNATIVE
from test_generation_choices import transport
from test_generation_slots import positive


def pair():
 p=positive();e=p['events'][1];e.update(path='/distinctive/request',method='POST')
 common={'collector':'saved source sample','collector_agent':'','detail':'sample','time_basis':'native event'}
 for event in p['events']:event['provenance']={**common,**event.get('provenance',{})}
 c={'candidate_id':'peer','current_events':[copy.deepcopy(e)],'historical_events':[{**copy.deepcopy(e),'id':'historical'}],'uncertainty':['Shared tools are not identity.']}
 return p,c


def expand(prompt):
 """Independent consumer of the documented wire references."""
 result=copy.deepcopy(prompt);events=list(result['packet']['events'])
 for candidate in result['candidates']:events+=candidate.get('current_events',[])+candidate.get('historical_events',[])
 for event in events:
  provenance=event.get('provenance',{})
  if 'template_ref' in provenance:
   fields=result['provenance_templates'][provenance.pop('template_ref')]
   assert not set(fields)&set(provenance)
   provenance.update(fields)
 own={event['id']:event for event in result['packet']['events']}
 for candidate in result['candidates']:
  if 'current_events' in candidate:candidate['current_events']=[copy.deepcopy(own[event['packet_event_ref']]) if set(event)=={'packet_event_ref'} else event for event in candidate['current_events']]
 for relation in result['offered']['relations'].values():
  relation.update(result[relation.pop('statement_ref')])
 return result


def test_wire_references_preserve_complete_facts_provenance_positive_context_and_relations():
 p,c=pair();before=copy.deepcopy((p,c));tables,_=gen.offers(p,[c],{})
 _,prompt,selected,meta=gen.prepare_bounded(p,[c],{});expanded=expand(prompt)
 assert expanded['packet']==p and expanded['candidates']==[c] and selected==[c]
 assert expanded['offered']['relations']==tables['relations']
 assert prompt['packet']['context']==p['context'] and tables['counterevidence']
 assert meta['wire_candidate_ids']==['peer'] and (p,c)==before
 assert 'provenance_templates' in prompt and prompt['candidates'][0]['current_events']==[{'packet_event_ref':p['events'][1]['id']}]
 assert len(gen.prompt_json(prompt).encode())==meta['input_preparation']['user_prompt_bytes']


@pytest.mark.parametrize('change',[lambda e:e.update(status='403'),lambda e:e['provenance'].update(detail='other'),lambda e:e.update(path='/other'),lambda e:e.update(independent_evidence=1)])
def test_same_id_with_different_source_fields_is_never_replaced_by_event_reference(change):
 p,c=pair();change(c['current_events'][0]);_,prompt=gen.prepare(p,[c],{})
 assert 'packet_event_ref' not in prompt['candidates'][0]['current_events'][0]
 assert expand(prompt)['candidates']==[c]


def test_provenance_factoring_preserves_types_and_existing_reference_named_fields():
 p,c=pair();p['events'][0]['provenance']['typed']=True;c['historical_events'][0]['provenance']['typed']=1
 _,prompt=gen.prepare(p,[c],{});full=expand(prompt)
 assert full['packet']==p and full['candidates']==[c]
 assert 'typed' not in prompt.get('provenance_templates',{}).get('p1',{})
 p['events'][0]['provenance']['template_ref']='source-reported-value'
 _,prompt=gen.prepare(p,[c],{})
 assert 'provenance_templates' not in prompt and prompt['packet']==p


def test_shared_in_memory_provenance_objects_remain_lossless():
 p,c=pair();p['events'][0]['provenance']=p['events'][1]['provenance']
 _,prompt=gen.prepare(p,[c],{})
 assert expand(prompt)['packet']==p and expand(prompt)['candidates']==[c]


def boundary_pair():
 p,c=pair();c['padding']='é漢🙂'
 _,prompt=gen.prepare(p,[c],{});gap=18000-len(gen.prompt_json(prompt).encode())
 assert gap>0;c['padding']+='x'*gap
 return p,c


def legacy_overbudget_pair():
 p,c=boundary_pair();_,prompt=gen.prepare(p,[c],{})
 old={**prompt,'synthesis_options':{key:{k:v[k] for k in ('kind','evidence_ids','interpretations')} for key,v in prompt['synthesis_options'].items()}}
 old=gen.without_summary_fields(old)
 c['padding']+='x'*(len(gen.prompt_json(prompt).encode())-len(gen.prompt_json(old).encode())+1)
 return p,c


def test_exact_escaped_utf8_boundary_keeps_history_and_card_overflow_fails_before_dispatch():
 p,c=boundary_pair();before=copy.deepcopy((p,c))
 _,prompt,selected,meta=gen.prepare_bounded(p,[c],{})
 assert len(gen.prompt_json(prompt).encode('utf-8'))==18000 and selected==[c]
 assert '\\u00e9' in gen.prompt_json(prompt) and 'é' not in gen.prompt_json(prompt)
 assert meta['input_preparation']['omission_reason']=='none' and (p,c)==before
 c['padding']+='x'
 with pytest.raises(ValueError) as exact:gen.prepare_bounded(p,[c],{})
 assert exact.value._edl_failure_metadata['input_preparation']['considered_prompt_bytes']==18001
 def forbidden(*a,**kw):pytest.fail('Card-induced history loss reached transport')
 with pytest.raises(ValueError) as caught:ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1'},p,[c],{},'',requester=forbidden)
 meta=caught.value._edl_failure_metadata
 assert meta['wire_packet_ids']==meta['wire_candidate_ids']==[] and meta['historical_windows_supplied']==0
 # infer selects registry metadata before preparing; its honest byte count can
 # exceed the direct empty-registry assembly above without dispatching either.
 assert meta['input_preparation']['considered_prompt_bytes']>=18001 and meta['input_preparation']['user_prompt_bytes'] is None
 assert meta['input_preparation']['omission_reason']=='summary_fields_exceed_input_limit'
 assert meta['input_preparation']['omitted_candidate_ids']==['peer'] and (p,c)==(before[0],{**before[1],'padding':before[1]['padding']+'x'})
 assert meta['failure_diagnostic']['phase']=='request_preparation'


def test_history_already_overbudget_without_cards_preserves_original_omission_policy():
 p,c=legacy_overbudget_pair();_,prompt,selected,meta=gen.prepare_bounded(p,[c],{})
 assert not selected and not prompt['offered']['relations'] and not prompt['candidates']
 assert meta['historical_windows_supplied']==0 and meta['wire_candidate_ids']==[]
 assert meta['wire_packet_ids']==[p['packet_id']]
 assert meta['input_preparation']['considered_prompt_bytes']>18001
 assert meta['input_preparation']['omission_reason']=='candidate_exceeds_input_limit'
 assert meta['input_preparation']['omitted_candidate_ids']==['peer'] and prompt['packet']['context']==p['context']


def test_overbudget_base_fails_before_transport_without_clipping_positive_context():
 p,c=pair();p['context'].append({'id':'oversized-context','kind':'untrusted','value':'漢'*4000});before=copy.deepcopy((p,c))
 def forbidden(*a,**kw):pytest.fail('Oversized base reached transport')
 with pytest.raises(ValueError) as caught:ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1'},p,[c],{},'',requester=forbidden)
 meta=caught.value._edl_failure_metadata
 assert meta['wire_packet_ids']==meta['wire_candidate_ids']==[] and meta['historical_windows_supplied']==0
 assert meta['input_preparation']['omission_reason']=='base_exceeds_input_limit' and meta['input_preparation']['user_prompt_bytes'] is None
 assert meta['failure_diagnostic']['phase']=='request_preparation' and (p,c)==before


def test_no_candidate_and_single_candidate_bound_do_not_manufacture_relationships():
 p,c=pair();_,prompt,selected,meta=gen.prepare_bounded(p,[],{})
 assert selected==[] and prompt['offered']['relations']=={} and meta['input_preparation']['omission_reason']=='no_candidate'
 other={**c,'candidate_id':'second'};_,prompt,selected,meta=gen.prepare_bounded(p,[c,other],{})
 assert selected==[c] and meta['wire_candidate_ids']==['peer'] and len(prompt['candidates'])==1


def test_transport_uses_exact_measured_serialization_and_canonical_validator():
 p,c=pair();w=gen.example(p,[c]);tables,_=gen.offers(p,[c],{})
 key=next(iter(tables['relations']));w['actor_correlation']=[{'choice_id':key,'confidence':.4}]
 (value,meta),calls=transport(p,w,[c]);wire=calls[0]['messages'][1]['content']
 assert len(wire.encode())==meta['input_preparation']['user_prompt_bytes']<=18000
 assert meta['wire_candidate_ids']==['peer'] and meta['historical_windows_supplied']==1
 assert value['actor_correlation']==[{**tables['relations'][key],'confidence':.4}]
 assert value['actor_correlation'][0]['explanation']==RELATION and value['actor_correlation'][0]['alternative_explanations']==[ALTERNATIVE]
 changed=copy.deepcopy(value);changed['actor_correlation'][0]['explanation']='Invented attribution'
 with pytest.raises(ValueError):ai.validate_result(changed,p,[c],{})
 changed=copy.deepcopy(value);changed['actor_correlation'][0]['evidence_ids']=[p['events'][1]['id']]
 with pytest.raises(ValueError):ai.validate_result(changed,p,[c],{})


def test_omitted_candidate_is_not_available_to_decoder_even_when_preassembly_reference_exists():
 p,c=legacy_overbudget_pair();w=gen.example(p,[c]);tables,_=gen.offers(p,[c],{})
 w['actor_correlation']=[{'choice_id':next(iter(tables['relations'])),'confidence':.4}]
 with pytest.raises(ai.ModelOutputError) as caught:transport(p,w,[c])
 assert caught.value.metadata['historical_windows_supplied']==0 and caught.value.metadata['wire_candidate_ids']==[]
 assert caught.value.metadata['input_preparation']['omission_reason']=='candidate_exceeds_input_limit'


def test_complete_history_overflow_refuses_before_claim_without_withholding(tmp_path,monkeypatch):
 from test_behavior_drain import queue
 from test_behavior_retention import packet
 s,b,cfg=queue(tmp_path,1);p,c=legacy_overbudget_pair();p['packet_id']='packet0';c['padding']+='x'*100
 calls=[]
 stage_mock(monkeypatch,ai,lambda *a:(calls.append(1),{}))
 with b.connect() as db:
  db.execute("UPDATE packets SET content=? WHERE id='packet0'",(json.dumps(p),));packet(db,'peer')
 assert ai.model_job(b,'packet0',p,set(),cfg,[c])=='input_verification_required'
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM usage').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM pipeline_stages').fetchone()[0]==0
  assert db.execute("SELECT 1 FROM packets WHERE id='peer'").fetchone()
 assert calls==[]


def test_protocol_change_deliberately_changes_job_identity_not_settings_or_candidate_references(monkeypatch):
 p,c=pair();settings_id=ai.config_id(ai.DEFAULTS);original=copy.deepcopy(c)
 new=ai.digest([{},[c],ai.VERSION,ai.PROMPT_VERSION,ai.GENERATION_SCHEMA_VERSION])
 old=ai.digest([{},[c],ai.VERSION,'behavior-3.16','grounded-groups-7'])
 assert new!=old and settings_id==ai.config_id(ai.DEFAULTS) and c==original
