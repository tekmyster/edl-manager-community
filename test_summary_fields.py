"""Fixed-statement content annotations, never source detail quality or output filtering."""
import copy,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
import behavior_grounding as grounding
from test_historical_prompt import pair
from test_generation_slots import positive
from test_source_observations import linked_packet


def event(**updates):
 return {'id':'e','source':'test-source','sensor':'test-sensor','action':'owa_request','seen':'2026-10-17T10:00:00+00:00',**updates}


def prepared(packet):
 _,prompt=gen.prepare(packet,[],{});return prompt


@pytest.mark.parametrize('extras',[
 {'path':'/secret-not-conveyed','port':'8088','destination':{'scope':'internal','asset_id':'private'},'client_type':'Browser','provenance':{'detail':'sample'}},
 {'path':'/secret-not-conveyed','status':'200','parameter_names':['secret'],'provenance':{'detail':'summary'}},
 {'method':'GET','port':'22'},
 {}])
def test_label_summary_never_claims_request_time_destination_or_provenance_content(extras):
 record=event(**extras);before=copy.deepcopy(record);fact,fields=grounding.observation_statement(record)
 assert fact=={'summary':'Saved test-source / test-sensor sample reports owa_request.','evidence_ids':['e']}
 assert fields==[['source','sensor','action']] and record==before
 packet={'packet_id':'label','coverage':'saved_samples','events':[record],'context':[]};prompt=prepared(packet)
 offered=next(iter(prompt['offered']['facts'].values()))
 assert offered['summary_fields']==fields and 'record_fields' not in offered and 'record_provenance' not in offered
 assert 'secret' not in json.dumps(offered['summary_fields'])


@pytest.mark.parametrize('status,printed',[('', 'unavailable'),(None,'unavailable'),(0,'unavailable'),('404','404')])
def test_request_branch_lists_only_conveyed_fields_and_unavailable_status(status,printed):
 record=event(method='GET',path='/only-in-source',status=status,port='8088',parameter_names=['secret'],client_type='Browser')
 fact,fields=grounding.observation_statement(record)
 assert fact=={'summary':f'Saved request: GET /only-in-source; status {printed}; source test-source.','evidence_ids':['e']}
 assert fields==[['method','path','status','source']]


def test_failure_action_does_not_claim_http_fields_ignored_by_constructor():
 fact,fields=grounding.observation_statement(event(action='cowrie.login.failed',method='GET',path='/not-conveyed',status='401'))
 assert fact['summary']=='Saved test-source / test-sensor sample reports cowrie.login.failed.'
 assert fields==[['source','sensor','action']]


def test_typed_content_and_relative_interval_exactly_map_both_citations():
 from source_observations import connections
 packet=linked_packet();linked=connections(packet['events']);records={e['id']:[e] for e in packet['events']}
 for e in packet['events'][1:]:
  fact,fields=grounding.observation_statement(e,linked[e['id']]);assert len(fact['evidence_ids'])==2
  expected=['source','sensor','source_observation.semantic']
  if e['source_observation']['semantic']=='shell_input':expected+=['source_observation.syntax_categories']
  expected+=['seen:elapsed'];assert fields==[expected,['seen:elapsed']]
  assert gen.observation_summary_fields(fact,records,linked,set(records))=={'summary_fields':fields}
  assert 'after its cited connection' in fact['summary']
  assert 'execution is unverified' in fact['summary'] if 'shell input' in fact['summary'] else 'network transfer is unverified' in fact['summary']


@pytest.mark.parametrize('syntax,phrase',[([], 'No allowlisted syntax category was recorded.'),(['unrecognized'],'Syntax detail unavailable.'),(None,'Syntax detail unavailable.')])
def test_syntax_unavailable_and_none_are_statement_content_not_source_presence(syntax,phrase):
 record=event(action='cowrie.command.input',source_observation={'version':'source-observations-1','semantic':'shell_input','syntax_categories':syntax})
 fact,fields=grounding.observation_statement(record)
 assert phrase in fact['summary'] and fields==[['source','sensor','source_observation.semantic','source_observation.syntax_categories']]


def test_request_overwrite_does_not_leave_incorrect_typed_semantic_annotation():
 record=event(action='cowrie.command.input',method='POST',path='/endpoint',source_observation={'version':'source-observations-1','semantic':'shell_input','syntax_categories':[]})
 fact,fields=grounding.observation_statement(record)
 assert fact['summary'].startswith('Saved request: POST /endpoint; status unavailable; source test-source.')
 assert fields==[['method','path','status','source','source_observation.syntax_categories']]
 assert 'shell input' not in fact['summary']


@pytest.mark.parametrize('mutation',['missing_primary','missing_connection','duplicate_primary','duplicate_connection','different_summary','different_refs'])
def test_missing_ambiguous_or_nonmatching_construction_is_explicit_unknown(mutation):
 from source_observations import connections
 packet=linked_packet();linked=connections(packet['events']);record=packet['events'][1];fact,_=grounding.observation_statement(record,linked[record['id']]);records={e['id']:[e] for e in packet['events']};event_ids=set(records)
 if mutation=='missing_primary':records.pop(fact['evidence_ids'][0])
 if mutation=='missing_connection':records.pop(fact['evidence_ids'][1])
 if mutation=='duplicate_primary':records[fact['evidence_ids'][0]]*=2
 if mutation=='duplicate_connection':records[fact['evidence_ids'][1]]*=2
 if mutation=='different_summary':fact['summary']+='invented'
 if mutation=='different_refs':fact['evidence_ids'].reverse()
 before=copy.deepcopy((fact,records));result=gen.observation_summary_fields(fact,records,linked,event_ids)
 assert result=={'summary_fields':[None,None]} and (fact,records)==before


@pytest.mark.parametrize('provider',['crawler','greynoise'])
def test_positive_summary_content_has_no_unprinted_status_expiry_or_verification_fields(provider,monkeypatch):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00');packet=positive();c=packet['context'][0]
 if provider=='greynoise':c.update(provider='greynoise',classification='benign',observation_fresh=True)
 before=copy.deepcopy(packet);tables,_=gen.offers(packet,[],{});prompt=prepared(packet);key=next(k for k,v in tables['counterevidence'].items() if v['evidence_ids']==['ctx'])
 fields=['provider','verified','cache_fresh'] if provider=='crawler' else ['provider','classification','cache_fresh']
 assert prompt['offered']['facts'][key]['summary_fields']==[fields]
 assert prompt['offered']['facts'][key]['allowed_roles']==['omit','finding','counterevidence'] and packet==before
 # Eligibility still depends on freshness fields which are not printed as dates/status.
 c['expires']='2000-01-01T00:00:00+00:00';assert gen.offers(packet,[],{})[0]['counterevidence']=={}


def test_every_annotation_is_wire_only_and_all_legal_label_selections_remain_available():
 from test_generation_choices import transport
 packet={'packet_id':'label','coverage':'saved_samples','events':[event(path='/unprinted',port='8088')],'context':[]};before=copy.deepcopy(packet);tables,_=gen.offers(packet,[],{});key=next(iter(tables['facts']));wire=gen.example(packet);wire['observations']={key:'finding'};wire['maliciousness_confidence']=0
 value=transport(packet,wire)[0][0];assert value['findings']==[tables['facts'][key]] and 'summary_fields' not in json.dumps(value)
 assert packet==before


@pytest.mark.parametrize('history',[False,True])
def test_annotation_only_overflow_fails_before_dispatch_without_losing_history(monkeypatch,history):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-19T00:00:00+00:00');packet,candidate=pair();candidates=[candidate] if history else [];target=candidate if history else packet
 from behavior_mapping import select
 registry=select({},packet);target['padding']='';_,prompt=gen.prepare(packet,candidates,registry)
 stripped=len(gen.prompt_json(gen.without_summary_fields(prompt)).encode());full=len(gen.prompt_json(prompt).encode());assert stripped<full<18000
 target['padding']='x'*(18000-stripped);_,prompt=gen.prepare(packet,candidates,registry);assert len(gen.prompt_json(gen.without_summary_fields(prompt)).encode())==18000
 before=copy.deepcopy((packet,candidates))
 def forbidden(*a,**kw):pytest.fail('Annotation overflow dispatched a request')
 with pytest.raises(ValueError) as caught:ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1'},packet,candidates,{},'',requester=forbidden)
 meta=caught.value._edl_failure_metadata
 assert meta['input_preparation']['omission_reason']=='summary_fields_exceed_input_limit' and meta['input_preparation']['user_prompt_bytes'] is None
 assert meta['wire_packet_ids']==meta['wire_candidate_ids']==[] and meta['historical_windows_supplied']==0
 assert meta['input_preparation']['omitted_candidate_ids']==(['peer'] if history else []) and meta['failure_diagnostic']['phase']=='request_preparation'
 assert (packet,candidates)==before
