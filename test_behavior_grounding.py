"""Isolated factual acceptance tests. No production labels or model calls."""
import copy,json
import pytest
import behavior_ai as ai
from behavior_grounding import contract,example,mapping_text,LIMITS,SUMMARIES,RELATION,ALTERNATIVE
from test_behavior_taxonomy import catalog,event

def packet(*events,context=None):return {'packet_id':'grounding-fixture','coverage':'saved_samples','events':list(events),'context':context or []}

def transport(p,value,registry=None,candidates=None):
 from test_generation_fixtures import wire_or_invalid_legacy
 value=wire_or_invalid_legacy(p,value,candidates,registry)
 calls=[]
 class Response:
  status_code=200
  def close(self):pass
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','message':{'content':json.dumps(value)}}).encode()
 def send(*args,**kw):calls.append(kw['json']);return Response()
 result=ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},p,candidates or [],registry or {},'',requester=send)
 return result,calls

@pytest.mark.parametrize('action',['connection observed','cowrie.session.connect','cowrie.client.version','cowrie.session.closed','SSH negotiation failed'])
def test_sparse_connections_are_observations_not_auth_failure_or_decisive_verdict(action):
 p=packet(event(action=action,source='tpot',sensor='Cowrie'));value=example(p)
 (accepted,metadata),calls=transport(p,value)
 assert accepted['classification']=='inconclusive' and action in accepted['findings'][0]['summary']
 assert metadata['grounding_contract_version']=='grounded-observations-5'
 assert calls[0]['format']['properties']['classification']['enum']==['inconclusive']
 bad=copy.deepcopy(value);bad['findings'][0]['summary']='Multiple authentication failures observed, indicating a brute-force attack.'
 with pytest.raises(ValueError,match='Unsupported observation'):ai.validate_result(bad,p,[],{})
 with pytest.raises(ai.ModelOutputError):transport(p,bad)
 for classification in ('benign','malicious'):
  bad=copy.deepcopy(value);bad.update(classification=classification,analysis_summary=SUMMARIES[classification])
  with pytest.raises(ValueError,match='Unsupported decisive'):ai.validate_result(bad,p,[],{})

def test_actual_auth_failures_are_reportable_and_map_broadly_without_inventing_intent(catalog):
 p=packet(event('f1','cowrie.login.failed'),event('f2','authentication failure'))
 value=example(p,catalog);value['findings']=contract(p,catalog)['facts']
 value['attack_techniques']=[{'support_id':'attack:T1110','explanation':mapping_text('attack','T1110',catalog['attack']['T1110'])}]
 (accepted,_),_=transport(p,value,catalog)
 assert accepted['classification']=='inconclusive' and accepted['attack_techniques'][0]['evidence_ids']==['f1','f2']
 assert any('cowrie.login.failed' in f['summary'] for f in accepted['findings'])
 assert not any('spraying' in f['summary'] or 'test' in f['summary'] for f in accepted['findings'])

@pytest.mark.parametrize('field',['analysis_summary','findings','contradictory_evidence','attack_techniques','d3fend_context'])
def test_free_form_fact_injection_cannot_cross_either_schema_or_canonical_validator(catalog,field):
 p=packet(event('f1','authentication failure'),event('f2','authentication failure'))
 bad=example(p,catalog);claim='A controlled test established collaboration and successful exploitation.'
 if field=='analysis_summary':bad[field]=claim
 elif field in ('findings','contradictory_evidence'):bad[field]=[{'summary':claim,'evidence_ids':['f1']}]
 else:
  kind='attack' if field=='attack_techniques' else 'd3fend';ident='T1110' if kind=='attack' else 'D3-ANET'
  bad[field]=[{'technique_id':ident,'evidence_ids':['f1','f2'],'explanation':claim}]
 with pytest.raises(ValueError):ai.validate_result(bad,p,[],catalog)
 wire=copy.deepcopy(bad)
 if field in ('attack_techniques','d3fend_context'):wire[field]=[{'support_id':kind+':'+ident,'explanation':claim}]
 with pytest.raises(ai.ModelOutputError) as error:transport(p,wire,catalog)
 assert claim not in json.dumps(error.value.metadata)

def test_fact_text_and_citation_must_match_even_when_both_exist_in_schema():
 p=packet(event('connection','connection observed'),event('failure','authentication failure'));bad=example(p)
 failure=next(f for f in contract(p,{})['facts'] if f['evidence_ids']==['failure'])
 bad['findings']=[{**failure,'evidence_ids':['connection']}]
 with pytest.raises(ai.ModelOutputError) as error:transport(p,bad)
 assert error.value.metadata['validation_diagnostic']['stage']=='response_schema' # Legacy text/citation wire is rejected, never repaired.

@pytest.mark.parametrize('sentence',[
 'No clear malicious activity detected. Multiple authentication failures may indicate a brute-force attack, but without additional context, this is not conclusive.',
 'No malicious activity detected. Multiple failed login attempts and a session closure event.',
 'Decoy Environment detected. Multiple failed login attempts and session closure event.',
 'Two authentication failures observed, likely indicative of a brute-force attack.',
 'Multiple authentication failures observed, indicating potential brute-force attack.',
])
def test_authentication_fabrications_from_legacy_outputs_fail_even_with_inconclusive_class(sentence):
 p=packet(event('connection','connection observed'),event('closed','cowrie.session.closed'));bad=example(p)
 bad['findings']=[{'summary':sentence,'evidence_ids':['connection','closed']}]
 with pytest.raises(ValueError,match='Unsupported observation'):ai.validate_result(bad,p,[],{})
 with pytest.raises(ai.ModelOutputError):transport(p,bad)

def test_empty_evidence_abstains_and_mismatched_allowed_summary_is_rejected():
 p=packet();assert transport(p,example(p))[0][0]['classification']=='inconclusive'
 bad=example(p);bad['analysis_summary']=SUMMARIES['benign']
 with pytest.raises(ai.ModelOutputError):transport(p,bad)

def test_d3fend_is_optional_context_and_cannot_assert_attack_test_or_control(catalog):
 p=packet(event(source='tpot',sensor='Dionaea',action='connection observed'))
 value=example(p,catalog);value['d3fend_context']=[{'support_id':'d3fend:D3-DE','explanation':mapping_text('d3fend','D3-DE',catalog['d3fend']['D3-DE'])}]
 (accepted,_),_=transport(p,value,catalog)
 assert 'unverified' in accepted['d3fend_context'][0]['explanation'] and accepted['classification']=='inconclusive'
 for text in ['Decoy Environment detected.','This is an authorized test.','A deployed decoy prevented brute force.']:
  value['d3fend_context'][0]['explanation']=text
  with pytest.raises(ai.ModelOutputError):transport(p,value,catalog)

def test_current_and_historical_tool_labels_support_only_bounded_behavioral_similarity():
 e=event('current','HTTP request',path='/distinctive/path',method='POST');p=packet(e)
 peer={**e,'id':'historical'};candidate={'candidate_id':'peer','current_events':[e],'historical_events':[peer]}
 value=example(p);value['actor_correlation']=[{'candidate_id':'peer','confidence':.4,'current_evidence_ids':['current'],'historical_evidence_ids':['historical'],'explanation':RELATION,'alternative_explanations':[ALTERNATIVE]}]
 (accepted,_),_=transport(p,value,candidates=[candidate]);assert accepted['actor_correlation'][0]['evidence_ids']==['current','historical']
 bad=copy.deepcopy(value);bad['actor_correlation'][0]['explanation']='Shared tools establish collaboration by the same attacker.'
 with pytest.raises(ai.ModelOutputError):transport(p,bad,candidates=[candidate])
 with pytest.raises(ai.ModelOutputError):transport(p,value,candidates=[])
 peer['path']='/different'
 with pytest.raises(ai.ModelOutputError):transport(p,value,candidates=[candidate])
 # A supplied identical client label is observable but spoofable, never identity.
 e['client_claim']={'label':'curl'};peer['client_claim']={'label':'curl'}
 assert transport(p,value,candidates=[candidate])[0][0]['actor_correlation']

def test_absent_tool_and_history_features_cannot_be_invented_in_top_level_hypotheses():
 p=packet(event(action='cowrie.session.closed'));bad=example(p);bad['automation'].update(classification='vulnerability_scanner',confidence=.9)
 with pytest.raises(ai.ModelOutputError):transport(p,bad)
 bad=example(p);bad['intent'].update(classification='credential_attack',confidence=.9)
 with pytest.raises(ai.ModelOutputError):transport(p,bad)
 bad=example(p);bad['automation']['confidence']=.9
 with pytest.raises(ai.ModelOutputError):transport(p,bad)

def test_fresh_positive_context_required_for_benign_and_not_replaced_by_absence():
 context={'id':'ctx-positive','kind':'intelligence','provider':'crawler','status':'ok','verified':True,'cache_fresh':True,'expires':'2099-01-01T00:00:00+00:00'}
 p=packet(event(action='connection observed',provenance={'detail':'sample'}),context=[context]);value=example(p)
 value.update(classification='benign',maliciousness_confidence=0,analysis_summary=SUMMARIES['benign'])
 assert transport(p,value)[0][0]['maliciousness_confidence']==0
 assert 'ordinary_browsing' not in contract(p,{})['intent']
 context['cache_fresh']=False
 with pytest.raises(ai.ModelOutputError):transport(p,value)
 context['cache_fresh']=True;p['events']=[]
 with pytest.raises(ai.ModelOutputError):transport(p,value)

def test_coherent_reported_command_and_transfer_can_permit_an_interpretation_not_execution_success():
 from test_source_observations import linked_packet
 p=linked_packet();value=example(p)
 value['findings']=[f for f in contract(p,{})['facts'] if len(f['evidence_ids'])==2]
 assert contract(p,{})['intent']==['unknown']
 value.update(classification='malicious',maliciousness_confidence=.91,analysis_summary=SUMMARIES['malicious'])
 assert transport(p,value)[0][0]['classification']=='malicious'
 value['findings']=[]
 with pytest.raises(ai.ModelOutputError) as error:transport(p,value)
 assert error.value.metadata['validation_diagnostic']['reason']=='object_fields' # Invalid legacy wire is not converted.

def test_fact_budget_and_existing_small_model_resource_limits(catalog):
 p=packet(*(event(str(i),action='connection observed') for i in range(100)))
 c=contract(p,catalog);assert c['available_facts']==100 and c['offered_facts']==12
 with pytest.raises(ValueError,match='input exceeds size'):transport(p,example(p),catalog)
 p['events']=p['events'][:40]
 (_,metadata),calls=transport(p,example(p),catalog)
 assert calls[0]['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}
 assert len(calls[0]['messages'][1]['content'].encode())<=18000
