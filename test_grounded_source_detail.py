"""Fixed privacy-safe source detail, not intent or execution ground truth."""
import copy,json
import pytest
from behavior_grounding import contract
from test_source_observations import linked_packet

def fact(p,ident):return next(f for f in contract(p,{})['facts'] if f['evidence_ids'][0]==ident)

def test_categories_and_session_interval_keep_exact_original_citations():
 p=linked_packet();p['events'][1]['source_observation']['syntax_categories'].append('relative_execution');before=copy.deepcopy(p);v=fact(p,p['events'][1]['id'])
 assert 'permission change' in v['summary'] and 'relative execution syntax' in v['summary']
 assert 'execution is unverified' in v['summary'] and 'after its cited connection' in v['summary']
 assert v['evidence_ids']==[p['events'][1]['id'],p['events'][0]['id']] and p==before
 assert len(v['summary'])<=600

@pytest.mark.parametrize('syntax',[None,'permission_change',['PRIVATE-command'],['permission_change']*6,[True]])
def test_unknown_or_malformed_categories_do_not_become_source_claims(syntax):
 p=linked_packet();p['events'][1]['source_observation']['syntax_categories']=syntax
 s=fact(p,p['events'][1]['id'])['summary'];assert 'Syntax detail unavailable' in s and 'PRIVATE' not in s

def test_no_category_or_valid_session_link_does_not_invent_execution_target_or_intent():
 p=linked_packet();p['events'][1]['source_observation']['syntax_categories']=[]
 s=fact(p,p['events'][1]['id'])['summary'];assert 'No allowlisted syntax category was recorded' in s
 p['events'][1]['source_observation']['connection_count']=2
 assert 'session link' not in fact(p,p['events'][1]['id'])['summary']
 assert 'malicious' not in contract(p,{})['classifications']
 p['events'][1]['source_observation']['semantic']='interactive_input'
 s=fact(p,p['events'][1]['id'])['summary'];assert 'Recorded syntax categories' not in s and 'command execution is unverified' in s

def test_ordinary_http_and_external_flow_records_stay_unpromoted():
 p={'packet_id':'flow','events':[{'id':'f','source':'research','sensor':'Argus','action':'icmp bidirectional flow record','seen':'2011-08-18T13:53:00+00:00','observed_fields':{'TotPkts':'1000000','Label':'PRIVATE-malicious'}}],'context':[]}
 c=contract(p,{});assert c['classifications']==['inconclusive'] and 'PRIVATE' not in json.dumps(c) and '1000000' not in json.dumps(c)
