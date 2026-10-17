"""Source-neutral contrast fixtures; permission to interpret is not a verdict."""
import pytest
from behavior_grounding import contract,example,SUMMARIES
from test_behavior_grounding import packet,transport
from test_behavior_taxonomy import event

def sample(ident,action,**changes):
 values={'source':'wazuh','sensor':'source-events','seen':'2026-10-17T10:00:00+00:00','destination':{'asset_id':'fixture-target'},'port':'443','provenance':{'detail':'sample','upstream_id':'record-'+ident}}
 values.update(changes);return event(ident,action,**values)

def families():
 second='2026-10-17T10:00:05+00:00'
 return {
  'http':packet(sample('php','HTTP request',source='nginx',sensor='web-request',method='POST',path='/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',status='404'),sample('cgi','HTTP request',source='nginx',sensor='web-request',method='POST',path='/cgi-bin/../../bin/sh',status='404',seen=second)),
  'http_waf':packet(sample('http','HTTP request',source='nginx',sensor='web-request',method='POST',path='/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',status='404'),sample('waf','public-facing application exploit attempt',source='waf',sensor='application-rule',method='POST',path='/upload',status='403',seen=second)),
  'wazuh':packet(sample('dump','os credential dumping',sensor='credential-event'),sample('ps','powershell execution',sensor='process-event',seen=second)),
  'waf':packet(sample('upload','web shell upload attempt',source='waf',sensor='application-rule'),sample('exploit','public-facing application exploit attempt',source='waf',sensor='application-rule',seen=second)),
  'honeypot':packet(sample('cmd','cowrie.command.input',source='tpot',sensor='Cowrie',port='22'),sample('file','cowrie.session.file_download',source='tpot',sensor='Cowrie',port='22',seen=second)),
 }

def malicious_value(p):
 c=contract(p,{});value=example(p);refs=set(c['malicious_support'][0]['evidence_ids'])
 value['findings']=[f for f in c['facts'] if set(f['evidence_ids'])<=refs]
 value.update(classification='malicious',maliciousness_confidence=.9,analysis_summary=SUMMARIES['malicious']);return value

@pytest.mark.parametrize('family',list(families()))
def test_coherent_distinct_observations_permit_but_never_force_malicious_interpretation(family):
 p=families()[family];c=contract(p,{})
 assert 'malicious' in c['classifications'] and 'inconclusive' in c['classifications']
 assert transport(p,example(p))[0][0]['classification']=='inconclusive'
 (value,_),_=transport(p,malicious_value(p))
 assert value['classification']=='malicious' and 'successful exploitation' in value['analysis_summary'] and 'unverified' in value['analysis_summary']
 # No provider-authored facts, tool names or success claims are introduced.
 assert all(f in c['facts'] for f in value['findings'])

@pytest.mark.parametrize('family',list(families()))
def test_single_label_or_endpoint_sample_does_not_permit_malicious_interpretation(family):
 p=families()[family];p['events']=p['events'][:1]
 assert contract(p,{})['classifications']==['inconclusive']
 assert transport(p,example(p))[0][0]['classification']=='inconclusive'

@pytest.mark.parametrize('mutation',[
 lambda a,b:b.update(destination={'asset_id':'different-target'}),
 lambda a,b:b.update(seen='2026-10-17T11:00:00+00:00'),
 lambda a,b:b.update(seen='invalid'),
 lambda a,b:b['provenance'].update(upstream_id=a['provenance']['upstream_id']),
 lambda a,b:b['provenance'].update(detail='summary'),
 lambda a,b:b['provenance'].update(upstream_id=''),
 lambda a,b:b.update(action=a['action']),
])
def test_ambiguous_repeated_unscoped_or_forwarded_detector_reports_abstain(mutation):
 p=families()['wazuh'];mutation(*p['events'])
 assert 'malicious' not in contract(p,{})['classifications']

def test_two_generic_reports_or_arbitrary_http_paths_cannot_be_promoted():
 for actions in [('connection observed','cowrie.session.closed'),('authentication failure','cowrie.login.failed'),('powershell execution test','os credential dumping test')]:
  p=packet(sample('a',actions[0]),sample('b',actions[1],seen='2026-10-17T10:00:05+00:00'))
  assert 'malicious' not in contract(p,{})['classifications']
 p=families()['http'];p['events'][0].update(path='/health',endpoint_hint='phpunit_eval_stdin');p['events'][1].update(path='/login',endpoint_hint='apache_cgi_traversal')
 assert 'malicious' not in contract(p,{})['classifications']

def test_same_request_forwarded_with_different_labels_is_not_corroboration():
 p=families()['http_waf'];p['events'][1].update(seen=p['events'][0]['seen'],path=p['events'][0]['path'],method=p['events'][0]['method'])
 assert 'malicious' not in contract(p,{})['classifications']
 p['events'][1]['seen']='2026-10-17T10:00:00.5+00:00'
 assert 'malicious' not in contract(p,{})['classifications']

def test_malicious_interpretation_requires_both_members_of_the_offered_bundle():
 p=families()['wazuh'];value=malicious_value(p);value['findings']=value['findings'][:1]
 with pytest.raises(ValueError):transport(p,value)

def test_collector_branding_is_not_an_eligibility_privilege():
 p=families()['wazuh']
 for e in p['events']:e.update(source='alternate-source',sensor='alternate-sensor')
 assert 'malicious' in contract(p,{})['classifications']
 assert transport(p,malicious_value(p))[0][0]['classification']=='malicious'

def test_explicit_collection_scope_can_correlate_unknown_targets_without_claiming_target_identity():
 p=families()['honeypot']
 for e in p['events']:e['destination']={'scope':'unknown'};e['provenance']['collector_agent']='fixture-agent'
 c=contract(p,{});assert 'malicious' in c['classifications'] and 'collector stream' in c['malicious_support'][0]['basis']
 p['events'][1]['provenance']['collector_agent']='other-agent'
 assert 'malicious' not in contract(p,{})['classifications']

def test_redacted_endpoint_category_requires_complete_sampled_request_and_pair():
 p=families()['http'];p['events'][0].update(path='[identifier].php',endpoint_hint='phpunit_eval_stdin')
 assert 'malicious' in contract(p,{})['classifications']
 p['events'][0]['status']=''
 assert 'malicious' not in contract(p,{})['classifications']

def test_pair_work_and_offered_fact_bounds_remain_explicit():
 p=packet(*(sample(str(i),'powershell execution' if i%2 else 'os credential dumping',seen=f'2026-10-17T10:00:{i:02d}+00:00') for i in range(40)))
 c=contract(p,{})
 assert c['offered_facts']<=12 and len(c['malicious_support'])<=6
 assert c['support_coverage']['examined_signal_events']==24 and c['support_coverage']['available_signal_events']==40 and c['support_coverage']['pair_bound']==276
 offered={i for f in c['facts'] for i in f['evidence_ids']}
 assert all(set(b['evidence_ids'])<=offered for b in c['malicious_support'])
