"""Prompt guidance must not filter legal source choices or erase useful detail."""
from test_generation_fixtures import decision
import copy
import behavior_ai as ai
import behavior_generation as gen
from test_generation_choices import transport
from test_generation_slots import positive
from test_source_observations import linked_packet


def omitted(packet):
 wire=gen.example(packet);wire['maliciousness_confidence']=0
 wire['observations']={key:decision('omit', packet=packet, key=key) for key in wire['observations']}
 return wire


def test_selected_group_preserves_individual_input_capture_intervals_and_caveats():
 packet=linked_packet();before=copy.deepcopy(packet);wire=omitted(packet)
 tables,_=gen.offers(packet,[],{})
 detail={key:fact for key,fact in tables['facts'].items() if len(fact['evidence_ids'])==2}
 assert len(detail)==2
 wire['observable_synthesis'][next(iter(wire['observable_synthesis']))]='reported_session_sequence'
 wire['observations'].update({key:decision('detail', packet=packet, key=key) for key in detail})
 (value,metadata),calls=transport(packet,wire)
 assert value['findings']==list(detail.values()) and len(value['observable_synthesis'])==1
 assert all('after its cited connection' in f['summary'] for f in value['findings'])
 by_event={fact['evidence_ids'][0]:fact for fact in value['findings']}
 assert 'execution is unverified' in by_event[packet['events'][1]['id']]['summary']
 assert 'network transfer is unverified' in by_event[packet['events'][2]['id']]['summary']
 assert packet==before and metadata['prompt_version']=='behavior-3.38'
 assert list(calls[0]['format']['properties'])[0]=='observable_synthesis'
 ai.validate_result(value,packet,[],{})


def test_guidance_does_not_filter_a_legal_label_only_selection():
 packet={'packet_id':'label-only','coverage':'saved_samples','events':[
  {'id':'label','source':'tpot','sensor':'Cowrie','action':'Cowrie','seen':'2026-10-17T10:00:00+00:00'}], 'context':[]}
 tables,_=gen.offers(packet,[],{});assert len(tables['facts'])==1
 wire=omitted(packet);key=next(iter(tables['facts']));wire['observations'][key]=decision('detail', packet=packet, key=key)
 (value,_),_=transport(packet,wire)
 assert value['findings']==[tables['facts'][key]]
 assert value['observable_synthesis']==[]
 ai.validate_result(value,packet,[],{})


def test_guidance_preserves_optional_qualifying_counterevidence():
 packet=positive();tables,_=gen.offers(packet,[],{});wire=omitted(packet)
 key=next(iter(tables['counterevidence']));wire['observations'][key]=decision('counterevidence', packet=packet, key=key)
 (value,_),_=transport(packet,wire)
 assert value['contradictory_evidence']==[tables['facts'][key]] and value['findings']==[]
 assert value['classification']=='inconclusive'
 ai.validate_result(value,packet,[],{})


def test_guidance_preserves_required_support_for_a_selected_malicious_verdict(monkeypatch):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00')
 packet=linked_packet();tables,coverage=gen.offers(packet,[],{})
 assert coverage['malicious_support_pairs']
 wire=omitted(packet);wire.update(classification='malicious',maliciousness_confidence=.5)
 for key in coverage['malicious_support_pairs'][0]:wire['observations'][key]=decision('detail', packet=packet, key=key)
 wire['observable_synthesis'][next(iter(wire['observable_synthesis']))]='reported_session_sequence'
 (value,_),_=transport(packet,wire)
 assert len(value['findings'])==2 and value['classification']=='malicious'
 assert len(value['observable_synthesis'])==1
 ai.validate_result(value,packet,[],{})
