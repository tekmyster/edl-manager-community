"""Test-only migration of valid storage fixtures to the new generation wire.

Invalid legacy payloads stay byte-for-byte equivalent objects and must reject at
the versioned wire boundary. Runtime never imports this helper or accepts them.
"""
import copy
from behavior_generation import offers,example

def wire_from_storage(packet,value,candidates=None,registry=None):
 import behavior_ai as ai
 from behavior_mapping import select
 candidates=candidates or [];registry=select(registry or {},packet);canonical=copy.deepcopy(value)
 # Historical test fixtures use the previous declared wire taxonomy/correlation.
 if any('support_id' in item for f in ('attack_techniques','d3fend_context') for item in canonical[f]):
  canonical=ai.decode_taxonomy_choices(canonical,ai.taxonomy_choices(packet,registry))
 for item in canonical['actor_correlation']:
  if 'current_evidence_ids' in item:item['evidence_ids']=item.pop('current_evidence_ids')+item.pop('historical_evidence_ids')
 ai.validate_result(canonical,packet,candidates,registry)
 table,_=offers(packet,candidates,registry);wire=example(packet,candidates,registry)
 wire.update(classification=canonical['classification'],maliciousness_confidence=canonical['maliciousness_confidence'])
 def find(kind,value):return next(k for k,v in table[kind].items() if v==value)
 wire['finding_ids']=[find('facts',claim) for claim in canonical['findings']]
 wire['counterevidence_ids']=[find('facts',claim) for claim in canonical['contradictory_evidence']]
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  chosen=[next(k for k,v in table[kind].items() if {f:x for f,x in v.items() if f!='name'}==item) for item in canonical[field]]
  if len(set(chosen))!=len(chosen):raise ValueError('Duplicate fixture selection')
  wire[field]={k:'include' if k in chosen else 'omit' for k in table[kind]}
 for field in ('automation','intent'):
  item=canonical[field];wire[field]=[] if item['classification']=='unknown' else [{'choice_id':find(field,item['classification']),'confidence':item['confidence']}]
 wire['actor_correlation']=[{'choice_id':find('relations',{k:v for k,v in item.items() if k!='confidence'}),'confidence':item['confidence']} for item in canonical['actor_correlation']]
 return wire

def wire_or_invalid_legacy(packet,value,candidates=None,registry=None):
 try:return wire_from_storage(packet,value,candidates,registry)
 except (ValueError,KeyError,TypeError,StopIteration):return copy.deepcopy(value)


def observation_roles(wire,findings=(),counterevidence=()):
 wire['finding_ids']=list(findings)
 wire['counterevidence_ids']=list(counterevidence)
 if any(key in wire['finding_ids'] for key in wire['counterevidence_ids']):raise ValueError('Fixture cannot assign both roles')
 return wire
