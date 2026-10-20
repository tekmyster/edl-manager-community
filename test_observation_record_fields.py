"""Factual wire metadata and admission only; no inference or utility assertion."""
import copy,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
from test_historical_prompt import pair
from test_generation_slots import positive


def test_inventory_exact_presence_order_false_zero_and_no_values():
 record={'id':'http','method':'GET-SECRET','path':'/SECRET','status':0,'port':'','parameter_names':[], 'destination':{'scope':'unknown'},'verified':False,'provenance':{'detail':'sample'},'password':'SECRET','extra':{'payload':'SECRET'}}
 before=copy.deepcopy(record)
 got=gen.observation_records({'evidence_ids':['http']},{'http':[record]})
 assert got=={'record_fields':[['method','path','status','destination.scope','verified']],'record_provenance':['sample']}
 assert record==before and 'SECRET' not in json.dumps(got)
 assert len(gen.RECORD_FIELDS)==len(set(gen.RECORD_FIELDS))


@pytest.mark.parametrize('provenance',[None,[], 'sample', {'detail':'fabricated'},{'detail':False}])
def test_unrecognized_provenance_is_not_reclassified(provenance):
 assert gen.observation_records({'evidence_ids':['e']},{'e':[{'action':'name','provenance':provenance}]})=={'record_fields':[['action']],'record_provenance':[None]}


def test_missing_ambiguous_and_multiple_citations_remain_aligned():
 records={'name':[{'action':'owa_request','provenance':{'detail':'summary'}}], 'handshake':[{'action':'cowrie.client.version','provenance':{'detail':'sample'}}], 'duplicate':[{'path':'/one'},{'path':'/two'}]}
 got=gen.observation_records({'evidence_ids':['missing','name','duplicate','handshake']},records)
 assert got=={'record_fields':[None,['action'],None,['action']],'record_provenance':[None,'summary',None,'sample']}


def test_wire_inventory_matches_each_original_citation_without_changing_offers_or_input():
 p=positive();before=copy.deepcopy(p);tables,_=gen.offers(p,[],{});schema,prompt=gen.prepare(p,[],{})
 records={e['id']:[e] for e in p['events']+p['context']}
 for key,fact in tables['facts'].items():
  offered=prompt['offered']['facts'][key]
  assert offered=={**fact,'allowed_roles':schema['properties']['observations']['properties'][key]['enum'],**gen.observation_records(fact,records)}
  if len(fact['evidence_ids'])==2:
   assert len(offered['record_fields'])==2
   assert all('source_observation.semantic' in fields for fields in offered['record_fields'])
   assert any('source_observation.syntax_categories' in fields for fields in offered['record_fields']) or 'capture' in fact['summary']
 ctx=next(k for k,f in tables['facts'].items() if f['evidence_ids']==['ctx'])
 assert prompt['offered']['facts'][ctx]['record_fields']==[['status','provider','verified','cache_fresh','expires']]
 assert prompt['offered']['facts'][ctx]['record_provenance']==[None]
 assert p==before and 'not fields necessarily printed by summary' in prompt['observation_record_definition']
 assert 'unknown values' in prompt['observation_record_definition']


@pytest.mark.parametrize('history',[False,True])
def test_metadata_only_overflow_fails_before_dispatch_without_losing_history(monkeypatch,history):
 monkeypatch.setattr(ai,'now',lambda:'2026-10-19T00:00:00+00:00')
 p,c=pair();candidates=[c] if history else [];target=c if history else p
 from behavior_mapping import select
 registry=select({},p)
 target['padding']='';_,prompt=gen.prepare(p,candidates,registry)
 old_size=len(gen.prompt_json(gen.without_observation_records(prompt)).encode())
 new_size=len(gen.prompt_json(prompt).encode());assert old_size<new_size<18000
 target['padding']='x'*(18000-old_size)
 _,prompt=gen.prepare(p,candidates,registry)
 assert len(gen.prompt_json(gen.without_observation_records(prompt)).encode())==18000
 before=copy.deepcopy((p,candidates))
 def forbidden(*a,**kw):pytest.fail('Metadata overflow dispatched a request')
 with pytest.raises(ValueError) as caught:ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1'},p,candidates,{},'',requester=forbidden)
 meta=caught.value._edl_failure_metadata
 assert meta['input_preparation']['omission_reason']=='observation_records_exceed_input_limit'
 assert meta['input_preparation']['user_prompt_bytes'] is None
 assert meta['wire_packet_ids']==meta['wire_candidate_ids']==[] and meta['historical_windows_supplied']==0
 assert meta['input_preparation']['omitted_candidate_ids']==(['peer'] if history else [])
 assert meta['failure_diagnostic']['phase']=='request_preparation' and (p,candidates)==before
