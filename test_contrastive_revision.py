"""Worked-example semantics through real constructors; no simulated model quality."""
import copy,json,itertools
import pytest
import behavior_ai as ai,behavior_generation as gen,behavior_revision as rev
import behavior_tokens as tokens,behavior_synthesis as sy,behavior_representation as rep
from behavior_pipeline import Pipeline
from test_pipeline_support import SyntheticCounter,choices
from test_observable_synthesis import event,packet

def build(monkeypatch,brand,accounted):
 monkeypatch.setattr(tokens,'load',lambda cfg:SyntheticCounter())
 p=packet(event('label',brand,source='collector',sensor=brand,provenance={'detail':'summary'},http_metadata={'request_line':'GET /hidden HTTP/1.1'}),
  event('request','HTTP request',source='edge',sensor=brand,method='HEAD',path='/manual',status='204',seen='2026-07-12T11:01:00+00:00'),
  event('report','Rule 906 reported',source='monitor',sensor=brand,seen='2026-07-12T11:01:06+00:00',provenance={'detail':'summary'}))
 plan=Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},p,[],{})
 draft=choices(plan.request,groups='selected' if accounted else 'omit',purpose=None);can=plan.decode(draft)
 final=plan._revision('SYNTHETIC-CONTRAST',json.dumps(draft),can,sy.presentation(can,p['events']))
 return p,plan,final

@pytest.mark.parametrize('brand',['Nacre','Kestrel','source_label_only/omit'])
@pytest.mark.parametrize('accounted',[False,True])
def test_unfamiliar_brand_does_not_control_available_actions_reports_or_purposes(monkeypatch,brand,accounted):
 p,plan,final=build(monkeypatch,brand,accounted);before=copy.deepcopy(p)
 logical=rep.expand(json.loads(final.request['messages'][1]['content']));shown=logical['provisional_answer']['rendered'];facts=rev.restore_facts(logical['offered']['facts'],shown)
 assert logical['packet']['events'][0]['http_metadata']['request_line']=='GET /hidden HTTP/1.1'
 label=next((k,f) for k,f in facts.items() if f['evidence_ids']==['label'])
 assert '/hidden' not in label[1]['summary']
 request=next((k,f) for k,f in facts.items() if f['evidence_ids']==['request'])
 assert all(s in request[1]['summary'] for s in ('HEAD','/manual','204'))
 report=next((k,f) for k,f in facts.items() if f['evidence_ids']==['report'])
 assert 'Rule 906 reported' in report[1]['summary']
 w=choices(final.request,groups='omit',purpose=None)
 for key,f in (request,report):w['observations'][key]={'comparison':'adds_behavior','purpose':'detail'}
 result=final.decode(w);assert result['findings']==[gen.offers(p,[],{})[0]['facts'][k] for k in (request[0],report[0])]
 assert result['classification']=='inconclusive' and result['actor_correlation']==[]
 # Even deliberately wrong judgments remain reachable; no output selection filter.
 for comp,purpose in itertools.product(rev.COMPARISONS,['omit','detail','support']):
  w['observations']={label[0]:{'comparison':comp,'purpose':purpose}};value=final.decode(w)
  assert value['findings']==([] if purpose=='omit' else [gen.offers(p,[],{})[0]['facts'][label[0]]])
 for absent in ({},{k:{'comparison':'unresolved','purpose':'omit'} for k in facts}):
  w['observations']=absent;assert not final.decode(w)['findings']
 assert p==before and plan.request['options']==final.request['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}

def test_later_report_is_not_replaced_by_an_earlier_same_named_report(monkeypatch):
 p,_,final=build(monkeypatch,'Nacre',True)
 w=choices(final.request,groups='selected',purpose=None);can=final.decode(w);details=sy.presentation(can,p['events'])['details']
 report=next(d for d in details if any(r['event_id']=='report' for r in d['rows']))
 assert 'Rule 906 reported' in report['account'] and '2026-07-12T11:01:06' in report['account']
 assert 'attacks or current enforcement' in report['uncertainty']
 assert 'Lumen' not in json.dumps(can) and 'Rule541' not in json.dumps(can)

def test_examples_are_system_data_only_and_draft_and_wire_contract_unchanged(monkeypatch):
 _,plan,final=build(monkeypatch,'Nacre',False)
 assert rev.REVISION_CONTRASTS in final.request['messages'][0]['content']
 assert rev.REVISION_CONTRASTS not in plan.request['messages'][0]['content']
 assert final.request['messages'][0]['content'].count(gen.OBSERVATION_RULES)==1
 assert plan.generation_version=='joint-answer-revision-3'
 assert plan.identity['prompt_version']=='behavior-3.40'
 assert not any(x in final.request['messages'][1]['content'] for x in ('Rule541','Lumen','/guide'))
