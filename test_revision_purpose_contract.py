"""Shared purpose guidance and literal-content contrasts; no model-quality oracle."""
import copy,json,itertools
import pytest
import behavior_ai as ai,behavior_tokens as tokens,behavior_generation as gen
import behavior_revision as rev,behavior_representation as rep,behavior_synthesis as sy
from behavior_pipeline import Pipeline
from test_pipeline_support import SyntheticCounter,choices
from test_observable_synthesis import event,packet

def mixed():
 return packet(event('brand','Atlas',source='collector',sensor='Atlas',provenance={'detail':'summary'},http_metadata={'request_line':'GET /richer-record HTTP/1.1'}),
  event('http','HTTP request',source='edge',sensor='web',method='GET',path='/catalog',status='200',seen='2026-08-01T03:04:05+00:00'),
  event('rule','Rule 782 reported',source='monitor',sensor='rule:782',seen='2026-08-01T03:04:05.032+00:00',provenance={'detail':'summary'}))

def revision(monkeypatch,p):
 monkeypatch.setattr(tokens,'load',lambda cfg:SyntheticCounter())
 plan=Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},p,[],{})
 draft=choices(plan.request,groups='omit',purpose=None);can=plan.decode(draft)
 final=plan._revision('synthetic-purpose-contract',json.dumps(draft),can,sy.presentation(can,p['events']))
 return plan,final

def test_both_stages_define_original_purposes_without_changing_wire_contract(monkeypatch):
 p=mixed();plan,final=revision(monkeypatch,p)
 for q in (plan.request,final.request):assert q['messages'][0]['content'].count(gen.OBSERVATION_RULES)==1
 assert final.request['format']['properties']['generation_schema_version']['enum']==['joint-answer-revision-3']
 for key,spec in final.request['format']['properties']['observations']['properties'].items():
  assert spec['properties']['comparison']['enum']==list(rev.COMPARISONS)
  assert spec['properties']['purpose']==plan.request['format']['properties']['observations']['properties'][key]

def test_literal_summary_and_richer_record_remain_distinct_and_lossless(monkeypatch):
 p=mixed();original=copy.deepcopy(p);_,final=revision(monkeypatch,p)
 logical=rep.expand(json.loads(final.request['messages'][1]['content']));shown=logical['provisional_answer']['rendered']
 facts=rev.restore_facts(logical['offered']['facts'],shown)
 label=next(f for f in facts.values() if f['evidence_ids']==['brand'])
 assert 'Atlas' in label['summary'] and '/richer-record' not in label['summary']
 assert logical['packet']['events'][0]['http_metadata']['request_line']=='GET /richer-record HTTP/1.1'
 assert rev.restore_accounts(logical['synthesis_options'],shown)==gen.prepare(p,[],{})[1]['synthesis_options']
 assert p==original

@pytest.mark.parametrize('same_time',[False,True])
def test_omitting_brand_keeps_actual_request_rule_time_and_uncertainty(monkeypatch,same_time):
 p=mixed()
 if same_time:p['events'][2]['seen']=p['events'][1]['seen']
 _,final=revision(monkeypatch,p);wire=choices(final.request,groups='omit');groups=sy.offers(p)
 for k,g in groups.items():
  if g['kind']!='insufficient_detail':wire['observable_synthesis'][k]=g['interpretations'][-1]
 can=final.decode(wire);assert not can['findings'];details=sy.presentation(can,p['events'])['details']
 for e in p['events'][1:]:
  assert any(e['id'] in [r['event_id'] for r in d['rows']] and sy.project_report(e)['seen'] in d['account'] for d in details)
 rule=next(d for d in details if any(r['event_id']=='rule' for r in d['rows']))
 assert 'Rule 782 reported' in rule['account'] and 'independent events' in rule['uncertainty']
 http=next(d for d in details if any(r['event_id']=='http' for r in d['rows']))
 row=next(r for r in http['rows'] if r['event_id']=='http')
 assert (row['method'],row['path'],row['status'])==('GET','/catalog','200')
 assert all(word in http['account'] for word in ('GET','/catalog','HTTP 200')) and 'authorization' in http['uncertainty']
 assert all('/richer-record' not in d['account'] for d in details)

def test_bad_source_label_detail_and_all_omit_stay_legal(monkeypatch):
 p=mixed();_,final=revision(monkeypatch,p);facts=gen.offers(p,[],{})[0]['facts'];key=next(k for k,v in facts.items() if v['evidence_ids']==['brand'])
 purposes=final.request['format']['properties']['observations']['properties'][key]['properties']['purpose']['enum']
 for comp,purpose in itertools.product(rev.COMPARISONS,purposes):
  w=choices(final.request,groups='omit');w['observations']={key:{'comparison':comp,'purpose':purpose}};can=final.decode(w)
  assert can['findings']==([] if purpose in ('omit','counterevidence') else [facts[key]])
 empty=final.decode(choices(final.request,groups='omit'))
 assert not empty['findings'] and not empty['observable_synthesis']
