"""Keyed contribution choices and explicit source timing. Synthetic, not model utility."""
from test_pipeline_mock import stage_mock
from test_generation_fixtures import decision
import copy,itertools,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
import behavior_synthesis as synth
from test_generation_slots import positive
from test_source_observations import linked_packet
from test_generation_choices import transport

@pytest.fixture(autouse=True)
def fixed_time(monkeypatch):monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00')

def empty(p):
 w=gen.example(p);w['observations']={};return w


def test_zero_one_and_all_twelve_contributions_keep_every_selected_statement():
 for n in [0,1,12]:
  p={'packet_id':'boundary-'+str(n),'events':[{'id':str(i),'source':'tpot','sensor':'Cowrie','action':'Cowrie','seen':'2026-10-17T10:00:00+00:00'} for i in range(n)],'context':[],'coverage':'saved_samples'}
  t,_=gen.offers(p,[],{});assert len(t['facts'])==n
  for purpose in ['detail','support']:
   w=empty(p);w['observations']={k:decision(purpose, packet=p, key=k) for k in t['facts']};before=copy.deepcopy((p,w));v=transport(p,w)[0][0]
   assert v['findings']==list(t['facts'].values()) and (p,w)==before
   assert v['contradictory_evidence']==[]
  w=empty(p);w['observations']['foreign']=decision('detail', packet=p, key='foreign')
  with pytest.raises(ValueError):gen.decode(w,p,[],{})


def test_each_purpose_assignment_is_lossless_and_order_preserved_not_a_utility_filter():
 p=positive();t,_=gen.offers(p,[],{});ids=list(t['facts']);before=copy.deepcopy(p)
 choices=[['omit','detail','support']+(['counterevidence'] if k in t['counterevidence'] else []) for k in ids]
 for roles in itertools.product(*choices):
  w=empty(p);w['observations']={k:decision(r, packet=p, key=k) for k,r in zip(reversed(ids),reversed(roles))};v=gen.decode(w,p,[],{});ai.validate_result(v,p,[],{})
  assert v['findings']==[t['facts'][k] for k,r in w['observations'].items() if r in ['detail','support']]
  assert v['contradictory_evidence']==[t['facts'][k] for k,r in w['observations'].items() if r=='counterevidence']
 assert p==before


@pytest.mark.parametrize('value',[['detail','counterevidence'],{'detail':True,'counterevidence':True},True,None,'finding','include'])
def test_two_roles_old_roles_and_non_scalar_values_reject_without_repair(value):
 p=positive();key=next(iter(gen.offers(p,[],{})[0]['counterevidence']));w=empty(p);w['observations']={key:value};before=copy.deepcopy(w)
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 assert w==before


@pytest.mark.parametrize('left,right',[('detail','detail'),('detail','support'),('support','counterevidence'),('omit','counterevidence')])
def test_repeated_observation_member_including_cross_role_rejects_before_decode(left,right):
 raw='{"observations":{"PRIVATE":"'+left+'","\\u0050RIVATE":"'+right+'"}}'
 with pytest.raises(gen.ChoiceError) as caught:gen.parse_wire(raw)
 assert caught.value.reason=='duplicate_object_key' and 'PRIVATE' not in str(caught.value)


@pytest.mark.parametrize('mutation',[
 lambda w:w.pop('observations'),lambda w:w.update(finding_ids=[]),lambda w:w.update(counterevidence_ids=[]),
 lambda w:w.update(generation_schema_version='grounded-groups-10'),lambda w:w.update(generation_schema_version='grounded-groups-9'),
 lambda w:w.update(observations=[]),lambda w:w.update(extra='PRIVATE'),
])
def test_old_array_wire_hybrid_and_old_dictionary_version_reject(mutation):
 p=linked_packet();w=empty(p);mutation(w);before=copy.deepcopy(w)
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 assert w==before


def test_detail_and_support_emit_identical_canonical_findings_without_judging_purpose_as_truth():
 p=linked_packet();k=next(iter(gen.offers(p,[],{})[0]['facts']));a=empty(p);a['observations']={k:decision('detail', packet=p, key=k)};b=copy.deepcopy(a);b['observations'][k]=decision('support', packet=p, key=k)
 assert transport(p,a)[0][0]==transport(p,b)[0][0]


@pytest.mark.parametrize('provider,extra',[
 ('crawler',{'verified':False}),('crawler',{'cache_fresh':False}),('crawler',{'expires':'2000-01-01T00:00:00+00:00'}),
 ('greynoise',{'classification':'benign','observation_fresh':False}),('greynoise',{'classification':'benign','observation_fresh':True,'cache_fresh':False}),
])
def test_nonqualifying_context_has_no_opposing_purpose(provider,extra):
 p=positive();p['context'][0].update(provider=provider,**extra);t,_=gen.offers(p,[],{});assert not t['counterevidence']
 w=empty(p);w['observations']={next(iter(t['facts'])):'counterevidence'}
 with pytest.raises(ValueError):gen.decode(w,p,[],{})


@pytest.mark.parametrize('provider',['crawler','greynoise'])
def test_positive_can_be_support_or_opposition_and_all_context_visible_with_synthesis(provider):
 p=positive()
 if provider=='greynoise':p['context'][0].update(provider=provider,classification='benign',observation_fresh=True)
 t,_=gen.offers(p,[],{});k=next(iter(t['counterevidence']));w=empty(p);w['observable_synthesis'][next(iter(w['observable_synthesis']))]='reported_session_sequence'
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 for purpose,classification in [('support','benign'),('counterevidence','inconclusive')]:
  w['observations']={k:decision(purpose, packet=p, key=k)};w['classification']=classification;v=transport(p,w)[0][0]
  assert t['facts'][k] in v['findings']+v['contradictory_evidence']


def test_malicious_support_must_remain_cited_findings_not_opposition_or_auto_added():
 p=linked_packet();t,c=gen.offers(p,[],{});pair=c['malicious_support_pairs'][0];w=empty(p);w['classification']='malicious';w['observations']={k:decision('support', packet=p, key=k) for k in pair}
 assert transport(p,w)[0][0]['classification']=='malicious'
 w['observations'].pop(pair[1])
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 assert pair[1] not in w['observations']
 w['observations'][pair[1]]=decision('counterevidence', packet=p, key=pair[1])
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 assert transport(p,empty(p))[0][0]['classification']=='inconclusive'


@pytest.mark.parametrize('shell,capture,input_seconds,capture_seconds,after_input',[
 ('2026-10-17T10:00:04.309+00:00','2026-10-17T10:00:04.532+00:00','4.309','4.532','0.223'),
 ('2026-10-17T10:00:03.858+00:00','2026-10-17T10:00:04.096+00:00','3.858','4.096','0.238'),
 ('2026-10-17T10:00:01.120+00:00','2026-10-17T10:00:02.345+00:00','1.12','2.345','1.225'),
])
def test_selected_session_renders_explicit_both_capture_intervals_without_forcing_any_finding(shell,capture,input_seconds,capture_seconds,after_input):
 p=linked_packet();p['events'][0]['seen']='2026-10-17T10:00:00+00:00';p['events'][1]['seen']=shell;p['events'][2]['seen']=capture
 before=copy.deepcopy(p);w=empty(p);group=next(k for k,v in synth.offers(p).items() if v['kind']=='session_sequence');w['observable_synthesis'][group]='reported_session_sequence'
 v=transport(p,w)[0][0];saved=copy.deepcopy(v);display=synth.presentation(v,p['events']);account=display['details'][0]['account']
 assert 'shell input '+input_seconds+' seconds after connection' in account
 assert 'capture '+after_input+' seconds after input and '+capture_seconds+' seconds after connection' in account
 assert display['details'][0]['uncertainty']==synth.LIMITS['session_sequence']
 assert v['findings']==[] and v==saved and p==before
 assert display['details'][0]['rows']==[dict(r,number=i+1) for i,r in enumerate(v['observable_synthesis'][0]['source_tuples'])]
 assert gen.prepare(p,[],{})[1]['synthesis_options'][group]['reported_account']==account


def test_prompt_selection_and_generation_boundaries_separate_cache_from_failed_array_version(tmp_path,monkeypatch):
 from core import Store,now
 from test_behavior_ai import result
 s=Store(tmp_path/'native');s.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50);b=ai.Brain(s);ident,p,f=b.packet(s.describe('8.8.8.8'));calls=[]
 def fake(*args):calls.append((ai.PROMPT_VERSION,ai.GENERATION_SCHEMA_VERSION));return result(p),{}
 stage_mock(monkeypatch,ai,fake);cfg={**ai.DEFAULTS,'enabled':True,'model_enabled':True,'daily_budget':None}
 monkeypatch.setattr(ai,'PROMPT_VERSION','behavior-3.27');monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','grounded-groups-11');assert ai.model_job(b,ident,p,f,cfg,candidates=[])=='completed'
 with b.connect() as db:old=tuple(db.execute('SELECT * FROM assessments').fetchone())
 monkeypatch.setattr(ai,'PROMPT_VERSION','behavior-3.38');monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','joint-answer-revision-3');assert ai.model_job(b,ident,p,f,cfg,candidates=[])=='completed';assert ai.model_job(b,ident,p,f,cfg,candidates=[])=='cached'
 with b.connect() as db:rows=[tuple(r) for r in db.execute('SELECT * FROM assessments')]
 assert old in rows and len(rows)==2 and len(calls)==2
@pytest.mark.parametrize('constant',['NaN','Infinity','-Infinity'])
def test_nonfinite_raw_json_constants_remain_strictly_rejected(constant):
 with pytest.raises(gen.ChoiceError) as caught:gen.parse_wire('{"observations":'+constant+'}')
 assert caught.value.reason=='json_constant'


def test_twelve_combined_unique_observations_in_both_roles_not_twelve_each_and_no_hidden_cap():
 p=positive();base=p['events'][0];p['context'].append({**p['context'][0],'id':'other-positive'});p['events'] += [{**base,'id':'extra-'+str(i)} for i in range(7)]
 t,_=gen.offers(p,[],{});assert len(t['facts'])==12 and len(t['counterevidence'])==2
 w=empty(p);w['observations']={k:decision('counterevidence' if k in t['counterevidence'] else 'detail', packet=p, key=k) for k in t['facts']};before=copy.deepcopy(w);v=transport(p,w)[0][0]
 assert len(v['findings'])==10 and len(v['contradictory_evidence'])==2 and w==before
 w['observations']['unoffered-thirteenth']=decision('support', packet=p, key='unoffered-thirteenth')
 with pytest.raises(ai.ModelOutputError):transport(p,w)
