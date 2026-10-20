"""Exploratory positive arrays: compatibility and strict rejection, never model utility."""
import copy,itertools,json
import pytest
import behavior_ai as ai
import behavior_generation as gen
from test_source_observations import linked_packet
from test_generation_slots import positive
from test_generation_choices import transport
from test_generation_fixtures import observation_roles

@pytest.fixture(autouse=True)
def fixed_time(monkeypatch):monkeypatch.setattr(ai,'now',lambda:'2026-10-17T10:01:00+00:00')

def empty(p):return observation_roles(gen.example(p))

def test_arrays_required_empty_legal_group_first_and_no_empty_enum():
 for p in [positive(),{'packet_id':'empty','events':[],'context':[],'coverage':'saved_samples'}]:
  w=empty(p);before=copy.deepcopy(w);(v,_),calls=transport(p,w);props=calls[0]['format']['properties'];tables,_=gen.offers(p,[],{})
  assert v['findings']==v['contradictory_evidence']==[] and w==before
  assert v['classification']=='inconclusive' and v['automation']==v['intent']=={'classification':'unknown','confidence':0}
  for field,kind in [('finding_ids','facts'),('counterevidence_ids','counterevidence')]:
   spec=props[field];assert spec['type']=='array' and spec['minItems']==0 and spec['maxItems']==len(tables[kind])
   assert field in calls[0]['format']['required']
   if tables[kind]:assert spec['items']['enum']==list(tables[kind])
   else:
    assert 'enum' not in spec['items']
    bad=copy.deepcopy(w);bad[field]=['foreign']
    with pytest.raises(ValueError):gen.decode(bad,p,[],{})
  assert 'observations' not in props and 'observations' not in w
  if w['observable_synthesis']:assert list(props)[0]=='observable_synthesis'


def test_every_small_legal_assignment_and_each_role_permutation_preserves_full_facts():
 p=positive();tables,_=gen.offers(p,[],{});ids=list(tables['facts']);before=copy.deepcopy((p,tables));checked=0
 choices=[['omit','finding']+(['counterevidence'] if k in tables['counterevidence'] else []) for k in ids]
 for roles in itertools.product(*choices):
  findings=[k for k,r in zip(ids,roles) if r=='finding'];opposing=[k for k,r in zip(ids,roles) if r=='counterevidence']
  for left in itertools.permutations(findings):
   for right in itertools.permutations(opposing):
    w=observation_roles(gen.example(p),left,right);original=copy.deepcopy(w);v=gen.decode(w,p,[],{});ai.validate_result(v,p,[],{})
    assert v['findings']==[tables['facts'][k] for k in left]
    assert v['contradictory_evidence']==[tables['facts'][k] for k in right]
    assert w==original;checked+=1
 assert checked>=24 and (p,tables)==before


@pytest.mark.parametrize('field',['finding_ids','counterevidence_ids'])
def test_same_array_duplicates_are_rejected_with_safe_index_and_without_mutation(field):
 p=positive();p['context'].append({**p['context'][0],'id':'second-positive'});tables,_=gen.offers(p,[],{});key=next(iter(tables['counterevidence']))
 w=empty(p);w[field]=[key,key];before=copy.deepcopy(w)
 with pytest.raises(gen.ChoiceError) as caught:gen.decode(w,p,[],{})
 assert caught.value.diagnostic()=={'category':'generation_choice','reason':'duplicate_choice','field':field,'index':1}
 assert key not in str(caught.value) and w==before
 with pytest.raises(ai.ModelOutputError) as caught:transport(p,w)
 assert caught.value.metadata['validation_diagnostic']['index']==1
 assert key not in json.dumps(caught.value.metadata)


def test_cross_array_reuse_rejects_before_observation_copy(monkeypatch):
 p=positive();tables,_=gen.offers(p,[],{});key=next(iter(tables['counterevidence']));w=observation_roles(gen.example(p),[key]);w['counterevidence_ids']=[key];before=copy.deepcopy(w)
 # No observation copies may happen on this invalid wire (prepare uses deepcopy).
 with pytest.raises(gen.ChoiceError) as caught:gen.decode(w,p,[],{})
 assert caught.value.diagnostic()=={'category':'generation_choice','reason':'duplicate_observation_sides','field':'counterevidence_ids','index':0}
 assert w==before


def test_maximum_combined_bound_is_twelve_not_twelve_per_side_and_no_clipping():
 p=positive();base=p['events'][0];p['context'].append({**p['context'][0],'id':'positive-two'})
 p['events'] += [{**base,'id':'extra-'+str(i)} for i in range(20)]
 tables,_=gen.offers(p,[],{});assert len(tables['facts'])==12 and len(tables['counterevidence'])==2
 ids=list(tables['facts']);w=observation_roles(gen.example(p),ids);before=copy.deepcopy(w);v=gen.decode(w,p,[],{});ai.validate_result(v,p,[],{})
 assert len(v['findings'])==12 and w==before
 pos=next(iter(tables['counterevidence']));w=observation_roles(gen.example(p),[k for k in ids if k!=pos],[pos]);v=gen.decode(w,p,[],{});ai.validate_result(v,p,[],{})
 assert len(v['findings'])+len(v['contradictory_evidence'])==12
 w['finding_ids'].append(pos);original=copy.deepcopy(w)
 with pytest.raises(gen.ChoiceError) as caught:gen.decode(w,p,[],{})
 assert caught.value.reason=='combined_observation_bound' and w==original
 w=observation_roles(gen.example(p),ids+[ids[0]])
 with pytest.raises(ValueError):gen.decode(w,p,[],{})


@pytest.mark.parametrize('mutation',[
 lambda w:w.pop('finding_ids'),lambda w:w.pop('counterevidence_ids'),
 lambda w:w.update(finding_ids={}),lambda w:w.update(finding_ids='foreign'),
 lambda w:w.update(finding_ids=[True]),lambda w:w.update(finding_ids=[None]),
 lambda w:w.update(finding_ids=[{'choice_id':'foreign'}]),lambda w:w.update(finding_ids=['PRIVATE-UNKNOWN']),
 lambda w:w.update(counterevidence_ids=[w['finding_ids'][0]]),
 lambda w:w.update(packet_id='foreign'),lambda w:w.update(generation_schema_version='grounded-groups-9'),
 lambda w:w.update(observations={}),lambda w:w.update(extra='PRIVATE-TEXT'),
 lambda w:w.update(maliciousness_confidence=True),lambda w:w.update(maliciousness_confidence=90),
])
def test_strict_shape_version_packet_ids_and_roles_reject_without_salvage(mutation):
 p=linked_packet();w=gen.example(p);mutation(w);before=copy.deepcopy(w)
 with pytest.raises(ai.ModelOutputError) as caught:transport(p,w)
 assert 'PRIVATE' not in json.dumps(caught.value.metadata) and w==before


def test_old_dictionary_new_version_and_old_version_arrays_both_reject():
 p=linked_packet();w=gen.example(p);old=copy.deepcopy(w);old['observations']={k:'finding' for k in old.pop('finding_ids')};old.pop('counterevidence_ids')
 for version in ['grounded-groups-9',gen.VERSION]:
  old['generation_schema_version']=version
  with pytest.raises(ValueError):gen.decode(old,p,[],{})
 w['generation_schema_version']='grounded-groups-9'
 with pytest.raises(ValueError):gen.decode(w,p,[],{})


@pytest.mark.parametrize('text',['NaN','Infinity','-Infinity'])
def test_json_constants_and_duplicate_members_never_repair(text):
 with pytest.raises(gen.ChoiceError):gen.parse_wire('{"finding_ids":'+text+'}')
 with pytest.raises(gen.ChoiceError):gen.parse_wire('{"finding_ids":[],"finding_ids":[]}')


def test_complete_malicious_support_only_in_findings_and_never_forced():
 p=linked_packet();tables,c=gen.offers(p,[],{});pair=c['malicious_support_pairs'][0];w=observation_roles(gen.example(p),pair);w['classification']='malicious'
 assert transport(p,w)[0][0]['classification']=='malicious'
 w['finding_ids']=pair[:1]
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 w['counterevidence_ids']=pair[1:]
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 w=empty(p);assert transport(p,w)[0][0]['classification']=='inconclusive'
 w['classification']='malicious'
 with pytest.raises(ai.ModelOutputError):transport(p,w)


def test_positive_context_benign_support_and_all_visible_with_synthesis():
 p=positive();tables,_=gen.offers(p,[],{});key=next(iter(tables['counterevidence']));w=observation_roles(gen.example(p),[],[key]);v=transport(p,w)[0][0]
 assert v['findings']==[] and v['contradictory_evidence']==[tables['facts'][key]]
 w=observation_roles(gen.example(p),[key]);w['classification']='benign';assert transport(p,w)[0][0]['classification']=='benign'
 w['finding_ids']=[]
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 w=empty(p);w['observable_synthesis'][next(iter(w['observable_synthesis']))]='reported_session_sequence'
 with pytest.raises(ai.ModelOutputError):transport(p,w)
 w['counterevidence_ids']=[key];assert transport(p,w)[0][0]['observable_synthesis']


@pytest.mark.parametrize('provider,extra',[
 ('crawler',{'verified':False}),('crawler',{'cache_fresh':False}),('crawler',{'expires':'2000-01-01T00:00:00+00:00'}),
 ('greynoise',{'classification':'benign','observation_fresh':False}),
 ('greynoise',{'classification':'benign','observation_fresh':True,'cache_fresh':False}),
])
def test_stale_or_unverified_positive_context_cannot_be_counterevidence(provider,extra):
 p=positive();p['context'][0].update(provider=provider,**extra);tables,_=gen.offers(p,[],{});assert tables['counterevidence']=={}
 w=empty(p);w['counterevidence_ids']=list(tables['facts'])[:1]
 with pytest.raises(ValueError):gen.decode(w,p,[],{})


def test_fresh_greynoise_context_retains_exact_binding_in_either_role():
 p=positive();p['context'][0].update(provider='greynoise',classification='benign',observation_fresh=True);tables,_=gen.offers(p,[],{});key=next(iter(tables['counterevidence']))
 for role in ['finding_ids','counterevidence_ids']:
  w=empty(p);w[role]=[key];v=transport(p,w)[0][0]
  assert tables['facts'][key] in v['findings']+v['contradictory_evidence']


def test_typed_details_with_group_and_generic_choices_both_remain_available():
 p=linked_packet();tables,_=gen.offers(p,[],{});w=empty(p);w['observable_synthesis'][next(iter(w['observable_synthesis']))]='reported_session_sequence'
 details=[k for k,v in tables['facts'].items() if len(v['evidence_ids'])==2];assert len(details)==2
 for order in itertools.permutations(details):
  w['finding_ids']=list(order);v=transport(p,w)[0][0];assert v['findings']==[tables['facts'][k] for k in order]
  assert all('after its cited connection' in f['summary'] for f in v['findings'])
 p={'packet_id':'label','events':[{'id':'label','source':'tpot','sensor':'Cowrie','action':'Cowrie','seen':'2026-10-17T10:00:00+00:00'}],'context':[],'coverage':'saved_samples'}
 tables,_=gen.offers(p,[],{});w=gen.example(p);assert transport(p,w)[0][0]['findings']==list(tables['facts'].values())


def test_mapping_required_slots_and_canonical_required_fields_remain_strict():
 p=linked_packet();registry={'attack':{'T1059':'Command and Scripting Interpreter'},'d3fend':{}};w=empty(p)
 w=gen.example(p,registry=registry);w['attack_techniques'].pop(next(iter(w['attack_techniques'])))
 with pytest.raises(ai.ModelOutputError):transport(p,w,registry=registry)
 v=transport(p,empty(p))[0][0]
 for key in ai.RESPONSE_SCHEMA['required']:
  bad=copy.deepcopy(v);bad.pop(key)
  with pytest.raises(ValueError):ai.validate_result(bad,p,[],{})


def test_generation_version_alone_separates_jobs_and_preserves_old_canonical(tmp_path,monkeypatch):
 from core import Store,now
 from test_behavior_ai import result
 store=Store(tmp_path/'native');store.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50)
 brain=ai.Brain(store);ident,packet,features=brain.packet(store.describe('8.8.8.8'));calls=[]
 def fake(*args):
  calls.append(ai.GENERATION_SCHEMA_VERSION)
  return result(packet),{'prompt_version':ai.PROMPT_VERSION,'generation_schema_version':ai.GENERATION_SCHEMA_VERSION}
 monkeypatch.setattr(ai,'infer',fake);cfg={**ai.DEFAULTS,'model_enabled':True,'daily_budget':None}
 monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','grounded-groups-9')
 assert ai.model_job(brain,ident,packet,features,cfg,candidates=[])=='completed'
 with brain.connect() as db:old=tuple(db.execute('SELECT * FROM assessments').fetchone())
 monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','grounded-groups-10')
 assert ai.model_job(brain,ident,packet,features,cfg,candidates=[])=='completed'
 assert ai.model_job(brain,ident,packet,features,cfg,candidates=[])=='cached'
 with brain.connect() as db:rows=[tuple(r) for r in db.execute('SELECT * FROM assessments')]
 assert old in rows and len(rows)==2 and len({r[2] for r in rows})==2
 assert calls==['grounded-groups-9','grounded-groups-10']
