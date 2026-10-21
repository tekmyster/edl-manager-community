"""Structural selection regressions. No model or production calls."""
from test_generation_fixtures import decision
import copy,json
import pytest
from behavior_generation import offers,prepare,decode,parse_wire,example,ChoiceError
from behavior_ai import shape,validate_result,ModelOutputError
from test_generation_choices import transport
from test_source_observations import linked_packet
from test_generation_fixtures import observation_roles
from test_behavior_taxonomy import event,catalog


def positive():
 p=linked_packet();p['context']=[{'id':'ctx','kind':'intelligence','provider':'crawler','verified':True,'cache_fresh':True,'status':'ok','expires':'2099-01-01T00:00:00+00:00'}]
 return p


def test_positive_observation_has_one_identity_and_exclusive_role_slot():
 p=positive();t,_=offers(p,[],{});schema,prompt=prepare(p,[],{})
 assert set(t['counterevidence'])<=set(t['facts']) and 'counterevidence' not in prompt['offered']
 key=next(iter(t['counterevidence']));spec=schema['properties']['observations']
 assert spec['properties'][key]['properties']['purpose']['enum']==['omit','detail','support','counterevidence']
 assert spec['required']==[] and list(spec['properties'])==list(t['facts'])
 for role in ('omit','detail','support','counterevidence'):
  wire=example(p);observation_roles(wire);wire['observations'][key]=decision(role, packet=p, key=key)
  value=decode(wire,p,[],{});validate_result(value,p,[],{})
  assert sum(t['facts'][key] in value[f] for f in ('findings','contradictory_evidence'))==int(role!='omit')
 assert all('counterevidence' not in v['properties']['purpose']['enum'] for k,v in spec['properties'].items() if k not in t['counterevidence'])


def test_single_mapping_has_one_optional_switch_not_two_repeatable_slots():
 p=linked_packet();registry={'attack':{'T1059':'Command and Scripting Interpreter'},'d3fend':{}}
 t,_=offers(p,[],registry);schema,_=prepare(p,[],registry);wire=example(p,registry=registry)
 assert len(t['attack'])==1;key=next(iter(t['attack']))
 assert schema['properties']['attack_techniques']['properties'][key]['enum']==['omit','include']
 assert decode(wire,p,[],registry)['attack_techniques']==[]
 wire['attack_techniques'][key]='include';value=decode(wire,p,[],registry);validate_result(value,p,[],registry)
 assert len(value['attack_techniques'])==1
 wire['attack_techniques']=[key,key]
 with pytest.raises(ValueError):decode(wire,p,[],registry)


@pytest.mark.parametrize('roles',[('detail','counterevidence'),('include','include'),('include','omit')])
def test_duplicate_json_members_reject_before_overwriting_including_escaped_keys(roles):
 key='PRIVATE-KEY';escaped='\\u0050RIVATE-KEY'
 raw='{"'+key+'":"'+roles[0]+'","'+escaped+'":"'+roles[1]+'"}'
 with pytest.raises(ChoiceError) as caught:parse_wire(raw)
 assert caught.value.diagnostic()=={'category':'generation_choice','reason':'duplicate_object_key','field':'generation_payload'}
 assert 'PRIVATE' not in str(caught.value)


def test_actual_infer_rejects_duplicate_members_without_normalizing_or_retaining_values():
 from behavior_ai import infer,DEFAULTS
 p=positive();t,_=offers(p,[],{});wire=example(p);key=next(iter(t['counterevidence']))
 raw=json.dumps(wire);old=json.dumps(key)+': '+json.dumps(wire['observations'][key])
 raw=raw.replace(old,json.dumps(key)+': "finding", '+json.dumps(key)+': "counterevidence"',1)
 class Response:
  status_code=200
  def close(self):pass
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','message':{'content':raw}}).encode()
 with pytest.raises(ModelOutputError) as caught:infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},p,[],{},'',requester=lambda *a,**kw:Response())
 assert caught.value.metadata['validation_diagnostic']['reason']=='duplicate_object_key'
 assert key not in json.dumps(caught.value.metadata)


def test_all_omit_and_unknown_stay_empty_without_forced_fact_or_mapping():
 p=positive();t,_=offers(p,[],{});wire=example(p);observation_roles(wire)
 value=transport(p,wire)[0][0]
 assert all(value[f]==[] for f in ('findings','contradictory_evidence','attack_techniques','d3fend_context','actor_correlation'))
 assert value['automation']==value['intent']=={'classification':'unknown','confidence':0}
 assert wire['observations']=={k:decision('omit', packet=p, key=k) for k in t['facts']}


@pytest.mark.parametrize('mutation',[
 lambda w:w['observations'].update({'foreign':'detail'}),
 lambda w:w['observations'].__setitem__(next(iter(w['observations'])),['detail','counterevidence']),
 lambda w:w['observations'].__setitem__(next(iter(w['observations'])),True),
 lambda w:w.update(generation_schema_version='grounded-choices-2'),
])
def test_foreign_cross_role_or_legacy_structures_reject(mutation):
 p=positive();w=example(p);mutation(w)
 with pytest.raises(ModelOutputError):transport(p,w)


def test_all_offered_slots_fit_accepted_counts_without_filtering(catalog):
 p={'packet_id':'bounds','coverage':'saved_samples','events':[event('a','powershell execution'),event('b','network service discovery'),event('c','credential dump attempt')],'context':[]}
 w=example(p,registry=catalog);w['observations']={k:decision('detail', packet=p, key=k) for k in w['observations']};before=copy.deepcopy(w)
 value=decode(w,p,[],catalog);validate_result(value,p,[],catalog)
 assert len(value['findings'])==len(w['observations'])>2 and w==before
 w['attack_techniques']={k:'include' for k in w['attack_techniques']}
 w['d3fend_context']={k:'include' for k in w['d3fend_context']}
 before=copy.deepcopy(w);value=decode(w,p,[],catalog);validate_result(value,p,[],catalog)
 assert len(value['attack_techniques'])==len(w['attack_techniques'])>=3
 assert len(value['d3fend_context'])==len(w['d3fend_context'])>1 and w==before


def test_maximum_source_offers_are_structurally_count_safe(catalog):
 from behavior_generation import SELECTION_BOUNDS
 p={'packet_id':'maximum','coverage':'saved_samples','context':[]}
 # Plain actions exercise every supported detector.
 actions=['password guessing','password spraying','credential stuffing','scanning ip blocks','vulnerability scanning','wordlist scanning','network service discovery','public-facing application exploit attempt','credential dump attempt','powershell execution','windows command shell execution','unix shell execution','system information discovery','file and directory discovery','system network configuration discovery','process discovery','system owner/user discovery','ingress tool transfer','web shell execution','network denial of service']
 p['events']=[event(str(i),action) for i,action in enumerate(actions)]
 t,_=offers(p,[],catalog);schema,prompt=prepare(p,[],catalog)
 assert {k:len(t[k]) for k in SELECTION_BOUNDS}==SELECTION_BOUNDS
 assert prompt['grounding']['selection_bounds']==SELECTION_BOUNDS
 w=example(p,registry=catalog)
 w['observations']={k:decision('detail', packet=p, key=k) for k in t['facts']}
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:w[field]={k:'include' for k in t[kind]}
 before=copy.deepcopy(w);shape(schema,w);v=decode(w,p,[],catalog);validate_result(v,p,[],catalog)
 assert (len(v['findings']),len(v['attack_techniques']),len(v['d3fend_context']))==(12,12,6)
 assert w==before
 for field in ('observations','attack_techniques','d3fend_context'):
  bad=copy.deepcopy(w);bad[field]['foreign']='detail' if field=='observations' else 'include'
  with pytest.raises(ValueError):decode(bad,p,[],catalog)
 bad=copy.deepcopy(v);bad['findings']*=2
 with pytest.raises(ValueError):validate_result(bad,p,[],catalog)


def test_offer_bound_regression_fails_closed(monkeypatch):
 import behavior_generation as g
 p=positive();real=g.contract
 def over(*args):
  c=real(*args);c['facts']=c['facts']*13;return c
 monkeypatch.setattr(g,'contract',over)
 with pytest.raises(ChoiceError) as caught:offers(p,[],{})
 assert caught.value.reason=='offer_bound'


def test_old_canonical_duplicate_mapping_and_cross_role_claims_are_not_new_wire():
 from behavior_grounding import example as stored
 p=positive();legacy=stored(p);legacy['contradictory_evidence']=copy.deepcopy(legacy['findings']);before=copy.deepcopy(legacy)
 with pytest.raises(ValueError):validate_result(legacy,p,[],{})
 with pytest.raises(ModelOutputError):transport(p,legacy)
 assert legacy==before
