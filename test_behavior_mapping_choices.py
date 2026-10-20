from behavior_grounding import RELATION,ALTERNATIVE,SUMMARIES
"""Synthetic protocol regressions, never production correctness labels/inference."""
import copy,json
import pytest
import behavior_ai as ai
from behavior_mapping import select,validate_mapping
from test_behavior_ai import result
from test_behavior_taxonomy import catalog,event

@pytest.fixture
def mixed():
 return {'packet_id':'mixed','coverage':'saved_samples','events':[
  event('ps','powershell execution',destination={'asset_id':'fixture-target'},provenance={'detail':'sample','upstream_id':'ps'}),event('net','network service discovery',seen='2026-10-16T12:00:05+00:00',destination={'asset_id':'fixture-target'},provenance={'detail':'sample','upstream_id':'net'}),
  event('f1','authentication failure'),event('f2','cowrie.login.failed'),
  event('http','HTTP request',path='/login',method='POST'),event('cmd','cowrie.command.input',source='tpot',sensor='Cowrie',destination={'asset_id':'fixture-target'},provenance={'detail':'sample','upstream_id':'command'}),event('download','cowrie.session.file_download',source='tpot',sensor='Cowrie',seen='2026-10-16T12:00:05+00:00',destination={'asset_id':'fixture-target'},provenance={'detail':'sample','upstream_id':'transfer'})],
  'context':[{'id':'context-only','classification':'malicious'}]}

def send_result(packet,catalog,value,candidates=None):
 # Taxonomy plumbing fixtures use exact contract text. Semantic-injection tests
 # exercise the raw transport separately in test_behavior_grounding.py.
 from behavior_grounding import mapping_text
 value=copy.deepcopy(value)
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  for entry in value[field]:
   if set(entry)=={'support_id','explanation'} and isinstance(entry['support_id'],str) and entry['support_id'].startswith(kind+':'):
    ident=entry['support_id'].split(':',1)[1]
    if ident in catalog.get(kind,{}):entry['explanation']=mapping_text(kind,ident,catalog[kind][ident])
 from test_generation_fixtures import wire_or_invalid_legacy
 value=wire_or_invalid_legacy(packet,value,candidates,catalog)
 calls=[]
 class Response:
  status_code=200
  def iter_content(self,n):yield json.dumps({'done':True,'model':'test','message':{'content':json.dumps(value)}}).encode()
  def close(self):pass
 def send(*a,**kw):calls.append(kw['json']);return Response()
 outcome=ai.infer({**ai.DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,candidates or [],catalog,'',requester=send)
 return outcome,calls

def test_mixed_choices_bind_exact_technique_events_not_packet_or_context(mixed,catalog):
 wire=result(mixed);wire['attack_techniques']=[{'support_id':'attack:T1059.001','explanation':'Unconfirmed detector observation'},{'support_id':'attack:T1046','explanation':'Separate observation'}];wire['d3fend_context']=[{'support_id':'d3fend:D3-ANET','explanation':'Defensive context only'}]
 (value,metadata),calls=send_result(mixed,catalog,wire);payload=calls[0];prompt=json.loads(payload['messages'][1]['content']);choices={kind:{kind+':'+v['technique_id']:v for v in prompt['offered'][kind].values()} for kind in ('attack','d3fend')};schema=payload['format']['properties']
 assert {v['technique_id']:v['evidence_ids'] for v in value['attack_techniques']}=={'T1059.001':['ps'],'T1046':['net']}
 assert value['d3fend_context'][0]['evidence_ids']==['f1','f2']
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  spec=schema[field];assert spec['type']=='object'
  assert list(spec['properties'])==list(prompt['offered'][kind])
  assert all(v['enum']==['omit','include'] for v in spec['properties'].values())
  for claim in choices[kind].values():
   assert 'context-only' not in claim['evidence_ids'];validate_mapping(kind,claim,select(catalog,mixed),mixed)
 assert choices['attack']['attack:T1110']['evidence_ids']==['f1','f2']
 assert metadata['prompt_version']=='behavior-3.24' and metadata['generation_schema_version']=='grounded-groups-9'
 assert len(payload['messages'][1]['content'].encode())<=18000 and payload['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}

@pytest.mark.parametrize('entry',[
 {'support_id':'attack:T1059.001','evidence_ids':['net'],'explanation':'PRIVATE'},
 {'support_id':'attack:T1059.001','evidence_ids':['context-only'],'explanation':'PRIVATE'},
 {'support_id':'attack:T1110','evidence_ids':['f1'],'explanation':'PRIVATE'},
 {'technique_id':'T1059.001','evidence_ids':['ps'],'explanation':'PRIVATE'},
 {'support_id':'d3fend:D3-ANET','explanation':'PRIVATE'},
 {'support_id':'PRIVATE-UNKNOWN','explanation':'PRIVATE'},
 {'support_id':None,'explanation':'PRIVATE'},
 {'support_id':{},'explanation':'PRIVATE'},
 {'support_id':['attack:T1059.001'],'explanation':'PRIVATE'},
])
def test_invalid_or_altered_wire_claim_rejects_whole_assessment(mixed,catalog,entry):
 wire=result(mixed);wire['attack_techniques']=[entry]
 with pytest.raises(ai.ModelOutputError) as e:send_result(mixed,catalog,wire)
 assert e.value.code=='invalid_assessment' and e.value.metadata['validation_diagnostic']['stage']=='response_schema'
 assert 'PRIVATE' not in json.dumps(e.value.metadata)

def test_duplicate_choices_reject_instead_of_silently_deduplicating(mixed,catalog):
 wire=result(mixed);entry={'support_id':'attack:T1046','explanation':'Observation'};wire['attack_techniques']=[entry,entry]
 with pytest.raises(ai.ModelOutputError) as e:send_result(mixed,catalog,wire)
 assert e.value.metadata['validation_diagnostic']=={'stage':'response_schema','reason':'object_fields','field':'$'}

def test_decoder_rejects_extra_citations_and_does_not_partially_mutate(mixed,catalog):
 choices=ai.taxonomy_choices(mixed,select(catalog,mixed));wire=result(mixed)
 wire['attack_techniques']=[{'support_id':'attack:T1046','explanation':'Unconfirmed'}]
 wire['d3fend_context']=[{'support_id':'d3fend:D3-UA','explanation':'Unconfirmed','evidence_ids':['ps']}]
 before=copy.deepcopy(wire)
 with pytest.raises(ValueError,match='Malformed taxonomy choice'):ai.decode_taxonomy_choices(wire,choices)
 assert wire==before

@pytest.mark.parametrize('refs',[None,'ps',[None],[{}],['unknown']])
def test_canonical_malformed_unknown_refs_remain_rejected(mixed,catalog,refs):
 value=result(mixed);value['attack_techniques']=[{'technique_id':'T1059.001','evidence_ids':refs,'explanation':'Unconfirmed'}]
 with pytest.raises(ValueError):ai.validate_result(value,mixed,[],select(catalog,mixed))

def test_empty_unsupported_mapping_is_offered_and_remains_empty(catalog):
 packet={'packet_id':'ordinary','coverage':'saved_samples','events':[event()],'context':[{'id':'ctx'}]}
 (value,_),calls=send_result(packet,catalog,result(packet));prompt=json.loads(calls[0]['messages'][1]['content'])
 assert not prompt['offered']['attack'] and not prompt['offered']['d3fend']
 assert not value['attack_techniques'] and not value['d3fend_context']
 assert all(calls[0]['format']['properties'][f]['properties']=={} for f in ['attack_techniques','d3fend_context'])

def test_single_failed_login_never_offers_bruteforce_choice(catalog):
 packet={'packet_id':'one','coverage':'saved_samples','events':[event(action='authentication failure')],'context':[]}
 (_,metadata),calls=send_result(packet,catalog,result(packet));prompt=json.loads(calls[0]['messages'][1]['content'])
 assert not prompt['offered']['attack']

def test_bruteforce_pair_is_not_borrowed_from_another_mapping(catalog):
 packet={'packet_id':'different-pairs','coverage':'saved_samples','events':[event('f0','authentication failure',seen='2026-10-16T14:00:00+00:00'),event('f1','authentication failure'),event('f2','authentication failure')],'context':[]}
 allowed=select(catalog,packet);assert select(allowed,packet)==allowed
 choices=ai.taxonomy_choices(packet,allowed)
 assert choices['attack']['attack:T1110']['evidence_ids']==['f1','f2']
 assert choices['d3fend']['d3fend:D3-ANET']['evidence_ids']==['f0','f1']
 wire=result(packet);wire['attack_techniques']=[{'support_id':'attack:T1110','explanation':'Nearby sampled failures only'}]
 (value,_),_=send_result(packet,catalog,wire)
 assert value['attack_techniques'][0]['evidence_ids']==['f1','f2']

def test_mapping_choices_preserve_current_historical_correlation_guards(mixed,catalog):
 mixed['events'][0].update(path='/peer-only',method='GET')
 candidate={'candidate_id':'peer','current_events':[mixed['events'][0]],'historical_events':[{**mixed['events'][0],'id':'peer-event','path':'/peer-only','method':'GET'}]}
 wire=result(mixed);wire['attack_techniques']=[{'support_id':'attack:T1046','explanation':'Separate observation'}]
 wire['actor_correlation']=[{'candidate_id':'peer','confidence':.5,'current_evidence_ids':['ps'],'historical_evidence_ids':['peer-event'],'explanation':RELATION,'alternative_explanations':[ALTERNATIVE]}]
 (value,_),_=send_result(mixed,catalog,wire,[candidate]);assert value['actor_correlation'][0]['evidence_ids']==['ps','peer-event']
 wire['actor_correlation'][0]['current_evidence_ids']=['context-only']
 with pytest.raises(ai.ModelOutputError):send_result(mixed,catalog,wire,[candidate])

@pytest.mark.parametrize('refs',[['f1'],['ps','net'],['context-only'],['f1','context-only'],['unknown'],[],['f1','f1']])
def test_canonical_bruteforce_guard_still_rejects_invalid_support(mixed,catalog,refs):
 value=result(mixed);value['attack_techniques']=[{'technique_id':'T1110','evidence_ids':refs,'explanation':'Unconfirmed'}]
 with pytest.raises(ValueError):ai.validate_result(value,mixed,[],select(catalog,mixed))

@pytest.mark.parametrize('kind,ident,wrong',[('attack','T1059.001',['net']),('attack','T1046',['ps']),('d3fend','D3-ANET',['ps']),('d3fend','D3-UA',['context-only'])])
def test_canonical_cross_technique_and_context_refs_still_rejected(mixed,catalog,kind,ident,wrong):
 value=result(mixed);field='attack_techniques' if kind=='attack' else 'd3fend_context';value[field]=[{'technique_id':ident,'evidence_ids':wrong,'explanation':'Unconfirmed'}]
 with pytest.raises(ValueError):ai.validate_result(value,mixed,[],select(catalog,mixed))

def test_selected_registry_recomputation_and_tampered_support_are_consistent(mixed,catalog):
 selected=select(catalog,mixed);assert select(selected,mixed)==selected
 full=ai.taxonomy_choices(mixed,selected)
 tampered=copy.deepcopy(selected);tampered['support']['attack']['T1059.001']=['context-only']
 with pytest.raises(ValueError):ai.taxonomy_choices(mixed,tampered)
 # Inference recomputes eligibility from observations even for an already selected registry.
 (_,unused),calls=send_result(mixed,tampered,result(mixed));prompt=json.loads(calls[0]['messages'][1]['content'])
 assert {kind:{kind+':'+v['technique_id']:{k:x for k,x in v.items() if k!='explanation'} for v in prompt['offered'][kind].values()} for kind in ('attack','d3fend')}==full

def test_complete_claim_normalization_still_invokes_canonical_validation(mixed,catalog,monkeypatch):
 original=ai.validate_result;seen=[]
 def guard(value,packet,candidates,registry):
  seen.append(copy.deepcopy(value));return original(value,packet,candidates,registry)
 monkeypatch.setattr(ai,'validate_result',guard)
 wire=result(mixed);wire['observable_synthesis']=[];wire['attack_techniques']=[{'support_id':'attack:T1110','explanation':'Sampled failures only'}]
 (value,_),_=send_result(mixed,catalog,wire)
 assert seen==[value,value] and value['attack_techniques'][0]['evidence_ids']==['f1','f2']

def test_malicious_verdict_missing_findings_is_not_salvaged(mixed,catalog):
 wire=result(mixed);wire.update(classification='malicious',analysis_summary=SUMMARIES['malicious']);wire['findings']=[];wire['attack_techniques']=[{'support_id':'attack:T1110','explanation':'Unconfirmed'}]
 with pytest.raises(ai.ModelOutputError) as e:send_result(mixed,catalog,wire)
 assert e.value.metadata['validation_diagnostic']=={'stage':'response_schema','reason':'object_fields','field':'$'}

def test_prompt_and_wire_schema_versions_invalidate_cache_without_native_changes(tmp_path,mixed,catalog,monkeypatch):
 from core import Store,now
 store=Store(tmp_path/'native');store.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50);brain=ai.Brain(store);ident,packet,features=brain.packet(store.describe('8.8.8.8'));before=store.describe('8.8.8.8')
 calls=[]
 def fake(*a):calls.append(1);return result(packet),{'prompt_version':ai.PROMPT_VERSION}
 monkeypatch.setattr(ai,'infer',fake);cfg={**ai.DEFAULTS,'model_enabled':True,'daily_budget':5}
 monkeypatch.setattr(ai,'PROMPT_VERSION','behavior-3.4');monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','legacy')
 assert ai.model_job(brain,ident,packet,features,cfg)=='completed'
 monkeypatch.setattr(ai,'PROMPT_VERSION','behavior-3.6');monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','taxonomy-choices-1')
 assert ai.model_job(brain,ident,packet,features,cfg)=='completed'
 assert ai.model_job(brain,ident,packet,features,cfg)=='cached'
 monkeypatch.setattr(ai,'GENERATION_SCHEMA_VERSION','synthetic-next-wire')
 assert ai.model_job(brain,ident,packet,features,cfg)=='completed' and calls==[1,1,1]
 with brain.connect() as db:assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==3
 after=store.describe('8.8.8.8');assert before['score']==after['score'] and before['retention']==after['retention']
