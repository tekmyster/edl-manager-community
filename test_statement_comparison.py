"""Structured comparison is membership, never semantic usefulness or scoring."""
import copy,json,pathlib
import pytest
import behavior_ai as ai,behavior_generation as gen,behavior_tokens
from behavior_pipeline import Pipeline,VERSION as TOPOLOGY
from behavior_pipeline_job import run
from test_source_observations import linked_packet
from test_generation_choices import transport
from test_pipeline_support import SyntheticCounter,choices,Reply,setup,close

def selected(packet):
 wire=gen.example(packet);wire['observations']={};key=next(iter(wire['observable_synthesis']))
 wire['observable_synthesis'][key]='reported_session_sequence'
 return wire,key

def test_every_source_field_and_account_comparison_leaves_complete_claim_identical():
 packet=linked_packet();schema,prompt=gen.prepare(packet,[],{});wire,group=selected(packet)
 for key,fact in gen.offers(packet,[],{})[0]['facts'].items():
  spec=schema['properties']['observations']['properties'][key]
  assert list(spec['properties'])==spec['required']==['field','compared_account','purpose']
  assert spec['properties']['field']['enum']==gen.statement_fields(prompt['offered']['facts'][key])
  for field in spec['properties']['field']['enum']:
   for ref in ['',group]:
    for purpose in ['omit','detail','support']:
     wire['observations']={key:{'field':field,'compared_account':ref,'purpose':purpose}}
     result=gen.decode(wire,packet,[],{});ai.validate_result(result,packet,[],{})
     assert result['findings']==([] if purpose=='omit' else [fact])
     assert result['contradictory_evidence']==[]
     assert 'compared_account' not in json.dumps(result)

@pytest.mark.parametrize('purpose',['omit','detail','support'])
def test_comparison_requires_same_response_selected_account_even_for_explicit_omit(purpose):
 packet=linked_packet();wire=gen.example(packet);key=next(iter(wire['observations']));group=next(iter(wire['observable_synthesis']))
 wire['observations']={key:{**wire['observations'][key],'compared_account':group,'purpose':purpose}}
 with pytest.raises(gen.ChoiceError) as error:gen.decode(wire,packet,[],{})
 assert error.value.diagnostic()=={'category':'generation_choice','reason':'comparison_account_not_selected','field':'observations'}
 wire['observations'][key]['compared_account']='';ai.validate_result(gen.decode(wire,packet,[],{}),packet,[],{})

@pytest.mark.parametrize('bad',['detail',{'purpose':'detail'},{'reason':'PRIVATE','purpose':'detail'},['detail','support'],{'field':'PRIVATE','compared_account':'','purpose':'detail'},{'field':'source','compared_account':'PRIVATE','purpose':'detail'}])
def test_old_wire_missing_witnesses_conflicts_and_unoffered_fields_fail_without_value_leak(bad):
 packet=linked_packet();wire=gen.example(packet);key=next(iter(wire['observations']));wire['observations']={key:bad};before=copy.deepcopy(wire)
 with pytest.raises(ai.ModelOutputError) as error:transport(packet,wire)
 assert error.value.code=='invalid_assessment' and 'PRIVATE' not in json.dumps(error.value.metadata) and wire==before

def test_null_summary_annotation_uses_only_summary_fallback_not_richer_source_fields(monkeypatch):
 packet=linked_packet();monkeypatch.setattr(gen,'observation_summary_fields',lambda fact,*a:{'summary_fields':[None for _ in fact['evidence_ids']]})
 schema,prompt=gen.prepare(packet,[],{})
 for spec in schema['properties']['observations']['properties'].values():assert spec['properties']['field']['enum']==['summary']
 wire=gen.example(packet);ai.validate_result(gen.decode(wire,packet,[],{}),packet,[],{})
 assert all(item['field']=='summary' for item in wire['observations'].values())

def test_plan_decode_keeps_cached_schema_tables_and_deep_identity(monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());packet=linked_packet();cfg={**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64}
 plan=Pipeline(cfg,packet,[],{});wire=choices(plan.request,groups='selected',purpose='detail');expected=plan.decode(wire)
 assert plan.generation_version==gen.VERSION==ai.GENERATION_SCHEMA_VERSION=='joint-statement-comparison-1'
 assert TOPOLOGY==plan.identity['topology']=='joint-keyed-purpose-1'
 assert plan.identity['input_contract_version']==gen.VERSION and plan.identity['prompt_version']=='behavior-3.31'
 altered=plan.request;altered['format']['properties']['observations']['properties'].clear();plan.identity['generation_schema_version']='old';packet['events'].clear()
 for name in ['prepare','prepare_bounded','offers','annotated_facts','statement_fields']:
  monkeypatch.setattr(gen,name,lambda *a,**kw:pytest.fail('No expensive source/schema reconstruction during decode'))
 assert plan.decode(wire)==expected and plan.generation_version==gen.VERSION

@pytest.mark.parametrize('valid',[True,False])
def test_new_generation_metadata_private_witnesses_and_one_unchanged_ledger_child(tmp_path,monkeypatch,valid):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 store,brain,cfg,packets=setup(tmp_path/'native');calls=[]
 def send(url,**kw):
  request=kw['json'];wire=choices(request,groups='selected',purpose='detail');calls.append(wire)
  group=next(iter(wire['observable_synthesis']))
  for item in wire['observations'].values():item['compared_account']=group
  if not valid:wire['observations'][next(iter(wire['observations']))]['field']='PRIVATE_BAD_FIELD'
  return Reply(request,wire)
 try:
  status=run(brain,packets[0]['packet_id'],packets[0],set(),cfg,requester=send)
  assert status==('completed' if valid else 'failed') and status.request_units==1 and len(calls)==1
  with brain.connect() as db:
   result=json.loads(db.execute('SELECT result FROM assessments').fetchone()[0]);plans=list(db.execute('SELECT topology FROM pipeline_plans'));children=list(db.execute('SELECT ordinal FROM pipeline_stages'))
   assert plans[0]['topology']==TOPOLOGY and len(plans)==len(children)==1 and children[0]['ordinal']==1
   assert db.execute('SELECT requests FROM usage').fetchone()[0]==1
   assert db.execute('SELECT version FROM pipeline_schema').fetchone()[0]==2
  meta=result['metadata'];assert meta['generation_schema_version']==gen.VERSION and meta['prompt_version']=='behavior-3.31' and meta['topology']==TOPOLOGY
  stage=meta['generation_stages'][0];assert stage['generation_schema_version']==gen.VERSION
  assert stage['input_preparation']['version']==gen.VERSION
  assert 'compared_account' not in json.dumps(result) and 'PRIVATE' not in json.dumps(result)
  directory=next(pathlib.Path(brain.path).with_suffix('.request-evidence').iterdir())
  raw=(directory/'raw-response.bin').read_text();assert 'compared_account' in raw and ('PRIVATE_BAD_FIELD' in raw)==(not valid)
  assert run(brain,packets[0]['packet_id'],packets[0],set(),cfg,requester=send)==('cached' if valid else 'persistence_review_required') and len(calls)==1
 finally:close(store)

def test_transport_failure_before_terminal_reports_actual_new_generation(tmp_path,monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());monkeypatch.setattr(ai,'local_endpoint',lambda _:None)
 store,brain,cfg,packets=setup(tmp_path/'native');calls=[]
 def send(url,**kw):calls.append(kw['json']);raise OSError('PRIVATE connection failure')
 try:
  status=run(brain,packets[0]['packet_id'],packets[0],set(),cfg,requester=send)
  assert status=='failed' and status.request_units==1 and len(calls)==1
  with brain.connect() as db:result=json.loads(db.execute('SELECT result FROM assessments').fetchone()[0])
  assert result['metadata']['generation_schema_version']==gen.VERSION
  assert result['metadata']['generation_stages'][0]['generation_schema_version']==gen.VERSION
  assert 'PRIVATE' not in json.dumps(result)
 finally:close(store)
