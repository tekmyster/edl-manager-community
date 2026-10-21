"""One immutable joint request; no generated value becomes another prompt."""
import copy,hashlib,json,pathlib
TOPOLOGY_VERSION='joint-keyed-purpose-1'
# Durable topology/ledger schema is unchanged; generation has a separate identity.
VERSION=TOPOLOGY_VERSION

def encoded(value):return json.dumps(value,sort_keys=False,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def hash_value(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
def request_digest(value):return hashlib.sha256(encoded(value)).hexdigest()

def source_identity():
 names=('behavior_pipeline.py','behavior_pipeline_job.py','behavior_pipeline_store.py','behavior_deadline.py','behavior_ai.py','behavior_generation.py','behavior_representation.py','behavior_grounding.py','behavior_synthesis.py','behavior_tokens.py','behavior_mapping.py','behavior_taxonomy.py','behavior_retention.py','behavior_persistence.py','behavior_request_evidence.py','behavior_accounting.py')
 return {n:hashlib.sha256(pathlib.Path(__file__).with_name(n).read_bytes()).hexdigest() for n in names}

class JointPlan:
 __slots__=('_packet','_candidates','_registry','_request','_schema','_tables','_preparation','_verification','_identity','tokenizer_value_hash','input_key','request_hash','_sealed')
 """Public data properties return copies; only immutable bytes are bound."""
 def __setattr__(self,name,value):
  if getattr(self,'_sealed',False):raise AttributeError('Joint plan is immutable')
  object.__setattr__(self,name,value)
 def __init__(self,cfg,packet,candidates,registry,check=lambda:None):
  import behavior_generation as gen
  from behavior_ai import config_id,PROMPT_VERSION
  from behavior_tokens import load
  check();cfg=copy.deepcopy(cfg);packet=copy.deepcopy(packet);candidates=copy.deepcopy(candidates);registry=copy.deepcopy(registry)
  self._packet=encoded(packet);self._candidates=encoded(candidates);self._registry=encoded(registry)
  schema,prompt,selected,preparation=gen.prepare_bounded(packet,candidates,registry)
  if selected!=candidates:raise ValueError('Complete historical input required')
  check();tokenizer=load(cfg);self.tokenizer_value_hash=hash_value(tokenizer.value)
  request={'model':cfg['model'],'messages':[{'role':'system','content':gen.INSTRUCTION},{'role':'user','content':gen.prompt_json(prompt)}],'stream':True,'format':schema,'options':{'temperature':0,'num_predict':1800,'num_ctx':8192}}
  if len(gen.prompt_json(request).encode())>65536:raise ValueError('Complete request exceeds size limit')
  self._request=encoded(request);self._schema=encoded(schema);self._tables=encoded(gen.offers(packet,candidates,registry)[0]);self._preparation=encoded(preparation)
  self._verification=encoded(tokenizer.check(request));check()
  model={k:tokenizer.value[k] for k in ('model','model_digest','runtime_sha256','template_sha256')}
  self._identity=encoded({'model':model,'tokenizer_sha256':cfg['tokenizer_sha256'],'topology':VERSION,'generation_schema_version':gen.VERSION,'input_contract_version':gen.VERSION,'prompt_version':PROMPT_VERSION,'client_sources':source_identity()})
  self.input_key=hash_value([VERSION,config_id(cfg),packet,candidates,registry,request,self.identity])
  self.request_hash=request_digest(request);self._sealed=True
 @property
 def generation_version(self):return self.identity['generation_schema_version']
 @property
 def packet(self):return json.loads(self._packet)
 @property
 def candidates(self):return json.loads(self._candidates)
 @property
 def registry(self):return json.loads(self._registry)
 @property
 def request(self):return json.loads(self._request)
 @property
 def preparation(self):return json.loads(self._preparation)
 @property
 def verification(self):return json.loads(self._verification)
 @property
 def identity(self):return json.loads(self._identity)
 def decode(self,wire):
  import behavior_generation as gen
  from behavior_ai import validate_result
  packet=self.packet;candidates=self.candidates;registry=self.registry
  result=gen.decode(wire,packet,candidates,registry,schema=json.loads(self._schema),tables=json.loads(self._tables))
  return validate_result(result,packet,candidates,registry)

Pipeline=JointPlan

def aggregate(stages,seconds):
 if len(stages)>1:raise ValueError('Joint assessment has at most one request receipt')
 stage=copy.deepcopy(stages[0]) if stages else {}
 return {**stage,'topology':VERSION,'planned_requests':1,'generation_stages':copy.deepcopy(stages),'pipeline_usage':{k:stage.get(k) for k in ('input_tokens','output_tokens','cached_input_tokens','uncached_input_tokens','request_seconds')},'assessment_seconds':seconds,'request_count':int(bool(stage.get('request_started_at'))),'note':'One joint request; missing charges remain unknown. First content is the actual request receipt, never an assessment total.'}
