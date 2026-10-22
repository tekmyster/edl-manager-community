"""Two complete joint decisions; only a durable owned draft permits revision."""
import copy,hashlib,json,pathlib
TOPOLOGY_VERSION='full-joint-draft-revision-1'
VERSION=TOPOLOGY_VERSION

def encoded(value):return json.dumps(value,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def hash_value(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
def request_digest(value):return hashlib.sha256(encoded(value)).hexdigest()

def source_identity():
 names=('behavior_pipeline.py','behavior_revision.py','behavior_pipeline_job.py','behavior_pipeline_store.py','behavior_deadline.py','behavior_ai.py','behavior_generation.py','behavior_representation.py','behavior_grounding.py','behavior_synthesis.py','behavior_tokens.py','behavior_mapping.py','behavior_taxonomy.py','behavior_retention.py','behavior_persistence.py','behavior_request_evidence.py','behavior_accounting.py')
 return {n:hashlib.sha256(pathlib.Path(__file__).with_name(n).read_bytes()).hexdigest() for n in names}

class JointPlan:
 __slots__=('_packet','_candidates','_registry','_request','_schema','_tables','_logical','_preparation','_verification','_identity','_cfg','_sealed','tokenizer_value_hash','input_key','request_hash')
 def __setattr__(self,name,value):
  if getattr(self,'_sealed',False):raise AttributeError('Joint plan is immutable')
  object.__setattr__(self,name,value)
 def __init__(self,cfg,packet,candidates,registry,check=lambda:None):
  import behavior_generation as gen
  from behavior_ai import config_id,PROMPT_VERSION
  from behavior_tokens import load
  from behavior_revision import request,POLICY
  check();cfg=copy.deepcopy(cfg);packet=copy.deepcopy(packet);candidates=copy.deepcopy(candidates);registry=copy.deepcopy(registry)
  self._packet=encoded(packet);self._candidates=encoded(candidates);self._registry=encoded(registry);self._cfg=encoded(cfg)
  schema,logical=gen.prepare(packet,candidates,registry);self._logical=encoded(logical)
  q=request(schema,logical,gen.INSTRUCTION,gen,cfg['model']);check()
  tokenizer=load(cfg);self.tokenizer_value_hash=hash_value(tokenizer.value)
  self._request=encoded(q);self._schema=encoded(schema);self._tables=encoded(gen.offers(packet,candidates,registry)[0])
  size=len(q['messages'][1]['content'].encode())
  self._preparation=encoded({'historical_windows_supplied':len(candidates),'wire_candidate_ids':[c['candidate_id'] for c in candidates],'wire_packet_ids':[packet['packet_id']]+[c['candidate_id'] for c in candidates],'input_preparation':{'version':gen.VERSION,'byte_limit':18000,'base_prompt_bytes':size,'considered_prompt_bytes':size,'user_prompt_bytes':size,'omission_reason':'none' if candidates else 'no_candidate','omitted_candidate_ids':[]}})
  self._verification=encoded(tokenizer.check(q));check()
  model={k:tokenizer.value[k] for k in ('model','model_digest','runtime_sha256','template_sha256')}
  self._identity=encoded({'model':model,'tokenizer_sha256':cfg['tokenizer_sha256'],'topology':VERSION,'draft_version':gen.VERSION,'generation_schema_version':gen.FINAL_VERSION,'input_contract_version':gen.FINAL_VERSION,'prompt_version':PROMPT_VERSION,'revision_policy_sha256':hashlib.sha256(POLICY.encode()).hexdigest(),'client_sources':source_identity()})
  self.input_key=hash_value([VERSION,config_id(cfg),packet,candidates,registry,q,self.identity]);self.request_hash=request_digest(q);self._sealed=True
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
 def decode(self,wire):return self._decode(wire,json.loads(self._schema))
 def _decode(self,wire,schema):
  import behavior_generation as gen
  from behavior_ai import validate_result
  if isinstance(wire,str):wire=gen.parse_wire(wire)
  packet=self.packet;candidates=self.candidates;registry=self.registry
  result=gen.decode(wire,packet,candidates,registry,schema=schema,tables=json.loads(self._tables))
  return validate_result(result,packet,candidates,registry)
 def _revision(self,parent,raw,canonical,rendering,check=lambda:None):
  """Internal pure builder. Ledger.revision authenticates durable ownership first."""
  import behavior_generation as gen,behavior_synthesis as sy
  from behavior_revision import request,pack_choices,unpack_choices,view,POLICY,selection_schema
  from behavior_tokens import load
  check()
  if self.decode(raw)!=canonical or sy.presentation(canonical,self.packet['events'])!=rendering:raise ValueError('Draft receipt mismatch')
  receipt={'parent':parent,'plan_input_key':self.input_key,'draft_request_sha256':self.request_hash,'draft_wire_sha256':hashlib.sha256(raw.encode()).hexdigest(),'draft_canonical_sha256':request_digest(canonical),'draft_rendering_sha256':request_digest(rendering),'identity_sha256':hash_value(self.identity)}
  binding=request_digest(receipt);logical=json.loads(self._logical);logical['generation_schema_version']=gen.FINAL_VERSION
  choices=gen.parse_wire(raw);tables=json.loads(self._tables);packed=pack_choices(choices,tables,logical)
  restored=unpack_choices(packed,tables,logical,self.packet);restored['generation_schema_version']=gen.VERSION
  if restored!=choices:raise ValueError('Nonreversible provisional choices')
  logical['provisional_answer']={'draft_binding':binding,'choices':packed,'rendered':view(canonical,self.packet,sy)}
  schema=selection_schema(json.loads(self._schema));schema['properties']['generation_schema_version']['enum']=[gen.FINAL_VERSION]
  schema['properties']['draft_binding']={'type':'string','maxLength':64,'enum':[binding]};schema['required'].append('draft_binding')
  cfg=json.loads(self._cfg);q=request(schema,logical,POLICY,gen,cfg['model']);check();tokenizer=load(cfg)
  if hash_value(tokenizer.value)!=self.tokenizer_value_hash:raise ValueError('Tokenizer identity changed')
  verification=tokenizer.check(q);check()
  return Revision(self,q,schema,receipt,verification)

class Revision:
 __slots__=('_plan','_request','_schema','_receipt','_verification','request_hash','input_key','_sealed')
 def __setattr__(self,name,value):
  if getattr(self,'_sealed',False):raise AttributeError('Revision is immutable')
  object.__setattr__(self,name,value)
 def __init__(self,plan,request,schema,receipt,verification):
  self._plan=plan;self._request=encoded(request);self._schema=encoded(schema);self._receipt=encoded(receipt);self._verification=encoded(verification)
  self.request_hash=request_digest(request);self.input_key=hash_value([plan.input_key,receipt,self.request_hash]);self._sealed=True
 @property
 def request(self):return json.loads(self._request)
 @property
 def receipt(self):return json.loads(self._receipt)
 @property
 def verification(self):return json.loads(self._verification)
 def decode(self,wire):return self._plan._decode(wire,json.loads(self._schema))

Pipeline=JointPlan

def aggregate(stages,seconds):
 if len(stages)>2:raise ValueError('Assessment permits at most two serial request receipts')
 stages=copy.deepcopy(stages)
 def total(field):
  values=[s.get(field) for s in stages]
  return sum(values) if len(values)==2 and all(type(v) in (int,float) for v in values) else None
 usage={k:total(k) for k in ('input_tokens','output_tokens','cached_input_tokens','uncached_input_tokens','request_seconds')}
 return {**usage,'topology':VERSION,'planned_requests':2,'generation_stages':stages,'pipeline_usage':usage,'assessment_seconds':seconds,'assessment_seconds_definition':'Parent preparation through this pre-finalization receipt snapshot; final ledger commit, publication and later recovery are excluded.','request_count':sum(bool(s.get('request_started_at')) for s in stages),'first_content_seconds':None,'first_content_definition':'Stage-specific dispatch to first nonfinal content is recorded per request; assessment_seconds stops at the pre-finalization receipt snapshot.','note':'Two serial provisional/replacement requests, one final assessment. Missing or conflicting counters remain unknown; model agreement is not independent evidence.'}
