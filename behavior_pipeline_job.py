"""Durable assessment coordinator. Two planned calls, exactly one final save."""
import copy,datetime as dt,json,pathlib,sqlite3,time
from behavior_deadline import Deadline
from behavior_pipeline import Pipeline,VERSION,STAGE1,STAGE2,aggregate,hash_value,source_identity
from behavior_pipeline_store import Ledger,Refused,alive

class Status(str):
 def __new__(cls,value,units=0):
  v=super().__new__(cls,value);v.request_units=units;return v

def run(brain,ident,packet,features,cfg,candidates=None,should_stop=None,*,requester=None,hook=lambda phase:None):
 import behavior_ai as ai
 from behavior_mapping import select
 from behavior_taxonomy import load
 import behavior_persistence as pending
 from analytics_store import Attempt
 if should_stop and should_stop():return Status('cancelled')
 deadline=Deadline(cfg['timeout'],should_stop);ledger=None;parent=None;stages=[];last={};cid=None;charged_units=0;outcome=None
 def live():
  current=deadline.call(lambda:brain.store.state('behavior_settings'))
  value={**ai.DEFAULTS,**current} if current is not None else cfg
  if ai.config_id(value)!=ai.config_id(cfg):raise Refused('configuration_changed')
  return value
 def persist(plan,units=0):
  outcome=json.loads(plan['outcome']);path=pending.stage(brain,outcome)
  hook('before_persist');status=pending.persist(brain,path,should_stop);hook('after_persist')
  # Recovery never acquires another stage. A durable result may be saved later.
  cleanup=Ledger(brain);cleanup.recovered(plan['id'],status)
  return Status(status,units)
 try:
  candidates=deadline.call(lambda:brain.candidates(ident,features)[:1] if cfg['correlation_enabled'] else []) if candidates is None else candidates[:1]
  registry=deadline.call(lambda:load(pathlib.Path(brain.store.path).parent/'behavior-taxonomy.json'));allowed=select(registry,packet)
  client_sources=deadline.call(source_identity)
  cid=ai.config_id(cfg)+'-'+ai.digest([allowed,candidates,ai.VERSION,ai.PROMPT_VERSION,ai.GENERATION_SCHEMA_VERSION,VERSION,client_sources])
  ledger=Ledger(brain,hook=hook);ledger.recover_active()
  existing=ledger.inspect(ident,cid)
  if existing:
   if existing['state']=='final_pending':return persist(existing)
   if existing['state']=='completed':
    with brain.connect() as db:db.execute("INSERT INTO analysis_counters VALUES(?,'cached',1) ON CONFLICT(hour,kind) DO UPDATE SET count=count+1",(ai.now(),))
    return Status('cached')
   if existing['state'] in ('failed','uncertain','review'):return Status('persistence_review_required')
   if existing['state'] not in ('failed','uncertain','review') and alive(existing['process']):return Status('leased_or_exhausted')
   ledger.uncertain(existing['id']);return Status('persistence_review_required')
  # Preserve legacy journal semantics. Never reinterpret a previous one-pass
  # dispatch under a new configuration/pipeline identity.
  directory=pending.directory(brain)
  if directory.exists():
   pending.recover(brain,should_stop)
   if (directory/'review'/'attention').exists() or next(directory.glob('*.inflight'),None) or next(directory.glob('*.json'),None):return Status('persistence_review_required')
  backoff_key='provider_backoff:'+ai.digest([cfg['endpoint'],cfg['model']])
  with brain.connect() as db:
   backoff=db.execute('SELECT value FROM retention_state WHERE name=?',(backoff_key,)).fetchone()
   if backoff and json.loads(backoff[0])['until']>time.time():return Status('backoff')
  deadline.check();livecfg=live()
  try:pipe=deadline.call(lambda:Pipeline(cfg,packet,candidates,allowed,deadline.check))
  except (ValueError,OSError,KeyError):return Status('input_verification_required')
  deadline.call(lambda:ai.local_endpoint(cfg['endpoint']))
  secret=pathlib.Path(brain.store.path).parent/'behavior-provider.json'
  def provider():
   if not secret.exists():
    if requester is not None:return ''
    raise Refused('provider_configuration_required')
   with secret.open('rb') as stream:data=stream.read(65537)
   if len(data)>65536:raise ValueError('Provider configuration exceeds size limit')
   key=json.loads(data).get('key','')
   if not isinstance(key,str) or not key:raise Refused('provider_configuration_required')
   return key
  key=deadline.call(provider);deadline.check()
  ledger.check=deadline.check
  refs=[ident]+[c['candidate_id'] for c in candidates]
  parent=ledger.begin(ident,cid,pipe.input_key,livecfg,time.time()+deadline.left(),refs)
  plan=ledger.plan(parent);frozen_receipt=None;ledger.packet_hash=hash_value(pipe.packet)
  def verify_inputs():
   deadline.check();value=live()
   if source_identity()!=pipe.identity['client_sources']:raise Refused('input_identity_changed')
   with brain.connect() as db:
    stored=db.execute('SELECT content FROM packets WHERE id=?',(ident,)).fetchone()
   if not stored or hash_value(json.loads(stored[0]))!=hash_value(pipe.packet):raise Refused('input_identity_changed')
   if select(load(pathlib.Path(brain.store.path).parent/'behavior-taxonomy.json'),packet)!=allowed:raise Refused('input_identity_changed')
   if frozen_receipt is not None:
    current=ledger.frozen(parent);pipe.validate_receipt(current)
    if current!=frozen_receipt:raise Refused('pipeline_frozen_identity_changed')
   # Recheck the operator-pinned asset before every claim/entry, not only at
   # preassembly. A source/config update never edits a frozen task in place.
   from behavior_tokens import load as verified
   if verified(value).value!=pipe.tokenizer.value:raise Refused('input_identity_changed')
   return value
  def guard():return deadline.call(verify_inputs)
  ledger.verify=guard
  def execute(stage,request,decode,check):
   nonlocal last,charged_units
   active=guard();request_hash=hash_value(request)
   receipt_hash=hash_value(frozen_receipt) if stage==2 else None
   request_id=ledger.claim(parent,stage,cid,request_hash,active['daily_budget'],receipt_hash)
   charged_units+=1
   attempt=Attempt(brain.store,ident);attempt.id=request_id
   def entry():active=guard();ledger.entry(parent,stage,cid,request_hash,active['daily_budget'],receipt_hash)
   preparation=copy.deepcopy(pipe.preparation)
   preparation['input_preparation'].update(version=STAGE1 if stage==1 else STAGE2,user_prompt_bytes=len(request['messages'][1]['content'].encode()),full_request_bytes=len(json.dumps(request,ensure_ascii=True,separators=(',',':')).encode()))
   wire={'request':request,'decode':decode,'preparation':{**preparation,'topology':VERSION,'stage':stage,'input_verification':check,'input_binding':pipe.input_key},'version':STAGE1 if stage==1 else STAGE2,'expected_input':check['input_tokens']}
   try:
    value,meta=deadline.call(lambda:ai.infer(cfg,packet,candidates,allowed,key,requester,attempt,_wire=wire,_deadline=deadline,_before_call=entry))
   except Exception as exc:
    last=copy.deepcopy(exc.metadata if isinstance(exc,ai.ModelOutputError) else getattr(exc,'_edl_failure_metadata',{}));last.update(stage=stage)
    if attempt.started is not None:last.setdefault('request_id',attempt.id);last.setdefault('request_started_at',attempt.started);last.setdefault('request_transport_state','failed')
    raise
   meta['stage']=stage;last=meta;stages.append(meta);deadline.check();return value,meta
  check=pipe.tokenizer.check(pipe.stage1)
  receipt,meta=execute(1,pipe.stage1,pipe.freeze,check)
  guard();ledger.freeze(parent,cid,receipt,meta)
  # Re-read the durable receipt. No in-memory/provider text becomes stage2 truth.
  receipt=ledger.frozen(parent);pipe.validate_receipt(receipt);frozen_receipt=copy.deepcopy(receipt);request,check=pipe.second(receipt)
  result,meta=execute(2,request,lambda wire:pipe.compose(wire,receipt),check)
  guard();deadline.check()
  metadata=aggregate(stages,time.monotonic()-deadline.started)
  metadata.update(model=cfg['model'],prompt_version=ai.PROMPT_VERSION,generation_schema_version=VERSION,input_binding=pipe.input_key,account_binding=receipt['binding'],supplied_packet_ids=refs,wire_packet_ids=refs,identity=pipe.identity)
  result={**result,'metadata':metadata};created=ai.now();expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=cfg['assessment_hours'])).isoformat(timespec='seconds')
  outcome={'version':1,'row':[plan['assessment'],ident,cid,created,expires,'completed',json.dumps(result,allow_nan=False),'',round(time.monotonic()-deadline.started,3)],'owner':plan['owner'],'backoff_key':backoff_key,'backoff_previous':backoff[0] if backoff else None,'backoff_at':time.time()}
  ledger.final(parent,cid,outcome,meta,True,hash_value(frozen_receipt))
  try:return persist(Ledger(brain).plan(parent),charged_units)
  finally:deadline.finish()
 except Refused as exc:
  reason=str(exc)
  if parent is None:return Status(reason if reason in ('budget','leased_or_exhausted','persistence_review_required','superseded_before_request','provider_configuration_required') else 'pipeline_review_required')
  error=reason
 except Exception as exc:
  if parent is None:
   if isinstance(exc,sqlite3.Error):return Status('persistence_deferred')
   return Status('cancelled' if should_stop and should_stop() else 'failed')
  error=exc.code if isinstance(exc,ai.ModelOutputError) else type(exc).__name__
  if not last:last=copy.deepcopy(getattr(exc,'_edl_failure_metadata',{}))
 except BaseException:
  if parent is not None:
   try:Ledger(brain).uncertain(parent)
   except sqlite3.Error:pass
  deadline.finish();raise
 finally:
  # Terminal persistence/failure cleanup is below; no further generation may
  # use this deadline after run returns, including late uncooperative callbacks.
  if parent is None:deadline.finish()
 # Failure path: save one failure receipt if ownership remains. Expired/lost
 # ownership becomes a durable uncertainty barrier, never a replacement request.
 if outcome is not None and outcome['row'][5]=='completed':
  # If SQLite cannot commit the validated final outcome, retain it privately
  # for review. This file never enters the automatic pending-result scan.
  # The unfinished plan remains an uncertainty barrier, not a retry token.
  try:
   review=pending.private_directory(pathlib.Path(brain.path).with_suffix('.pipeline-review'),True)
   pending.publish(review/(parent+'.json'),json.dumps(outcome,allow_nan=False).encode())
  except (OSError,ValueError):pass
 try:
  saved=Ledger(brain).receipts(parent)
  if last and not any(v.get('request_id')==last.get('request_id') and v.get('stage')==last.get('stage') for v in saved):saved.append(last)
  meta=aggregate(saved,time.monotonic()-deadline.started);meta.update(model=cfg['model'],prompt_version=ai.PROMPT_VERSION,supplied_packet_ids=refs,failure_diagnostic={'category':'pipeline','stage':'assessment','reason':error if error in ('budget','configuration_changed','deadline_expired','superseded_before_request','pipeline_ownership_lost') else 'assessment_failed'})
  for field in ('failure_diagnostic','validation_diagnostic'):
   if isinstance(last.get(field),dict):meta[field]=copy.deepcopy(last[field])
  created=ai.now();outcome={'version':1,'row':[plan['assessment'],ident,cid,created,(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat(timespec='seconds'),'failed',json.dumps({'metadata':meta},allow_nan=False),error[:60],round(time.monotonic()-deadline.started,3)],'owner':plan['owner'],'backoff_key':backoff_key,'backoff_previous':backoff[0] if backoff else None,'backoff_at':time.time()}
  ledger.final(parent,cid,outcome,last,False);result=persist(Ledger(brain).plan(parent),charged_units)
 except Exception:
  try:Ledger(brain).uncertain(parent)
  except sqlite3.Error:pass
  result=Status('persistence_review_required',charged_units)
 finally:deadline.finish()
 return result
