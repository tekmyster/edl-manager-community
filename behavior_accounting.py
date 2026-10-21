"""Reported measurements only. Immutable as-of views; append-only late accounting."""
import copy,datetime,hashlib,json,math,pathlib,threading,time
from behavior_request_evidence import put,read,compact,sha
FIELDS={'input_tokens':'prompt_eval_count','output_tokens':'eval_count','cached_input_tokens':'prompt_eval_cached_count'}
def frozen(value):
 value=copy.deepcopy(value)
 def safe(v):
  if isinstance(v,float) and not math.isfinite(v):return {'invalid_nonfinite':repr(v)}
  if isinstance(v,dict):return {k:safe(x) for k,x in v.items()}
  if isinstance(v,(list,tuple)):return [safe(x) for x in v]
  return v
 return safe(value)
def stamp():return {'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'monotonic':time.monotonic()}
def valid(v):return type(v) is int and 0<=v<=10000000
def capture_report(capture,model=None):
 if capture is None:return None
 with capture.lock:raw=bytes(capture.data);complete=capture.complete;error=capture.error
 frames=[];invalid=[]
 for i,line in enumerate(raw.splitlines()):
  if not line.strip():continue
  try:frames.append(json.loads(line))
  except (ValueError,TypeError):invalid.append(i)
 envelope=next((f for f in reversed(frames) if isinstance(f,dict) and f.get('done') is True and isinstance(f.get('model'),str) and (model is None or f['model']==model)),None)
 return {'name':'capture_snapshot','kind':'envelope','value':frozen(envelope),'evidence':{'raw_sha256':sha(raw),'bytes':len(raw),'complete_at_observation':complete,'error_at_observation':error,'invalid_lines':invalid},'observed':stamp()}
def usage(directory,metadata,entered,*,capture=None,model=None,extra_reports=(),read_artifacts=True):
 directory=pathlib.Path(directory);meta=frozen(metadata);observed=stamp()
 reports=[{'name':'infer_metadata','kind':'metadata','value':meta,'observed':observed}]
 if read_artifacts:
  try:
   raw=(directory/'envelope.json').read_bytes();envelope=json.loads(raw)
   reports.append({'name':'envelope_artifact','kind':'envelope','value':frozen(envelope),'evidence':{'sha256':sha(raw)},'observed':stamp()})
  except (OSError,ValueError) as exc:reports.append({'name':'envelope_artifact','kind':'unavailable','error_type':type(exc).__name__,'observed':stamp()})
 current=capture_report(capture,model)
 if current:reports.append(current)
 # Preserve every terminal report when an invalid stream supplies more than
 # one; selecting only the last could conceal contradictory reported charges.
 raw=None
 if capture is not None:
  with capture.lock:raw=bytes(capture.data)
 elif read_artifacts:
  try:raw=(directory/'raw-response.bin').read_bytes()
  except OSError:pass
 if raw is not None:
  terminals=[]
  for index,line in enumerate(raw.splitlines()):
   try:value=json.loads(line)
   except (ValueError,TypeError):continue
   if isinstance(value,dict) and value.get('done') is True:terminals.append((index,value))
  if len(terminals)>1:
   for index,value in terminals:reports.append({'name':'terminal_frame_'+str(index),'kind':'envelope','value':frozen(value),'observed':stamp(),'evidence':{'raw_sha256':sha(raw),'frame_index':index}})
 reports.extend(frozen(list(extra_reports)))
 return normalize(reports,meta,entered,stamp(),model)
def normalize(reports,metadata,entered,observed,model=None):
 counts={};provenance={};invalid=[];conflicts={}
 for field,envelope_key in FIELDS.items():
  supplied=[]
  for report in reports:
   value=report.get('value');kind=report.get('kind')
   if not isinstance(value,dict) or kind not in ('metadata','envelope'):continue
   key=field if kind=='metadata' else envelope_key
   if key not in value:continue
   raw=value[key]
   if kind=='envelope' and (value.get('done') is not True or not isinstance(value.get('model'),str) or (model is not None and value['model']!=model)):
    invalid.append({'source':report['name'],'field':field,'raw':raw,'reason':'unmatched_terminal_envelope'});continue
   if not valid(raw):
    if raw is not None:invalid.append({'source':report['name'],'field':field,'raw':raw,'reason':'reported_count_type_or_bound'})
    continue
   supplied.append({'source':report['name'],'value':raw})
  unique={r['value'] for r in supplied};counts[field]=next(iter(unique)) if len(unique)==1 else None;provenance[field]=supplied
  if len(unique)>1:conflicts[field]=supplied
 total=counts['input_tokens'];cached=counts['cached_input_tokens']
 consistency='conflict' if any(k in conflicts for k in ('input_tokens','cached_input_tokens')) else 'unknown' if total is None or cached is None else 'consistent' if cached<=total else 'inconsistent'
 first=metadata.get('first_content_seconds');first=first if type(first) in (int,float) and math.isfinite(first) and first>=0 else None
 return {'client_transport_entered':entered,'gateway_or_model_receipt':'not established by client entry','accounting_version':'reported-snapshot-2','expected_model':model,'as_of':observed,**counts,'uncached_input_tokens':total-cached if consistency=='consistent' else None,'cache_accounting':consistency,'count_provenance':provenance,'count_conflicts':conflicts,'invalid_reports':invalid,'reports':frozen(reports),'first_content_seconds':first,'first_content_definition':'dispatch to nonempty done:false content only; final-only/absent remains unknown','charged_tokens':'Reported counters only; missing or conflicting counts unknown; no billing inference.','dollar_cost':None,'metadata':frozen(metadata)}
class MetadataReports:
 """Published dictionaries are deeply copied; I/O never holds snapshot lock."""
 def __init__(self,directory):self.directory=pathlib.Path(directory);self.lock=threading.Lock();self.value={};self.serial=0
 def publish(self,metadata):
  value=frozen(metadata);at=stamp()
  with self.lock:self.serial+=1;serial=self.serial;self.value=value
  put(self.directory/f'accounting-metadata-{serial:04d}.json',{'schema':'reported-metadata-snapshot-1','observed':at,'metadata':value,'after_outcome':(self.directory/'outcome.json').exists(),'measurement_only_no_status_change':True})
  return frozen(value)
 def snapshot(self):
  with self.lock:return frozen(self.value)
def reconcile(directory,model=None):
 """No waits, attempts, state edits or output acceptance. Original bytes stay fixed."""
 directory=pathlib.Path(directory);original=(directory/'outcome.json').read_bytes();outcome=json.loads(original)
 reports=frozen(outcome['usage']['reports'])
 for p in sorted(directory.glob('accounting-metadata-*.json')):
  value=read(p);reports.append({'name':p.name,'kind':'metadata','value':value['metadata'],'observed':value['observed'],'evidence':{'sha256':sha(p.read_bytes())}})
 # Capture terminal files that became durable after the original measurement.
 meta=frozen(outcome['usage']['metadata']);latest=usage(directory,meta,outcome['dispatch_entered'],model=model,extra_reports=reports)
 value={'schema':'append-only-accounting-reconciliation-1','observed':stamp(),'original_outcome_sha256':sha(original),'original_status':outcome['status'],'status_unchanged':True,'attempts_added':0,'accepted_outputs_added':0,'request_deadline_extended':False,'usage':latest}
 for serial in range(1,10001):
  p=directory/f'accounting-reconciliation-{serial:04d}.json'
  try:put(p,value);return p,value
  except FileExistsError:continue
 raise ValueError('Accounting reconciliation namespace exhausted')
def check_usage(value):
 """Strictly rederive a frozen view from its exact reports, never current files."""
 derived=normalize(value['reports'],value['metadata'],value['client_transport_entered'],value['as_of'],value.get('expected_model'))
 keys=[*FIELDS,'uncached_input_tokens','cache_accounting','count_provenance','count_conflicts','invalid_reports']
 return all(derived[k]==value[k] for k in keys)
