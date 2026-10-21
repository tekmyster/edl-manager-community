"""Private bounded per-request evidence. Never stores credentials or headers."""
import pathlib,json,hashlib,os
def compact(value):return json.dumps(value,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path):return json.loads(pathlib.Path(path).read_bytes())
def put(path,value):
 path=pathlib.Path(path);raw=value if isinstance(value,bytes) else compact(value)
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 from behavior_persistence import sync_directory
 sync_directory(path.parent)
import json,threading
class CaptureFinalizationError(RuntimeError):pass
class Capture:
 """One locked bounded snapshot; all closers observe completion or explicit error."""
 def __init__(self,response,path,deadline):
  self.response=response;self.status_code=response.status_code;self.path=path;self.deadline=deadline
  self.data=bytearray();self.complete=False;self.error=None;self.closed=False
  self.lock=threading.Lock();self.done=threading.Event();self.started=False;self.sealed=False;self.finalization_errors=[];self.wait_failed=False;self.worker=None
 def iter_content(self,n):
  try:
   for chunk in self.response.iter_content(n):
    self.deadline.check()
    with self.lock:
     if self.sealed:raise CaptureFinalizationError('Capture snapshot already sealed')
     room=1048577-len(self.data);self.data.extend(chunk[:max(0,room)])
     if len(chunk)>room or len(self.data)>1048576:raise ValueError('Capture bound')
    yield chunk
   with self.lock:
    if not self.sealed:self.complete=True
  except BaseException as exc:
   with self.lock:
    if not self.sealed:self.error=type(exc).__name__
   raise
 def _finalize(self,raw,complete,error):
  errors=[];frames=[];invalid=[]
  # Preserve original bytes even when hostile JSON defeats diagnostic parsing.
  try:put(self.path/'raw-response.bin',raw)
  except BaseException as exc:errors.append({'artifact':'raw-response.bin','error':type(exc).__name__})
  try:
   for i,line in enumerate(raw.splitlines()):
    try:frames.append(json.loads(line))
    except ValueError:invalid.append(i)
  except BaseException as exc:errors.append({'artifact':'frames_parser','error':type(exc).__name__})
  content=''.join(f.get('message',{}).get('content','') for f in frames if isinstance(f,dict) and isinstance(f.get('message'),dict) and isinstance(f['message'].get('content'),str))
  envelope=next((f for f in reversed(frames) if isinstance(f,dict) and f.get('done') is True),None)
  artifacts=[('frames.json',{'frames':frames,'invalid_lines':invalid}),('choice-content.utf8',content.encode('utf-8',errors='backslashreplace')),('envelope.json',envelope)]
  try:
   for name,value in artifacts:
    try:put(self.path/name,value)
    except BaseException as exc:errors.append({'artifact':name,'error':type(exc).__name__})
   proof={'bytes':len(raw),'sha256':sha(raw),'complete_application_body':complete,'error':error,'unread_tail':'not drained; missing bytes remain unknown','http_status':self.status_code,'snapshot_evidence_complete':not errors,'snapshot_errors':errors[:],'transport_close':'pending; see finalization.json'}
   try:put(self.path/'capture.json',proof)
   except BaseException as exc:errors.append({'artifact':'capture.json','error':type(exc).__name__})
   # Snapshot is durable before possibly blocked underlying close. No draining.
   try:self.response.close()
   except BaseException as exc:errors.append({'artifact':'transport_close','error':type(exc).__name__})
   with self.lock:
    if self.wait_failed:errors.append({'artifact':'deadline_wait','error':'CaptureFinalizationError'})
   try:put(self.path/'finalization.json',{'complete':not errors,'errors':errors[:],'transport_close':'failed' if any(x['artifact']=='transport_close' for x in errors) else 'returned','snapshot_bytes':len(raw)})
   except BaseException as exc:errors.append({'artifact':'finalization.json','error':type(exc).__name__})
  except BaseException as exc:errors.append({'artifact':'finalizer','error':type(exc).__name__})
  finally:
   with self.lock:
    if self.wait_failed and not any(x['artifact']=='deadline_wait' for x in errors):errors.append({'artifact':'deadline_wait','error':'CaptureFinalizationError'})
    self.finalization_errors=errors;self.closed=not errors
   self.done.set()
 def close(self):
  with self.lock:
   if not self.started:
    self.started=True;self.sealed=True
    self.worker=threading.Thread(target=self._finalize,args=(bytes(self.data),self.complete,self.error),daemon=True);self.worker.start()
  while not self.done.is_set():
   # This may be called by Deadline.abort itself. Calling left() here would
   # recursively abort/watch/close and spawn unbounded closer threads.
   remaining=self.deadline.end-self.deadline.clock()
   if remaining<=0 or self.deadline.cancelled.is_set() or self.deadline.stopped():
    with self.lock:self.wait_failed=True
    raise CaptureFinalizationError('Capture finalization pending at assessment deadline')
   self.done.wait(min(.025,remaining))
  if self.finalization_errors or self.wait_failed:raise CaptureFinalizationError('Capture durable finalization failed')
 def resolved(self,model):
  if not self.done.is_set() or not self.closed or not self.complete or self.error:return False
  try:
   envelope=read(self.path/'envelope.json')
   return isinstance(envelope,dict) and envelope.get('model')==model and envelope.get('done') is True
  except (OSError,ValueError):return False

class RequestEvidence:
 def __init__(self,brain,parent,request,input_key,deadline,model):
  from behavior_persistence import private_directory
  from behavior_accounting import MetadataReports
  self.deadline=deadline;self.model=model;self.capture=None
  root=private_directory(pathlib.Path(brain.path).with_suffix('.request-evidence'),True)
  self.path=root/parent;self.path.mkdir(mode=0o700)
  self.measurements=MetadataReports(self.path)
  put(self.path/'request.json',compact(request));put(self.path/'binding.json',{'input_key':input_key,'request_sha256':sha(compact(request))})
 def wrap(self,response):
  self.capture=Capture(response,self.path,self.deadline)
  self.deadline.watch(self.capture);return self.capture
 def publish(self,metadata):return self.measurements.publish(metadata)
 def _snapshot(self,status,entered,metadata=None):
  from behavior_accounting import usage
  original={'status':status,'dispatch_entered':entered,'usage':usage(self.path,self.measurements.snapshot() if metadata is None else metadata,entered,capture=self.capture,model=self.model,read_artifacts=False),'assessment_acceptance':'separate durable ledger finalization; validation alone is not acceptance'}
  return original
 def _public(self,original,published):
  status=original['status']
  public={k:original['usage'][k] for k in ('as_of','input_tokens','output_tokens','cached_input_tokens','uncached_input_tokens','cache_accounting','first_content_seconds','dollar_cost','count_provenance','count_conflicts')}
  public['invalid_report_count']=len(original['usage']['invalid_reports'])
  return {'directory':self.path.name,'outcome_sha256':sha(compact(original)) if published else None,'snapshot_sha256':sha(compact(original)),'publication_complete':published,'validation_status':status,'usage':public}

 def finish(self,status,entered,metadata=None):
  self.deadline.check()
  if self.capture is None:raise CaptureFinalizationError('Request capture missing')
  self.capture.close();self.deadline.check()
  if not self.capture.resolved(self.model):raise CaptureFinalizationError('Unresolved request evidence')
  original=self._snapshot(status,entered,metadata)
  put(self.path/'outcome.json',original);return self._public(original,True)
 def failure_snapshot(self,entered,metadata):
  # No filesystem read/wait on the expired controller. Immutable in-memory
  # counters are available now; file publication is best effort and append-only.
  original=self._snapshot('not_accepted',entered,metadata)
  def publish():
   try:put(self.path/'outcome.json',original)
   except (OSError,ValueError):pass
  threading.Thread(target=publish,daemon=True).start()
  return self._public(original,False)

def prune(brain,limit=20):
 """Existing retention compaction determines eligibility; delete outside writer.

 Never remove uncertainty/pending evidence, or a live assessment. The ordinary
 retention cursor first compacts an expired completed/failed plan to a permanent
 tombstone, and this bounded read-only scan follows that decision.
 """
 import sqlite3,shutil,contextlib
 limit=max(1,min(500,int(limit)))
 from behavior_persistence import private_directory
 root=private_directory(pathlib.Path(brain.path).with_suffix('.request-evidence'))
 if not root.exists():return 0
 with contextlib.closing(sqlite3.connect(str(brain.path),timeout=.025)) as db:
  if not db.execute("SELECT 1 FROM sqlite_master WHERE name='pipeline_plans'").fetchone():return 0
  with db:
   db.execute('BEGIN IMMEDIATE')
   marker=db.execute("SELECT value FROM retention_state WHERE name='request_evidence_cursor'").fetchone();cursor=int(marker[0]) if marker else 0
   rows=db.execute("SELECT rowid,id FROM pipeline_plans p WHERE rowid>? AND outcome IS NULL AND state IN ('completed','failed') AND NOT EXISTS(SELECT 1 FROM assessments a WHERE a.id=p.assessment) ORDER BY rowid LIMIT ?",(cursor,limit)).fetchall()
   db.execute("INSERT OR REPLACE INTO retention_state VALUES('request_evidence_cursor',?)",(str(rows[-1][0] if len(rows)==limit else 0),))
 count=0
 for _,ident in rows:
  if not isinstance(ident,str) or len(ident)!=32 or any(c not in '0123456789abcdef' for c in ident):continue
  path=root/ident
  if path.is_symlink():continue
  if path.exists():
   private_directory(path)
   if path.resolve().parent!=root.resolve():raise ValueError('Evidence path outside private root')
   shutil.rmtree(path);count+=1
 return count
