"""One assessment deadline, including blocking/trickled I/O. No request retry."""
import contextlib,http.client,json,queue,socket,ssl,threading,time,urllib.parse

class Expired(TimeoutError):pass
class Cancelled(TimeoutError):pass

class Deadline:
 def __init__(self,seconds,should_stop=None,clock=time.monotonic):
  if type(seconds) not in (int,float) or not 0<seconds<=180:raise ValueError('Invalid assessment deadline')
  self.clock=clock;self.started=clock();self.end=self.started+seconds;self.seconds=seconds;self.stopped=should_stop or (lambda:False);self.cancelled=threading.Event();self.resources=[];self.lock=threading.Lock();self.timer=threading.Timer(seconds,self.abort);self.timer.daemon=True;self.timer.start()
 def left(self):
  if self.stopped():self.abort();raise Cancelled('Analysis cancelled')
  left=self.end-self.clock()
  if self.cancelled.is_set() or left<=0:self.abort();raise Expired('Analysis deadline exceeded')
  return left
 def check(self):self.left()
 def watch(self,value):
  with self.lock:
   if self.cancelled.is_set():self.close(value);raise Expired('Analysis deadline exceeded')
   self.resources.append(value)
  self.check();return value
 @staticmethod
 def close(value):
  # Shutdown wakes blocked reads before close. http.client's socket may be
  # transferred into response.fp once Connection:close headers are received.
  candidates=[getattr(value,'sock',None)]
  fp=getattr(value,'fp',None);candidates.append(getattr(getattr(fp,'raw',None),'_sock',None))
  for s in candidates:
   if s is not None:
    with contextlib.suppress(OSError):s.shutdown(socket.SHUT_RDWR)
  with contextlib.suppress(Exception):value.close()
 def abort(self):
  self.cancelled.set()
  with self.lock:values=self.resources[:]
  # A third-party close may block; never let it hold the deadline/control thread.
  for value in values:
   t=threading.Thread(target=self.close,args=(value,),daemon=True);t.start()
 def call(self,fn):
  self.check();out=queue.Queue(maxsize=1)
  def run():
   try:
    self.check();value=fn()
    if self.cancelled.is_set():
     if hasattr(value,'close'):self.close(value)
     return
    out.put((True,value))
   except BaseException as e:
    if not self.cancelled.is_set():out.put((False,e))
  thread=threading.Thread(target=run,daemon=True);thread.start()
  while True:
   remaining=self.left()
   try:ok,value=out.get(timeout=min(.025,remaining))
   except queue.Empty:continue
   self.check()
   if not ok:raise value
   return value
 def chunks(self,response):
  self.watch(response);out=queue.Queue(maxsize=1)
  def put(value):
   while not self.cancelled.is_set():
    try:out.put(value,timeout=.025);return
    except queue.Full:pass
  def run():
   try:
    for value in response.iter_content(1):
     self.check();put((True,value))
    put((True,None))
   except BaseException as e:put((False,e))
  thread=threading.Thread(target=run,daemon=True);thread.start()
  while True:
   self.check()
   try:ok,value=out.get(timeout=min(.025,self.left()))
   except queue.Empty:continue
   self.check()
   if not ok:raise value
   if value is None:return
   yield value
 def finish(self):
  self.timer.cancel();self.abort()

class Response:
 def __init__(self,raw,connection,deadline):self.raw=raw;self.connection=connection;self.deadline=deadline;self.status_code=raw.status
 def iter_content(self,_):
  while True:
   self.deadline.check();part=self.raw.read1(65536)
   if not part:return
   yield part
 def close(self):
  Deadline.close(self.raw);Deadline.close(self.connection)

def post(url,headers,*,json,verify,deadline,admission=False,**kwargs):
 """Pinned standard-library HTTPS path; no environment proxy or redirect handling."""
 parsed=urllib.parse.urlsplit(url)
 if parsed.scheme!='https' or parsed.username or parsed.password or parsed.query or parsed.fragment:raise ValueError('Invalid model transport')
 deadline.check();context=ssl.create_default_context(cafile=verify if isinstance(verify,str) and verify else None)
 connection=http.client.HTTPSConnection(parsed.hostname,parsed.port or 443,timeout=min(5,deadline.left()),context=context);deadline.watch(connection)
 body=__import__('json').dumps(json,ensure_ascii=True,separators=(',',':')).encode()
 if len(body)>65536:raise ValueError('Model request exceeds size limit')
 headers={**headers,'Content-Type':'application/json','Connection':'close'}
 if admission:headers['X-EDL-Admission-Wait']='15'
 connection.connect();deadline.watch(connection.sock);deadline.check();connection.sock.settimeout(deadline.left())
 connection.request('POST',parsed.path or '/',body=body,headers=headers);deadline.check();connection.sock.settimeout(deadline.left())
 raw=connection.getresponse();deadline.watch(raw);deadline.check()
 return Response(raw,connection,deadline)
