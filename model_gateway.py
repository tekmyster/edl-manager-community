"""Optional private TLS gateway for a loopback-only Ollama server.

Run with: python model_gateway.py /private/path/gateway.json
No administrator or enforcement tools are exposed to the model.
"""
import contextlib,hashlib,hmac,http.client,http.server,ipaddress,json,pathlib,socket,ssl,sys,threading,time,urllib.error,urllib.request

def stream_lines(response,model,timeout=180):
 """Bound transport overhead separately from generated content; no buffering to EOF."""
 started=time.monotonic();size=content_size=0;done=False
 while True:
  line=response.readline(131073)
  if not line:break
  size+=len(line)
  if size>1048576 or len(line)>131072 or time.monotonic()-started>timeout:raise ValueError('Stream bound exceeded')
  if not line.strip():continue
  value=json.loads(line)
  if not isinstance(value,dict) or done or value.get('model')!=model:raise ValueError('Invalid model stream')
  content=value.get('message',{}).get('content','')
  if not isinstance(content,str):raise ValueError('Invalid model content')
  content_size+=len(content.encode('utf-8'))
  if content_size>131072:raise ValueError('Content bound exceeded')
  done=value.get('done') is True
  yield line.rstrip(b'\r\n')+b'\n'
 if not done:raise ValueError('Incomplete model stream')


# Explicit opt-in for an evaluation caller with the approved 180-second budget.
# Missing header leaves the existing ordinary path unchanged.
ADMISSION_HEADER='X-EDL-Admission-Wait'
ADMISSION_VALUE='15'
ADMISSION_WAIT_SECONDS=15.0
ADMISSION_TOTAL_SECONDS=180.0

class AdmissionBusy(Exception):pass
class ClientGone(Exception):pass
class DeadlineExceeded(TimeoutError):pass

class AbsoluteDeadline:
 def __init__(self,connection,deadline,clock=time.monotonic):
  self.deadline=deadline;self.clock=clock;self.expired=threading.Event()
  self.lock=threading.Lock();self.sockets=[];self.watch(connection)
  self.timer=threading.Timer(max(0,deadline-clock()),self.expire);self.timer.daemon=True
 def left(self):
  remaining=self.deadline-self.clock()
  if self.expired.is_set() or remaining<=0:raise DeadlineExceeded()
  return remaining
 def watch(self,connection):
  with self.lock:
   self.left();self.sockets.append(connection)
 def expire(self):
  self.expired.set()
  with self.lock:
   for connection in self.sockets:
    with contextlib.suppress(OSError):connection.shutdown(socket.SHUT_RDWR)
    with contextlib.suppress(OSError):connection.close()
 def __enter__(self):self.timer.start();return self
 def __exit__(self,*args):self.timer.cancel();self.timer.join()

def peer_alive(connection):
 # After exactly Content-Length bytes, no more application bytes are expected.
 # Nonblocking TLS recv processes close_notify/EOF without a MSG_PEEK shortcut.
 previous=connection.gettimeout()
 try:
  connection.setblocking(False)
  try:
   connection.recv(1)
  except (BlockingIOError,ssl.SSLWantReadError,ssl.SSLWantWriteError):return True
  except (OSError,ssl.SSLError):return False
  return False  # EOF or extra/pipelined data: do not start new upstream work.
 finally:
  with contextlib.suppress(OSError):connection.settimeout(previous)

def acquire_admission(slots,connection,budget,clock=time.monotonic):
 until=min(budget.deadline,clock()+ADMISSION_WAIT_SECONDS)
 while True:
  budget.left()
  if not peer_alive(connection):raise ClientGone()
  remaining=until-clock()
  if remaining<=0:raise AdmissionBusy()
  if slots.acquire(timeout=min(.05,remaining)):
   try:
    budget.left()
    if not peer_alive(connection):raise ClientGone()
    return
   except BaseException:
    slots.release();raise

def opted_post(handler,cfg,slots,entered):
 acquired=False;upstream=None;response=None;streaming_started=False
 try:budget=AbsoluteDeadline(handler.connection,entered+ADMISSION_TOTAL_SECONDS)
 except DeadlineExceeded:handler.close_connection=True;return
 with budget:
  try:
   handler.connection.settimeout(budget.left())
   try:
    size=int(handler.headers.get('Content-Length','0'))
    if not 0<size<=65536 or handler.headers.get('Transfer-Encoding'):raise ValueError()
    payload=json.loads(handler.rfile.read(size))
    if set(payload)-{'model','messages','stream','format','options'} or payload.get('model')!=cfg['model'] or type(payload.get('stream')) is not bool:raise ValueError()
    messages=payload['messages']
    if not isinstance(messages,list) or not 1<=len(messages)<=4:raise ValueError()
    for item in messages:
     if set(item)!={'role','content'} or item['role'] not in ('system','user') or not isinstance(item['content'],str):raise ValueError()
    if not isinstance(payload.get('format'),dict):raise ValueError()
    payload['options']={'temperature':0,'num_predict':1800,'num_ctx':8192}
    payload['keep_alive']='2m'
   except (ValueError,KeyError,TypeError):
    handler.connection.settimeout(budget.left());handler.reply(400,{'error':'Invalid inference request'});return
   acquire_admission(slots,handler.connection,budget);acquired=True
   # One fixed-loopback connection, registered before request/header/stream I/O.
   # HTTPConnection does not follow redirects or retry this POST.
   upstream=http.client.HTTPConnection('127.0.0.1',11434,timeout=budget.left())
   upstream.connect();budget.watch(upstream.sock)
   if not peer_alive(handler.connection):raise ClientGone()
   upstream.sock.settimeout(budget.left())
   upstream.request('POST','/api/chat',body=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Connection':'close'})
   upstream.sock.settimeout(budget.left());response=upstream.getresponse()
   if response.status!=200:raise ValueError('Upstream rejected request')
   handler.connection.settimeout(budget.left())
   if payload['stream']:
    handler.send_response(200);handler.send_header('Content-Type','application/x-ndjson');handler.send_header('Cache-Control','no-store');handler.send_header('Connection','close');handler.end_headers();handler.close_connection=True;streaming_started=True
    for line in stream_lines(response,cfg['model'],timeout=budget.left()):
     handler.connection.settimeout(budget.left());handler.wfile.write(line);handler.wfile.flush()
   else:
    body=response.read(131073);budget.left()
    if len(body)>131072:raise ValueError()
    handler.connection.settimeout(budget.left());handler.reply(200,json.loads(body))
  except AdmissionBusy:
   handler.connection.settimeout(budget.left());handler.reply(429,{'error':'Model is busy'})
  except (ClientGone,TimeoutError):handler.close_connection=True
  except Exception:
   if not streaming_started:
    try:
     handler.connection.settimeout(budget.left());handler.reply(502,{'error':'Model request failed'})
    except (OSError,DeadlineExceeded):handler.close_connection=True
   else:handler.close_connection=True
  finally:
   # Shut down upstream before releasing the single permit. A dispatched model
   # may outlive its closed socket; no gateway can undo already-started inference.
   try:
    if upstream:
     with contextlib.suppress(Exception):upstream.close()
    if response:
     with contextlib.suppress(Exception):response.close()
   finally:
    if acquired:slots.release()

def serve(config):
 cfg=json.loads(pathlib.Path(config).read_text(encoding='utf-8'))
 if len(cfg['key'])<32:raise ValueError('Use a dedicated gateway key of at least 32 characters')
 networks=[ipaddress.ip_network(v) for v in cfg['allowed_sources']]
 slots=threading.BoundedSemaphore(1)
 class Handler(http.server.BaseHTTPRequestHandler):
  protocol_version='HTTP/1.1'
  def log_message(self,*args):pass
  def reply(self,status,payload):
   body=json.dumps(payload).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.end_headers();self.wfile.write(body);self.close_connection=True
  def authorized(self):
   source=ipaddress.ip_address(self.client_address[0])
   if not any(source.version==n.version and source in n for n in networks):self.reply(403,{'error':'Access denied'});return False
   if not hmac.compare_digest(hashlib.sha256(self.headers.get('Authorization','').encode()).digest(),hashlib.sha256(('Bearer '+cfg['key']).encode()).digest()):self.reply(401,{'error':'Authentication required'});return False
   return True
  def do_GET(self):
   if not self.authorized():return
   if self.path!='/health':self.reply(404,{'error':'Not found'});return
   self.reply(200,{'status':'ready','source':self.client_address[0],'model':cfg['model'],'scope':'inference-only'})
  def do_POST(self):
   entered=time.monotonic()
   if not self.authorized():return
   if self.path!='/api/chat':self.reply(404,{'error':'Not found'});return
   admission=self.headers.get_all(ADMISSION_HEADER)
   if admission is not None:
    if admission!=[ADMISSION_VALUE]:self.reply(400,{'error':'Invalid admission request'});return
    return opted_post(self,cfg,slots,entered)
   try:
    size=int(self.headers.get('Content-Length','0'))
    if not 0<size<=65536 or self.headers.get('Transfer-Encoding'):raise ValueError()
    payload=json.loads(self.rfile.read(size))
    if set(payload)-{'model','messages','stream','format','options'} or payload.get('model')!=cfg['model'] or type(payload.get('stream')) is not bool:raise ValueError()
    messages=payload['messages']
    if not isinstance(messages,list) or not 1<=len(messages)<=4:raise ValueError()
    for item in messages:
     if set(item)!={'role','content'} or item['role'] not in ('system','user') or not isinstance(item['content'],str):raise ValueError()
    if not isinstance(payload.get('format'),dict):raise ValueError()
    payload['options']={'temperature':0,'num_predict':1800,'num_ctx':8192}
    payload['keep_alive']='2m'
   except (ValueError,KeyError,TypeError):self.reply(400,{'error':'Invalid inference request'});return
   if not slots.acquire(blocking=False):self.reply(429,{'error':'Model is busy'});return
   streaming_started=False
   try:
    req=urllib.request.Request('http://127.0.0.1:11434/api/chat',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json'})
    # Fixed loopback upstream; no user supplied URLs, proxies, redirects or tools.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(req,timeout=180) as response:
     if payload['stream']:
      self.send_response(200);self.send_header('Content-Type','application/x-ndjson');self.send_header('Cache-Control','no-store');self.send_header('Connection','close');self.end_headers();self.close_connection=True;streaming_started=True
      for line in stream_lines(response,cfg['model']):self.wfile.write(line);self.wfile.flush()
     else:
      body=response.read(131073)
      if len(body)>131072:raise ValueError()
      self.reply(200,json.loads(body))
   except Exception:
    if not streaming_started:self.reply(502,{'error':'Model request failed'})
    else:self.close_connection=True
   finally:slots.release()
 class Server(http.server.ThreadingHTTPServer):
  daemon_threads=True
  def get_request(self):
   conn,address=super().get_request();conn.settimeout(190);return conn,address
 server=Server((cfg['bind'],int(cfg['port'])),Handler)
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cfg['cert'],cfg['cert_key']);server.socket=context.wrap_socket(server.socket,server_side=True)
 server.serve_forever()

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

if __name__=='__main__':serve(sys.argv[1])
