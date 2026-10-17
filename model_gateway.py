"""Optional private TLS gateway for a loopback-only Ollama server.

Run with: python model_gateway.py /private/path/gateway.json
No administrator or enforcement tools are exposed to the model.
"""
import hashlib,hmac,http.server,ipaddress,json,pathlib,ssl,sys,threading,time,urllib.error,urllib.request

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
   if not self.authorized():return
   if self.path!='/api/chat':self.reply(404,{'error':'Not found'});return
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
