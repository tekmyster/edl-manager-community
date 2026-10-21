"""Isolated loopback TLS, synthetic disposable certificate, no model service."""
import datetime as dt,http.server,ipaddress,json,ssl,threading,time
import pytest
from behavior_deadline import Deadline,Expired,post

@pytest.fixture
def server(tmp_path):
 # Existing optional QA library only; no runtime dependency or installation.
 pytest.importorskip('cryptography')
 from cryptography import x509
 from cryptography.hazmat.primitives import hashes,serialization
 from cryptography.hazmat.primitives.asymmetric import rsa
 from cryptography.x509.oid import NameOID
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=dt.datetime.now(dt.timezone.utc)
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'isolated-pipeline-fixture')])
 cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256())
 cp=tmp_path/'fixture-cert.pem';kp=tmp_path/'fixture-key.pem';cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM));kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 seen=[];release=threading.Event()
 class Handler(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_POST(self):
   seen.append((self.path,json.loads(self.rfile.read(int(self.headers['Content-Length']))),dict(self.headers)))
   if self.path=='/blocked':release.wait(2);return
   self.send_response(302 if self.path=='/redirect' else 200)
   if self.path=='/redirect':self.send_header('Location','https://127.0.0.1/forbidden')
   self.end_headers()
   if self.path=='/trickle':
    try:
     while not release.wait(.015):self.wfile.write(b'x');self.wfile.flush()
    except (OSError,ssl.SSLError):pass
   else:self.wfile.write(b'{"synthetic":true}\n')
 httpd=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);httpd.daemon_threads=True
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cp,kp);httpd.socket=context.wrap_socket(httpd.socket,server_side=True)
 thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
 try:yield 'https://127.0.0.1:'+str(httpd.server_port),str(cp),seen
 finally:release.set();httpd.shutdown();httpd.server_close();thread.join(2)

@pytest.mark.parametrize('path',['/blocked','/trickle'])
def test_actual_tls_blocked_headers_or_trickling_body_obey_one_deadline(server,path):
 url,ca,seen=server;d=Deadline(.25);start=time.monotonic()
 try:
  with pytest.raises((Expired,TimeoutError,OSError)):
   response=d.call(lambda:post(url+path,{},json={'fixture':1},verify=ca,deadline=d))
   list(d.chunks(response))
  assert time.monotonic()-start<1 and len(seen)==1
 finally:d.finish()

def test_actual_tls_ca_and_no_redirect_or_post_retry(server):
 url,ca,seen=server;d=Deadline(10)
 try:
  response=d.call(lambda:post(url+'/redirect',{},json={'fixture':2},verify=ca,deadline=d,admission=True))
  assert response.status_code==302 and len(seen)==1 and 0<=int(seen[0][2]['X-EDL-Admission-Wait'])<=10
 finally:d.finish()
 d=Deadline(10)
 try:
  with pytest.raises(ssl.SSLCertVerificationError):d.call(lambda:post(url+'/untrusted',{},json={},verify=True,deadline=d))
  assert len(seen)==1
 finally:d.finish()
