"""Regression coverage for the Richer evidence supervisor QA corrections."""
import datetime as dt,json,ssl
import pytest

@pytest.mark.parametrize('system_trust',[True,False])
def test_fetch_uses_verified_requests_transport_for_system_or_custom_ca(monkeypatch,tmp_path,system_trust):
 import requests
 from evidence_history import fetch
 trust=True if system_trust else str(tmp_path/'trusted-ca.pem');calls=[]
 if not system_trust:
  import shutil
  shutil.copyfile(requests.certs.where(),trust)
 original=requests.Session
 class Stub(original):
  def post(self,url,**kwargs):
   calls.append(url)
   assert self.verify is True if system_trust else self.verify==trust
   assert self.auth==('fixture','fixture-only')
   prepared=requests.Request('POST',url).prepare()
   unused,pool=self.get_adapter(url).build_connection_pool_key_attributes(prepared,self.verify,None)
   assert pool['cert_reqs']=='CERT_REQUIRED'
   if system_trust:assert not pool.get('ca_certs')
   else:
    assert pool['ca_certs']==trust and pool.get('ssl_context') is not None
    assert not pool['ssl_context'].verify_flags & ssl.VERIFY_X509_STRICT
   if pool.get('ssl_context'):
    assert pool['ssl_context'].verify_mode==ssl.CERT_REQUIRED and pool['ssl_context'].check_hostname
   filters=kwargs['json']['query']['bool']['filter']
   assert {'term':{'data.srcip':'8.8.8.8'}} in filters
   assert kwargs['json']['size']==500 and kwargs['timeout']==(5,40)
   class Response:
    def raise_for_status(self):pass
    def json(self):return {'hits':{'total':{'value':0},'hits':[]}}
   return Response()
 monkeypatch.setattr(requests,'Session',Stub)
 records,meta=fetch({'index_url':'https://index.example.invalid','source_agents':{'nginx':'fixture-edge'},'index_ca':trust,'index_user':'fixture','index_password':'fixture-only'},'8.8.8.8')
 assert calls==['https://index.example.invalid/wazuh-alerts-*/_search'] and records==[] and meta['status']=='ok'

@pytest.mark.parametrize('trust',[False,None,''])
def test_fetch_rejects_disabled_or_empty_trust_before_transport(monkeypatch,trust):
 import requests
 from evidence_history import fetch
 monkeypatch.setattr(requests,'Session',lambda:pytest.fail('Invalid TLS settings reached transport'))
 with pytest.raises(ValueError,match='trusted CA'):
  fetch({'index_url':'https://index.example.invalid','source_agents':{'nginx':'*'},'index_ca':trust},'8.8.8.8')

@pytest.mark.parametrize('custom_ca',[False,True])
def test_certificate_failure_is_not_retried_with_verification_disabled(monkeypatch,custom_ca):
 import requests
 from evidence_history import fetch
 calls=[];original=requests.Session;trust=requests.certs.where() if custom_ca else True
 class Stub(original):
  def post(self,*args,**kwargs):calls.append(self.verify);raise requests.exceptions.SSLError('fixture certificate validation failure')
 monkeypatch.setattr(requests,'Session',Stub)
 with pytest.raises(requests.exceptions.SSLError):fetch({'index_url':'https://index.example.invalid','source_agents':{'nginx':'*'},'index_ca':trust,'index_user':'fixture','index_password':'fixture-only'},'8.8.8.8')
 assert calls==[trust]

def scored_app(tmp_path):
 from test_behavior_scoring import fixture
 from test_behavior_ai import result
 from app import create_app
 store,brain,packet,assessment,expiry=fixture(tmp_path)
 # Deliberate stored-score display fixture, independent of model acceptance.
 value=result(packet);value.update(classification='malicious',maliciousness_confidence=.95,metadata=assessment['metadata'])
 value['findings']=[{'summary':'Distinct request observations','evidence_ids':assessment['findings'][0]['evidence_ids']}]
 with brain.connect() as db:db.execute('UPDATE assessments SET result=?',(json.dumps(value),))
 app=create_app({'database':str(tmp_path/'manager.sqlite3'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'fixture','hosts':['localhost']});app.testing=True;client=app.test_client()
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('reviewer','fixture-hash',1))
 with client.session_transaction() as session:session.update(user='reviewer',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='fixture')
 return app,client

def test_rendered_ip_detail_separates_actual_adjustment_from_simulation(tmp_path):
 app,client=scored_app(tmp_path)
 response=client.get('/ip/8.8.8.8',base_url='https://localhost');assert response.status_code==200
 html=response.get_data(as_text=True)
 assert 'Applied AI adjustment: +9.5 points' in html and 'Effective score: 79.5' in html
 assert '<summary>Score simulation</summary>' in html and 'Simulated score at analysis: 79.5' in html
 assert 'applied adjustment: 0' not in html
 cfg=app.store.state('behavior_settings');cfg['scoring_enabled']=False;app.store.state('behavior_settings',cfg)
 html=client.get('/ip/8.8.8.8',base_url='https://localhost').get_data(as_text=True)
 assert 'Applied AI adjustment: +0 points' in html and 'Effective score: 70' in html
 assert 'Simulated score at analysis: 79.5' in html

@pytest.mark.parametrize('status',['not_queried','error'])
def test_history_help_is_closed_and_preserves_empty_and_error_states(tmp_path,status):
 from flask import render_template
 app,client=scored_app(tmp_path)
 history={'total':0,'events':[],'collection':{'status':status},'offset':0,'limited':False}
 with app.test_request_context('/behavior/8.8.8.8/history',base_url='https://localhost'):
  html=render_template('evidence_history.html',history=history,address='8.8.8.8')
 help_html=html.split('<details class="info-help">',1)[1].split('</details>',1)[0]
 assert 'aria-label="Cached history help"' in help_html and 'TLS and header-order fingerprints' in help_html
 assert 'Query values, credentials and bodies' in help_html
 assert '<details class="info-help" open' not in html and '0 observations' in html and 'Partial coverage' in html
 assert 'No locally cached observations' in html
 if status=='error':assert 'role="status"' in html and 'Unavailable; saved history retained' in html
 else:assert 'Collection: Not yet queried' in html
