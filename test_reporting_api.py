import datetime as dt,json,re
import pytest
from app import create_app
from core import now
from reporting_api import issue

@pytest.fixture
def api(tmp_path):
 cfg={'database':str(tmp_path/'db'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'test-secret','hosts':['localhost']}
 app=create_app(cfg);app.testing=True;c=app.test_client()
 with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 token=issue(app.store,'Grafana',90,'admin')
 app.store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 return app,c,{'Authorization':'Bearer '+token},token

def login(c):
 with c.session_transaction() as s:s.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')

def test_reporting_token_is_required_even_with_admin_cookie_and_cannot_write(api):
 app,c,h,token=api;login(c)
 assert c.get('/api/v1/summary',base_url='https://localhost').status_code==401
 assert c.get('/api/v1/summary?token='+token,base_url='https://localhost').status_code==401
 assert c.post('/api/v1/summary',base_url='https://localhost',headers=h).status_code==405
 assert c.post('/rules',data={'action':'block','value':'8.8.8.8','reason':'Unauthorized'},base_url='https://localhost',headers=h).status_code==400
 assert not app.store.active_rules()

def test_revoked_expired_tokens_fail_and_management_acl_still_applies(api):
 app,c,h,token=api
 assert c.get('/api/v1/summary',base_url='https://localhost',headers=h,environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code==403
 with app.store.connect() as d:d.execute("UPDATE api_tokens SET expires='2020-01-01T00:00:00+00:00'")
 assert c.get('/api/v1/summary',base_url='https://localhost',headers=h).status_code==401
 token=issue(app.store,'Temporary',30,'admin');h={'Authorization':'Bearer '+token}
 login(c)
 with app.store.connect() as d:ident=d.execute('SELECT id FROM api_tokens WHERE name=?',('Temporary',)).fetchone()[0]
 assert c.post('/settings/api-tokens/'+ident+'/revoke',data={'csrf':'csrf'},base_url='https://localhost').status_code==302
 assert c.get('/api/v1/summary',base_url='https://localhost',headers=h).status_code==401

def test_all_read_endpoints_are_json_bounded_and_stateless(api):
 app,c,h,token=api
 for route in ['/api/v1/summary','/api/v1/ips','/api/v1/ips/8.8.8.8','/api/v1/ips/8.8.8.8/activity','/api/v1/history?days=365','/api/v1/rules']:
  r=c.get(route,base_url='https://localhost',headers=h)
  assert r.status_code==200 and r.is_json and 'Set-Cookie' not in r.headers
  assert token not in r.text and 'test-secret' not in r.text
 assert c.get('/api/v1/ips?limit=0',base_url='https://localhost',headers=h).status_code==400
 assert c.get('/api/v1/ips?limit=1001',base_url='https://localhost',headers=h).status_code==400
 assert c.get('/api/v1/ips?repeat=invalid',base_url='https://localhost',headers=h).status_code==400
 assert c.get('/api/v1/history?days=31',base_url='https://localhost',headers=h).status_code==400
 assert c.get('/api/v1/ips/10.0.0.1',base_url='https://localhost',headers=h).status_code==400
 assert c.get('/api/v1/ips/9.9.9.9',base_url='https://localhost',headers=h).status_code==404

def test_token_creation_requires_csrf_and_token_is_not_in_cookie_or_audit(api):
 app,c,h,token=api;login(c)
 assert c.post('/settings/api-tokens',data={'name':'New','days':'90'},base_url='https://localhost').status_code==400
 r=c.post('/settings/api-tokens',data={'csrf':'csrf','name':'New','days':'90'},base_url='https://localhost');assert r.status_code==200
 secret=re.search(r'id="new-api-token" value="([^"]+)"',r.text)[1]
 assert secret not in r.headers.get('Set-Cookie','')
 assert secret not in c.get('/settings',base_url='https://localhost').text
 with app.store.connect() as d:
  assert secret not in json.dumps([dict(x) for x in d.execute('SELECT * FROM audit')])
  assert secret not in json.dumps([dict(x) for x in d.execute('SELECT * FROM api_tokens')])

def test_repeat_filter_and_ui_match_summary_and_detail(api):
 app,c,h,token=api;s=app.store;t=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=40)).isoformat(timespec='seconds')
 with s.connect() as d:d.execute('INSERT INTO offender_blocks VALUES(?,?,?,?,?)',('8.8.8.8',t,t,t,75))
 s.source_activity('8.8.8.8','nginx','web-request',now(),{})
 assert c.get('/api/v1/summary',base_url='https://localhost',headers=h).json['repeat_offenders']==1
 assert c.get('/api/v1/ips?repeat=true&days=60',base_url='https://localhost',headers=h).json['total']==1
 assert c.get('/api/v1/ips?repeat=false',base_url='https://localhost',headers=h).json['total']==0
 login(c)
 assert 'Repeat offender' in c.get('/?f_repeat=60',base_url='https://localhost').text
 assert '1 year' in c.get('/ip/8.8.8.8',base_url='https://localhost').text
 assert '8.8.8.8' in c.get('/results/repeat?days=60',base_url='https://localhost').text

def test_grafana_authentication_cache_and_failure_preserve_contract(api,monkeypatch):
 import grafana_snapshot
 app,c,h,token=api;calls=[]
 def snapshot(cfg):calls.append(cfg);return {'summary':{'listed_ips':2},'generation':now(),'window_days':30}
 monkeypatch.setattr(grafana_snapshot,'snapshot',snapshot)
 assert c.get('/api/v1/grafana',base_url='https://localhost').status_code==401
 for _ in range(2):
  r=c.get('/api/v1/grafana',base_url='https://localhost',headers=h)
  assert r.status_code==200 and 'Set-Cookie' not in r.headers
  assert r.json['summary']['listed_ips']==2 and r.json['summary']['repeat_offenders']==0
  assert r.json['repeat_counts']['365']==0 and 'repeat_coverage' in r.json
 assert len(calls)==1

def test_grafana_snapshot_preserves_published_membership_and_aggregates(api,monkeypatch,tmp_path):
 import os,types,grafana_snapshot
 if os.name=='nt':pytest.skip('Published output ownership is validated on Linux')
 app,c,h,token=api
 app.store.evidence('9.9.9.9','tpot','Cowrie',now(),'ssh',100)
 app.store.add_rule('allow','9.9.9.9','Protected test address',None,'admin',False)
 output=str(tmp_path/'out');app.store.build(output)
 monkeypatch.setattr(grafana_snapshot.subprocess,'run',lambda *a,**kw:types.SimpleNamespace(stdout='active\nsuccess\n'))
 r=c.get('/api/v1/grafana',base_url='https://localhost',headers=h)
 assert r.status_code==200
 v=r.json;assert v['summary']['observed_ips']==2 and v['summary']['listed_ips']==0
 assert v['counts']['manual-allow']==1 and v['window_days']==30
 assert v['sources'][0]['ips']==2 and len(v['score_bands'])==5
 assert v['reporting_transport']=='authenticated HTTPS API'
