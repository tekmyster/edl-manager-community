import datetime as dt,json,sys,pathlib
from activity import normalize,local_activity,ActivityCache
from core import Store,now

def test_native_palo_details_preserve_private_nat_and_block_outcome():
 hit={'_id':'abc','_source':{'data':{'source_address':'8.8.8.8','destination_address':'9.9.9.9','destination_port':'443','nat_destination_ip':'10.99.100.50','nat_destination_port':'8443','action':'deny','high_resolution_timestamp':'2026-10-10T01:00:00-04:00','application':'ssl','rule_name':'edge-block'}}}
 e=normalize(hit,'8.8.8.8');assert e['destination']=='9.9.9.9' and e['nat']=='10.99.100.50' and e['action']=='deny'
 assert e['seen']=='2026-10-10T05:00:00+00:00'
 assert normalize(hit,'1.1.1.1') is None
 hit['_source']['data']['high_resolution_timestamp']='2026/10/10 01:00:00';assert normalize(hit,'8.8.8.8') is None

def test_activity_samples_dedup_window_and_no_score_or_ttl_change(tmp_path):
 s=Store(tmp_path/'manager.sqlite3');before=now()
 activity={'events':[{'id':'e1','seen':before,'destination':'10.0.0.5','port':'8088','action':'request','path':'/owa/auth.owa'},{'id':'old','seen':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).isoformat(),'action':'request'}],'paths':['/owa/auth.owa']}
 for path in ['hash1','hash2']:s.evidence('8.8.8.8','owapot','OWA-Honeypot',before,'http',0,path,{'activity':json.dumps(activity),'native_attempt_count':2})
 row=s.describe('8.8.8.8');score=row['score'];events,summary=local_activity(row)
 assert len(events)==1 and events[0]['destination']=='10.0.0.5';assert len(summary)==1
 cache=ActivityCache(s,{})
 assert not cache.get('8.8.8.8')['enabled'];assert s.describe('8.8.8.8')['score']==score
 with s.connect() as d:assert d.execute('SELECT COUNT(*) FROM block_retention').fetchone()[0]==0
 s.source_activity('8.8.8.8','owapot','OWA-Honeypot',before,{'activity':activity,'native_attempt_count':2})
 assert len(s.describe('8.8.8.8')['activity'])==1
 assert s.describe('8.8.8.8')['score']==score
 s.source_activity('8.8.8.8','owapot','OWA-Honeypot',(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=1)).isoformat(),{'activity':{'events':[]}})
 assert len(local_activity(s.describe('8.8.8.8'))[0])==1

def test_sensor_activity_redacts_secrets_and_keeps_private_destination():
 sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent))
 from source_events import activity_event
 e=activity_event({'@timestamp':now(),'dest_ip':'10.1.2.3','dest_port':443,'uri_path':'https://user:pass@example.net/owa/auth.owa?token=secret','password':'secret','eventid':'cowrie.login.failed'})
 assert e['path']=='/owa/auth.owa' and e['destination']=='10.1.2.3'
 assert 'secret' not in json.dumps(e) and 'password' not in e

def test_authenticated_ip_page_filters_and_escapes_attacker_content(tmp_path):
 from app import create_app
 from werkzeug.security import generate_password_hash
 app=create_app({'session_secret':'test','database':str(tmp_path/'db.sqlite'),'hosts':['localhost'],'source_agents':{'owapot':'*'}});app.testing=True
 with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,1)',('admin',generate_password_hash('test-password')))
 app.store.evidence('8.8.8.8','owapot','OWA-Honeypot',now(),'http',0,details={'native_attempt_count':1,'activity':json.dumps({'events':[{'id':'a','seen':now(),'destination':'10.1.2.3','port':'8088','action':'request','path':'/<script>alert(1)</script>'}]})})
 client=app.test_client()
 assert client.get('/ip-activity/8.8.8.8',base_url='https://localhost').status_code==302
 with client.session_transaction() as sess:sess.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+1800)
 r=client.get('/ip/8.8.8.8',base_url='https://localhost');assert r.status_code==200
 assert b'10.1.2.3' in r.data and b'&lt;script&gt;alert(1)&lt;/script&gt;' in r.data
 assert b'<script>alert(1)</script>' not in r.data
 assert b'Network activity' in r.data and b'data-activity-url=' in r.data
 r=client.get('/ip-activity/8.8.8.8?a_f_action=deny',base_url='https://localhost');assert r.status_code==200 and b'No event samples recorded for these filters' in r.data
