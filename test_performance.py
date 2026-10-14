import datetime as dt,hashlib,json,os,pathlib,pytest
from app import create_app
from core import now

@pytest.mark.skipif(os.name=='nt',reason='Atomic symlink publication runs on Linux')
def test_dashboard_snapshot_changes_with_generation_and_never_drives_build(tmp_path,monkeypatch):
 cfg={'session_secret':'test','database':str(tmp_path/'db'),'output':str(tmp_path/'out'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True;s=app.store
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':2})
 m=s.build(cfg['output']);p=pathlib.Path(cfg['output'])/'current';old=p.resolve()
 assert hashlib.sha256((p/'scored-block.txt').read_bytes()).hexdigest()==m['sha256']['scored-block']
 assert (p/'scored-block.txt').read_text()=='8.8.8.8\n'
 snapshot=json.loads((p/'dashboard.json').read_text());assert len(snapshot['rows'])==1
 assert 'evidence' not in snapshot['rows'][0]
 c=app.test_client()
 monkeypatch.setattr('app.check_password_hash',lambda *a:True)
 with s.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 with c.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600)
 real=s.all_scores
 monkeypatch.setattr(s,'all_scores',lambda:pytest.fail('Dashboard unexpectedly rescored'))
 assert c.get('/',base_url='https://localhost').status_code==200
 # A second background generation must invalidate the process cache immediately.
 monkeypatch.setattr(s,'all_scores',real)
 s.evidence('9.9.9.9','waf','waf',now(),'http',75);s.build(cfg['output']);assert p.resolve()!=old
 monkeypatch.setattr(s,'all_scores',lambda:pytest.fail('New snapshot unexpectedly rescored'))
 assert '9.9.9.9' in c.get('/',base_url='https://localhost').text
 # Corrupt display data cannot change authoritative list decisions.
 (p/'dashboard.json').write_text('{bad')
 monkeypatch.setattr(s,'all_scores',real)
 assert c.get('/',base_url='https://localhost').status_code==200
 s.add_rule('allow','8.8.8.8','Business exception',None,'admin');s.build(cfg['output'])
 assert '8.8.8.8' not in (p/'scored-block.txt').read_text()

@pytest.mark.skipif(os.name=='nt',reason='Production worker uses Linux dependencies')
def test_incremental_native_ingest_overlap_reconcile_and_failure_retry(tmp_path,monkeypatch):
 import ssl,worker,requests
 from types import SimpleNamespace
 from core import Store
 s=Store(tmp_path/'db');calls=[];fail=[False];original=worker.requests.Session
 class FakeSession(original):
  def post(self,url,json,timeout):
   calls.append(json)
   if fail[0]:raise requests.ConnectionError('index unavailable')
   return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'aggregations':{'items':{'buckets':[]}}})
 monkeypatch.setattr(worker.requests,'Session',FakeSession)
 cfg={'incremental_ingest':True,'index_url':'https://index.example.test:9200','index_user':'reader','index_password':'test','index_ca':ssl.get_default_verify_paths().cafile}
 worker.collect(s,cfg,include_palo=False)
 first=s.state('native_ingest_cursor');assert first['mode']=='full'
 assert 'gte' not in calls[0]['query']['bool']['filter'][-1]['range']['timestamp']
 calls.clear();worker.collect(s,cfg,include_palo=False)
 assert s.state('native_ingest_cursor')['mode']=='incremental'
 fence=calls[0]['query']['bool']['filter'][-1]['range']['timestamp']
 assert dt.datetime.fromisoformat(fence['gte'])==dt.datetime.fromisoformat(first['through'])-dt.timedelta(minutes=10)
 prior=s.state('native_ingest_cursor');fail[0]=True
 with pytest.raises(requests.ConnectionError):worker.collect(s,cfg,include_palo=False)
 assert s.state('native_ingest_cursor')==prior
 fail[0]=False;calls.clear()
 s.state('native_ingest_cursor',{**prior,'reconciled':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=2)).isoformat()})
 worker.collect(s,cfg,include_palo=False)
 assert s.state('native_ingest_cursor')['mode']=='full'
 assert 'gte' not in calls[0]['query']['bool']['filter'][-1]['range']['timestamp']

def test_transport_rejects_partial_corrupt_private_and_stale_generations():
 import copy
 from transport import NAMES,validate
 files={name:'8.8.8.8\n' for name in NAMES}
 package={'files':files,'manifest':{'created':now(),'counts':{n:1 for n in NAMES},'sha256':{n:hashlib.sha256(v.encode()).hexdigest() for n,v in files.items()}}}
 assert validate(package)==package
 for kind in ['partial','corrupt','private','stale']:
  bad=copy.deepcopy(package)
  if kind=='partial':bad['files'].pop('owapot-review')
  elif kind=='corrupt':bad['files']['scored-block']='9.9.9.9\n'
  elif kind=='private':
   bad['files']['scored-block']='10.0.0.1\n';bad['manifest']['sha256']['scored-block']=hashlib.sha256(b'10.0.0.1\n').hexdigest()
  else:bad['manifest']['created']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=1)).isoformat()
  with pytest.raises(ValueError):validate(bad)
