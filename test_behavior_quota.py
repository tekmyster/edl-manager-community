"""Isolated quota/settings lifecycle; all model transport is mocked."""
from test_pipeline_mock import stage_mock
import datetime as dt,json,os,pathlib,threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from core import Store,now
from behavior_ai import Brain,DEFAULTS,config_id,model_job,run,settings,validate_settings
from behavior_grounding import example
from behavior_metrics import metrics

@pytest.mark.parametrize('limit',['1','24','96','10000'])
def test_existing_finite_limits_and_defaults(limit):
 assert validate_settings({'daily_budget':limit})['daily_budget']==int(limit)
 assert validate_settings({'daily_budget_mode':'limited','daily_budget':limit})['daily_budget']==int(limit)
 assert validate_settings({})['daily_budget']==DEFAULTS['daily_budget']==24
 assert not DEFAULTS['enabled'] and not DEFAULTS['model_enabled'] and not DEFAULTS['scoring_enabled']

@pytest.mark.parametrize('invalid',['0','-1','10001','1.5','nan','inf','Unlimited','',None])
def test_invalid_finite_limits_rejected(invalid):
 with pytest.raises(ValueError):validate_settings({'daily_budget_mode':'limited','daily_budget':invalid})

@pytest.mark.parametrize('mode',['infinite','UNLIMITED','',None])
def test_unknown_mode_rejected(mode):
 with pytest.raises(ValueError):validate_settings({'daily_budget_mode':mode})

def test_unlimited_is_null_and_does_not_change_other_limits():
 value=validate_settings({'daily_budget_mode':'unlimited','daily_budget':''})
 assert value['daily_budget'] is None and json.loads(json.dumps(value))['daily_budget'] is None
 for key in ['batch_size','timeout','palo_daily_budget','packet_retention_days','cleanup_batch']:
  assert value[key]==DEFAULTS[key]
 with pytest.raises(ValueError):validate_settings({'daily_budget_mode':'unlimited','palo_daily_budget':'0'})

@pytest.fixture
def sample(tmp_path):
 s=Store(tmp_path/'manager.sqlite3')
 s.evidence('8.8.8.8','nginx','synthetic',now(),'http',0,details={'activity':{'events':[{'id':'a','seen':now(),'action':'HTTP request','method':'GET','path':'/example','status':'200'}]}})
 b=Brain(s);ident,packet,features=b.packet(s.describe('8.8.8.8'))
 cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'endpoint':'https://127.0.0.1','model':'synthetic','daily_budget':None}
 s.state('behavior_settings',cfg)
 return s,b,ident,packet,features,cfg

def test_no_finite_sentinel_usage_persists_cache_does_not_consume(sample,monkeypatch):
 s,b,ident,p,f,cfg=sample;calls=[]
 with b.connect() as db:
  db.execute('INSERT INTO usage VALUES(?,?)',(now()[:10],10000001))
  db.execute("INSERT INTO usage VALUES('2020-01-01',96)")
 stage_mock(monkeypatch,'behavior_ai.infer',lambda *args:(calls.append(1) or example(p),{}))
 assert model_job(b,ident,p,f,cfg)=='completed'
 assert model_job(b,ident,p,f,{**cfg,'daily_budget':1})=='cached'
 assert config_id(cfg)==config_id({**cfg,'daily_budget':96})
 with b.connect() as db:
  assert dict(db.execute('SELECT day,requests FROM usage'))=={now()[:10]:10000002,'2020-01-01':96}
 assert calls==[1] and Brain(s).summary()['requests_today']==10000002
 assert settings(s)['daily_budget'] is None

def test_finite_exhaustion_then_unlimited_then_finite_does_not_reset(sample,monkeypatch):
 s,b,ident,p,f,cfg=sample
 with b.connect() as db:db.execute('INSERT INTO usage VALUES(?,96)',(now()[:10],))
 stage_mock(monkeypatch,'behavior_ai.infer',lambda *args:(example(p),{}))
 s.state('behavior_settings',{**cfg,'daily_budget':96})
 assert model_job(b,ident,p,f,{**cfg,'daily_budget':96})=='budget'
 s.state('behavior_settings',cfg)
 assert model_job(b,ident,p,f,cfg)=='completed'
 with b.connect() as db:db.execute("UPDATE assessments SET expires='2020-01-01'")
 s.state('behavior_settings',{**cfg,'daily_budget':96})
 assert model_job(b,ident,p,f,{**cfg,'daily_budget':96})=='budget'
 with b.connect() as db:assert db.execute('SELECT requests FROM usage WHERE day=?',(now()[:10],)).fetchone()[0]==97

def test_unlimited_preserves_provider_backoff_and_retry_exhaustion(sample,monkeypatch):
 s,b,ident,p,f,cfg=sample;calls=[]
 def fail(*args):calls.append(1);raise TimeoutError('synthetic')
 stage_mock(monkeypatch,'behavior_ai.infer',fail)
 assert model_job(b,ident,p,f,cfg)=='failed'
 with b.connect() as db:db.execute("UPDATE assessments SET expires='2020-01-01'")
 # A consumed failed two-stage plan requires review; expiry cannot create a
 # replacement attempt, even with Unlimited or a configuration alias.
 assert model_job(b,ident,p,f,cfg)=='persistence_review_required'
 assert model_job(b,ident,p,f,{**cfg,'timeout':121})=='persistence_review_required'
 with b.connect() as db:
  assert db.execute('SELECT requests FROM usage WHERE day=?',(now()[:10],)).fetchone()[0]==1
  assert db.execute('SELECT attempts FROM jobs').fetchone()[0]==1
 assert len(calls)==1

def test_unlimited_concurrent_same_packet_still_uses_lease(sample,monkeypatch):
 s,b,ident,p,f,cfg=sample;entered=threading.Event();release=threading.Event()
 def infer(*args):entered.set();assert release.wait(10);return example(p),{}
 stage_mock(monkeypatch,'behavior_ai.infer',infer)
 with ThreadPoolExecutor(max_workers=1) as pool:
  future=pool.submit(model_job,b,ident,p,f,cfg)
  try:
   assert entered.wait(10)
   assert model_job(b,ident,p,f,cfg)=='leased_or_exhausted'
   with b.connect() as db:assert db.execute('SELECT requests FROM usage WHERE day=?',(now()[:10],)).fetchone()[0]==1
  finally:release.set()
  assert future.result(timeout=10)=='completed'

@pytest.mark.parametrize('limit',[24,None])
def test_worker_finite_cap_and_unlimited_drain(tmp_path,monkeypatch,limit):
 s=Store(tmp_path/'manager.sqlite3');cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'endpoint':'https://127.0.0.1','model':'synthetic','daily_budget':limit};s.state('behavior_settings',cfg)
 for i in range(3):s.evidence('8.8.8.'+str(i+1),'nginx','synthetic',now(),'http',0,details={'activity':{'events':[{'id':'e'+str(i),'seen':now(),'action':'HTTP request','method':'GET','path':'/example'}]}})
 calls=[]
 def infer(cfg,p,*args):calls.append(p['packet_id']);return example(p),{}
 stage_mock(monkeypatch,'behavior_ai.infer',infer)
 expected=2 if limit is not None else 3
 result=run(s);assert len(calls)==expected and result['analysis']=={'completed':expected}
 with Brain(s).connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==3-expected

@pytest.fixture
def web(tmp_path):
 from app import create_app
 app=create_app({'database':str(tmp_path/'manager.sqlite3'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'synthetic','hosts':['localhost']});app.testing=True;c=app.test_client()
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 with c.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 return app,c

def test_save_reload_warning_consumed_usage_and_history_preserved(web):
 app,c=web;b=Brain(app.store)
 with b.connect() as db:
  db.execute('INSERT INTO usage VALUES(?,96)',(now()[:10],))
  db.execute("INSERT INTO assessments VALUES('saved','p','cfg','2020','2021','failed','{}','historical',1)")
  before=list(db.execute('SELECT * FROM assessments'))
 form={'csrf':'csrf','daily_budget_mode':'unlimited','daily_budget':''}
 response=c.post('/settings/behavior',data=form,base_url='https://localhost',follow_redirects=True)
 assert response.status_code==200;html=response.get_data(as_text=True)
 assert html.count('Using a paid provider can incur substantial charges')==1 and 'Local inference has no provider token fees' in html
 assert '96 / Unlimited' in html and '<option value="unlimited" selected>Unlimited</option>' in html
 assert app.store.state('behavior_settings')['daily_budget'] is None
 page=c.get('/behavior',base_url='https://localhost').get_data(as_text=True)
 assert 'Using a paid provider can incur substantial charges' not in page
 assert '96 / Unlimited' in page
 metric=c.get('/behavior/metrics',base_url='https://localhost').get_data(as_text=True)
 assert '96 / Unlimited' in metric and 'NaN' not in metric and 'Infinity' not in metric
 assert metrics(b)['daily_usage']['limit'] is None and b.summary()['daily_budget'] is None
 with b.connect() as db:
  assert list(db.execute('SELECT * FROM assessments'))==before
  assert db.execute('SELECT requests FROM usage WHERE day=?',(now()[:10],)).fetchone()[0]==96
 # Each explicit successful Unlimited save warns once; refreshes never repeat it.
 again=c.post('/settings/behavior',data=form,base_url='https://localhost',follow_redirects=True).get_data(as_text=True)
 assert again.count('Using a paid provider can incur substantial charges')==1
 assert 'Using a paid provider can incur substantial charges' not in c.get('/behavior',base_url='https://localhost').get_data(as_text=True)
 limited=c.post('/settings/behavior',data={**form,'daily_budget_mode':'limited','daily_budget':'24'},base_url='https://localhost',follow_redirects=True).get_data(as_text=True)
 assert 'Using a paid provider can incur substantial charges' not in limited and '96 / 24' in limited
 assert settings(app.store)['daily_budget']==24
 export=os.environ.get('INTELLIGENCE_UI_EXPORT')
 if export:
  folder=pathlib.Path(export);folder.mkdir(parents=True,exist_ok=True)
  for name,content in [('quota-warning.html',html),('quota-saved.html',page),('quota-metrics.html',metric)]:folder.joinpath(name).write_text(content,encoding='utf-8')

def test_failed_save_and_csrf_do_not_enable_unlimited_or_warn(web):
 app,c=web;app.store.state('behavior_settings',dict(DEFAULTS))
 invalid=c.post('/settings/behavior',data={'csrf':'csrf','daily_budget_mode':'unlimited','palo_daily_budget':'0'},base_url='https://localhost',follow_redirects=True).get_data(as_text=True)
 assert 'outside the supported range' in invalid and 'Using a paid provider' not in invalid
 assert settings(app.store)['daily_budget']==24
 assert c.post('/settings/behavior',data={'daily_budget_mode':'unlimited'},base_url='https://localhost').status_code==400
 assert settings(app.store)['daily_budget']==24
