import datetime as dt,json,ipaddress,pytest,os,sqlite3,re
from core import Store,selector,subtract,now
from app import create_app
from werkzeug.security import generate_password_hash
@pytest.fixture
def store(tmp_path):return Store(tmp_path/'test.sqlite3')
@pytest.mark.parametrize('value',['8.8.8.8','8.8.8.0/24','8.8.8.0/255.255.255.0','8.8.8.10-8.8.8.30','2606:4700:4700::1111','AS8075'])
def test_valid_selectors(value):assert selector(value)[1]
@pytest.mark.parametrize('value',['10.0.0.1','100.64.1.1','224.0.0.1','8.0.0.0/5','8.0.0.0-12.0.0.0','fc00::1','ff00::1','AS0','8.8.8.20-8.8.8.1','8.8.8.1-2606:4700::1'])
def test_invalid_selectors(value):
 with pytest.raises(ValueError):selector(value)
def test_whitelist_subtracts_from_range():
 blocked=selector('8.8.8.0/24')[2];allow=selector('8.8.8.20-8.8.8.30')[2];result=subtract(blocked,allow)
 assert sum(n.num_addresses for n in result)==245
 assert not any(ipaddress.ip_address('8.8.8.25') in n for n in result)
def test_event_dedup_and_palo_no_renewal(store):
 seen=now()
 store.evidence('8.8.8.8','tpot','Cowrie',seen,'ssh',75)
 store.evidence('8.8.8.8','tpot','Cowrie',seen,'ssh',75)
 before=store.describe('8.8.8.8');store.cache('8.8.8.8','palo',{'drops':500})
 after=store.describe('8.8.8.8');assert before['score']==after['score']==75
 with store.connect() as d:assert d.execute('select count(*) from evidence').fetchone()[0]==1

def test_bulk_enrichment_keeps_one_result_per_ip_provider(store):
 store.cache_many([('8.8.8.8','misp',{'matches':0},'ok',24),('8.8.8.8','misp',{'matches':1},'ok',24),('8.8.8.8','palo',{'alert_records':5},'ok',1)])
 with store.connect() as d:assert d.execute('select count(*) from cache').fetchone()[0]==2
 assert json.loads(store.cached('8.8.8.8','misp')['payload'])['matches']==1

def test_stale_database_does_not_gate_score_but_cannot_expand_asn_rule(store,tmp_path):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75)
 store.cache('8.8.8.8','asn',{'asn':'15169','organization':'test owner','database_build_epoch':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).timestamp()})
 store.cache('8.8.8.8','crawler',{'verified':False})
 r=store.describe('8.8.8.8');assert r['auto_candidate'] and 'ASN database is older than 30 days' in r['review_notes']
 if os.name!='nt':
  store.add_rule('block','AS15169','test',None,'admin');m=store.build(tmp_path/'lists');assert m['counts']['manual-block']==0

def test_worker_connection_commits_visible_to_ui(store):
 store._worker_connection=sqlite3.connect(store.path)
 try:
  store.cache('8.8.8.8','asn',{'asn':'15169'})
  ui=Store(store.path);assert ui.cached('8.8.8.8','asn') is not None
 finally:store._worker_connection.close();store._worker_connection=None

@pytest.mark.skipif(os.name=='nt',reason='Linux publication check')
def test_verified_crawler_survives_manual_asn_block(store,tmp_path):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75);store.cache('8.8.8.8','asn',{'asn':'15169','organization':'test owner'});store.cache('8.8.8.8','crawler',{'verified':True})
 store.add_rule('block','AS15169','test',None,'admin');out=tmp_path/'lists';m=store.build(out);assert m['counts']['combined-block']==0
 assert (out/'current'/'protected-crawlers.txt').read_text()=='8.8.8.8\n'
 store.add_rule('block','8.8.8.8','Emergency reviewed override',None,'admin',True);m=store.build(out);assert (out/'current'/'combined-block.txt').read_text()=='8.8.8.8\n'
def test_stale_crawler_and_shared_provider_hold(store):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75);store.cache('8.8.8.8','asn',{'asn':'15169','organization':'Google LLC'})
 r=store.describe('8.8.8.8');assert r['auto_candidate'] and any('Crawler verification' in x for x in r['review_notes'])
 store.cache('8.8.8.8','crawler',{'verified':False});assert store.describe('8.8.8.8')['auto_candidate']
 store.cache('8.8.8.8','crawler',{'verified':True});assert not store.describe('8.8.8.8')['auto_candidate']
def test_multi_http_not_independent_attack_families(store):
 for src in ['nginx','waf','crowdsec']:store.evidence('8.8.4.4',src,src,now(),'http',25)
 r=store.describe('8.8.4.4');assert r['score_breakdown']['independent_family_bonus']==0 and not r['auto_candidate']

@pytest.mark.parametrize('source',['tpot','owapot'])
def test_first_honeypot_observation_starts_at_fifty(store,source):
 store.evidence('8.8.4.4',source,'http honeypot',now(),'http',0)
 r=store.describe('8.8.4.4')
 assert r['score']==50 and not r['auto_candidate']
 assert r['score_breakdown']['honeypot_floor_bonus']==50
 assert r['holds'] and r['review_notes']

@pytest.mark.parametrize('count,score,blocked',[(1,50,False),(2,75,True),(3,100,True),(100,100,True)])
def test_native_honeypot_event_counts(store,count,score,blocked):
 store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',10,details={'detector':'Cowrie','native_attempt_count':count})
 r=store.describe('8.8.4.4');assert r['score']==score and r['auto_candidate']==blocked

def test_honeypot_snapshots_paths_and_behavioral_subsets_not_double_counted(store):
 seen=now()
 for path in ['one','two','three']:
  store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,path,{'detector':'Cowrie','native_attempt_count':1})
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,details={'detector':'Cowrie:failed-login','native_attempt_count':9})
 r=store.describe('8.8.4.4');assert r['score']==50 and r['honeypot_native_events']==1
 # Corrected counters with the same last event timestamp update the original record.
 for path in ['one','two','three']:
  store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,path,{'detector':'Cowrie','native_attempt_count':2})
 r=store.describe('8.8.4.4');assert r['score']==75 and r['honeypot_native_events']==2

def test_latest_native_counter_can_decrease_without_a_new_last_event(store):
 seen=now();old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=1)).isoformat()
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,'old-path',{'native_attempt_count':3,'native_counter_updated_at':old})
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,'new-path',{'native_attempt_count':1,'native_counter_updated_at':seen})
 r=store.describe('8.8.4.4');assert r['score']==50 and r['honeypot_native_events']==1

def test_batched_evidence_is_committed_before_state_is_published(store):
 store._worker_connection=sqlite3.connect(store.path);store._batch_evidence=True
 try:
  store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',10)
  with sqlite3.connect(store.path) as d:assert d.execute('select count(*) from evidence').fetchone()[0]==0
  store.state('ingest_status',{'status':'ok'})
  with sqlite3.connect(store.path) as d:assert d.execute('select count(*) from evidence').fetchone()[0]==1
 finally:store._worker_connection.close();store._worker_connection=None

@pytest.mark.skipif(os.name=='nt',reason='Production worker dependencies are on Linux')
def test_http_weights_do_not_confuse_generic_alerts_with_active_bans():
 from worker import strength
 assert strength('nginx','sensitive-path-probe')==('http',50)
 assert strength('waf','coraza-interruption')==('http',50)
 assert strength('crowdsec','crowdsec-ban:crowdsecurity/http-probing')==('http',75)
 assert strength('crowdsec','crowdsecurity/http-probing')==('http',25)

@pytest.mark.skipif(os.name=='nt',reason='Production worker dependencies are on Linux')
def test_palo_enrichment_keeps_tls_context_and_does_not_renew_attack_evidence(store,monkeypatch):
 import worker,ssl,requests
 from types import SimpleNamespace
 original=worker.requests.Session;calls=[]
 for address in ['8.8.4.4','9.9.9.9']:store.evidence(address,'tpot','Cowrie',now(),'ssh',10)
 with store.connect() as d:before=[tuple(r) for r in d.execute('select ip,last_seen from ips order by ip')]
 class FakeSession(original):
  def post(self,url,json,timeout):
   prepared=requests.Request('POST',url).prepare()
   host,kw=self.get_adapter(url).build_connection_pool_key_attributes(prepared,self.verify)
   assert isinstance(kw['ssl_context'],ssl.SSLContext)
   address='8.8.4.4' if not calls else '9.9.9.9';calls.append(url)
   result={'aggregations':{'ips':{'buckets':[{'key':{'ip':address},'doc_count':3,'last':{'value':dt.datetime.now(dt.timezone.utc).timestamp()*1000}}]}}}
   return SimpleNamespace(raise_for_status=lambda:None,json=lambda:result)
 monkeypatch.setattr(worker.requests,'Session',FakeSession)
 cfg={'index_url':'https://index.example.test:9200','index_user':'reader','index_password':'test','index_ca':ssl.get_default_verify_paths().cafile,'palo_location':'firewall.example.test'}
 worker.collect(store,cfg,palo_only=True)
 rows=store.all_scores();assert len(calls)==2 and {r['ip'] for r in rows}=={'8.8.4.4','9.9.9.9'}
 assert all(r['score']==50 and not r['auto_candidate'] and r['palo_context_records']==3 for r in rows)
 with store.connect() as d:assert before==[tuple(r) for r in d.execute('select ip,last_seen from ips order by ip')]

def test_fresh_malicious_enrichment_promotes_fifty_but_is_capped(store):
 store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',10)
 store.cache('8.8.4.4','misp',{'matches':1,'snapshot_fetched':now(),'fresh_to_ids_and_warninglists_enforced':True})
 store.cache('8.8.4.4','abuseipdb',{'abuseConfidenceScore':95,'totalReports':5,'lastReportedAt':now(),'isWhitelisted':False})
 r=store.describe('8.8.4.4');assert r['score']==75 and r['score_breakdown']['enrichment_bonus']==25 and len(r['enrichment_signals'])==2

def test_stale_unverified_or_benign_enrichment_does_not_score(store):
 store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',10)
 old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).isoformat()
 store.cache('8.8.4.4','misp',{'matches':50,'snapshot_fetched':now()})
 store.cache('8.8.4.4','abuseipdb',{'abuseConfidenceScore':100,'totalReports':5,'lastReportedAt':old})
 store.cache('8.8.4.4','virustotal',{'last_analysis_stats':{'malicious':20},'last_analysis_date':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).timestamp()})
 store.cache('8.8.4.4','asn',{'asn':'1','organization':'Unknown provider'})
 r=store.describe('8.8.4.4');assert r['score']==50 and not r['auto_candidate']

def test_palo_only_drop_and_positive_intel_do_not_automatically_block(store):
 store.evidence('8.8.4.4','palo','deny-drop',now(),'firewall-decision',0)
 store.cache('8.8.4.4','misp',{'matches':1,'snapshot_fetched':now(),'fresh_to_ids_and_warninglists_enforced':True})
 r=store.describe('8.8.4.4');assert r['score']==0 and not r['auto_candidate']

def test_new_crawler_is_protected_by_local_ranges_before_enrichment(store):
 store.state('crawler_feeds',{'data':{'test-operator':[{'ipv4Prefix':'8.8.4.0/24'}]}})
 store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',10,details={'native_attempt_count':3})
 r=store.describe('8.8.4.4');assert r['score']==100 and r['verified_crawler'] and not r['auto_candidate']

def test_honeypot_labels_and_native_ports_do_not_change_score(store):
 seen=now()
 for source,sensor,family,strength in [('tpot','Cowrie','ssh',10),('owapot','OWA-Honeypot','http',5)]:
  store.evidence('8.8.4.4',source,sensor,seen,family,strength,details={'native_attempt_count':1})
 before=store.describe('8.8.4.4')['score']
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,details={'native_attempt_count':1,'destination_ports':['22','23','0','65536','bad']})
 store.evidence('8.8.4.4','owapot','OWA-Honeypot',seen,'http',5,details={'native_attempt_count':1,'destination_ports':['8088']})
 r=store.describe('8.8.4.4');assert r['score']==before==100 and r['ports']==[22,23,8088]
 assert {d['label']:d['ports'] for d in r['source_details']}=={'T-Pot (Cowrie)':[22,23],'T-Pot (OWAPot)':[8088]}

def test_latest_port_summary_replaces_old_rolling_window_ports(store):
 seen=now();old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=1)).isoformat()
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,'old',{'destination_ports':[22],'native_counter_updated_at':old})
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,'new',{'destination_ports':[23],'native_counter_updated_at':seen})
 assert store.describe('8.8.4.4')['ports']==[23]

@pytest.mark.parametrize('strength,blocked',[(74,False),(75,True),(76,True)])
def test_exact_automatic_block_threshold_without_enrichment(store,strength,blocked):
 store.evidence('8.8.4.4','waf','waf',now(),'http',strength)
 r=store.describe('8.8.4.4');assert r['score']==strength and r['auto_candidate']==blocked

def test_expired_honeypot_does_not_raise_current_other_source(store):
 store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',0)
 old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).isoformat()
 with store.connect() as d:d.execute('update evidence set seen=?',(old,))
 store.evidence('8.8.4.4','nginx','nginx',now(),'http',10)
 r=store.describe('8.8.4.4');assert r['score']==10 and not r['auto_candidate']

@pytest.mark.skipif(os.name=='nt',reason='Linux publication check')
def test_honeypot_floor_keeps_whitelist_and_verified_crawler_protection(store,tmp_path):
 for address in ['8.8.8.8','8.8.4.4','9.9.9.9']:store.evidence(address,'tpot','honeypot',now(),'http',0,details={'native_attempt_count':2})
 store.add_rule('allow','8.8.8.0/24','Business exception',None,'admin')
 store.cache('8.8.4.4','crawler',{'verified':True})
 out=tmp_path/'lists';m=store.build(out)
 assert (out/'current'/'scored-block.txt').read_text()=='9.9.9.9\n'
 assert m['scoring_policy']['block_threshold']==75
def test_rule_requirements_expiry_and_emergency(store):
 with pytest.raises(ValueError):store.add_rule('allow','8.8.8.8','',None,'admin')
 with pytest.raises(ValueError):store.add_rule('block','8.8.8.0/24','test',None,'admin',True)
 with pytest.raises(ValueError):store.add_rule('block','8.8.8.8','test','2020-01-01T00:00:00+00:00','admin')
 id=store.add_rule('allow','AS8075','Business dependency',None,'admin');assert len(store.active_rules())==1
 store.disable_rule(id,'admin');assert not store.active_rules()
def test_expired_native_event_rejected(store):
 store.evidence('8.8.8.8','tpot','Cowrie',(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).isoformat(),'ssh',75)
 assert not store.all_scores()

def test_recent_metadata_cannot_keep_expired_evidence_active(store):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75)
 old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=31)).isoformat()
 with store.connect() as d:d.execute('update evidence set seen=?',(old,))
 store.cache('8.8.8.8','palo',{'alert_records':999})
 assert not store.all_scores()
def test_table_sort_filter_and_paging(tmp_path,monkeypatch):
 from flask import template_rendered
 cfg={'session_secret':'test-secret','database':str(tmp_path/'browse.sqlite3'),'output':str(tmp_path/'output'),'providers_file':str(tmp_path/'providers.json'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 import app as app_module
 clock=[100.0];monkeypatch.setattr(app_module.time,'monotonic',lambda:clock[0])
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('admin',generate_password_hash('test-password-long')))
 app.store.all_scores=lambda:[{'ip':'8.8.8.'+str(i),'asn':str(100+i),'organization':'Search operator' if i%2 else 'Cloud operator','sources':['owapot' if i%2 else 'tpot'],'score':i,'auto_candidate':i>=80,'verified_crawler':i==1} for i in range(1,121)]
 app.store.add_rule('allow','8.8.8.8','Search dependency',None,'admin')
 app.store.add_rule('block','9.9.9.9','Incident',None,'admin')
 c=app.test_client()
 with c.session_transaction() as sess:sess.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+1800)
 contexts=[]
 def capture(sender,template,context,**extra):contexts.append(context)
 template_rendered.connect(capture,app)
 try:
  def get(query):
   clock[0]+=16
   r=c.get('/?'+query,base_url='https://localhost');assert r.status_code==200
   return contexts[-1],r.data
  ctx,html=get('sort=ip&direction=asc&page=2&size=25')
  assert ctx['evidence']['rows'][0]['ip']=='8.8.8.26'
  assert ctx['evidence']['pages']==5 and len(ctx['evidence']['rows'])==25
  assert b'>First</a>' in html and b'>Last</a>' in html and b'<button>Go</button>' in html
  ctx,html=get('f_sources=owapot&f_asn=Search&min_score=80&max_score=100&sort=score&direction=desc&page=999')
  assert [r['score'] for r in ctx['evidence']['rows']]==list(range(99,80,-2))
  assert ctx['evidence']['page']==1
  with app.test_request_context():assert 'f_sources=owapot' in ctx['table_url'](ctx['evidence'],page=1)
  ctx,html=get('f_policy=Allowed&f_asn=Search&sort=asn')
  assert ctx['evidence']['total']==1 and ctx['evidence']['rows'][0]['score']==1
  ctx,html=get('f_ip=no-match&page=-2')
  assert ctx['evidence']['page']==1 and ctx['evidence']['pages']==1 and ctx['evidence']['start']==0
  assert b'No addresses match' in html
  ctx,html=get('sort=invalid&direction=invalid&page=bad&size=1000000&min_score=bad')
  assert ctx['evidence']['size']==50 and ctx['evidence']['page']==1 and ctx['evidence']['sort']=='score'
  ctx,html=get('f_policy=Allowed&f_ip=8.8.8.8')
  assert ctx['evidence']['total']==1 and ctx['evidence']['rows'][0]['policy']=='Allowed'
  assert b'Active policy rules' not in html
  samples=app.store.all_scores();samples[-1]['sources']=['owapot-extra'];samples[-1]['asn']='1010';app.store.all_scores=lambda:samples
  ctx,html=get('f_sources=owapot&size=25&page=2')
  assert ctx['evidence']['total']==60
  assert re.search(br'<select[^>]*name="f_sources"',html) and b'list="asn-suggestions"' in html
  assert b'<option value="owapot" selected>' in html and b'<option value="owapot-extra"' in html
  assert b'<option value="AS101 Search operator"' in html
  ctx,html=get('f_asn=AS101+Search+operator&f_policy=Allowed')
  assert ctx['evidence']['total']==1 and ctx['evidence']['rows'][0]['ip']=='8.8.8.1'
  ctx,html=get('f_asn=AS101')
  assert ctx['evidence']['total']==1 and ctx['evidence']['rows'][0]['asn']=='101'
  ctx,html=get('f_policy=Evaluating')
  assert all(r['policy']=='Evaluating' for r in ctx['evidence']['rows'])
  ctx,html=get('f_asn=Search')
  assert ctx['evidence']['total']==60 and b'name="f_asn" value="Search"' in html
  samples[1].update(ports=[22],source_labels=['T-Pot (Cowrie)'],source_details=[{'source':'tpot','sensor':'Cowrie','label':'T-Pot (Cowrie)','ports':[22]}])
  samples[-1]['ports']=[2222]
  ctx,html=get('f_ports=22')
  assert ctx['evidence']['total']==1 and ctx['evidence']['rows'][0]['ip']=='8.8.8.2'
  assert b'T-Pot (Cowrie)' in html and b'Destination ports' in html
  ctx,html=get('f_sources=tpot%3ACowrie')
  assert ctx['evidence']['total']==1 and ctx['evidence']['rows'][0]['ports']==[22]
  expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=1)).isoformat()
  for i,row in enumerate(samples,1):
   row['cache']={'asn':{'asn':row['asn']},'misp':{'matches':int(i%2==1)},'palo':{'alert_records':int(i%3==0)}}
   row['cache_status']=[{'provider':p,'status':'ok','expires':expires} for p in row['cache']]
  ctx,html=get('f_enrichment_sources=MISP&f_enrichment_sources=Palo&size=25&page=2')
  assert ctx['evidence']['total']==80 and len(ctx['evidence']['rows'])==25
  assert ctx['evidence']['state']['f_enrichment_sources']==['MISP','Palo']
  assert all('MISP' in r['enrichment_sources'] or 'Palo' in r['enrichment_sources'] for r in ctx['evidence']['rows'])
  assert b'name="f_enrichment_sources" value="MISP" checked' in html and b'name="f_enrichment_sources" value="Palo" checked' in html
  # Hidden controls and navigation retain both values, instead of a serialized list.
  assert b'type="hidden" name="f_enrichment_sources" value="MISP"' in html
  assert b'type="hidden" name="f_enrichment_sources" value="Palo"' in html
  with app.test_request_context():
   link=ctx['table_url'](ctx['evidence'],sort='enrichment_sources',page=1)
   assert 'f_enrichment_sources=MISP' in link and 'f_enrichment_sources=Palo' in link
  ctx,html=get('f_enrichment_sources=MISP&f_enrichment_sources=Palo&f_sources=tpot')
  assert ctx['evidence']['total']==79
  ctx,html=get('f_enrichment_sources=')
  assert ctx['evidence']['total']==121 and b'All sources</span>' in html
  ctx,html=get('f_enrichment_sources=unavailable')
  assert ctx['evidence']['total']==0
  assert b'Unavailable source: unavailable' in html
  samples[0]['cache_status'][1]['expires']='2000-01-01T00:00:00+00:00'
  ctx,html=get('f_enrichment_sources=MISP&f_ip=8.8.8.1&sort=enrichment_sources')
  assert '8.8.8.1' not in {r['ip'] for r in ctx['evidence']['rows']}
 finally:template_rendered.disconnect(capture,app)

def test_auth_csrf_and_audit(tmp_path):
 cfg={'session_secret':'test-secret','database':str(tmp_path/'ui.sqlite3'),'output':str(tmp_path/'output'),'providers_file':str(tmp_path/'providers.json'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True;s=app.store
 with s.connect() as d:d.execute('insert into users values(?,?,1)',('admin',generate_password_hash('test-password-long')))
 c=app.test_client();assert c.get('/',base_url='https://localhost').status_code==302
 c.get('/login',base_url='https://localhost')
 with c.session_transaction() as sess:csrf=sess['csrf']
 assert c.post('/login',data={'username':'admin','password':'test-password-long'},base_url='https://localhost').status_code==400
 assert c.post('/login',data={'csrf':csrf,'username':'admin','password':'test-password-long'},base_url='https://localhost').status_code==302
 r=c.get('/',base_url='https://localhost');assert r.status_code==200 and b'External dynamic lists' in r.data
 with c.session_transaction() as sess:csrf=sess['csrf']
 assert c.post('/rules',data={'csrf':csrf,'action':'allow','value':'8.8.8.8','reason':'Unit test'},base_url='https://localhost').status_code==302
 assert len(s.active_rules())==1
 assert c.get('/',base_url='https://localhost',environ_overrides={'REMOTE_ADDR':'1.1.1.1'}).status_code==403
 assert 'frame-ancestors' in r.headers['Content-Security-Policy']
@pytest.mark.skipif(os.name=='nt',reason='Production snapshot symlinks are verified on the Linux host')
def test_build_whitelist_emergency_and_asn_observed_scope(store,tmp_path):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75);store.cache('8.8.8.8','asn',{'asn':'15169','organization':'test provider'});store.cache('8.8.8.8','crawler',{'verified':False})
 store.add_rule('block','8.8.8.0/24','test',None,'admin');store.add_rule('allow','8.8.8.20-8.8.8.30','exception',None,'admin')
 out=tmp_path/'lists';m=store.build(out)
 vals=[ipaddress.ip_network(x,strict=False) for x in (out/'current'/'combined-block.txt').read_text().splitlines()]
 assert not any(ipaddress.ip_address('8.8.8.25') in n for n in vals)
 store.add_rule('block','8.8.8.25','emergency',None,'admin',True);store.build(out)
 assert '8.8.8.25' in (out/'current'/'combined-block.txt').read_text().splitlines()
 store.add_rule('allow','AS15169','ASN exception',None,'admin');store.build(out)
 assert '8.8.8.8' in (out/'current'/'manual-allow.txt').read_text().splitlines()


def test_login_cookie_isolation_and_expired_form_recovery(tmp_path):
 import re
 cfg={'session_secret':'test-secret','database':str(tmp_path/'login.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('admin',generate_password_hash('test-password-long')))
 c=app.test_client();c.set_cookie('session','another-application-cookie')
 page=c.get('/login',base_url='https://localhost')
 cookie=page.headers['Set-Cookie']
 assert cookie.startswith('__Host-edl_manager_session=')
 assert 'Secure' in cookie and 'HttpOnly' in cookie and 'Path=/' in cookie and 'SameSite=Strict' in cookie
 old=re.search(rb'name="csrf" value="([^"]+)"',page.data).group(1).decode()
 # A lost cookie or replaced session must reject the old form without authenticating.
 c.delete_cookie('__Host-edl_manager_session')
 rejected=c.post('/login',data={'csrf':old,'username':'admin','password':'test-password-long'},base_url='https://localhost')
 assert rejected.status_code==400 and b'sign-in page expired' in rejected.data
 with c.session_transaction() as sess:assert 'user' not in sess
 fresh=re.search(rb'name="csrf" value="([^"]+)"',rejected.data).group(1).decode()
 assert fresh!=old
 assert c.post('/login',data={'csrf':fresh,'username':'admin','password':'test-password-long'},base_url='https://localhost').status_code==302
 # Login recovery must not weaken protection on any administrative write.
 assert c.post('/logout',data={'csrf':old},base_url='https://localhost').status_code==400
 with c.session_transaction() as sess:assert sess['user']=='admin'


@pytest.mark.parametrize('username',['labadmin','LabAdmin','LABADMIN','LaBaDmIn'])
def test_username_case_insensitive_password_stays_exact(tmp_path,username):
 cfg={'session_secret':'test-secret','database':str(tmp_path/'case.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 password='Case-Sensitive-Password'
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('labadmin',generate_password_hash(password)))
 c=app.test_client();c.get('/login',base_url='https://localhost')
 with c.session_transaction() as sess:csrf=sess['csrf']
 rejected=c.post('/login',data={'csrf':csrf,'username':username,'password':password.swapcase()},base_url='https://localhost')
 assert rejected.status_code==200 and b'Invalid username or password' in rejected.data
 with c.session_transaction() as sess:assert 'user' not in sess
 accepted=c.post('/login',data={'csrf':csrf,'username':username,'password':password},base_url='https://localhost')
 assert accepted.status_code==302
 with c.session_transaction() as sess:assert sess['user']=='labadmin'
 with app.store.connect() as d:assert d.execute("select actor from audit where action='login'").fetchone()[0]=='labadmin'


def test_case_colliding_accounts_fail_closed(tmp_path):
 cfg={'session_secret':'test-secret','database':str(tmp_path/'collision.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:
  for name in ['admin','ADMIN']:d.execute('insert into users values(?,?,1)',(name,generate_password_hash('test-password-long')))
 c=app.test_client();c.get('/login',base_url='https://localhost')
 with c.session_transaction() as sess:csrf=sess['csrf']
 result=c.post('/login',data={'csrf':csrf,'username':'Admin','password':'test-password-long'},base_url='https://localhost')
 assert b'Invalid username or password' in result.data
 with c.session_transaction() as sess:assert 'user' not in sess


@pytest.mark.parametrize('duration',[1800,3600,28800,86400,604800,2592000])
def test_selected_session_duration_and_remembered_username(tmp_path,duration):
 import re
 from email.utils import parsedate_to_datetime
 cfg={'session_secret':'test-secret','database':str(tmp_path/'remember.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('labadmin',generate_password_hash('test-password-long')))
 c=app.test_client();page=c.get('/login',base_url='https://localhost')
 token=re.search(rb'name="csrf" value="([^"]+)"',page.data).group(1).decode()
 before=dt.datetime.now(dt.timezone.utc).timestamp()
 r=c.post('/login',data={'csrf':token,'username':'LABADMIN','password':'test-password-long','remember_username':'on','session_timeout':str(duration)},base_url='https://localhost')
 assert r.status_code==302
 cookie=next(h for h in r.headers.getlist('Set-Cookie') if h.startswith('__Host-edl_manager_session='))
 expiry=parsedate_to_datetime(cookie.split('Expires=')[1].split(';')[0]).timestamp()
 assert duration-2<=expiry-before<=duration+3
 assert 'Secure' in cookie and 'HttpOnly' in cookie and 'SameSite=Strict' in cookie
 with c.session_transaction() as sess:
  deadline=sess['expires_at'];assert duration-1<=deadline-before<=duration+3
  csrf=sess['csrf']
 assert c.get_cookie('__Host-edl_manager_username').value=='labadmin'
 # Viewing a page must not silently extend the chosen absolute timeout.
 again=c.get('/login',base_url='https://localhost')
 assert not any(h.startswith('__Host-edl_manager_session=') for h in again.headers.getlist('Set-Cookie'))
 with c.session_transaction() as sess:assert sess['expires_at']==deadline
 assert c.post('/logout',data={'csrf':csrf},base_url='https://localhost').status_code==302
 page=c.get('/login',base_url='https://localhost')
 assert b'value="labadmin"' in page.data and b'name="remember_username" checked' in page.data
 assert b'name="session_timeout"' not in page.data
 fresh=re.search(rb'name="csrf" value="([^"]+)"',page.data).group(1).decode()
 # Unchecking Remember username removes the previously saved username.
 c.post('/login',data={'csrf':fresh,'username':'labadmin','password':'test-password-long','session_timeout':'unlimited'},base_url='https://localhost')
 assert c.get_cookie('__Host-edl_manager_username') is None
 with c.session_transaction() as sess:
  assert 1798<=sess['expires_at']-dt.datetime.now(dt.timezone.utc).timestamp()<=1801
  sess['expires_at']=dt.datetime.now(dt.timezone.utc).timestamp()-1
 # The server rejects an expired signed session even if a cookie is still sent.
 assert c.get('/',base_url='https://localhost').status_code==302
 with c.session_transaction() as sess:assert 'user' not in sess


def test_remember_options_do_not_save_after_failed_authentication(tmp_path):
 cfg={'session_secret':'test-secret','database':str(tmp_path/'failed.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True;c=app.test_client();c.get('/login',base_url='https://localhost')
 with c.session_transaction() as sess:token=sess['csrf']
 c.post('/login',data={'csrf':token,'username':'unknown','password':'secret','remember_username':'on','session_timeout':'2592000'},base_url='https://localhost')
 assert c.get_cookie('__Host-edl_manager_username') is None
 assert c.get_cookie('__Host-edl_manager_timeout') is None


@pytest.mark.parametrize('duration',[1800,3600,28800,86400,604800,2592000])
def test_settings_timeout_persists_for_account_and_updates_cookie(tmp_path,duration):
 import re
 from email.utils import parsedate_to_datetime
 cfg={'session_secret':'test-secret','database':str(tmp_path/'settings.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('labadmin',generate_password_hash('test-password-long')))
 c=app.test_client();assert c.get('/settings',base_url='https://localhost').status_code==302
 c.get('/login',base_url='https://localhost')
 with c.session_transaction() as sess:csrf=sess['csrf']
 c.post('/login',data={'csrf':csrf,'username':'LABADMIN','password':'test-password-long'},base_url='https://localhost')
 page=c.get('/settings',base_url='https://localhost');assert page.status_code==200
 assert b'action="/password"' in page.data and b'System settings' in page.data
 with c.session_transaction() as sess:csrf=sess['csrf'];original=sess['expires_at']
 assert c.post('/settings',data={'session_timeout':duration},base_url='https://localhost').status_code==400
 assert app.store.state('user_preferences:labadmin') is None
 assert c.post('/settings',data={'csrf':csrf,'session_timeout':'unlimited'},base_url='https://localhost').status_code==400
 with c.session_transaction() as sess:assert sess['expires_at']==original
 before=dt.datetime.now(dt.timezone.utc).timestamp()
 saved=c.post('/settings',data={'csrf':csrf,'session_timeout':duration},base_url='https://localhost')
 assert saved.status_code==302 and saved.headers['Location'].endswith('/settings')
 assert app.store.state('user_preferences:labadmin')['session_timeout']==duration
 cookie=next(h for h in saved.headers.getlist('Set-Cookie') if h.startswith('__Host-edl_manager_session='))
 expiry=parsedate_to_datetime(cookie.split('Expires=')[1].split(';')[0]).timestamp()
 assert duration-2<=expiry-before<=duration+3
 page=c.get('/settings',base_url='https://localhost')
 assert ('value="'+str(duration)+'" selected').encode() in page.data
 # A different browser with no preference cookie must use the saved account setting.
 other=app.test_client();other.get('/login',base_url='https://localhost')
 with other.session_transaction() as sess:csrf=sess['csrf']
 other.post('/login',data={'csrf':csrf,'username':'LabAdmin','password':'test-password-long'},base_url='https://localhost')
 with other.session_transaction() as sess:assert duration-2<=sess['expires_at']-dt.datetime.now(dt.timezone.utc).timestamp()<=duration+1


def test_password_change_under_settings_preserves_authentication_checks(tmp_path):
 cfg={'session_secret':'test-secret','database':str(tmp_path/'password.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('admin',generate_password_hash('test-password-long')))
 c=app.test_client();c.get('/login',base_url='https://localhost')
 with c.session_transaction() as sess:csrf=sess['csrf']
 c.post('/login',data={'csrf':csrf,'username':'admin','password':'test-password-long'},base_url='https://localhost')
 with c.session_transaction() as sess:csrf=sess['csrf']
 assert c.post('/password',data={'current':'test-password-long','new':'new-test-password-long'},base_url='https://localhost').status_code==400
 rejected=c.post('/password',data={'csrf':csrf,'current':'wrong','new':'new-test-password-long'},base_url='https://localhost')
 assert rejected.headers['Location'].endswith('/settings#password-settings')
 assert c.get('/settings',base_url='https://localhost').status_code==200
 changed=c.post('/password',data={'csrf':csrf,'current':'test-password-long','new':'new-test-password-long'},base_url='https://localhost')
 assert changed.headers['Location'].endswith('/login')
 assert c.get('/settings',base_url='https://localhost').status_code==302
 with app.store.connect() as d:
  from werkzeug.security import check_password_hash
  row=d.execute('select * from users where name=?',('admin',)).fetchone()
  assert row['version']==2 and check_password_hash(row['password_hash'],'new-test-password-long')



def test_dashboard_cache_expires_and_mutations_invalidate_it(tmp_path,monkeypatch):
 import app as app_module
 cfg={'session_secret':'test-secret','database':str(tmp_path/'display.sqlite3'),'hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:d.execute('insert into users values(?,?,1)',('admin',generate_password_hash('test-password-long')))
 clock=[100.0];calls=[]
 monkeypatch.setattr(app_module.time,'monotonic',lambda:clock[0])
 app.store.all_scores=lambda:(calls.append(clock[0]) or [])
 c=app.test_client()
 with c.session_transaction() as sess:sess.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+1800,csrf='test-csrf')
 assert c.get('/',base_url='https://localhost').status_code==200
 assert c.get('/?page=2',base_url='https://localhost').status_code==200
 assert len(calls)==1
 clock[0]+=16
 assert c.get('/',base_url='https://localhost').status_code==200
 assert len(calls)==2
 c.post('/rules',data={'csrf':'test-csrf','action':'allow','value':'8.8.8.8','reason':'Cache invalidation test'},base_url='https://localhost')
 assert c.get('/',base_url='https://localhost').status_code==200
 assert len(calls)==3


@pytest.mark.parametrize('sensors,ports,counts,expected',[
 (['Cowrie'],[[22]],[1],50),(['Cowrie'],[[22]],[2],75),(['Cowrie'],[[22]],[3],100),
 (['Cowrie','Dionaea'],[[22],[445]],[1,1],100),(['Cowrie'],[[22,23]],[2],100),
 (['Cowrie','OWAPot'],[[22],[8088]],[1,1],100),(['Cowrie'],[[]],[2],75)])
def test_attempts_and_independent_honeypot_ports(store,sensors,ports,counts,expected):
 for sensor,values,count in zip(sensors,ports,counts):
  store.evidence('8.8.4.4','tpot',sensor,now(),'http',5,details={'detector':sensor,'native_event_count':99,'native_attempt_count':count,'destination_ports':values})
 row=store.describe('8.8.4.4');assert row['score']==expected
 assert row['honeypot_attempts']==sum(counts)
 assert row['auto_candidate']==(expected>=75)


def test_port_corrections_and_owa_aliases_do_not_double_count(store):
 seen=now();old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=1)).isoformat()
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,'old',{'native_attempt_count':2,'destination_ports':[22,23],'native_counter_updated_at':old})
 store.evidence('8.8.4.4','tpot','Cowrie',seen,'ssh',10,'new',{'native_attempt_count':1,'destination_ports':[22],'native_counter_updated_at':seen})
 assert store.describe('8.8.4.4')['score']==50
 store.evidence('8.8.8.8','tpot','OWAPot',seen,'http',5,details={'native_attempt_count':1,'destination_ports':[8088]})
 store.evidence('8.8.8.8','owapot','OWA-Honeypot',seen,'http',5,details={'native_attempt_count':1,'destination_ports':[8088]})
 assert store.describe('8.8.8.8')['score']==50



def test_enrichment_details_and_multiple_sources_are_preserved(store):
 for source,sensor in [('tpot','Cowrie'),('nginx','sensitive-path-probe'),('waf','coraza-interruption'),('crowdsec','http-probing')]:
  store.evidence('8.8.4.4',source,sensor,now(),'http',25,details={'native_attempt_count':1,'destination_ports':[22 if source=='tpot' else 443]})
 store.cache('8.8.4.4','misp',{'matches':2,'sources':['ThreatFox','CIRCL']})
 store.cache('8.8.4.4','palo',{'alert_records':9})
 row=store.describe('8.8.4.4')
 assert row['source_count']==4 and row['honeypot_count']==1
 assert set(row['sources'])=={'tpot','nginx','waf','crowdsec'}
 assert 'MISP: 2 actionable' in row['enrichment_text'] and 'Palo: 9 drop / deny records' in row['enrichment_text']
 assert {e['provider'] for e in row['enrichment_details']}=={'misp','palo'}



def test_block_retention_renews_from_native_activity_not_poll_time(store):
 address='8.8.4.4';past=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=5)).isoformat(timespec='seconds')
 expires=(dt.datetime.fromisoformat(past)+dt.timedelta(days=30)).isoformat(timespec='seconds')
 with store.connect() as d:
  d.execute('insert into ips(ip,first_seen,last_seen) values(?,?,?)',(address,past,past))
  d.execute('insert into block_retention values(?,?,?,?,?,?,?)',(address,past,past,expires,'tpot',75,'{"sources":["tpot"],"source_details":[]}'))
 observed=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=1)).isoformat(timespec='seconds')
 assert store.renew_block(address,observed,'palo')
 row=store.describe(address);deadline=row['retention']['expires']
 assert deadline==(dt.datetime.fromisoformat(observed)+dt.timedelta(days=30)).isoformat(timespec='seconds')
 assert row['score']==75 and row['auto_candidate'] and row['score_breakdown']['palo_drop_bonus']==0
 assert not store.renew_block(address,observed,'palo')
 assert store.describe(address)['retention']['expires']==deadline
 with store.connect() as d:assert d.execute('select last_seen from ips where ip=?',(address,)).fetchone()[0]==past
 assert not store.renew_block('9.9.9.9',observed,'palo')
 assert '9.9.9.9' not in {r['ip'] for r in store.all_scores()}
 store.evidence(address,'nginx','sensitive-path-probe',now(),'http',50)
 row=store.describe(address);assert row['retention']['last_source']=='nginx' and row['retention']['expires']>deadline


def test_expired_blocks_and_pre_block_palo_events_cannot_renew(store):
 address='8.8.4.4';old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=40)).isoformat(timespec='seconds')
 expiry=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=10)).isoformat(timespec='seconds')
 with store.connect() as d:
  d.execute('insert into ips(ip,first_seen,last_seen) values(?,?,?)',(address,old,old))
  d.execute('insert into block_retention values(?,?,?,?,?,?,?)',(address,old,old,expiry,'tpot',75,'{}'))
 assert not store.renew_block(address,now(),'palo')
 assert not store.all_scores()
 assert not store.describe(address)['auto_candidate']
 with store.connect() as d:d.execute('update block_retention set first_blocked=?,expires=? where ip=?',(now(),(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=30)).isoformat(),address))
 before=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=1)).isoformat()
 assert not store.renew_block(address,before,'palo')


@pytest.mark.skipif(os.name=='nt',reason='Linux list publication')
def test_retention_still_excludes_verified_crawlers_and_whitelisted_ips(store,tmp_path):
 address='8.8.4.4';seen=now();expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=30)).isoformat()
 with store.connect() as d:
  d.execute('insert into ips(ip,first_seen,last_seen) values(?,?,?)',(address,seen,seen))
  d.execute('insert into block_retention values(?,?,?,?,?,?,?)',(address,seen,seen,expires,'palo',75,'{}'))
 assert store.build(tmp_path/'lists')['counts']['scored-block']==1
 store.add_rule('allow',address,'Dependency',None,'admin')
 assert store.build(tmp_path/'lists')['counts']['scored-block']==0
 store.cache(address,'crawler',{'verified':True})
 assert not store.describe(address)['auto_candidate']

def test_legacy_raw_log_count_does_not_inflate_attempts(store):
 store.evidence('8.8.4.4','tpot','Cowrie',now(),'ssh',10,details={'native_event_count':1000})
 assert store.describe('8.8.4.4')['score']==50

@pytest.mark.skipif(os.name=='nt',reason='Linux list publication')
def test_new_native_attack_can_start_a_new_block_after_expiry(store,tmp_path):
 address='8.8.4.4';old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=40)).isoformat(timespec='seconds')
 expired=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=10)).isoformat(timespec='seconds')
 with store.connect() as d:
  d.execute('insert into ips(ip,first_seen,last_seen) values(?,?,?)',(address,old,old))
  d.execute('insert into block_retention values(?,?,?,?,?,?,?)',(address,old,old,expired,'tpot',75,'{}'))
 seen=now();store.evidence(address,'tpot','Cowrie',seen,'ssh',10,details={'native_attempt_count':2})
 assert store.build(tmp_path/'lists')['counts']['scored-block']==1
 retained=store.describe(address)['retention']
 assert retained and retained['last_seen']==seen and retained['first_blocked']>old
 assert retained['expires']==(dt.datetime.fromisoformat(seen)+dt.timedelta(days=30)).isoformat(timespec='seconds')

@pytest.mark.skipif(os.name=='nt',reason='Linux worker')
def test_misp_snapshot_matches_composite_ip_locally_and_reuses_cache(store,tmp_path,monkeypatch):
 import worker
 class Database:
  def __enter__(self):return self
  def __exit__(self,*args):pass
  def get(self,address):return {'autonomous_system_number':15169,'autonomous_system_organization':'Test owner'}
  def metadata(self):
   return type('Metadata',(),{'build_epoch':dt.datetime.now(dt.timezone.utc).timestamp()})()
 monkeypatch.setattr(worker.maxminddb,'open_database',lambda path:Database())
 monkeypatch.setattr(worker.requests.Session,'post',lambda *args,**kwargs:pytest.fail('Fresh snapshot must not query a remote provider'))
 expiry=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=1)).isoformat()
 store.evidence('8.8.4.4','nginx','sensitive-path-probe',now(),'http',50)
 store.evidence('9.9.9.9','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':1})
 store.cache('8.8.4.4','misp',{'matches':0,'snapshot_generation':'old'})
 store.state('crawler_feeds',{'fetched':now(),'expires':expiry,'providers':{}})
 store.state('misp_snapshot',{'fetched':now(),'expires':expiry,'generation':'new','attributes':[{'value':'8.8.4.4|443','id':'1','source':'Test intelligence'},{'value':'9.9.9.0/24','id':'2','source':'Context network','to_ids':False},{'value':'9.9.9.9','id':'3','source':'Context address','to_ids':False}]})
 keys=tmp_path/'keys.json';keys.write_text('{"misp":"test-only-key"}')
 cfg={'providers_file':str(keys),'database':str(store.path),'asn_database':'unused','misp_url':'https://misp.example.test','crawler_feed_file':str(tmp_path/'no-feeds.json')}
 worker.enrich(store,cfg);payload=json.loads(store.cached('8.8.4.4','misp')['payload'])
 assert payload['matches']==1 and payload['sources']==['Test intelligence']
 assert store.describe('8.8.4.4')['score']==75
 contextual=json.loads(store.cached('9.9.9.9','misp')['payload'])
 assert contextual['matches']==0 and contextual['context_matches']==2 and contextual['score_contribution']==0
 assert store.describe('9.9.9.9')['score']==50 and not store.describe('9.9.9.9')['auto_candidate']
 with store.connect() as d:before=dict(d.execute("select * from cache where ip='8.8.4.4' and provider='misp'").fetchone())
 worker.enrich(store,cfg)
 with store.connect() as d:after=dict(d.execute("select * from cache where ip='8.8.4.4' and provider='misp'").fetchone())
 assert before==after
