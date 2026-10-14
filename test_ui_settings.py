import datetime as dt
import pytest
import re
from html.parser import HTMLParser
class Inputs(HTMLParser):
 def __init__(self,text):super().__init__();self.stack=[];self.fields={};self.feed(text)
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag=="input" and a.get("name") and a.get("type")!="hidden":self.fields[a["name"]]=(a,list(self.stack))
  if tag not in ["input","br","meta","link","hr"]:self.stack.append(tag)
 def handle_endtag(self,tag):
  if tag in self.stack:self.stack=self.stack[:len(self.stack)-1-self.stack[::-1].index(tag)]
def body_rows(text):return re.findall(r"<tr>",text.split("<tbody>")[1].split("</tbody>")[0])
from app import create_app
from core import now
from source_settings import effective,validate
from werkzeug.datastructures import MultiDict

@pytest.fixture
def ui(tmp_path):
 cfg={'database':str(tmp_path/'db'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'test','hosts':['localhost']}
 app=create_app(cfg);app.testing=True
 with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 c=app.test_client()
 with c.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 return app,c,cfg

def test_manual_count_and_all_metric_results_are_exact_and_paged(ui):
 app,c,cfg=ui;s=app.store
 for n in range(1,32):s.add_rule('block','8.8.8.'+str(n),'Incident '+str(n),None,'admin')
 s.add_rule('allow','9.9.9.9','Dependency',None,'admin')
 expired=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=1)).isoformat()
 s.add_rule('block','1.1.1.1','Expired',None,'admin')
 with s.connect() as d:d.execute("UPDATE rules SET expires=? WHERE value='1.1.1.1'",(expired,))
 s.evidence('8.8.8.100','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':2})
 s.cache('8.8.8.100','crawler',{'verified':False})
 html=c.get('/',base_url='https://localhost').text
 assert html.count('data-results-modal href=')==13
 assert re.search(r'href="/results/blacklisted".*?<strong>31</strong>',html)
 r=c.get('/results/blacklisted?m_size=25&m_page=2',base_url='https://localhost',headers={'X-EDL-Modal':'1'})
 assert r.status_code==200
 assert len(body_rows(r.text))==6 and 'of 31 matches' in r.text and 'Expired' not in r.text
 assert '<html' not in r.text
 r=c.get('/results/blacklisted?m_f_reason=Incident+31',base_url='https://localhost');assert len(body_rows(r.text))==1
 for key in ['total','candidate','crawler','policy']:assert c.get('/results/'+key,base_url='https://localhost').status_code==200
 assert app.test_client().get('/results/blacklisted',base_url='https://localhost').status_code==302

def test_header_controls_and_optional_sources_do_not_break_paging(ui):
 app,c,cfg=ui;s=app.store
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 s.cache('8.8.8.8','crawler',{'verified':False})
 soup=Inputs(c.get('/',base_url='https://localhost').text)
 field,parents=soup.fields['f_ip'];assert 'th' in parents and field['form']=='evidence-filters'
 assert 'form' not in parents
 payload=MultiDict([('csrf','csrf'),('index_url',''),('misp_url',''),('palo_location',''),('source_tpot',''),('source_owapot',''),('fields','ports')])
 assert c.post('/settings/sources',data=payload,base_url='https://localhost').status_code==302
 assert s.describe('8.8.8.8')['sources']==[]
 assert effective(s,cfg)['index_url']=='' and not any(effective(s,cfg)['source_agents'].values())
 soup=Inputs(c.get('/?sort=asn&f_asn=AS15169',base_url='https://localhost').text)
 assert 'f_asn' not in soup.fields and 'name="f_ports"' in c.get('/',base_url='https://localhost').text
 assert c.get('/ip/8.8.8.8',base_url='https://localhost').status_code==200
 settings=c.get('/settings',base_url='https://localhost').text
 assert 'Servers and collected data' in settings and '<pre' not in settings and 'session_secret' not in settings
 # Malformed endpoints cannot overwrite saved settings.
 r=c.post('/settings/sources',data={'csrf':'csrf','index_url':'http://insecure'},base_url='https://localhost');assert r.status_code==302 and effective(s,cfg)['index_url']==''
 assert c.post('/settings/sources',data={'index_url':'https://other'},base_url='https://localhost').status_code==400

@pytest.mark.skipif(__import__('os').name=='nt',reason='Production collector runs on Linux')
def test_blank_index_skips_collection_without_connection(ui,monkeypatch):
 from worker import collect
 app,c,cfg=ui
 c.post('/settings/sources',data={'csrf':'csrf'},base_url='https://localhost')
 monkeypatch.setattr('worker.requests.Session',lambda:pytest.fail('Disabled index should not connect'))
 assert collect(app.store,cfg)==0

def test_misp_server_change_invalidates_prior_intelligence_but_keeps_crawler_protection(ui):
 app,c,cfg=ui;s=app.store
 s.cache('8.8.8.8','misp',{'matches':3})
 s.cache('8.8.8.8','crawler',{'verified':True})
 s.state('misp_snapshot',{'generation':'old'})
 data={'csrf':'csrf','index_url':'https://indexer:9200','misp_url':'https://new-misp','misp_sha256':'a'*64,'source_tpot':'*','fields':['asn']}
 assert c.post('/settings/sources',data=data,base_url='https://localhost').status_code==302
 assert s.cached('8.8.8.8','misp') is None and s.cached('8.8.8.8','crawler') is not None
 assert s.state('misp_snapshot')=={} and effective(s,cfg)['misp_sha256']=='a'*64
 data['misp_sha256']='not-a-fingerprint'
 c.post('/settings/sources',data=data,base_url='https://localhost')
 assert effective(s,cfg)['misp_sha256']=='a'*64

@pytest.mark.parametrize('action',['allow','block'])
def test_ip_details_policy_saves_notes_for_exact_ip_with_actor_and_csrf(ui,action):
 app,c,cfg=ui;s=app.store
 note='User ticket INC-123\nVerified by owner <script>alert(1)</script>'
 result=c.post('/ip/8.8.8.8/policy',data={'csrf':'csrf','action':action,'reason':note,'value':'9.9.9.9','expires':'2099-01-01T12:00'},base_url='https://localhost')
 assert result.status_code==302 and result.headers['Location']=='/ip/8.8.8.8#ip-policy'
 rules=s.active_rules();assert len(rules)==1
 rule=rules[0];assert rule['value']=='8.8.8.8' and rule['action']==action and rule['actor']=='admin' and rule['reason']==note
 assert rule['expires']=='2099-01-01T12:00:00+00:00'
 page=c.get('/ip/8.8.8.8',base_url='https://localhost').text
 assert 'Save whitelist' in page and 'Save blacklist' in page and 'Related rules and notes' in page and 'INC-123' in page
 assert '<script>alert(1)</script>' not in page and '&lt;script&gt;alert(1)&lt;/script&gt;' in page
 with s.connect() as d:assert d.execute("SELECT COUNT(*) FROM audit WHERE action='rule.add'").fetchone()[0]==1
 assert c.post('/ip/8.8.8.8/policy',data={'action':action,'reason':'No CSRF'},base_url='https://localhost').status_code==400
 assert app.test_client().post('/ip/8.8.8.8/policy',data={'action':action,'reason':'Not logged in','csrf':'csrf'},base_url='https://localhost').status_code==400
 assert len(s.active_rules())==1

@pytest.mark.parametrize('notes',['','   ','x'*1001])
def test_invalid_ip_policy_notes_do_not_create_rule(ui,notes):
 app,c,cfg=ui
 result=c.post('/ip/8.8.8.8/policy',data={'csrf':'csrf','action':'block','reason':notes},base_url='https://localhost')
 assert result.status_code==302 and not app.store.active_rules()
 assert c.post('/ip/10.0.0.1/policy',data={'csrf':'csrf','action':'block','reason':'Private address'},base_url='https://localhost').status_code==400

@pytest.mark.parametrize('value',['8.8.8.0/24','8.8.8.1-8.8.8.20'])
def test_blacklist_notes_for_subnets_and_ranges_visible_on_member_ip(ui,value):
 app,c,cfg=ui
 note='Incident 42\nMultiple attacking addresses'
 assert c.post('/rules',data={'csrf':'csrf','action':'block','value':value,'reason':note},base_url='https://localhost').status_code==302
 page=c.get('/ip/8.8.8.8',base_url='https://localhost').text
 assert 'Incident 42' in page and 'Multiple attacking addresses' in page and value in page and 'Active' in page

@pytest.mark.skipif(__import__('os').name=='nt',reason='Atomic EDL publication runs on Linux')
def test_details_whitelist_removes_scored_ip_and_notes_do_not_leak_to_edl(ui):
 app,c,cfg=ui;s=app.store
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':2})
 s.cache('8.8.8.8','crawler',{'verified':False})
 s.build(cfg['output']);output=__import__('pathlib').Path(cfg['output'])/'current'/'combined-block.txt'
 assert output.read_text()=='8.8.8.8\n'
 c.post('/ip/8.8.8.8/policy',data={'csrf':'csrf','action':'allow','reason':'INC-123 customer exception'},base_url='https://localhost')
 s.build(cfg['output']);assert output.read_text()==''
 assert 'INC-123' not in (__import__('pathlib').Path(cfg['output'])/'current'/'manual-allow.txt').read_text()

def test_bulk_whitelist_saves_shared_comments_atomically_and_deduplicates(ui):
 app,c,cfg=ui;s=app.store
 payload=MultiDict([('csrf','csrf'),('addresses','8.8.8.8'),('addresses','9.9.9.9'),('addresses','8.8.8.8/32'),('reason','INC-456\nConfirmed customer addresses'),('expires','2099-01-01T10:00'),('action','block')])
 response=c.post('/rules/bulk-whitelist',data=payload,base_url='https://localhost')
 assert response.status_code==302 and response.headers['Location']=='/#ip-evidence'
 rules=s.active_rules();assert len(rules)==2
 assert {r['value'] for r in rules}=={'8.8.8.8','9.9.9.9'}
 assert all(r['action']=='allow' and r['actor']=='admin' and r['reason']=='INC-456\nConfirmed customer addresses' and r['expires']=='2099-01-01T10:00:00+00:00' for r in rules)
 with s.connect() as d:assert d.execute("SELECT COUNT(*) FROM audit WHERE action='rule.add'").fetchone()[0]==2
 assert 'INC-456' in c.get('/ip/9.9.9.9',base_url='https://localhost').text
 assert c.post('/rules/bulk-whitelist',data={'addresses':'1.1.1.1','reason':'Missing CSRF'},base_url='https://localhost').status_code==400
 assert len(s.active_rules())==2

@pytest.mark.parametrize('addresses',[[],['8.8.8.8','10.0.0.1'],['8.8.8.0/24'],['8.8.8.1-8.8.8.3']])
def test_bulk_whitelist_invalid_selection_writes_no_rules(ui,addresses):
 app,c,cfg=ui
 data=MultiDict([('csrf','csrf'),('reason','Customer issue')]+[('addresses',v) for v in addresses])
 assert c.post('/rules/bulk-whitelist',data=data,base_url='https://localhost').status_code==302
 assert not app.store.active_rules()

@pytest.mark.parametrize('notes',['','x'*1001])
def test_bulk_whitelist_requires_valid_comments(ui,notes):
 app,c,cfg=ui
 c.post('/rules/bulk-whitelist',data={'csrf':'csrf','addresses':'8.8.8.8','reason':notes},base_url='https://localhost')
 assert not app.store.active_rules()

def test_bulk_whitelist_transaction_rolls_back_on_audit_storage_failure(ui):
 import sqlite3
 app,c,cfg=ui;s=app.store
 with s.connect() as d:d.execute("CREATE TRIGGER fail_second_audit BEFORE INSERT ON audit WHEN json_extract(NEW.details,'$.value')='9.9.9.9' BEGIN SELECT RAISE(ABORT,'Audit unavailable'); END")
 with pytest.raises(sqlite3.IntegrityError):s.add_rules('allow',['8.8.8.8','9.9.9.9'],'Customer exception',None,'admin')
 assert not s.active_rules()
 with s.connect() as d:assert d.execute('SELECT COUNT(*) FROM audit').fetchone()[0]==0

def test_bulk_whitelist_selection_controls_only_include_current_page(ui):
 app,c,cfg=ui;s=app.store
 for n in range(1,31):s.evidence('8.8.8.'+str(n),'tpot','Cowrie',now(),'ssh',50)
 html=c.get('/?size=25&page=2',base_url='https://localhost').text
 assert html.count('data-ip-selection aria-label=')==5
 assert html.count('form="bulk-whitelist" name="addresses"')==5
 assert 'data-select-page' in html and 'ip-selection.js' in html and 'Comments / reason' in html
 assert 'name="reason" rows="2" maxlength="1000" required' in html

def test_bulk_whitelist_rejects_more_than_one_page_of_entries(ui):
 app,c,cfg=ui;s=app.store
 with pytest.raises(ValueError,match='250'):s.add_rules('allow',['8.8.4.'+str(n) for n in range(252)],'Too many',None,'admin')
 assert not s.active_rules()

def test_production_pages_remove_review_mode_and_preview_labels(ui):
 app,c,cfg=ui
 for path in ['/login','/','/settings','/ip/8.8.8.8']:
  html=c.get(path,base_url='https://localhost').text
  assert 'REVIEW MODE' not in html and 'Build list preview' not in html and 'List preview' not in html
 dashboard=c.get('/',base_url='https://localhost').text
 assert 'Rebuild lists' in dashboard and 'Published lists' in dashboard

@pytest.mark.skipif(__import__('os').name=='nt',reason='Atomic production publication runs on Linux')
def test_production_generation_and_build_audit_preserve_whitelist_and_crawler_safety(ui):
 app,c,cfg=ui;s=app.store
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':2})
 s.evidence('9.9.9.9','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':2})
 s.cache('9.9.9.9','crawler',{'verified':True})
 s.add_rule('allow','8.8.8.8','Customer exception',None,'admin')
 r=c.post('/build',data={'csrf':'csrf'},base_url='https://localhost');assert r.status_code==302
 m=s.state('latest_build');assert m['mode']=='production' and m['palo_policy_managed'] is False
 assert m['counts']['combined-block']==0 and m['counts']['manual-allow']==1 and m['counts']['protected-crawlers']==1
 with s.connect() as d:assert d.execute("SELECT COUNT(*) FROM audit WHERE action='lists.build'").fetchone()[0]==1
