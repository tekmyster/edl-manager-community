from behavior_grounding import mapping_text
"""Isolated synthetic contracts; fixtures are not production accuracy labels."""
import copy
import hashlib
import json
import pathlib
import re
import pytest
from behavior_mapping import DETECTORS,MAX_ATTACK,MAX_DEFEND,select,validate_mapping
from behavior_taxonomy import build,fingerprint,load
from behavior_ai import DEFAULTS,Brain,infer,model_job,validate_result
from test_behavior_ai import result
from core import Store


def event(ident='one',action='HTTP request',**kwargs):
 return {'id':ident,'action':action,'source':'nginx','sensor':'web-request','path':'','method':'','seen':'2026-10-16T12:00:00+00:00',**kwargs}


@pytest.fixture
def catalog():
 attack={i:i+' example label' for i,p,d in DETECTORS}
 attack.update({i:i+' example label' for i in ('T1110','T1059','T1595')})
 defense={d:d+' example label' for i,p,d in DETECTORS}
 defense.update({i:i+' example label' for i in ('D3-UA','D3-WSAA','D3-DE')})
 value={'schema':2,'version':'synthetic test catalog','attack':attack,'d3fend':defense,'provenance':{}}
 value['registry_sha256']=fingerprint(value)
 return value


@pytest.fixture
def sources(tmp_path):
 a={'objects':[{'type':'x-mitre-collection','name':'Enterprise ATT&CK','x_mitre_version':'1.0'},
 {'type':'attack-pattern','name':'Example behavior','external_references':[{'source_name':'mitre-attack','external_id':'T1110'}]},
 {'type':'attack-pattern','name':'Revoked','revoked':True,'external_references':[{'source_name':'mitre-attack','external_id':'T1111'}]},
 {'type':'attack-pattern','name':'Deprecated','x_mitre_deprecated':True,'external_references':[{'source_name':'mitre-attack','external_id':'T1112'}]},
 {'type':'malware','name':'Wrong object type','external_references':[{'source_name':'mitre-attack','external_id':'T1113'}]}]}
 d={'@graph':[{'@id':'http://d3fend.mitre.org/ontologies/d3fend.owl','owl:versionInfo':'2.0'},
 {'@id':'d3f:Example','rdfs:subClassOf':{'@id':'d3f:DefensiveTechnique'},'d3f:d3fend-id':'D3-ANET','rdfs:label':'Example analysis'},
 {'@id':'d3f:ARMA','rdfs:subClassOf':{'@id':'d3f:Algorithm'},'d3f:d3fend-id':'D3-ARMA','rdfs:label':'Nondefensive algorithm with D3 prefix'},
 {'d3f:d3fend-id':'D3A-AL','rdfs:label':'Algorithm, not defensive technique'},
 {'d3f:d3fend-id':'D3-OLD','rdfs:label':'Deprecated','owl:deprecated':True}]}
 paths=[];manifest={}
 for kind,data,version in [('attack',a,'1.0'),('d3fend',d,'2.0')]:
  p=tmp_path/(kind+'.json');p.write_text(json.dumps(data));paths.append(p)
  manifest[kind]={'version':version,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'url':'https://example.invalid/synthetic'}
 return paths,manifest


def test_import_versions_hashes_revocation_and_algorithms(sources,tmp_path):
 paths,manifest=sources;r=build(*paths,'1.0','2.0',manifest)
 assert r['attack']=={'T1110':'Example behavior'} and r['d3fend']=={'D3-ANET':'Example analysis'}
 assert r['provenance']==manifest
 p=tmp_path/'registry.json';p.write_text(json.dumps(r));assert load(p)==r
 r['attack']['T0000']='Tampered';p.write_text(json.dumps(r));assert not load(p)['attack']
 with pytest.raises(ValueError,match='version or SHA256'):build(*paths,'different','2.0',manifest)
 paths[0].write_text(paths[0].read_text()+' ')
 with pytest.raises(ValueError,match='SHA256'):build(*paths,'1.0','2.0',manifest)


def test_embedded_versions_and_conflicting_ids_fail_closed(sources):
 paths,manifest=sources
 a=json.loads(paths[0].read_text());a['objects'][0]['x_mitre_version']='mislabelled'
 paths[0].write_text(json.dumps(a));manifest['attack']['sha256']=hashlib.sha256(paths[0].read_bytes()).hexdigest()
 with pytest.raises(ValueError,match='collection version'):build(*paths,'1.0','2.0',manifest)
 a['objects'][0]['x_mitre_version']='1.0';a['objects'].append({**a['objects'][1],'name':'Conflicting name'})
 paths[0].write_text(json.dumps(a));manifest['attack']['sha256']=hashlib.sha256(paths[0].read_bytes()).hexdigest()
 with pytest.raises(ValueError,match='Conflicting'):build(*paths,'1.0','2.0',manifest)


@pytest.mark.parametrize('content',['{','[]','{}','{"version":"legacy","attack":{"T1110":"Brute Force"}}'])
def test_unavailable_catalogs_are_safe(content,tmp_path):
 p=tmp_path/'registry';assert load(p)['attack']=={}
 p.write_text(content);assert load(p)['attack']=={}


@pytest.mark.parametrize('ident,action',[
 ('T1110.004','credential stuffing'),('T1595.001','ip block scanning'),
 ('T1595.003','wordlist scanning'),('T1046','network service discovery'),
 ('T1003','os credential dumping'),('T1059.001','powershell execution'),
 ('T1059.003','windows command shell execution'),('T1059.004','unix shell execution'),
 ('T1082','system information discovery'),('T1016','system network configuration discovery'),
 ('T1057','process discovery'),('T1033','system owner/user discovery'),
 ('T1105','ingress tool transfer'),('T1505.003','web shell upload attempt'),
 ('T1498','network denial of service')])
def test_broader_explicit_observations_remain_candidates(catalog,ident,action):
 packet={'events':[event(action=action)]};allowed=select(catalog,packet)
 assert ident in allowed['attack']
 validate_mapping('attack',{'technique_id':ident,'evidence_ids':['one']},allowed,packet)
 assert 'not confirmed compromise' in allowed['uncertainty']


@pytest.mark.parametrize('action',['allow','drop','deny','HTTP request','WAF interrupted','connection observed','no powershell execution','test credential stuffing','powershell execution not detected','200'])
def test_unsupported_text_paths_and_ports_do_not_prove_host_behavior(catalog,action):
 packet={'events':[event(action=action,path='/powershell/credential-stuffing',method='GET',port='22')],
         'context':[{'id':'ctx','classification':'malicious','technique_id':'T1003'}]}
 assert not select(catalog,packet)['attack']
 with pytest.raises(ValueError,match='supporting observations'):
  validate_mapping('attack',{'technique_id':'T1003','evidence_ids':['one']},catalog,packet)


def test_failed_logins_not_subtypes_and_context_cannot_support_mapping(catalog):
 packet={'packet_id':'packet','events':[event('one','authentication failure'),event('two','cowrie.login.failed')],'context':[{'id':'ctx'}]}
 allowed=select(catalog,packet);assert list(allowed['attack'])==['T1110']
 r=result(packet);r['attack_techniques']=[{'technique_id':'T1110','evidence_ids':['one','two'],'explanation':mapping_text('attack','T1110',catalog['attack']['T1110'])}]
 assert validate_result(r,packet,[],allowed)
 for refs in [['one'],['one','ctx'],['ctx']]:
  r['attack_techniques'][0]['evidence_ids']=refs
  with pytest.raises(ValueError):validate_result(r,packet,[],allowed)
 r['attack_techniques']=[];r['d3fend_context']=[{'technique_id':'D3-ANET','evidence_ids':['ctx'],'explanation':'Context only'}]
 with pytest.raises(ValueError):validate_result(r,packet,[],allowed)
 assert not select(catalog,{'events':[packet['events'][0]]})['attack']


def test_real_collector_actions_and_http_scan_boundaries(catalog):
 packet={'events':[event('cmd','cowrie.command.input',source='tpot',sensor='cowrie'),event('download','cowrie.session.file_download',source='tpot',sensor='cowrie')]}
 assert not select(catalog,packet)['attack']
 for e,semantic in zip(packet['events'],('shell_input','network_fetch')):e['source_observation']={'semantic':semantic}
 assert set(select(catalog,packet)['attack'])=={'T1059','T1105'}
 assert 'T1059.004' not in select(catalog,packet)['attack']
 for e in packet['events']:e['source']='nginx'
 assert not select(catalog,packet)['attack']
 probes=[event(str(i),'sensitive path request',path=p,method='GET') for i,p in enumerate(['/.env','/.git/config','/wp-admin'])]
 assert list(select(catalog,{'events':probes})['attack'])==['T1595']
 assert not select(catalog,{'events':probes[:2]})['attack']
 probes[-1]['seen']='2026-10-16T13:00:00+00:00'
 assert not select(catalog,{'events':probes})['attack']
 probes[-1]['seen']=probes[0]['seen'];probes[-1]['sensor']='other'
 assert not select(catalog,{'events':probes})['attack']


def test_ids_removed_by_dataset_update_are_not_offered(catalog):
 packet={'events':[event(action='powershell execution')]}
 assert select(catalog,packet)['attack']
 del catalog['attack']['T1059.001']
 assert not select(catalog,packet)['attack']
 with pytest.raises(ValueError):validate_mapping('attack',{'technique_id':'T1059.001','evidence_ids':['one']},catalog,packet)


def test_candidate_caps_disclose_truncation_and_are_deterministic(catalog):
 actions=['password guessing','password spraying','credential stuffing','ip block scanning','vulnerability scanning','wordlist scanning','network service discovery','public-facing application exploit attempt','os credential dumping','powershell execution','windows command shell execution','unix shell execution','system information discovery','file and directory discovery','system network configuration discovery','process discovery','system owner/user discovery','ingress tool transfer','web shell execution','network denial of service']
 packet={'events':[event(str(i),action) for i,action in enumerate(actions)]}
 allowed=select(catalog,packet)
 assert len(allowed['attack'])==MAX_ATTACK and len(allowed['d3fend'])==MAX_DEFEND
 assert allowed['coverage']['attack']=={'eligible':20,'supplied':12}
 assert allowed['coverage']['d3fend']['eligible']>MAX_DEFEND
 assert select(catalog,{'events':list(reversed(packet['events']))})==allowed
 assert select(allowed,packet)['coverage']==allowed['coverage']


def test_oversized_input_fails_before_network_request(catalog):
 packet={'packet_id':'large','coverage':'saved_samples','events':[event(action='powershell execution')],'context':[{'id':'context','text':'x'*18000}]}
 cfg={**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'}
 with pytest.raises(ValueError,match='input exceeds size'):
  infer(cfg,packet,[],catalog,'unused',requester=lambda *a,**k:pytest.fail('Oversized input reached network'))


def test_small_gpu_budget_and_validated_display_metadata(catalog):
 packet={'packet_id':'example','coverage':'saved_samples','events':[event(action='powershell execution')],'context':[]}
 cfg={**DEFAULTS,'endpoint':'https://127.0.0.1','model':'example'};captured=[]
 r=result(packet);r['attack_techniques']=[{'support_id':'attack:T1059.001','explanation':mapping_text('attack','T1059.001',catalog['attack']['T1059.001'])}]
 class Response:
  status_code=200
  def iter_content(self,n):yield json.dumps({'done':True,'model':'example','message':{'content':json.dumps(r)}}).encode()
  def close(self):pass
 def send(*args,**kwargs):captured.append(kwargs['json']);return Response()
 assessment,metadata=infer(cfg,packet,[],catalog,'unused',requester=send)
 payload=captured[0];prompt=json.loads(payload['messages'][1]['content'])
 assert len(prompt['allowed_mappings']['attack'])<=MAX_ATTACK and len(prompt['allowed_mappings']['d3fend'])<=MAX_DEFEND
 assert len(payload['messages'][1]['content'].encode())<=18000
 assert payload['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}
 assert prompt['allowed_mappings']['attack']['attack:T1059.001']['evidence_ids']==['one']
 assert metadata['taxonomy_mappings']['attack_techniques'][0]['name']==catalog['attack']['T1059.001']
 assert metadata['taxonomy_registry_sha256']==catalog['registry_sha256']
 r['attack_techniques'][0]['evidence_ids']=['ctx'];packet['context']=[{'id':'ctx'}]
 with pytest.raises(ValueError,match='invalid_assessment'):infer(cfg,packet,[],catalog,'unused',requester=send)


def test_catalog_identity_invalidates_cache_without_native_changes(catalog,tmp_path,monkeypatch):
 import behavior_ai
 store=Store(tmp_path/'manager.sqlite3');brain=Brain(store)
 p=tmp_path/'behavior-taxonomy.json';p.write_text(json.dumps(catalog))
 packet={'packet_id':'packet','events':[event()],'coverage':'saved_samples'}
 calls=[]
 def fake(*args):calls.append(args[3]);return result(packet),{}
 monkeypatch.setattr(behavior_ai,'infer',fake)
 cfg={**DEFAULTS,'model_enabled':True,'daily_budget':5}
 assert model_job(brain,'packet',packet,[],cfg)=='completed'
 assert model_job(brain,'packet',packet,[],cfg)=='cached'
 catalog['version']='new synthetic release';catalog.pop('registry_sha256');catalog['registry_sha256']=fingerprint(catalog);p.write_text(json.dumps(catalog))
 assert model_job(brain,'packet',packet,[],cfg)=='completed' and len(calls)==2
 assert calls[0]['registry_sha256']!=calls[1]['registry_sha256']
 p.write_text('{broken')
 assert model_job(brain,'packet',packet,[],cfg)=='completed'
 assert calls[-1]['attack']=={} and calls[-1]['version']=='unavailable'
 with store.connect() as db:assert db.execute('SELECT count(*) FROM evidence').fetchone()[0]==0


def test_mapping_ui_names_citations_uncertainty_and_legacy_fallback():
 from jinja2 import Environment,FileSystemLoader,select_autoescape
 env=Environment(loader=FileSystemLoader(pathlib.Path(__file__).parent/'templates'),autoescape=select_autoescape())
 assessment={'attack_techniques':[{'technique_id':'T1059.001','explanation':'<script>untrusted</script>','evidence_ids':['one']}],'d3fend_context':[],
  'metadata':{'taxonomy_version':'synthetic 1','taxonomy_mappings':{'attack_techniques':[{'technique_id':'T1059.001','name':'PowerShell'}]}}}
 rendered=env.get_template('behavior_taxonomy.html').render(analysis={'assessment':assessment})
 assert 'PowerShell' in rendered and '#behavior-one' in rendered and '<script>' not in rendered
 assert 'control is deployed' in rendered and 'No supported mapping recorded' in rendered
 assessment.pop('metadata');rendered=env.get_template('behavior_taxonomy.html').render(analysis={'assessment':assessment})
 assert 'Dataset version unavailable' in rendered and 'T1059.001' in rendered


def test_authenticated_detail_renders_mapping_and_preserves_native_policy(catalog,tmp_path,monkeypatch):
 import datetime as dt
 import os
 import shutil
 from app import create_app
 from core import now
 import behavior_ai
 app=create_app({'database':str(tmp_path/'manager.sqlite3'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'synthetic','hosts':['localhost']});app.testing=True
 store=app.store
 store.evidence('8.8.8.8','tpot','cowrie',now(),'ssh',50,details={'activity':{'events':[{'id':'synthetic','seen':now(),'action':'powershell execution'}]}})
 brain=Brain(store);ident,packet,features=brain.packet(store.describe('8.8.8.8'));before=store.describe('8.8.8.8')
 (tmp_path/'behavior-taxonomy.json').write_text(json.dumps(catalog))
 cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'endpoint':'https://127.0.0.1','model':'fixture'}
 store.state('behavior_settings',cfg)
 def fake(*args):
  r=result(packet);r.update(maliciousness_confidence=0)
  # Grounded findings remain unchanged; this fixture tests display metadata.
  r['attack_techniques']=[{'support_id':'attack:T1059.001','explanation':mapping_text('attack','T1059.001',catalog['attack']['T1059.001'])}]
  class Response:
   status_code=200
   def iter_content(self,n):yield json.dumps({'done':True,'model':'fixture','message':{'content':json.dumps(r)}}).encode()
   def close(self):pass
  return infer(*args[:5],requester=lambda *a,**k:Response(),attempt=args[6] if len(args)>6 else None)
 monkeypatch.setattr(behavior_ai,'infer',fake)
 assert model_job(brain,ident,packet,features,cfg)=='completed'
 with store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('fixture','hash',1))
 client=app.test_client()
 assert client.get('/ip/8.8.8.8',base_url='https://localhost').status_code==302
 with client.session_transaction() as session:session.update(user='fixture',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='synthetic')
 response=client.get('/ip/8.8.8.8',base_url='https://localhost');assert response.status_code==200
 body=response.get_data(as_text=True)
 assert 'T1059.001 example label' in body and 'D3FEND defensive context' in body and '#behavior-'+packet['events'][0]['id'] in body
 assert 'control is deployed' in body and 'compromise and maliciousness remain unconfirmed' in body
 assert store.describe('8.8.8.8')['score']==before['score'] and store.describe('8.8.8.8')['retention']==before['retention']
 assert not store.active_rules() and store.state('behavior_settings')==cfg
 export=os.environ.get('MITRE_UI_DIR')
 if export:
  root=pathlib.Path(export);root.mkdir(exist_ok=True)
  def save(name,html):
   html=re.sub(r'<script\b[^>]*>.*?</script>','',html,flags=re.S|re.I)
   html=re.sub(r'<form\b[^>]*>.*?</form>','<p>Synthetic fixture: controls omitted.</p>',html,flags=re.S|re.I)
   html=html.replace('<main ','<aside style="padding:12px;background:#fff4cf;color:#312500">Synthetic isolated fixture. No live data, deployed UI or model accuracy claim.</aside><main ')
   (root/name).write_text(html,encoding='utf-8')
  save('after.html',body)
  baseline=pathlib.Path('baseline-behavior_ip.html')
  if baseline.exists():
   from jinja2 import ChoiceLoader,DictLoader
   app.jinja_loader=ChoiceLoader([DictLoader({'behavior_ip.html':baseline.read_text(encoding='utf-8')}),app.jinja_loader]);app.jinja_env.cache.clear()
   save('before.html',client.get('/ip/8.8.8.8',base_url='https://localhost').get_data(as_text=True))
  shutil.copytree(pathlib.Path(__file__).parent/'static',root/'static',dirs_exist_ok=True)
