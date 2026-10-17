"""Synthetic mechanics; never independent accuracy labels or production requests."""
import datetime as dt,hashlib,json,os,pathlib
import pytest
from core import Store
from behavior_ai import Brain
from behavior_intelligence import inspect,alerts,load_catalog
from behavior_scheduling import schedule,backfill
from behavior_references import active,refresh,review,PUBLIC_SOURCES,matches,endpoint_hint
from test_behavior_intelligence import packet,AT

def queue(b,count=110):
 for i in range(count):
  ident='candidate'+str(i);address='198.51.100.'+str(i+1)
  packet(b,ident,address=address,paths=('/',) if i<100 else ('/.env','/admin'))
  with b.connect() as db:db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',(address,ident,(AT+dt.timedelta(seconds=i)).isoformat()))

def test_rich_nonempty_packet_outside_oldest_100_gets_priority_and_age_slot(tmp_path):
 b=Brain(Store(tmp_path/'native'));queue(b)
 with b.connect() as db:
  before=list(db.iterdump());result=schedule(db);assert list(db.iterdump())==before
 assert [r['packet_id'] for r in result[:3]]==['candidate0','candidate100','candidate1']
 assert len(result)==100
 with b.connect() as db:
  for query in ["SELECT ip FROM queue_priority INDEXED BY queue_priority_rich WHERE richness>0 ORDER BY richness DESC,last_seen DESC,queued,ip LIMIT 64","SELECT ip FROM queue_priority INDEXED BY queue_priority_recent WHERE last_seen>'' ORDER BY last_seen DESC,richness DESC,queued,ip LIMIT 64"]:
   plan=' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN '+query));assert 'SEARCH' in plan and 'INDEX' in plan and 'TEMP B-TREE' not in plan

def test_legacy_priority_backfill_is_restartable_bounded_and_partial(tmp_path):
 b=Brain(Store(tmp_path/'native'));queue(b)
 with b.connect() as db:db.execute('DELETE FROM packet_scheduling');db.execute('DELETE FROM queue_priority')
 assert backfill(b,50)=={'scanned':50,'bound':200,'partial':True}
 b=Brain(b.store);assert backfill(b,50)['partial']
 assert backfill(b,50)=={'scanned':10,'bound':200,'partial':False}
 with b.connect() as db:assert schedule(db)[1]['packet_id']=='candidate100'

def test_priority_metadata_follows_current_window_and_queue_deletion(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'old',paths=('/',))
 with b.connect() as db:db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',('8.8.8.8','old',AT.isoformat()))
 packet(b,'new',hours=1,paths=('/.env','/admin'))
 with b.connect() as db:
  row=db.execute('SELECT * FROM queue_priority').fetchone();assert row['packet_id']=='new' and row['richness']>0
  selected=schedule(db)[0];assert selected['packet_id']=='new' and selected['original_packet_id']=='old'
  db.execute('DELETE FROM analysis_queue');assert not db.execute('SELECT 1 FROM queue_priority').fetchone()
  db.execute("DELETE FROM packets WHERE id='old'");assert not db.execute("SELECT 1 FROM packet_scheduling WHERE packet_id='old'").fetchone()

def fake_fetch(version='a'):
 def fetch(url):
  marker=next(marker for source,marker in PUBLIC_SOURCES.values() if source==url)
  return marker+version.encode(),{'etag':'synthetic-'+version,'last_modified':None}
 return fetch

def test_source_refresh_stages_only_cooldown_and_exact_hash_review(tmp_path):
 b=Brain(Store(tmp_path/'native'));base=active(tmp_path);assert len(base['rules'])==2
 assert refresh(tmp_path,fake_fetch(),AT)['status']=='pending_review'
 assert active(tmp_path)['sha256']==base['sha256']
 pending=json.loads((tmp_path/'behavior-references.pending.json').read_text())
 with pytest.raises(ValueError):refresh(tmp_path,fake_fetch(),AT+dt.timedelta(seconds=1))
 with pytest.raises(ValueError):review(b,'wrong','accepted','Synthetic source review','fixture')
 review(b,pending['hash'],'accepted','Synthetic mechanics only; public test fixture sources.','fixture')
 assert active(tmp_path)['status']=='reviewed_local' and active(tmp_path)['sha256']!=base['sha256']
 versions=[r['version'] for r in active(tmp_path)['rules']]
 refresh(tmp_path,fake_fetch(),AT+dt.timedelta(days=1));same=json.loads((tmp_path/'behavior-references.pending.json').read_text())
 assert same['changes']==[] and [r['version'] for r in same['candidate']['rules']]==versions
 (tmp_path/'behavior-references.json').write_text('broken')
 assert active(tmp_path)['status']=='last_good' and active(tmp_path)['sha256']==base['sha256']
 with b.connect() as db:assert db.execute('SELECT count(*) FROM reference_reviews').fetchone()[0]==1
 assert not b.store.all_scores() and not b.store.active_rules()

def test_failed_source_refresh_and_rejection_preserve_active(tmp_path):
 b=Brain(Store(tmp_path/'native'));base=active(tmp_path)['sha256']
 def fail(url):raise OSError('synthetic unavailable')
 assert refresh(tmp_path,fail,AT)['status']=='failed_last_good_retained'
 assert active(tmp_path)['sha256']==base
 refresh(tmp_path,fake_fetch(),AT+dt.timedelta(days=1));pending=json.loads((tmp_path/'behavior-references.pending.json').read_text())
 review(b,pending['hash'],'rejected','Synthetic source change not accepted','fixture');assert active(tmp_path)['sha256']==base

def test_source_bytes_tamper_blocks_activation(tmp_path):
 b=Brain(Store(tmp_path/'native'));refresh(tmp_path,fake_fetch(),AT);p=json.loads((tmp_path/'behavior-references.pending.json').read_text());sha=next(iter(p['sources'].values()))['sha256']
 (tmp_path/'reference-sources'/(sha+'.source')).write_text('tampered')
 with pytest.raises(ValueError):review(b,p['hash'],'accepted','Synthetic attempted review','fixture')
 assert active(tmp_path)['status']=='packaged_starter'

def test_public_bundle_import_works_without_egress_and_does_not_reset_cooldown(tmp_path):
 import zipfile
 from behavior_references import import_bundle
 b=Brain(Store(tmp_path/'native'))
 def unavailable(url):raise OSError('synthetic unavailable')
 refresh(tmp_path,unavailable,AT);network_state=(tmp_path/'reference-refresh.json').read_bytes()
 bundle=tmp_path/'public.zip';manifest=[]
 with zipfile.ZipFile(bundle,'w') as archive:
  for ident,(url,marker) in PUBLIC_SOURCES.items():
   body=marker+b' synthetic test bytes';name=ident+'.source';archive.writestr(name,body)
   manifest.append({'id':ident,'url':url,'file':name,'status':200,'sha256':hashlib.sha256(body).hexdigest(),'retrieved_at':AT.isoformat()})
  archive.writestr('manifest.json',json.dumps(manifest))
 result=import_bundle(tmp_path,bundle,AT);assert result['status']=='pending_review' and result['network'] is False
 assert (tmp_path/'reference-refresh.json').read_bytes()==network_state
 assert active(tmp_path)['status']=='packaged_starter'
 pending=json.loads((tmp_path/'behavior-references.pending.json').read_text());assert all(s['retrieved_at']==AT.isoformat() for s in pending['sources'].values())
 review(b,pending['hash'],'accepted','Synthetic offline bundle review only','fixture');assert active(tmp_path)['status']=='reviewed_local'
 bad=tmp_path/'bad.zip'
 with zipfile.ZipFile(bad,'w') as archive:archive.writestr('../private','should not extract');archive.writestr('manifest.json','[]')
 with pytest.raises(ValueError):import_bundle(tmp_path,bad,AT)
 assert not (tmp_path.parent/'private').exists()

def test_two_request_fields_support_targeting_not_payload_or_named_tool():
 catalog=active(pathlib.Path('/nonexistent-synthetic-directory'));rule=next(r for r in catalog['rules'] if r['label']=='CVE-2017-9841')
 raw='/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
 from evidence_history import normalize
 e=normalize('8.8.8.8','nginx','synthetic',{'id':'test','seen':AT.isoformat(),'path':raw,'method':'POST'},AT.isoformat())
 assert e['endpoint_hint']=='phpunit_eval_stdin' and matches(rule,e)
 assert rule['evidence_level']=='targeting_only' and len(rule['match'])==2
 assert not matches(rule,{**e,'method':'GET'})
 assert not matches(rule,{'path':'[identifier].php','method':'POST'})
 assert not endpoint_hint('/app?service=page/SetupCompleted')
 assert not any(matches(r,{'path':'/app','method':'POST'}) for r in catalog['rules'])

def test_apache_rule_matches_only_traversal_terminal_and_method():
 rule=next(r for r in active(pathlib.Path('/nonexistent-synthetic-directory'))['rules'] if r['label']=='CVE-2021-41773')
 assert matches(rule,{'path':'/cgi-bin/../../bin/sh','method':'POST'})
 for event in [{'path':'/cgi-bin/php','method':'POST'},{'path':'/cgi-bin/../../bin/sh','method':'GET'},{'path':'/normal/../../bin/sh','method':'POST'}]:assert not matches(rule,event)
 assert rule['evidence_level']=='traversal_probe' and 'not a unique' in rule['rationale']

def test_indexed_advisory_event_survives_latest_200_and_byte_bound_without_points(tmp_path):
 from evidence_history import save,query
 from behavior_references import representative_events
 from behavior_ai import DEFAULTS
 b=Brain(Store(tmp_path/'native'));address='8.8.8.8'
 old=AT-dt.timedelta(days=2)
 save(b,address,'nginx','fixture',[{'id':'old-probe','seen':old.isoformat(),'path':'/cgi-bin/../../bin/sh','method':'POST'}],AT.isoformat())
 save(b,address,'nginx','fixture',[{'id':'generic-'+str(i),'seen':(AT-dt.timedelta(seconds=i)).isoformat(),'path':'/','method':'GET'} for i in range(300)],AT.isoformat())
 assert all('cgi-bin' not in e['path'] for e in query(b,address,AT)['events'])
 retrieved=representative_events(b,address,None,AT);assert len(retrieved)==1 and not retrieved[0]['independent_evidence']
 ident,content,_=b.packet(b.store.describe(address),at=AT)
 assert any('cgi-bin' in e['path'] for e in content['events']) and len(json.dumps(content).encode())<12000
 assert not any(e['independent_evidence'] for e in content['events'])
 assert representative_events(b,address,None,AT,days=1)==[]
 _,short,_=b.packet(b.store.describe(address),cfg={**DEFAULTS,'window_days':1},at=AT)
 assert not any('cgi-bin' in e['path'] for e in short['events'])
 with b.connect() as db:
  plan=' '.join(r[3] for r in db.execute("EXPLAIN QUERY PLAN SELECT id,scope FROM history_reference_index WHERE ip=? AND scope=? AND pattern=? AND seen>=? AND seen<=? ORDER BY seen DESC,id LIMIT 2",(address,'','apache_cgi_traversal','2020','2030')));assert 'SEARCH' in plan and 'history_reference_lookup' in plan and 'TEMP B-TREE' not in plan
  db.execute('DELETE FROM event_history');assert not db.execute('SELECT 1 FROM history_reference_index').fetchone()

def test_advisory_routes_source_download_csrf_and_render(tmp_path):
 from app import create_app
 app=create_app({'database':str(tmp_path/'native'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'synthetic','hosts':['localhost']});app.testing=True;b=Brain(app.store)
 p=packet(b,'probe',paths=('/cgi-bin/../../bin/sh',));p['events'][0]['method']='POST'
 with b.connect() as db:db.execute('UPDATE packets SET content=? WHERE id=?',(json.dumps(p),'probe'))
 inspect(b,'probe',catalog=active(tmp_path));refresh(tmp_path,fake_fetch(),AT)
 client=app.test_client();assert client.get('/behavior/references').status_code==302
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('reviewer','hash',1))
 with client.session_transaction() as session:session.update(user='reviewer',version=1,csrf='fixture',expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600)
 assert client.post('/behavior/references/review',data={}).status_code==400
 paths={'references.html':'/behavior/references','activity.html':'/behavior/activity','activity-detail.html':'/behavior/activity/'+alerts(b)[0]['id'],'evaluation.html':'/behavior/evaluation','behavior.html':'/behavior'}
 htmls={}
 for filename,url in paths.items():
  response=client.get(url);assert response.status_code==200;htmls[filename]=response.get_data(as_text=True)
 assert 'Pending review' in htmls['references.html'] and 'No PaperCut rule is enabled' in htmls['references.html']
 assert 'traversal probe' in htmls['activity-detail.html']
 pending=json.loads((tmp_path/'behavior-references.pending.json').read_text());sha=next(iter(pending['sources'].values()))['sha256']
 response=client.get('/behavior/references/sources/'+sha);assert response.status_code==200 and response.headers['X-Content-Type-Options']=='nosniff'
 assert client.get('/behavior/references/sources/not-a-hash').status_code==404
 if os.environ.get('INTELLIGENCE_UI_EXPORT'):
  out=pathlib.Path(os.environ['INTELLIGENCE_UI_EXPORT']);out.mkdir(exist_ok=True)
  for filename,html in htmls.items():(out/filename).write_text(html,encoding='utf-8')
