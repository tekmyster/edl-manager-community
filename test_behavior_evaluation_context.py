"""Frozen-review and blinding regressions. Synthetic fixtures, never truth labels."""
import datetime as dt,json,os,pathlib
from core import now
from behavior_ai import Brain
from behavior_evaluation import capture,cases,label
from behavior_intelligence import inspect,alerts,review as review_alert
from behavior_references import active
from test_behavior_intelligence import packet
from test_behavior_ai import result

def app_fixture(tmp_path):
 from app import create_app
 app=create_app({'database':str(tmp_path/'native'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'synthetic','hosts':['localhost']});app.testing=True
 client=app.test_client()
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('fixture','hash',1))
 with client.session_transaction() as session:session.update(user='fixture',version=1,csrf='fixture',expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600)
 return app,client,Brain(app.store)

def review_form(**values):
 return {'csrf':'fixture','label':'legitimate','basis':'raw_event_review','independent':'on','provenance':'Synthetic independent record; mechanics only','notes':'Synthetic fixture only; no authentic ground truth is asserted.',**values}

def test_case_stays_blind_then_renders_frozen_context_despite_later_live_changes(tmp_path):
 app,client,b=app_fixture(tmp_path)
 historical=packet(b,'historical',address='1.1.1.1',hours=-4)
 current=packet(b,'current',paths=('/admin','/.env','/cgi-bin/../../bin/sh'))
 current['events'][2]['method']='POST'
 with b.connect() as db:db.execute('UPDATE packets SET content=? WHERE id=?',(json.dumps(current),'current'))
 candidates=b.candidates('current',set());assert len(candidates)==1
 with b.connect() as db:relationship=db.execute('SELECT id FROM links LIMIT 1').fetchone()[0]
 b.review(relationship,'accepted','CAPTURED_RELATION_REVIEW: shared behavior only','captured-reviewer')
 inspect(b,'current',candidates,catalog=active(tmp_path))
 for alert in alerts(b):review_alert(b,alert['id'],'accepted','CAPTURED_ALERT_REVIEW: synthetic evidence only','captured-reviewer')
 model=result(current);model.update(analysis_summary='CAPTURED_MODEL_SUMMARY: synthetic only',metadata={'model':'synthetic','prompt_version':'synthetic-fixture'})
 with b.connect() as db:db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('synthetic-assessment','current','synthetic',now(),'2099-01-01T00:00:00+00:00','completed',json.dumps(model),'',0))
 allow=app.store.add_rule('allow','8.8.8.8','Synthetic captured allowed policy',None,'fixture')
 ident=capture(b,'current');url='/behavior/evaluation/'+ident
 with b.connect() as db:original=db.execute('SELECT snapshot FROM evaluation_cases WHERE id=?',(ident,)).fetchone()[0]
 snap=json.loads(original);assert snap['decision_at_capture']['native_policy']=='Allowed'
 assert snap['comparisons'][0]['reviews'][0]['actor']=='captured-reviewer'
 blind=client.get(url).get_data(as_text=True)
 for hidden in ('historical-0','CAPTURED_RELATION_REVIEW','CAPTURED_ALERT_REVIEW','CAPTURED_MODEL_SUMMARY','CVE-2021-41773','Captured native and pilot policy','name="correlation"'):
  assert hidden not in blind
 # Change real source state after capture. The case must not read it on review.
 b.review(relationship,'rejected','LATER_LIVE_RELATION_REVIEW','later-reviewer')
 for alert in alerts(b):review_alert(b,alert['id'],'rejected','LATER_LIVE_ALERT_REVIEW','later-reviewer')
 with b.connect() as db:
  for row in db.execute('SELECT id,details FROM intelligence_observations').fetchall():
   detail=json.loads(row['details']);detail['interpretation']='LATER_LIVE_INTERPRETATION'
   if 'association' in detail:detail['association']['title']='LATER_LIVE_ADVISORY_TITLE'
   db.execute('UPDATE intelligence_observations SET details=? WHERE id=?',(json.dumps(detail),row['id']))
 app.store.disable_rule(allow,'fixture');app.store.add_rule('block','8.8.8.8','LATER_LIVE_POLICY',None,'fixture')
 assert capture(b,'current')==ident
 response=client.post(url,data=review_form(correlation='supported'));assert response.status_code==302
 assert all(value=='unknown' for value in json.loads(cases(b,ident)[0]['labels'][0]['quality']).values())
 html=client.get(url).get_data(as_text=True)
 for visible in ('Frozen review context','historical-0','current-0','CAPTURED_RELATION_REVIEW','CAPTURED_ALERT_REVIEW','CAPTURED_MODEL_SUMMARY','CVE-2021-41773','Apache HTTP Server Project','Source SHA-256','Allowed','Accepted','Current navigation','not the case snapshot'):
  assert visible in html,visible
 for later in ('LATER_LIVE_RELATION_REVIEW','LATER_LIVE_ALERT_REVIEW','LATER_LIVE_INTERPRETATION','LATER_LIVE_ADVISORY_TITLE','LATER_LIVE_POLICY'):
  assert later not in html
 assert 'value="legitimate" selected' in html and 'Synthetic independent record; mechanics only' in html
 assert client.post(url,data=review_form(correlation='unsupported',return_activity='unknown',tool_exploit='not_applicable')).status_code==302
 latest=cases(b,ident)[0]['labels'][0];assert latest['label']=='legitimate'
 assert json.loads(latest['quality'])['correlation']=='unsupported' and json.loads(latest['quality'])['tool_exploit']=='not_applicable'
 with b.connect() as db:
  assert db.execute('SELECT snapshot FROM evaluation_cases WHERE id=?',(ident,)).fetchone()[0]==original
  assert db.execute("SELECT state FROM links WHERE id=?",(relationship,)).fetchone()[0]=='rejected'
  assert db.execute("SELECT count(*) FROM retention_refs WHERE kind='evaluation' AND packet_id='historical'").fetchone()[0]==1
 # Export actual route renders for browser QA; source remains explicitly synthetic.
 if os.environ.get('INTELLIGENCE_UI_EXPORT'):
  out=pathlib.Path(os.environ['INTELLIGENCE_UI_EXPORT']);out.mkdir(exist_ok=True)
  (out/'case-blind.html').write_text(blind,encoding='utf-8')
  (out/'case-labeled.html').write_text(client.get(url).get_data(as_text=True),encoding='utf-8')

def test_older_missing_review_history_and_context_are_unknown_not_reconstructed(tmp_path):
 app,client,b=app_fixture(tmp_path);current=packet(b,'legacy-current');peer=packet(b,'legacy-historical',address='1.1.1.1',hours=-2)
 old={'packet':current,'ip':'8.8.8.8','indexed':now(),'assessment':None,'assessment_status':'unassessed','native_score_at_index':0,'decision_at_capture':None,'limitations':['Synthetic older capture'],
      'comparisons':[],'activity':[{'kind':'similar_activity','state':'proposed','packet_id':'legacy-current','peer_packet':'legacy-historical','details':json.dumps({'interpretation':'LEGACY_CAPTURED_FINDING','current_events':current['events'],'historical_events':peer['events'],'uncertainty':['LEGACY_UNCERTAINTY']})}]}
 with b.connect() as db:db.execute('INSERT INTO evaluation_cases VALUES(?,?,?,?,?)',('legacy','legacy-current','',now(),json.dumps(old)))
 label(b,'legacy',review_form(),'fixture');html=client.get('/behavior/evaluation/legacy').get_data(as_text=True)
 for expected in ('LEGACY_CAPTURED_FINDING','legacy-historical-0','LEGACY_UNCERTAINTY','Review history was not saved','No policy decision was captured','No relationship finding was saved','Not applicable'):
  assert expected in html

def test_empty_saved_context_keeps_unknown_and_not_applicable_available(tmp_path):
 app,client,b=app_fixture(tmp_path);packet(b,'empty');ident=capture(b,'empty')
 label(b,ident,review_form(),'fixture');url='/behavior/evaluation/'+ident
 html=client.get(url).get_data(as_text=True)
 assert 'No relationship finding was saved' in html and 'No activity finding was saved' in html
 assert 'value="unknown" selected' in html and 'value="not_applicable"' in html
 assert client.post(url,data=review_form(correlation='not_applicable',return_activity='unknown',tool_exploit='not_applicable')).status_code==302
 assert json.loads(cases(b,ident)[0]['labels'][0]['quality'])['correlation']=='not_applicable'
