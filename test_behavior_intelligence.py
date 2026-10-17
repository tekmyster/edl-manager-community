"""Synthetic mechanics only. These cases are not independently labeled telemetry."""
import copy,datetime as dt,json
import pytest
from core import Store
from behavior_ai import Brain
from behavior_intelligence import profile,inspect,alerts,review,schedule,cleanup,load_catalog
from behavior_evaluation import capture,label,cases,evaluate,report

AT=dt.datetime(2026,10,17,2,tzinfo=dt.timezone.utc)

def packet(b,ident,address='8.8.8.8',hours=0,paths=('/admin','/.env'),events_prefix=None):
 when=AT+dt.timedelta(hours=hours)
 events=[{'id':(events_prefix or ident)+'-'+str(i),'seen':(when+dt.timedelta(seconds=i)).isoformat(),'path':path,'action':'sensitive path request','method':'GET','source':'nginx','sensor':'synthetic','destination':{'scope':'unknown'},'port':'443','provenance':{'detail':'sample'}} for i,path in enumerate(paths)]
 content={'packet_id':ident,'coverage':'synthetic','events':events,'limitations':[],'source_counts':{'nginx':len(events)}}
 features={'path:'+p for p in paths}
 with b.connect() as db:
  db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,address,when.isoformat(),json.dumps(content),json.dumps(sorted(features)),0))
  db.execute('INSERT OR REPLACE INTO current_packets VALUES(?,?)',(address,ident));b.index_features(db,ident,features)
 return content

def test_recurrence_deduplicates_replay_and_keeps_rejection(tmp_path):
 s=Store(tmp_path/'native');b=Brain(s)
 with s.connect() as db:before=list(db.iterdump())
 packet(b,'old',hours=-4);packet(b,'new');inspect(b,'new')
 with s.connect() as db:assert list(db.iterdump())==before
 first=alerts(b);assert [a['kind'] for a in first]==['same_ip_return']
 assert first[0]['gap_seconds']>=3600 and first[0]['operator_hypothesis'].startswith('unknown')
 review(b,first[0]['id'],'rejected','Synthetic unrelated address reassignment','test')
 packet(b,'rebuilt',hours=1,events_prefix='new');inspect(b,'rebuilt')
 assert alerts(b)[0]['state']=='rejected' and alerts(b)[0]['window_count']==1
 # Only the explicit audit record changes native storage, never scores/evidence/rules.
 assert not s.active_rules() and not s.all_scores()
 with b.connect() as db:assert db.execute("SELECT count(*) FROM retention_refs WHERE kind='intelligence'").fetchone()[0]==2

def test_overlapping_or_same_events_are_not_returning_activity(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'old');packet(b,'new',hours=.1);inspect(b,'new')
 assert not alerts(b)
 packet(b,'rebuild',hours=10,events_prefix='new');inspect(b,'rebuild')
 assert all(a['kind']!='same_ip_return' for a in alerts(b))

def test_generic_assets_do_not_make_a_two_path_match(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'own',paths=('/favicon.ico','/owa/auth.owa'));packet(b,'peer',address='1.1.1.1',paths=('/favicon.ico','/owa/auth.owa'))
 assert b.candidates('own',set())==[]

def test_reference_window_is_not_assumed_to_precede_current_events(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'own');packet(b,'peer',address='1.1.1.1',hours=1)
 with b.connect() as db:
  own=json.loads(db.execute('SELECT content FROM packets WHERE id=?',('own',)).fetchone()[0]);peer=json.loads(db.execute('SELECT content FROM packets WHERE id=?',('peer',)).fetchone()[0])
 inspect(b,'own',[{'candidate_id':'peer','current_events':own['events'],'historical_events':peer['events'],'shared_features':['path:/admin','path:/.env'],'similarity':1,'retrieval_version':'synthetic'}])
 a=alerts(b)[0];assert a['gap_seconds']<0 and 'unproven' in a['temporal_relation']

def test_change_and_cross_ip_are_evidence_only(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'old',hours=-3,paths=('/admin','/.env','/old'));packet(b,'new',paths=('/admin','/.env','/new'));packet(b,'peer',address='1.1.1.1',hours=-1,paths=('/admin','/.env','/new'))
 candidate=b.candidates('new',set());inspect(b,'new',candidate)
 found=alerts(b);assert {'same_ip_return','behavior_change','similar_activity'}<={a['kind'] for a in found}
 cross=next(a for a in found if a['kind']=='similar_activity')
 assert len(cross['current_events'])>=2 and len(cross['historical_events'])>=2
 assert cross['relationship_id'] and 'path:/new' in next(a for a in found if a['kind']=='behavior_change')['added']
 review(b,cross['id'],'accepted','Synthetic useful shared-tool candidate','test')
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM behavior_groups').fetchone()[0]==0
  assert db.execute("SELECT count(*) FROM links WHERE state='accepted'").fetchone()[0]==0

def test_unreviewed_cleanup_releases_refs_reviewed_alerts_remain(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'old',hours=-5);packet(b,'new');inspect(b,'new');ident=alerts(b)[0]['id']
 review(b,ident,'rejected','Synthetic false link preserved','test')
 with b.connect() as db:
  db.execute("UPDATE intelligence_observations SET created='2020'");cleanup(db,AT+dt.timedelta(days=200));assert db.execute('SELECT count(*) FROM intelligence_observations').fetchone()[0]==1
 packet(b,'changed',hours=1,paths=('/new','/second'));inspect(b,'changed')
 with b.connect() as db:
  db.execute("UPDATE intelligence_observations SET created='2020'");cleanup(db,AT+dt.timedelta(days=200))
  assert db.execute("SELECT count(*) FROM intelligence_alerts WHERE state='proposed'").fetchone()[0]==0
  assert db.execute("SELECT count(*) FROM retention_refs WHERE kind='intelligence'").fetchone()[0]==2

def test_queue_fairness_diversity_budget_neutral_and_bounded(tmp_path):
 b=Brain(Store(tmp_path/'native'))
 for i in range(102):
  ident='p'+str(i);packet(b,ident,address='1.1.1.'+str(i+1),paths=() if i<95 else ('/.env','/admin'))
  with b.connect() as db:db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',('1.1.1.'+str(i+1),ident,AT.isoformat()+f'-{i:03}'))
 with b.connect() as db:
  before=list(db.iterdump());result=schedule(db);assert list(db.iterdump())==before
 assert len(result)==100 and result[0]['packet_id']=='p0' and result[1]['packet_id']=='p95'
 assert 'p100' not in {r['packet_id'] for r in result}

def catalog_rule():
 return {'id':'synthetic-rule','version':'test-1','label':'CVE-2099-12345','kind':'cve','reviewed_by':'fixture','rationale':'Synthetic conjunction for matcher mechanics; no actual advisory.',
 'match':{'path':'/synthetic/exploit','method':'POST','action':'synthetic payload marker'},'references':[{'url':'https://example.org/synthetic','primary':True,'publisher':'Synthetic test','version':'fixture','retrieved_at':AT.isoformat(),'sha256':'a'*64}]}

@pytest.mark.parametrize('mutation',[lambda r:r['match'].pop('action'),lambda r:r['references'][0].update(primary=False),lambda r:r['references'][0].update(sha256='invalid'),lambda r:r.update(label='invented'),lambda r:r['match'].update(authorization='secret')])
def test_reference_catalog_requires_review_and_exact_conjunction(tmp_path,mutation):
 rule=catalog_rule();mutation(rule);path=tmp_path/'references.json';path.write_text(json.dumps({'schema':1,'rules':[rule]}))
 assert load_catalog(path)['rules']==[]

def test_cve_match_requires_all_observed_fields_no_generic_scan(tmp_path):
 path=tmp_path/'refs.json';path.write_text(json.dumps({'schema':1,'rules':[catalog_rule()]}));catalog=load_catalog(path)
 assert catalog['status']=='reviewed_local'
 b=Brain(Store(tmp_path/'native'));content=packet(b,'p',paths=('/synthetic/exploit','/admin'));inspect(b,'p',catalog=catalog);assert not alerts(b)
 content['events'][0].update(method='POST',action='synthetic payload marker')
 with b.connect() as db:db.execute('UPDATE packets SET content=? WHERE id=?',(json.dumps(content),'p'))
 inspect(b,'p',catalog=catalog);a=alerts(b)[0];assert a['association']['label']=='CVE-2099-12345' and 'unverified' in a['interpretation']

def test_no_metrics_without_independent_labels_and_no_policy_write(tmp_path):
 b=Brain(Store(tmp_path/'native'));packet(b,'p');case=capture(b,'p');assert capture(b,'p')==case
 result=report(b);assert result['cases']==1 and result['reviewed']==0 and result['model']['precision'] is None
 with pytest.raises(ValueError):label(b,case,{'label':'malicious','basis':'model','independent':'on'},'test')
 form={'label':'borderline','basis':'raw_event_review','independent':'on','provenance':'Synthetic record','notes':'Synthetic mechanics only; not an authentic independent label.'}
 label(b,case,form,'test');label(b,case,{**form,'label':'legitimate'},'test2')
 found=cases(b)[0];assert len(found['labels'])==2 and found['labels'][0]['label']=='legitimate'
 assert report(b)['model']['abstained_or_unknown']==1 and report(b)['model']['cohort_recall'] is None
 assert not b.store.active_rules()

def item(truth,pred,confidence=.95,native='Evaluating',effective='Evaluating'):
 return {'assessment_id':'a','snapshot':{'assessment':{'classification':pred,'maliciousness_confidence':confidence},'decision_at_capture':{'native_policy':native,'effective_policy':effective,'native_score':70,'effective_score':79 if effective=='Denied' else 70,'applied_assessment_id':'a'}},'labels':[{'label':truth,'quality':json.dumps({'correlation':'unsupported'})}]}

def test_metrics_denominators_abstention_borderline_and_incremental_policy():
 result=evaluate([item('malicious','malicious',native='Evaluating',effective='Denied'),item('legitimate','malicious',native='Allowed',effective='Allowed'),item('malicious','inconclusive'),item('borderline','benign')])
 assert result['decisive']==3 and result['borderline']==1
 assert result['model']['precision']==.5 and result['model']['cohort_recall']==.5 and result['model']['false_positive_rate']==1
 assert result['model']['misses_including_abstained']==1 and result['model']['abstained_or_unknown']==1
 assert result['paired_policy']['improved']==1 and result['paired_policy']['harmed']==0
 assert result['ai_only_score_crossings']['count']==1 and result['quality']['correlation']['unsupported']==4
 assert sum(b['count'] for b in result['confidence_bins'])==3

def test_client_claim_is_fixed_vocabulary_and_not_identity_feature():
 from evidence_history import normalize
 sample={'id':'a','seen':AT.isoformat(),'client':'curl','path':'/admin','method':'GET'}
 value=normalize('8.8.8.8','nginx','synthetic',sample,AT.isoformat());assert value['client_claim']['label']=='curl'
 spoof=normalize('8.8.8.8','nginx','synthetic',{**sample,'client':'Bearer super-secret'},AT.isoformat())
 assert 'client_claim' not in spoof and value['id']==spoof['id']
 assert profile({'events':[value]})['fingerprint']==profile({'events':[spoof]})['fingerprint']

def test_authenticated_routes_blind_initial_review_and_csrf(tmp_path):
 from app import create_app
 app=create_app({'database':str(tmp_path/'native'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'synthetic','hosts':['localhost']});app.testing=True
 b=Brain(app.store);packet(b,'old',hours=-3);packet(b,'new');inspect(b,'new')
 client=app.test_client();assert client.get('/behavior/evaluation').status_code in (302,401)
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('test','hash',1))
 with client.session_transaction() as session:session.update(user='test',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='test')
 for url in ('/behavior/evaluation','/behavior/activity','/behavior/activity/'+alerts(b)[0]['id']):assert client.get(url).status_code==200
 detail=client.get('/behavior/activity/'+alerts(b)[0]['id']).get_data(as_text=True)
 assert 'Sample gap' in detail and 'Observed request / action' in detail and 'operator' in detail
 assert client.post('/behavior/observations/new/evaluate',data={}).status_code==400
 response=client.post('/behavior/observations/new/evaluate',data={'csrf':'test'});assert response.status_code==302
 page=client.get(response.location);assert page.status_code==200 and b'Initial' not in page.data and b'Native score' not in page.data
