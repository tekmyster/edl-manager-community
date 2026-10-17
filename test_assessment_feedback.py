"""Synthetic human-rating mechanics, never production ratings or model calls."""
import copy,json,sqlite3,os,pathlib
import pytest
from core import now
from behavior_evaluation import capture,cases,label,report
from behavior_feedback import save,report as feedback_report
from test_behavior_evaluation_context import app_fixture,review_form
from test_behavior_intelligence import packet
from test_behavior_ai import result

def case(brain,ident='p',reviewed=True):
 p=packet(brain,ident);assessment=result(p);assessment['findings']=[{'summary':'Synthetic source observation','evidence_ids':[p['events'][0]['id']]}]
 with brain.connect() as db:db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',(ident+'-answer',ident,'synthetic',now(),'2099-01-01T00:00:00+00:00','completed',json.dumps(assessment),'',0))
 ident=capture(brain,ident)
 if reviewed:label(brain,ident,review_form(attack='supported'),'fixture')
 return cases(brain,ident)[0]

def form(c,rating='helpful',ids=None,**kw):
 return {'csrf':'fixture','assessment_id':c['assessment_id'],'rating':rating,'evidence_ids':[c['snapshot']['packet']['events'][0]['id']] if ids is None else ids,'rationale':'Synthetic: identifies a cited detail that changes the next investigation step.',**kw}

def test_append_only_ratings_are_independent_of_labels_support_and_native_policy(tmp_path):
 app,client,b=app_fixture(tmp_path);c=case(b);before=copy.deepcopy(c['snapshot'])
 with b.connect() as db:oldlabels=[tuple(r) for r in db.execute('SELECT * FROM evaluation_labels')];oldassessments=[tuple(r) for r in db.execute('SELECT * FROM assessments')]
 native=app.store.describe('8.8.8.8');save(b,c['id'],form(c,'not_helpful',ids=[]),'reviewer-A')
 label(b,c['id'],review_form(attack='supported'),'fixture')
 assert feedback_report(b)['not_helpful']==1 and report(b)['quality']['attack']['supported']==1
 save(b,c['id'],form(c),'reviewer-B');found=cases(b,c['id'])[0]
 assert len(found['feedback'])==2 and found['feedback'][0]['reviewer']=='reviewer-B'
 assert feedback_report(b)['helpful_rate']==1 and feedback_report(b)['rated']==1
 label(b,c['id'],review_form(attack='unsupported'),'fixture')
 assert report(b)['quality']['attack']['unsupported']==1 and feedback_report(b)['helpful']==1
 assert found['snapshot']==before and app.store.describe('8.8.8.8')==native
 with b.connect() as db:
  assert [tuple(r) for r in db.execute('SELECT * FROM assessments')]==oldassessments
  assert [tuple(r) for r in db.execute('SELECT * FROM evaluation_labels')][:len(oldlabels)]==oldlabels
  for sql in ('UPDATE assessment_feedback SET rating="uncertain"','DELETE FROM assessment_feedback'):
   with pytest.raises(sqlite3.IntegrityError,match='append-only'):db.execute(sql)

@pytest.mark.parametrize('mutation',[
 lambda c:form(c,ids=[]),lambda c:form(c,ids=['foreign']),lambda c:form(c,ids=[c['snapshot']['packet']['events'][0]['id']]*2),
 lambda c:form(c,assessment_id='other-answer'),lambda c:form(c,rating='supported'),lambda c:form(c,rationale=''),
 lambda c:form(c,ids=[str(i) for i in range(13)]),
])
def test_invalid_or_foreign_provenance_never_writes_rating(tmp_path,mutation):
 app,client,b=app_fixture(tmp_path);c=case(b)
 with pytest.raises(ValueError):save(b,c['id'],mutation(c),'fixture')
 assert feedback_report(b)['unrated']==1 and feedback_report(b)['helpful_rate'] is None

def test_blind_initial_review_unknown_assessment_and_no_inferred_prior_ratings(tmp_path):
 app,client,b=app_fixture(tmp_path);c=case(b,reviewed=False);url='/behavior/evaluation/'+c['id']
 assert 'name="rating"' not in client.get(url).get_data(as_text=True)
 with pytest.raises(ValueError,match='initial independent label'):save(b,c['id'],form(c),'fixture')
 label(b,c['id'],review_form(),'fixture');label(b,c['id'],review_form(attack='supported'),'fixture')
 assert feedback_report(b)['unrated']==1 and feedback_report(b)['rated']==0 and feedback_report(b)['helpful_rate'] is None
 packet(b,'unassessed');unknown=capture(b,'unassessed');label(b,unknown,review_form(),'fixture')
 assert 'No completed assessment' in client.get('/behavior/evaluation/'+unknown).get_data(as_text=True)
 with pytest.raises(ValueError):save(b,unknown,form(c),'fixture')
 assert feedback_report(b)['eligible_assessments']==1

def test_frozen_citations_not_new_live_observations_and_snapshot_mutation_excluded(tmp_path):
 app,client,b=app_fixture(tmp_path);c=case(b);save(b,c['id'],form(c),'fixture')
 live=copy.deepcopy(c['snapshot']['packet']);live['events'][0]['id']='later-live-record'
 with b.connect() as db:db.execute('UPDATE packets SET content=? WHERE id=?',(json.dumps(live),'p'))
 with pytest.raises(ValueError):save(b,c['id'],form(c,ids=['later-live-record']),'fixture')
 assert feedback_report(b)['helpful']==1
 # Simulated corrupt legacy snapshot cannot relabel existing feedback provenance.
 modified=copy.deepcopy(c['snapshot']);modified['limitations'].append('synthetic mutation')
 with b.connect() as db:db.execute('UPDATE evaluation_cases SET snapshot=? WHERE id=?',(json.dumps(modified),c['id']))
 r=feedback_report(b);assert r['helpful']==0 and r['unrated']==1 and r['invalid_provenance_rows']==1
 with b.connect() as db:assert db.execute('SELECT count(*) FROM assessment_feedback').fetchone()[0]==1

def test_dashboard_analytics_json_and_review_drilldowns_reconcile(tmp_path):
 app,client,b=app_fixture(tmp_path);items=[case(b,'p'+str(i)) for i in range(5)]
 for c,rating in zip(items,('helpful','helpful','not_helpful','uncertain')):save(b,c['id'],form(c,rating,ids=[] if rating!='helpful' else None),'fixture')
 expected=feedback_report(b)
 assert (expected['helpful'],expected['not_helpful'],expected['rated'],expected['uncertain'],expected['unrated'],expected['eligible_assessments'],expected['helpful_rate'])==(2,1,3,1,1,5,.6667)
 assert report(b)['usefulness']==expected
 data=client.get('/analytics/data',base_url='https://localhost');assert data.status_code==200 and data.headers['Cache-Control']=='no-store'
 assert data.json['usefulness']==expected
 pages={url:client.get(url,base_url='https://localhost').get_data(as_text=True) for url in ('/','/analytics','/behavior/evaluation','/behavior/evaluation/'+items[0]['id'])}
 for url in ('/','/analytics','/behavior/evaluation'):
  assert '66.7%' in pages[url] and '2 / 3 helpful' in pages[url] and '1 uncertain' in pages[url] and '1 unrated' in pages[url]
  assert '/behavior/evaluation#assessment-feedback' in pages[url]
 page=pages['/behavior/evaluation/'+items[0]['id']];assert 'name="rating"' in page and 'Supported / useful' not in page
 from test_chart_copy import Page
 section=next(n for n in Page(page).root.walk() if n.attrs.get('id')=='assessment-feedback')
 parent=section.parent
 while parent and 'evaluation-case' not in parent.attrs.get('class','').split():parent=parent.parent
 assert parent is not None,'Feedback must inherit the responsive evaluation form layout'
 url='/behavior/evaluation/'+items[0]['id']+'/feedback'
 assert client.post(url,data={**form(items[0]),'csrf':'wrong'}).status_code==400
 assert client.post(url,data=form(items[0],'uncertain')).status_code==302
 with client.session_transaction() as session:session.clear()
 assert client.post(url,data=form(items[0])).status_code in (302,401,400)
 if os.environ.get('INTELLIGENCE_UI_EXPORT'):
  folder=pathlib.Path(os.environ['INTELLIGENCE_UI_EXPORT']);folder.mkdir(exist_ok=True)
  for url,name in [('/','feedback-dashboard.html'),('/analytics','feedback-analytics.html'),('/behavior/evaluation','feedback-reviews.html'),('/behavior/evaluation/'+items[0]['id'],'feedback-case.html')]:
   (folder/name).write_text(pages[url],encoding='utf-8')

def test_reporting_busy_is_unknown_not_zero_success(tmp_path,monkeypatch):
 app,client,b=app_fixture(tmp_path)
 def fail(*a):raise sqlite3.OperationalError('synthetic busy')
 monkeypatch.setattr('behavior_feedback.report',fail)
 from production_analytics import summary
 assert summary(b)['usefulness']=={'available':False,'helpful_rate':None}
