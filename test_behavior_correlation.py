from behavior_grounding import RELATION,ALTERNATIVE
"""Explicitly synthetic correlation fixtures; expectations are not reviewer labels."""
import copy,datetime as dt,json,time
import pytest
from core import Store
from behavior_ai import Brain
from behavior_correlation import retrieve,POSTING_LIMIT,TOKEN_LIMIT,POOL_LIMIT,VERSION
from test_behavior_ai import evidence

AT=dt.datetime(2026,10,16,18,tzinfo=dt.timezone.utc)

def packet(brain,ident,address,paths,extra=(),days=0,events=True):
 features={'path:'+p for p in paths}|set(extra)
 content={'coverage':'synthetic_partial','events':[{'id':ident+'-event-'+str(i),'seen':(AT-dt.timedelta(days=days,seconds=i)).isoformat(),'source':'synthetic','sensor':'fixture','path':p,'action':'scan','parameter_names':[]} for i,p in enumerate(paths)] if events else []}
 with brain.connect() as db:
  db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,address,(AT-dt.timedelta(days=days)).isoformat(),json.dumps(content),json.dumps(sorted(features)),0));brain.index_features(db,ident,features)
 return features

def fetch(brain,ident):
 with brain.connect() as db:return retrieve(db,ident,at=AT)

@pytest.mark.parametrize('name,peer_paths,extra,days,events,expected',[
 ('shared_scanner',['/login','/admin'],[],0,True,True),
 ('nat_proxy',['/login','/admin'],['sensor:other'],1,True,True),
 ('ownership_change',['/login','/admin'],['asn:changed'],180,True,True),
 ('partial_history',['/login'],[],2,True,False),
 ('clock_distortion',['/login','/admin'],['sequence:/admin -> /login'],2,True,True),
 ('generic_action',[],['action:scan','params:q'],0,True,False),
 ('common_root',['/','/login'],[],0,True,False),
 ('missing_citations',['/login','/admin'],[],0,False,False),
 ('outside_window',['/login','/admin'],[],366,True,False),
 ('future_index',['/login','/admin'],[],-1,True,False),
])
def test_synthetic_scenarios(tmp_path,name,peer_paths,extra,days,events,expected):
 b=Brain(Store(tmp_path/'manager.sqlite3'));packet(b,'current','192.0.2.1',['/login','/admin'],['action:scan','params:q'])
 packet(b,'peer','192.0.2.2',peer_paths,extra,days,events)
 result,details=fetch(b,'current');assert bool(result)==expected,name
 if expected:
  candidate=result[0];assert not any(v.startswith(('sensor:','method:','sequence:','asn:')) for v in candidate['shared_features'])
  assert candidate['candidate_id']=='peer' and len(candidate['current_events'])==2 and len(candidate['historical_events'])==2
  assert 'uncalibrated' in ' '.join(candidate['uncertainty']) and 'NAT' in ' '.join(candidate['uncertainty'])
  # Timing/ownership are not features which contribute positive similarity.
  assert candidate['similarity']==pytest.approx(2/2.7,abs=.001) if name=='clock_distortion' else candidate['similarity']>0
 assert details['version']==VERSION

def test_bounded_high_fanout_and_plan(tmp_path):
 b=Brain(Store(tmp_path/'manager.sqlite3'));packet(b,'own','192.0.2.1',['/a','/b'])
 for i in range(1500):packet(b,'synthetic-'+str(i),'198.51.'+str(i//250)+'.'+str(i%250+1),['/a','/b'])
 result,details=fetch(b,'own')
 assert len(result)==3 and details['postings_read']<=2*(POSTING_LIMIT+1) and details['pool_examined']<=POOL_LIMIT
 assert details['saturated_token_kinds']==['path']
 with b.connect() as db:
  plan=' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT packet_id FROM correlation_features WHERE feature=? AND created>=? AND created<=? ORDER BY created DESC,packet_id DESC LIMIT ?',('path:/a','2025','2027',129)))
 assert 'SEARCH' in plan and 'INDEX' in plan and 'TEMP B-TREE' not in plan

def test_stored_features_authoritative_unique_peer_and_rejected_state(evidence):
 b=Brain(evidence);row=evidence.describe('8.8.8.8');own,_,f=b.packet(row)
 for address in ('1.1.1.1','9.9.9.9'):
  peer=copy.deepcopy(row);peer['ip']=address;b.packet(peer)
 result=b.candidates(own,{'path:forged'})
 assert len(result)==2
 with b.connect() as db:link=db.execute('SELECT id FROM links LIMIT 1').fetchone()[0]
 b.review(link,'rejected','Synthetic test review, shared tooling','fixture')
 b.candidates(own,f)
 with b.connect() as db:assert db.execute('SELECT state FROM links WHERE id=?',(link,)).fetchone()[0]=='rejected'
 assert evidence.describe('8.8.8.8')['score']==row['score'] and not evidence.active_rules()

def test_incremental_index_and_replay(tmp_path):
 b=Brain(Store(tmp_path/'manager.sqlite3'));packet(b,'own','192.0.2.1',['/a','/b'])
 with b.connect() as db:db.execute('DELETE FROM correlation_ready');db.execute('DELETE FROM correlation_features')
 assert b.backfill_features(limit=1)==1 and fetch(b,'own')[1]['index_partial']
 assert b.backfill_features(limit=1)==0 and not fetch(b,'own')[1]['index_partial']
 with b.connect() as db:assert db.execute('SELECT count(*) FROM correlation_features').fetchone()[0]==2


def evaluation(path):
 """Reproducible scale/abstention evidence, not accuracy calibration."""
 import tempfile,pathlib,statistics
 with tempfile.TemporaryDirectory() as tmp:
  b=Brain(Store(pathlib.Path(tmp)/'manager.sqlite3'));packet(b,'own','192.0.2.1',['/login','/admin'],['action:scan','method:POST','sensor:a'])
  packet(b,'sparse','192.0.2.2',['/login','/admin'],['action:scan','method:GET','sensor:b'],days=180)
  start=time.perf_counter();candidate,details=fetch(b,'own');sparse_ms=(time.perf_counter()-start)*1000
  baseline_common=3;baseline_union=7
  sparse={'fixture':'synthetic partial history with changed metadata','old_jaccard':round(baseline_common/baseline_union,3),'old_threshold':.6,'old_returned':False,'new_returned':bool(candidate),'new_similarity':candidate[0]['similarity'] if candidate else None,'milliseconds':round(sparse_ms,3)}
  for i in range(3000):packet(b,'fanout-'+str(i),'198.51.'+str(i//250)+'.'+str(i%250+1),['/login','/admin'],['action:scan'])
  timings=[]
  for _ in range(20):
   start=time.perf_counter();candidate,details=fetch(b,'own');timings.append((time.perf_counter()-start)*1000)
  with b.connect() as db:
   count=db.execute('SELECT count(*) FROM packets').fetchone()[0]
   plan=[r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT packet_id FROM correlation_features WHERE feature=? AND created>=? AND created<=? ORDER BY created DESC,packet_id DESC LIMIT ?',('path:/login','2025','2027',129))]
  output={'kind':'explicit_synthetic_retrieval_evaluation','independent_reviewer_labels':0,'calibrated_accuracy':False,'sparse_history':sparse,'high_fanout':{'packets':count,'runs':20,'median_ms':round(statistics.median(timings),3),'max_ms':round(max(timings),3),'query_plan':plan,'retrieval':details},'limits':['Synthetic expectations test mechanics only; shared scanner and NAT matches remain candidates, not actor labels.','Bounded recent postings may miss old relevant windows; saturation is exposed.','No live model or production event injection.']}
  pathlib.Path(path).write_text(json.dumps(output,indent=2));print(json.dumps(output))

if __name__=='__main__':
 import sys
 evaluation(sys.argv[1])

def test_comparison_snapshot_and_rendered_lineage_are_reviewable(tmp_path):
 from app import create_app
 from core import now
 from behavior_groups import groups
 app=create_app({'database':str(tmp_path/'manager.sqlite3'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'synthetic','hosts':['localhost']});app.testing=True
 b=Brain(app.store);ids=[]
 before=app.store.state('behavior_settings')
 for i,address in enumerate(('8.8.8.8','1.1.1.1','9.9.9.9','8.8.4.4')):
  activity={'events':[{'id':'synthetic-'+str(i)+'-'+str(j),'seen':now(),'path':path,'action':'synthetic scan'} for j,path in enumerate(('/login','/admin'))]}
  app.store.evidence(address,'owapot','synthetic',now(),'http',0,details={'activity':activity})
  ident,_,f=b.packet(app.store.describe(address));ids.append(ident);b.candidates(ident,f)
 native_before={address:app.store.describe(address)['score'] for address in ('8.8.8.8','1.1.1.1','9.9.9.9','8.8.4.4')}
 def review(a,z,outcome):
  left,right=sorted((ids[a],ids[z]))
  with b.connect() as db:link=db.execute('SELECT id FROM links WHERE left_packet=? AND right_packet=?',(left,right)).fetchone()[0]
  b.review(link,outcome,'Synthetic fixture review; not an independent label','fixture')
 review(0,1,'accepted');review(2,3,'accepted');review(1,2,'accepted');review(1,2,'rejected')
 group=groups(b)[0]
 with b.connect() as db:snapshot=db.execute('SELECT details FROM correlation_link_evidence ORDER BY link_id').fetchall()
 for ident in ids:b.candidates(ident,{'path:forged'})
 with b.connect() as db:assert [r[0] for r in snapshot]==[r[0] for r in db.execute('SELECT details FROM correlation_link_evidence ORDER BY link_id')]
 c=app.test_client()
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('fixture','hash',1))
 with c.session_transaction() as session:session.update(user='fixture',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='synthetic')
 html=c.get('/behavior/groups/'+group['id'],base_url='https://localhost').get_data(as_text=True)
 assert 'Previous groups:' in html and 'Revision observations' in html and 'Historical window' in html and 'Compared window' in html and VERSION in html
 assert 'NAT' in html and 'No score or enforcement is inherited' in html
 html=c.get('/ip/8.8.8.8',base_url='https://localhost').get_data(as_text=True)
 assert 'Historical activity candidates' in html and 'uncalibrated' in html and 'Shared observations' in html
 import os,pathlib,re,shutil
 export=os.environ.get('CORRELATION_UI_DIR')
 if export:
  root=pathlib.Path(export);root.mkdir(exist_ok=True)
  pages={'ip.html':html,'group.html':c.get('/behavior/groups/'+group['id'],base_url='https://localhost').get_data(as_text=True)}
  for name,body in pages.items():
   body=re.sub(r'<script\b[^>]*>.*?</script>','',body,flags=re.S|re.I)
   body=re.sub(r'<form\b[^>]*>.*?</form>','<p>Fixture: review controls omitted.</p>',body,flags=re.S|re.I)
   body=body.replace('<main ', '<aside style="padding:12px;background:#fff4cf;color:#312500">Synthetic local UI fixture. No live data, independent labels or deployed UI claim.</aside><main ')
   body=body.replace('/behavior/groups/'+group['id'],'group.html').replace('/ip/8.8.8.8#behavior','ip.html#behavior')
   (root/name).write_text(body,encoding='utf8')
  shutil.copytree(pathlib.Path(__file__).parent/'static',root/'static',dirs_exist_ok=True)
 assert app.store.state('behavior_settings')==before and not app.store.active_rules()
 assert {address:app.store.describe(address)['score'] for address in native_before}==native_before


def test_feature_overlap_without_common_saved_paths_abstains(tmp_path):
 b=Brain(Store(tmp_path/'manager.sqlite3'))
 packet(b,'own','192.0.2.1',['/a','/b','/c','/d'])
 packet(b,'peer','192.0.2.2',['/a','/b','/c','/d'])
 with b.connect() as db:
  for ident,keep in [('own',{'/a','/b'}),('peer',{'/c','/d'})]:
   row=json.loads(db.execute('SELECT content FROM packets WHERE id=?',(ident,)).fetchone()[0]);row['events']=[e for e in row['events'] if e['path'] in keep]
   db.execute('UPDATE packets SET content=? WHERE id=?',(json.dumps(row),ident))
 assert not fetch(b,'own')[0]


from test_permanent_policy import timeline

def test_reviewed_correlation_does_not_transfer_permanent_or_ai_status(timeline):
 from test_permanent_policy import seed,hit
 from permanent_policy import active,view
 from behavior_scoring import apply
 store,clock=timeline;seed(store)
 for day in (30,60,90):hit(store,clock,day)
 clock.current=AT
 before=view(store,'8.8.8.8');assert before['earned']
 b=Brain(store);f=packet(b,'source','8.8.8.8',['/a','/b']);packet(b,'peer','1.1.1.1',['/a','/b'])
 assert b.candidates('source',f)
 with b.connect() as db:link=db.execute('SELECT id FROM links').fetchone()[0]
 b.review(link,'accepted','Synthetic review only','fixture')
 assert view(store,'8.8.8.8')==before and view(store,'1.1.1.1') is None
 assert set(active(store))=={'8.8.8.8'}
 peer=apply(store,[store.describe('1.1.1.1')])[0]
 assert peer['score']==0 and peer.get('ai_bump',0)==0


def test_model_match_requires_supporting_current_citation(evidence):
 from test_behavior_ai import result
 from behavior_ai import validate_result
 b=Brain(evidence);_,current,_=b.packet(evidence.describe('8.8.8.8'))
 current['events'][0].update(path='/shared-request',method='POST')
 candidate={'candidate_id':'synthetic-peer','current_events':[current['events'][0]],'historical_events':[{**current['events'][0],'id':'synthetic-historical'}]}
 verdict=result(current);verdict['actor_correlation']=[{'candidate_id':'synthetic-peer','confidence':.5,'evidence_ids':[current['events'][1]['id'],'synthetic-historical'],'explanation':RELATION,'alternative_explanations':[ALTERNATIVE]}]
 with pytest.raises(ValueError,match='supporting current'):validate_result(verdict,current,[candidate],{})
 verdict['actor_correlation'][0]['evidence_ids'][0]=current['events'][0]['id']
 assert validate_result(verdict,current,[candidate],{})==verdict
