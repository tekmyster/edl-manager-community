import datetime as dt,json,sqlite3
import pytest
from core import Store,now
from behavior_ai import Brain,DEFAULTS,config_id,model_job,run
from behavior_retention import cleanup,hold,backfill

OLD='2020-01-01T00:00:00+00:00'

def packet(db,ident,created=OLD):
 db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,'8.8.8.8',created,json.dumps({'events':[]}),json.dumps(['path:/a','path:/b']),0))

def sweep(b,n=12,batch=2):
 return [cleanup(b,{**DEFAULTS,'cleanup_batch':batch}) for _ in range(n)]

def test_expiry_preserves_review_revision_citations_current_holds_and_native(tmp_path):
 s=Store(tmp_path/'native');b=Brain(s)
 s.evidence('8.8.8.8','waf','test',now(),'http',75)
 with s.connect() as db:before=list(db.iterdump())
 with b.connect() as db:
  for ident in ('free','reviewed','peer','revision','current','held','cited','assessment-own'):packet(db,ident)
  db.execute('INSERT INTO current_packets VALUES(?,?)',('8.8.8.8','current'))
  db.execute('INSERT INTO links VALUES(?,?,?,?,?,?,?)',('rel','reviewed','peer',.8,'[]','rejected',OLD))
  db.execute('INSERT INTO reviews VALUES(?,?,?,?,?,?)',('rev','rel','rejected','Reviewed','admin',OLD))
  # Archived revisions must pin packets even if no current membership remains.
  db.execute('INSERT INTO behavior_group_revisions VALUES(?,?,?,?,?,?,?)',('revision-id','group',OLD,'admin','archived','[]','["revision"]'))
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('assessment','assessment-own','cfg',now(),'2099','completed','{"actor_correlation":[{"candidate_id":"cited"}]}','',1))
 hold(b,'packet','held','Open investigation')
 result=sweep(b)
 with b.connect() as db:
  assert {r[0] for r in db.execute('SELECT id FROM packets')}=={'reviewed','peer','revision','current','held','cited','assessment-own'}
  assert db.execute('SELECT count(*) FROM reviews').fetchone()[0]==1
  assert db.execute('SELECT count(*) FROM behavior_group_revisions').fetchone()[0]==1
  assert db.execute('SELECT count(*) FROM correlation_features').fetchone()[0]==0
 with s.connect() as db:assert list(db.iterdump())==before
 assert all(max(r['scanned'].values(),default=0)<=2 for r in result)

def test_unreferenced_assessment_link_and_children_expire_without_orphans(tmp_path):
 b=Brain(Store(tmp_path/'native'))
 with b.connect() as db:
  for ident in ('one','two'):packet(db,ident);b.index_features(db,ident,{'path:/a','path:/b'})
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('a','one','cfg',OLD,OLD,'completed','{"actor_correlation":[{"candidate_id":"two"}]}','',1))
  db.execute('INSERT INTO links VALUES(?,?,?,?,?,?,?)',('l','one','two',.8,'[]','proposed',OLD))
  db.execute('INSERT INTO correlation_link_evidence VALUES(?,?,?)',('l','test','{}'))
  db.execute('INSERT INTO usage VALUES(?,?)',(OLD[:10],2));db.execute('INSERT INTO usage VALUES(?,?)',(now()[:10],96))
 sweep(b)
 with b.connect() as db:
  for table in ('packets','assessments','links','retention_refs','packet_feature_index','correlation_features','correlation_ready','correlation_link_evidence'):
   assert db.execute('SELECT count(*) FROM '+table).fetchone()[0]==0,table
  assert db.execute('SELECT requests FROM usage').fetchone()[0]==96

def test_restartable_legacy_backfill_blocks_deletion_and_transaction_rolls_back(tmp_path):
 b=Brain(Store(tmp_path/'native'))
 with b.connect() as db:
  db.execute('DROP TRIGGER retention_assessment_insert')
  packet(db,'own');packet(db,'peer')
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('a','own','cfg',now(),'2099','completed','{"actor_correlation":[{"candidate_id":"peer"}]}','',1))
 assert not cleanup(b,{**DEFAULTS,'cleanup_batch':1})['reference_index_ready']
 b=Brain(b.store);sweep(b,batch=1)
 with b.connect() as db:assert db.execute('SELECT count(*) FROM packets').fetchone()[0]==2
 with pytest.raises(RuntimeError):
  with b.connect() as db:
   db.execute('BEGIN IMMEDIATE');db.execute('DELETE FROM assessments');db.execute("DELETE FROM retention_state");raise RuntimeError('interrupted')
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==1
  assert db.execute('SELECT count(*) FROM retention_refs').fetchone()[0]==2
  assert db.execute('SELECT count(*) FROM retention_state').fetchone()[0]>0

def test_held_assessment_retains_own_and_peer_packet_and_cleanup_uses_indexes(tmp_path):
 b=Brain(Store(tmp_path/'native'))
 with b.connect() as db:
  packet(db,'own');packet(db,'peer')
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('a','own','cfg',OLD,OLD,'completed','{"metadata":{"supplied_packet_ids":["peer"]}}','',1))
 hold(b,'assessment','a','Investigation')
 sweep(b)
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM packets').fetchone()[0]==2
  plan=' '.join(str(tuple(r)) for r in db.execute('EXPLAIN QUERY PLAN SELECT * FROM packets WHERE created<? AND (created,id)>(?,?) ORDER BY created,id LIMIT 2',('2026','','')))
  assert 'packets_retention' in plan and 'SEARCH' in plan
  assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'

def test_retention_settings_do_not_invalidate_model_cache():
 assert config_id(DEFAULTS)==config_id({**DEFAULTS,'cleanup_batch':1,'packet_retention_days':180})

def test_real_cleanup_failure_rolls_back_deletions_and_cursors_then_recovers(tmp_path):
 b=Brain(Store(tmp_path/'native'))
 with b.connect() as db:
  packet(db,'old')
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('a','old','cfg',OLD,OLD,'failed','{}','TimeoutError',1))
  backfill(db,100);backfill(db,100)
  db.execute("CREATE TRIGGER interrupt_cleanup BEFORE DELETE ON packets BEGIN SELECT RAISE(ABORT,'interrupted'); END")
 with b.connect() as db:before=list(db.iterdump())
 with pytest.raises(sqlite3.IntegrityError,match='interrupted'):cleanup(b,DEFAULTS)
 with b.connect() as db:
  assert list(db.iterdump())==before
  db.execute('DROP TRIGGER interrupt_cleanup')
 cleanup(b,DEFAULTS)
 with b.connect() as db:assert db.execute('SELECT count(*) FROM packets').fetchone()[0]==0

def test_sweep_advances_past_protected_old_pages_and_respects_live_leases(tmp_path):
 b=Brain(Store(tmp_path/'native'))
 with b.connect() as db:
  for i in range(9):packet(db,str(i))
  db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',('job','8','cfg','running',dt.datetime.now(dt.timezone.utc).timestamp()+300,1,OLD))
 for i in range(6):hold(b,'packet',str(i),'Protected old investigation')
 sweep(b,n=10,batch=2)
 with b.connect() as db:
  assert {r[0] for r in db.execute('SELECT id FROM packets')}=={'0','1','2','3','4','5','8'}
  assert db.execute('SELECT count(*) FROM jobs').fetchone()[0]==1

@pytest.mark.parametrize('key,value',[('packet_retention_days','29'),('assessment_retention_days','3651'),('metrics_retention_days','bad'),('cleanup_batch','501')])
def test_retention_validation(key,value):
 from behavior_ai import validate_settings
 with pytest.raises(ValueError):validate_settings({key:value})

def test_investigation_hold_requires_auth_csrf_and_renders_limits(tmp_path):
 from app import create_app
 app=create_app({'database':str(tmp_path/'manager'),'output':str(tmp_path/'out'),'session_secret':'test','hosts':['localhost']});app.testing=True;c=app.test_client();b=Brain(app.store)
 with b.connect() as db:packet(db,'saved')
 route='/behavior/observations/saved/retain'
 assert c.post(route,base_url='https://localhost').status_code in (302,400)
 with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
 with c.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 assert c.post(route,base_url='https://localhost',data={'reason':'Case'}).status_code==400
 response=c.post(route,base_url='https://localhost',data={'csrf':'csrf','reason':'Case'})
 assert response.status_code==302
 with b.connect() as db:assert db.execute('SELECT reason FROM retention_holds').fetchone()[0]=='Case'
 page=c.get('/behavior',base_url='https://localhost').text
 assert 'name="packet_retention_days"' in page and 'Awaiting AI inspection' in page
 assert 'Native evidence and block history keep their own policy' in page

def test_provider_failure_backs_off_other_packets_without_consuming_quota(tmp_path,monkeypatch):
 import behavior_ai
 s=Store(tmp_path/'native');b=Brain(s)
 with b.connect() as db:packet(db,'one');packet(db,'two')
 cfg={**DEFAULTS,'model':'test'}
 monkeypatch.setattr(behavior_ai,'infer',lambda *a:(_ for _ in ()).throw(TimeoutError()))
 assert model_job(b,'one',{'events':[]},set(),cfg)=='failed'
 assert model_job(b,'two',{'events':[]},set(),cfg)=='backoff'
 with b.connect() as db:assert db.execute('SELECT requests FROM usage').fetchone()[0]==1

def test_queue_drains_oldest_first_even_when_indexing_moves_on(tmp_path,monkeypatch):
 import behavior_ai
 s=Store(tmp_path/'native');b=Brain(s);cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'batch_size':2,'correlation_enabled':False}
 s.state('behavior_settings',cfg)
 for i in range(1,7):s.evidence('8.8.8.'+str(i),'waf','test',now(),'http',75)
 calls=[]
 def model(brain,ident,packet,features,cfg,**kwargs):calls.append(ident);return 'completed'
 monkeypatch.setattr(behavior_ai,'model_job',model)
 # Seed older pending work that is not in this indexing batch.
 oldrow=s.describe('8.8.8.6');ident=b.packet(oldrow)[0]
 with b.connect() as db:db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',('8.8.8.6',ident,OLD))
 run(s,index_only=True)
 assert calls==[]
 run(s)
 assert calls[0]==ident and len(calls)==2
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM queue_samples').fetchone()[0]==2
  assert db.execute('SELECT wait_seconds FROM queue_samples ORDER BY id LIMIT 1').fetchone()[0]>86400

def test_stale_queue_is_removed_without_quota_or_inference(tmp_path,monkeypatch):
 import behavior_ai
 s=Store(tmp_path/'native');b=Brain(s);s.state('behavior_settings',{**DEFAULTS,'enabled':True,'model_enabled':True})
 with b.connect() as db:
  packet(db,'stale');db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',('8.8.8.8','stale',OLD))
 monkeypatch.setattr(behavior_ai,'model_job',lambda *a,**k:pytest.fail('Stale evidence dispatched'))
 assert run(s)['analysis']=={'stale_evidence':1}
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM usage').fetchone()[0]==0

def test_queue_cap_defers_new_work_without_affecting_native_scores(tmp_path):
 s=Store(tmp_path/'native');b=Brain(s);s.state('behavior_settings',{**DEFAULTS,'enabled':True,'model_enabled':True,'batch_size':2})
 s.evidence('8.8.8.8','waf','test',now(),'http',75);before=s.describe('8.8.8.8')['score']
 with b.connect() as db:
  packet(db,'pending')
  db.executemany('INSERT INTO analysis_queue VALUES(?,?,?)',[(str(i),'pending',now()) for i in range(10000)])
 run(s,index_only=True)
 with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==10000
 assert s.describe('8.8.8.8')['score']==before

def test_changed_priority_cannot_starve_fair_sweep(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');s.state('behavior_settings',{**DEFAULTS,'enabled':True,'batch_size':4,'correlation_enabled':False})
 future=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=1)).isoformat()
 for i in range(1,9):s.evidence('8.8.8.'+str(i),'waf','fixture',future,'http',75)
 visited=set();original=Brain.packet
 def capture(self,row,*args,**kwargs):visited.add(row['ip']);return original(self,row,*args,**kwargs)
 monkeypatch.setattr(Brain,'packet',capture)
 for _ in range(4):run(s,index_only=True)
 assert visited=={'8.8.8.'+str(i) for i in range(1,9)}
