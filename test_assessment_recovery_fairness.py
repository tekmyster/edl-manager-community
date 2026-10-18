"""Bounded recovery past retained review prefixes, with real restart/file SQLite."""
import hashlib,json,os,pathlib,sqlite3,subprocess,sys,time
import pytest
import behavior_ai as ai
import behavior_persistence as pending
import analytics_store as ledger
from test_behavior_drain import queue


def restart(b):
 code="from core import Store;from behavior_ai import Brain;from behavior_persistence import recover;import sys,json;print(json.dumps(recover(Brain(Store(sys.argv[1])))))"
 r=subprocess.run([sys.executable,'-c',code,str(b.store.path)],cwd=pathlib.Path(ai.__file__).parent,capture_output=True,text=True,timeout=25)
 assert r.returncode==0,r.stderr
 v=json.loads(r.stdout);assert v['entries_scanned']<=51 and v['scanned']<=50 and v['dispatch_markers_scanned']<=50
 return v


def snapshot_ledger(b):
 with ledger.connect(b.store) as db:return {t:[tuple(r) for r in db.execute('SELECT * FROM '+t+' ORDER BY 1')] for t in ('requests','request_recovery','counters')}


def setup_results(tmp_path,with_markers=False):
 s,b,cfg=queue(tmp_path,51);original={}
 for n in range(51):
  ident='packet'+str(n);owner='owner'+str(n);attempt=ledger.Attempt(s,ident);assert attempt.start();meta={'request_id':attempt.id,'input_tokens':23,'output_tokens':7,'request_seconds':.1};assert attempt.finish('accepted',meta)
  with b.connect() as db:db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(owner,ident,'config','running',time.time()+300,1,ai.now()))
  if with_markers:pending.reserve(b,ident,'config',owner,'assessment'+str(n),attempt.id)
  p=pending.stage(b,{'version':1,'row':['assessment'+str(n),ident,'config',ai.now(),'2099-01-01T00:00:00+00:00','completed',json.dumps({'metadata':meta}),'',.1],'owner':owner,'backoff_key':'fixture','backoff_previous':None,'backoff_at':time.time()});original[p.name]=p.read_bytes()
 with os.scandir(pending.directory(b)) as entries:ordered=[pathlib.Path(e.path) for e in entries if e.name.endswith('.json')]
 ready=pending.read(ordered[-1])
 with b.connect() as db:
  row=list(db.execute('SELECT * FROM packets WHERE id=?',(ready['row'][1],)).fetchone());address=row[1];row[0]='new-current';db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',row);db.execute('UPDATE current_packets SET packet_id=? WHERE ip=?',('new-current',address));db.execute('UPDATE analysis_queue SET packet_id=? WHERE ip=?',('new-current',address))
  for p in ordered[:50]:
   v=pending.read(p);db.execute('UPDATE jobs SET id=?,lease=? WHERE packet_id=? AND config_id=?',('successor-'+v['owner'],9999999999,v['row'][1],v['row'][2]))
  successors=[tuple(r) for r in db.execute("SELECT * FROM jobs WHERE id LIKE 'successor-%' ORDER BY id")]
 return b,ordered,original,ready,successors,address


@pytest.mark.parametrize('fresh_process',[False,True])
@pytest.mark.parametrize('with_markers',[False,True])
def test_more_than_fifty_review_results_cannot_starve_superseded_result(tmp_path,fresh_process,with_markers):
 b,ordered,original,ready,successors,address=setup_results(tmp_path,with_markers);before=snapshot_ledger(b);states=[]
 for _ in range(3):
  state=restart(b) if fresh_process else pending.recover(b);states.append(state);assert state['entries_scanned']<=51 and state['scanned']<=50 and state['dispatch_markers_scanned']<=50
 with b.connect() as db:
  rows=list(db.execute('SELECT * FROM assessments'));assert len(rows)==1;expected=list(ready['row']);expected[5]='superseded';assert list(rows[0])==expected
  assert [tuple(r) for r in db.execute("SELECT * FROM jobs WHERE id LIKE 'successor-%' ORDER BY id")]==successors
  own=db.execute('SELECT state,lease FROM jobs WHERE packet_id=?',(ready['row'][1],)).fetchone();assert tuple(own)==('superseded',0)
  assert db.execute('SELECT packet_id FROM analysis_queue WHERE ip=?',(address,)).fetchone()[0]=='new-current'
  assert db.execute('SELECT count(*) FROM usage').fetchone()[0]==0
 assert snapshot_ledger(b)==before and sum(s['saved'] for s in states)==1 and not list(pending.directory(b).glob('*.json'))
 for p in ordered[:50]:
  body=original[p.name];q=pending.review_key(b,p)/(hashlib.sha256(body).hexdigest()+'.json');assert q.read_bytes()==body
  if os.name=='posix':assert q.stat().st_mode&0o777==0o600 and q.parent.stat().st_mode&0o777==0o700
 again=restart(b);assert again['review_retained'] and again['saved']==0 and snapshot_ledger(b)==before


def test_more_than_fifty_expired_inflight_markers_cannot_hide_committed_marker(tmp_path):
 s,b,cfg=queue(tmp_path,51);original={}
 for n in range(51):
  ident='packet'+str(n);owner='owner'+str(n)
  with b.connect() as db:db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(owner,ident,'config','running',0,1,ai.now()))
  p=pending.reserve(b,ident,'config',owner,'assessment'+str(n),str(n).zfill(32));original[p.name]=p.read_bytes()
 with os.scandir(pending.directory(b)) as entries:ordered=[pathlib.Path(e.path) for e in entries if e.name.endswith('.inflight')]
 last=json.loads(ordered[-1].read_bytes())
 with b.connect() as db:
  db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',(last['assessment'],last['packet'],'config',ai.now(),'2099','completed','{}','',.1));db.execute('UPDATE jobs SET state=?,lease=0 WHERE id=?',('completed',last['owner']))
 states=[restart(b) for _ in range(3)];assert sum(v['uncertain_dispatches'] for v in states)==50 and all(v['review_retained'] for v in states)
 assert not list(pending.directory(b).glob('*.inflight'))
 for p in ordered[:50]:
  body=original[p.name];q=pending.review_key(b,p.with_suffix('.json'))/(hashlib.sha256(body).hexdigest()+'.inflight');assert q.read_bytes()==body
 with b.connect() as db:assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==1


def test_review_move_survives_unlink_failure_without_evidence_loss(tmp_path,monkeypatch):
 b,ordered,original,ready,successors,address=setup_results(tmp_path);p=ordered[0];unlink=pathlib.Path.unlink
 def fail(self,*args,**kw):
  if self==p:raise OSError('isolated pending unlink failure')
  return unlink(self,*args,**kw)
 with monkeypatch.context() as patch:
  patch.setattr(pathlib.Path,'unlink',fail)
  with pytest.raises(OSError):pending.persist(b,p)
 body=original[p.name];q=pending.review_key(b,p)/(hashlib.sha256(body).hexdigest()+'.json');assert p.read_bytes()==q.read_bytes()==body
 assert pending.persist(b,p)=='lease_lost' and not p.exists() and q.read_bytes()==body


def test_more_than_fifty_ready_pairs_progress_with_marker_prefix(tmp_path):
 s,b,cfg=queue(tmp_path,51)
 for n in range(51):
  owner='owner'+str(n);ident='packet'+str(n)
  with b.connect() as db:db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(owner,ident,'config','running',time.time()+300,1,ai.now()))
  pending.reserve(b,ident,'config',owner,'assessment'+str(n),str(n).zfill(32))
 for n in range(51):pending.stage(b,{'version':1,'row':['assessment'+str(n),'packet'+str(n),'config',ai.now(),'2099-01-01T00:00:00+00:00','completed','{}','',.1],'owner':'owner'+str(n),'backoff_key':'fixture','backoff_previous':None,'backoff_at':time.time()})
 states=[restart(b) for _ in range(3)];assert sum(v['saved'] for v in states)==51 and not any(v['review_retained'] for v in states)
 assert not list(pending.directory(b).glob('*.json')) and not list(pending.directory(b).glob('*.inflight'))
 with b.connect() as db:assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==51 and db.execute("SELECT count(*) FROM jobs WHERE lease!=0 OR state!='completed'").fetchone()[0]==0
