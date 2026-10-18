"""Isolated delivery mechanics, never production labels or model requests."""
import contextlib,copy,datetime as dt,json,sqlite3
import pytest
from core import Store
from behavior_ai import Brain,DEFAULTS,run
from evidence_history import query,normalize,collection_scope
from source_handoff import deliver,ready,indexed
from test_binding_receipts import proven
from test_source_observation_cache import AT,ADDRESS,samples,history

def ingest(s,values,seen=AT,**kw):
 s.source_activity(ADDRESS,'tpot','Cowrie',seen.isoformat(),{'activity':{'events':values},'native_event_count':17,'native_attempt_count':3},**kw)

def counts(s):
 with s.connect() as db:return [tuple(r) for r in db.execute('SELECT revision,id,received,delivered FROM source_sample_handoff ORDER BY revision')]

def test_replacement_metadata_only_revision_keeps_first_receipt_and_native_counts(tmp_path,monkeypatch):
 import core
 monkeypatch.setattr(core,'now',lambda:AT.isoformat())
 s=Store(tmp_path/'native');b=Brain(s);partial=samples()
 for v in partial:v['source_observation'].pop('connection_id',None);v['source_observation'].pop('connection_count',None)
 ingest(s,partial);assert deliver(b)['applied']==len(partial)
 old=history(b);before=s.describe(ADDRESS)
 monkeypatch.setattr(core,'now',lambda:(AT+dt.timedelta(minutes=1)).isoformat())
 ingest(s,proven());assert len(counts(s))==2*len(partial)
 after=s.describe(ADDRESS)
 for k in ('evidence','retention','score','native_score','sources','ports'):assert after.get(k)==before.get(k)
 assert after['activity'][0]['seen']==before['activity'][0]['seen']
 # A later bounded native subset omits the file before derived delivery runs.
 ingest(s,[proven()[0]])
 b=Brain(Store(s.path));result=deliver(b);assert result['applied']==len(partial)
 new=history(b);assert [(r['id'],r['received']) for r in new]==[(r['id'],r['received']) for r in old]
 with b.connect() as db:assert db.execute('SELECT count(*) FROM source_binding_receipts').fetchone()[0]==len(partial)
 assert all(json.loads(r['content'])['source_observation'].get('binding_proof') for r in new)
 before=counts(s);ingest(s,list(reversed(proven())));assert counts(s)==before
 assert deliver(Brain(Store(s.path)))['applied']==0

def test_derived_busy_does_not_block_native_commit_or_lose_receipts(tmp_path):
 s=Store(tmp_path/'native');b=Brain(s)
 lock=sqlite3.connect(b.path);lock.execute('BEGIN IMMEDIATE')
 try:
  ingest(s,proven());assert len(counts(s))==len(samples())
  assert deliver(b)['status']=='busy_retry_next_pass'
  assert all(not r[-1] for r in counts(s))
 finally:lock.rollback();lock.close()
 assert deliver(Brain(Store(s.path)))['applied']==len(samples())
 assert all(r[-1] for r in counts(s))

def test_crash_between_derived_commit_and_ack_replays_idempotently(tmp_path,monkeypatch):
 s=Store(tmp_path/'native');b=Brain(s);ingest(s,proven());connect=s.connect;calls=0
 @contextlib.contextmanager
 def interrupted(*a,**kw):
  nonlocal calls
  calls+=1
  if calls==2:raise sqlite3.OperationalError('simulated crash before native acknowledgement')
  with connect(*a,**kw) as db:yield db
 monkeypatch.setattr(s,'connect',interrupted)
 assert deliver(b)['status']=='busy_retry_next_pass'
 before=history(b);b=Brain(Store(s.path))
 assert deliver(b)['applied']==0 and history(b)==before
 assert all(r[-1] for r in counts(b.store))

@pytest.mark.parametrize('count',[0,2])
def test_real_reuse_receipt_invalidates_file_omitted_from_later_subset(tmp_path,count):
 s=Store(tmp_path/'native');b=Brain(s);ingest(s,proven());deliver(b)
 changed=proven(count=count,at=AT+dt.timedelta(minutes=1))
 ingest(s,[next(v for v in changed if v['id']=='zconn')]);deliver(b)
 with b.connect() as db:
  event=json.loads(db.execute("SELECT content FROM event_history WHERE json_extract(content,'$.provenance.upstream_id')='file'").fetchone()[0])
  assert event['source_observation']['connection_count']==count
  assert 'connection_id' not in event['source_observation']
 before=history(b);ingest(s,proven(at=AT+dt.timedelta(minutes=2)));deliver(b)
 with b.connect() as db:
  event=json.loads(db.execute("SELECT content FROM event_history WHERE json_extract(content,'$.provenance.upstream_id')='file'").fetchone()[0])
  assert 'connection_id' not in event['source_observation']
  assert db.execute("SELECT count(*) FROM source_binding_audit WHERE action LIKE 'session_%'").fetchone()[0]>0

def test_bounded_delivery_restart_scope_and_exact_ready_ack(tmp_path):
 from source_settings import effective
 s=Store(tmp_path/'native');b=Brain(s);cfg=effective(s,{'index_url':'https://index.example'})
 values=[{'id':'record'+str(i),'seen':AT.isoformat(),'action':'HTTP request','path':'/'} for i in range(520)]
 ingest(s,values[:500],source_cfg=cfg);ingest(s,values[500:],source_cfg=cfg)
 assert deliver(b,7)['read']==7 and len([r for r in counts(s) if r[-1]])==7
 pending=ready(b,cfg);assert ADDRESS in pending and not ready(b)
 assert not ready(b,cfg,addresses=['1.1.1.1'])
 assert deliver(b,5000)['read']==500
 indexed(b,ADDRESS,pending[ADDRESS],cfg);assert ready(b,cfg)[ADDRESS]>pending[ADDRESS]
 assert deliver(Brain(Store(s.path)))['read']==13
 with b.connect() as db:assert db.execute('SELECT count(*) FROM event_history WHERE scope=?',(collection_scope(b,cfg),)).fetchone()[0]==520

def test_capture_rolls_back_with_native_transaction_and_redacts(tmp_path):
 s=Store(tmp_path/'native');db=sqlite3.connect(s.path);db.row_factory=sqlite3.Row;s._worker_connection=db;s._batch_evidence=True
 ingest(s,[{'id':'event','seen':AT.isoformat(),'action':'HTTP request','path':'/token/PRIVATE?password=SECRET','raw_command':'PRIVATE','user_agent':'PRIVATE'}])
 db.rollback();s._worker_connection=None;s._batch_evidence=False;db.close();assert not counts(s)
 ingest(s,[None,{'seen':'invalid'},{'id':'event','seen':AT.isoformat(),'action':'HTTP request','path':'/token/PRIVATE?password=SECRET','raw_command':'PRIVATE'}])
 with s.connect() as db:
  raw=db.execute('SELECT content FROM source_sample_handoff').fetchone()[0]
  assert 'PRIVATE' not in raw and 'SECRET' not in raw and 'raw_command' not in raw

def test_normal_run_indexes_metadata_change_without_event_time_change(tmp_path):
 s=Store(tmp_path/'native');b=Brain(s)
 for address in ('1.1.1.1','8.8.4.4',ADDRESS,'9.9.9.9'):
  s.evidence(address,'tpot','Cowrie',AT.isoformat(),'ssh',50,'',{})
 partial=copy.deepcopy(proven())
 for v in partial:v['source_observation'].pop('binding_proof',None);v['source_observation'].pop('connection_count',None);v['source_observation'].pop('connection_id',None)
 ingest(s,partial);deliver(b)
 for row in s.all_scores():b.packet(s.describe(row['ip']),DEFAULTS)
 for address,revision in ready(b).items():indexed(b,address,revision)
 with b.connect() as db:old=db.execute('SELECT p.id,p.created FROM current_packets c JOIN packets p ON p.id=c.packet_id WHERE c.ip=?',(ADDRESS,)).fetchone();old_id=old['id'];assert old['created']>AT.isoformat()
 native_before=s.describe(ADDRESS);ingest(s,proven())
 s.state('behavior_settings',{'enabled':True,'model_enabled':False,'correlation_enabled':False,'batch_size':2})
 result=run(s,index_only=True)
 assert result['indexed']<=2 and result['source_sample_handoff']['applied']==len(samples())
 with b.connect() as db:
  new=db.execute('SELECT packet_id FROM current_packets WHERE ip=?',(ADDRESS,)).fetchone()[0]
  assert new!=old_id
  assert db.execute('SELECT count(*) FROM assessments').fetchone()[0]==0
 assert ADDRESS not in ready(b)
 assert s.describe(ADDRESS)['activity'][0]['seen']==native_before['activity'][0]['seen']
 assert s.describe(ADDRESS)['evidence']==native_before['evidence']
