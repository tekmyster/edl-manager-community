"""Real isolated SQLite and actual worker owners; all external inputs are stubs."""
import contextlib,datetime as dt,importlib,json,os,pathlib,sqlite3,sys,types,subprocess,time
import pytest
from core import Store,now
from behavior_ai import Brain
UTC=dt.timezone.utc

@pytest.fixture
def w(monkeypatch):
 if os.name=='nt' and 'worker' not in sys.modules:
  # Windows can exercise actual owner/SQL code; real flock/publication tests
  # below run on Linux. Never substitute native locking on the target.
  with monkeypatch.context() as patch:
   patch.setitem(sys.modules,'fcntl',types.SimpleNamespace(flock=lambda *a:None,LOCK_EX=1,LOCK_NB=2))
   if importlib.util.find_spec('maxminddb') is None:
    def missing(*a):raise AssertionError('Stub the isolated local ASN input explicitly')
    patch.setitem(sys.modules,'maxminddb',types.SimpleNamespace(open_database=missing))
   module=importlib.import_module('worker')
 else:module=importlib.import_module('worker')
 return module

@pytest.fixture(autouse=True)
def isolated_network_and_wait(monkeypatch):
 import socket
 def forbidden(*a,**k):raise AssertionError('Isolated tests forbid all network/model calls')
 monkeypatch.setattr(socket.socket,'connect',forbidden)
 original=sqlite3.connect
 class Short(sqlite3.Connection):
  def execute(self,sql,*a,**k):
   if sql=='PRAGMA busy_timeout=30000':sql='PRAGMA busy_timeout=5'
   return super().execute(sql,*a,**k)
 def connect(*a,**k):k.setdefault('factory',Short);return original(*a,**k)
 monkeypatch.setattr(sqlite3,'connect',connect)

def owner(w,s,tmp_path,monkeypatch,fast=True,build=False):
 cfg={'database':str(s.path),'output':str(tmp_path/'out'),'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','incremental_ingest':True,'palo_location':'','asn_database':'fixture','providers_file':str(tmp_path/'keys'),'crawler_feed_file':str(tmp_path/'crawler-feeds.json'),'greynoise_transport':'ops'}
 p=tmp_path/'config.json';p.write_text(json.dumps(cfg));monkeypatch.setenv('EDL_CONFIG',str(p));monkeypatch.setattr(sys,'argv',['worker']+(['--ingest-only'] if fast else ['--enrich-only']))
 monkeypatch.setattr(w,'Store',lambda path:s)
 import source_types
 monkeypatch.setattr(source_types,'refresh',lambda store:0)
 if not build:monkeypatch.setattr(s,'build',lambda *a,**k:{'created':now()})
 return cfg

def state(s,key):return s.state(key)
def count(s,table):
 with s.connect() as d:return d.execute('SELECT count(*) FROM '+table).fetchone()[0]
def addresses(n):return ['11.0.'+str(i//250)+'.'+str(i%250+1) for i in range(n)]
def inputs(w,s,monkeypatch,n=105,activity=False):
 s.state('source_configuration',{'index_url':'https://fixture.invalid','sources':{'nginx':'*'},'palo_location':''})
 seen=now();buckets=[]
 for address in addresses(n):
  data={'edl_seen_utc':seen,'edl_qualifying':'no' if activity else 'yes','edl_path_hashes':'/fixture','edl_native_event_count':'1'}
  if activity:data['edl_activity_json']=json.dumps({'events':[{'id':address,'seen':seen,'path':'/fixture'}]})
  buckets.append({'key':{'ip':address,'source':'nginx','detector':'sensitive-path-probe'},'doc_count':1,'last':{'hits':{'hits':[{'_source':{'data':data,'timestamp':seen,'agent':{'name':'fixture'}}}]}}})
 class Session:
  def mount(self,*a):pass
  def post(self,*a,**k):return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'aggregations':{'items':{'buckets':buckets}}})
 monkeypatch.setattr(w.requests,'Session',Session)
 monkeypatch.setattr(w.ssl,'create_default_context',lambda **k:types.SimpleNamespace(verify_flags=0))
 return buckets

@pytest.mark.parametrize('fail_at',[99,100,101])
def test_actual_main_collect_100_boundary_rollback_and_ordinary_replay(w,tmp_path,monkeypatch,fail_at):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);inputs(w,s,monkeypatch)
 original=w.ingest_source;calls=[0];primary=OSError('private fixture message')
 def ingest(*a,**k):
  result=original(*a,**k);calls[0]+=1
  if calls[0]==fail_at:raise primary
  return result
 monkeypatch.setattr(w,'ingest_source',ingest)
 with pytest.raises(OSError) as caught:w.main()
 assert caught.value is primary and count(s,'evidence')==fail_at//100*100
 assert s._pipeline_receipts=={'invalidated':True} and s._evidence_pending==0 and s._worker_connection is None and s._batch_evidence is False
 saved=state(s,'ingest_status');assert saved['status']=='error' and 'evidence_buckets' not in saved and 'private fixture' not in json.dumps(saved)
 assert state(s,'native_ingest_cursor') is None
 monkeypatch.setattr(w,'ingest_source',original);w.main()
 assert count(s,'evidence')==105 and state(s,'native_ingest_cursor')['mode']=='bounded_daily_partitions' and state(s,'ingest_status')['status']=='partial'

@pytest.mark.parametrize('after',[False,True])
@pytest.mark.parametrize('activity',[False,True])
def test_actual_collect_cursor_commit_and_source_activity_only(w,tmp_path,monkeypatch,after,activity):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);inputs(w,s,monkeypatch,n=12,activity=activity)
 original=s.state;primary=TypeError('fixture outside context');fired=[False]
 def save(key,value=None):
  if key=='native_ingest_cursor' and value is not None and not fired[0]:
   fired[0]=True
   if after:original(key,value)
   raise primary
  return original(key,value)
 monkeypatch.setattr(s,'state',save)
 with pytest.raises(TypeError) as caught:w.main()
 assert caught.value is primary
 # Lane data/checkpoint already committed before the compatibility cursor mirror.
 assert count(s,'source_activity' if activity else 'evidence')==12
 assert state(s,'ingest_partition_native_live')['through']
 assert bool(state(s,'native_ingest_cursor'))==after
 assert 'evidence_buckets' not in state(s,'ingest_status')
 monkeypatch.setattr(s,'state',original);w.main()
 assert count(s,'source_activity' if activity else 'evidence')==12
 if activity:assert count(s,'evidence')==0 and count(s,'source_sample_handoff')==12

def test_actual_two_page_source_only_commit_before_next_fetch_and_replay(w,tmp_path,monkeypatch):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);buckets=inputs(w,s,monkeypatch,n=8,activity=True);fail=[True]
 class Session:
  def mount(self,*a):pass
  def post(self,*a,**k):
   second=bool(k['json']['aggs']['items']['composite'].get('after'))
   if second and fail[0]:raise TimeoutError('fixture next-page fetch failure')
   items={'buckets':buckets[4:] if second else buckets[:4]}
   if not second:items['after_key']={'page':'second'}
   return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'aggregations':{'items':items}})
 monkeypatch.setattr(w.requests,'Session',Session)
 w.main() # one bounded page, checkpointed before the next timer pass
 assert state(s,'ingest_partition_native_live')['pending']['after']=={'page':'second'}
 with pytest.raises(TimeoutError):w.main()
 assert count(s,'source_activity')==4 and count(s,'evidence')==0 and state(s,'native_ingest_cursor') is None
 assert state(s,'ingest_status')['last_direct_commit_boundary']=='native_page_before_fetch' and 'ingestion_committed' not in state(s,'ingest_status')
 fail[0]=False;w.main()
 assert count(s,'source_activity')==8 and count(s,'source_sample_handoff')==8 and state(s,'native_ingest_cursor')

def test_actual_pre_network_direct_commit_failure_owner_rollback(w,tmp_path,monkeypatch):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);inputs(w,s,monkeypatch,n=1)
 original=w.sqlite3.connect
 fired=[False]
 class Failing(sqlite3.Connection):
  def commit(self):
   if s._worker_last_direct_commit=='native_page_before_fetch' and not fired[0]:
    fired[0]=True;raise OSError('fixture direct commit')
   return super().commit()
 def connection(*a,**k):k['factory']=Failing;return original(*a,**k)
 monkeypatch.setattr(w.sqlite3,'connect',connection)
 with pytest.raises(OSError,match='direct commit'):w.main()
 assert count(s,'evidence')==0 and s._pipeline_receipts=={'invalidated':True}
 assert state(s,'ingest_status')['last_direct_commit_boundary']=='native_page_before_fetch'

@pytest.mark.parametrize('mechanism',['writer','snapshot','commit','shared'])
def test_actual_SQLite_owner_contention_rolls_back_before_defer(w,tmp_path,monkeypatch,mechanism):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch)
 if mechanism=='shared':
  original=sqlite3.connect
  def connect(path,*a,**k):
   if str(path)==str(s.path):path='file:'+str(path)+'?cache=shared';k['uri']=True
   return original(path,*a,**k)
  monkeypatch.setattr(sqlite3,'connect',connect)
 if mechanism=='commit':
  d=sqlite3.connect(s.path);assert d.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete';d.close()
 held=[]
 def collect(*a,**k):
  if mechanism=='snapshot':
   s._worker_connection.execute('BEGIN');s._worker_connection.execute('SELECT * FROM state').fetchall()
   d=sqlite3.connect(s.path);d.execute("INSERT INTO state VALUES('other_committed','1')");d.commit();d.close()
   s.state('cannot_upgrade',{})
  elif mechanism=='shared':
   d=sqlite3.connect(s.path);d.execute('BEGIN');d.execute('SELECT * FROM state').fetchall();held.append(d);s.state('blocked',{})
  elif mechanism=='writer':
   d=sqlite3.connect(s.path);d.execute('BEGIN IMMEDIATE');held.append(d);s.state('blocked',{})
  else:
   with s.connect(commit=False) as d:d.execute("INSERT INTO state VALUES('pending_fixture','1')")
   reader=sqlite3.connect(s.path);reader.execute('BEGIN');reader.execute('SELECT * FROM state').fetchall();held.append(reader)
   s._worker_last_direct_commit='fixture_direct_commit';s._worker_connection.commit()
  pytest.fail('Contention did not occur')
 monkeypatch.setattr(w,'collect',collect)
 result=w.main()
 for d in held:d.rollback();d.close()
 assert result['status']=='deferred' and result['sqlite_code']==({'snapshot':517,'shared':262}.get(mechanism,5))
 assert state(s,'pending_fixture') is None and state(s,'blocked') is None and s._pipeline_receipts=={'invalidated':True}

def test_actual_collect_evidence_100_direct_commit_BUSY_and_replay(w,tmp_path,monkeypatch,caplog):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch);inputs(w,s,monkeypatch)
 d=sqlite3.connect(s.path);assert d.execute('PRAGMA journal_mode=DELETE').fetchone()[0]=='delete';d.close()
 original=sqlite3.connect;held=[]
 class CommitBoundary(sqlite3.Connection):
  def execute(self,q,*a,**k):return super().execute('PRAGMA busy_timeout=5' if q=='PRAGMA busy_timeout=30000' else q,*a,**k)
  def commit(self):
   if s._worker_last_direct_commit=='evidence_100' and not held:
    reader=original(s.path);reader.execute('BEGIN');reader.execute('SELECT * FROM evidence').fetchall();held.append(reader)
   return super().commit()
 def connect(*a,**k):k['factory']=CommitBoundary;return original(*a,**k)
 monkeypatch.setattr(sqlite3,'connect',connect)
 result=w.main()
 for d in held:d.rollback();d.close()
 assert result['status']=='deferred' and result['sqlite_code']==5 and result['last_direct_commit_boundary']=='evidence_100'
 assert 'status=deferred' in caplog.text and 'last_direct_commit=evidence_100' in caplog.text and 'pending_transaction=rolled_back' in caplog.text
 assert count(s,'evidence')==0 and state(s,'native_ingest_cursor') is None
 monkeypatch.setattr(sqlite3,'connect',original);w.main()
 assert count(s,'evidence')==105 and state(s,'ingest_status')['status']=='partial'

@pytest.mark.parametrize('code',[5,517,262,8,None,True])
def test_owner_only_real_numeric_contention_defers_and_secondary_preserves_primary(w,tmp_path,monkeypatch,code):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch)
 primary=sqlite3.OperationalError('locked fixture, not classification')
 if code is not None:primary.sqlite_errorcode=code
 def collect(*a,**k):
  with s.connect(commit=False) as d:d.execute("INSERT INTO state VALUES('pending_fixture','1')")
  raise primary
 monkeypatch.setattr(w,'collect',collect)
 # A genuine sqlite exception subclass and its numeric code are the API; real
 # held-writer/517/commit fixtures below establish mechanisms separately.
 if type(code) is int and code&255 in (5,6):assert w.main()['status']=='deferred'
 else:
  with pytest.raises(sqlite3.OperationalError) as caught:w.main()
  assert caught.value is primary
 assert state(s,'pending_fixture') is None
 original=s.state
 def fail_status(key,value=None):
  if value and value.get('status') in ('error','deferred'):raise sqlite3.OperationalError('secondary uncoded schema failure')
  return original(key,value)
 monkeypatch.setattr(s,'state',fail_status)
 with pytest.raises(sqlite3.OperationalError) as caught:w.main()
 assert caught.value is primary

@pytest.mark.parametrize('failure',['before_cache','after_cache','after_257'])
def test_actual_palo_256_chunk_arrival_renewal_and_replay(w,tmp_path,monkeypatch,failure):
 s=Store(tmp_path/'native');cfg=owner(w,s,tmp_path,monkeypatch,fast=False);cfg['palo_location']='fixture-firewall'
 (tmp_path/'config.json').write_text(json.dumps(cfg));s.state('source_configuration',{'index_url':cfg['index_url'],'sources':{},'palo_location':'fixture-firewall'})
 at=dt.datetime.now(UTC).replace(microsecond=0);old=(at-dt.timedelta(days=2)).isoformat();seen=(at-dt.timedelta(hours=1)).isoformat();expiry=(at+dt.timedelta(days=5)).isoformat();ips=addresses(257)
 with s.connect() as d:
  for address in ips:
   d.execute('INSERT INTO ips(ip,first_seen,last_seen) VALUES(?,?,?)',(address,old,old))
   d.execute('INSERT INTO block_retention VALUES(?,?,?,?,?,?,?)',(address,old,old,expiry,'fixture',75,'{}'))
   d.execute('INSERT INTO offender_blocks VALUES(?,?,?,?,?)',(address,old,old,old,75))
 class Session:
  def mount(self,*a):pass
  def post(self,*a,**k):
   field=k['json']['aggs']['ips']['composite']['sources'][0]['ip']['terms']['field']
   buckets=[{'key':{'ip':a},'doc_count':1,'native_last':{'value':dt.datetime.fromisoformat(seen).timestamp()*1000}} for a in ips] if field.endswith('source_address') else []
   return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'aggregations':{'ips':{'buckets':buckets}}})
 monkeypatch.setattr(w.requests,'Session',Session);monkeypatch.setattr(w.ssl,'create_default_context',lambda **k:types.SimpleNamespace(verify_flags=0));monkeypatch.setattr(w,'enrich',lambda *a:0)
 original=s.cache_many;renew=s.renew_block;calls=[0]
 def cache(records):
  if failure=='before_cache':raise OSError('fixture before cache chunk')
  result=original(records)
  if failure=='after_cache':raise OSError('fixture after cache chunk')
  return result
 def renewal(*a):
  result=renew(*a);calls[0]+=1
  if failure=='after_257' and calls[0]==257:raise OSError('fixture last renewal')
  return result
 monkeypatch.setattr(s,'cache_many',cache);monkeypatch.setattr(s,'renew_block',renewal)
 with pytest.raises(OSError):w.main()
 expected=0 if failure=='before_cache' else 256
 assert count(s,'ip_observations')==expected and count(s,'offender_returns')==expected
 assert state(s,'worker_status')['status']=='error' and state(s,'palo_status')['status']=='collecting'
 monkeypatch.setattr(s,'cache_many',original);monkeypatch.setattr(s,'renew_block',renew);w.main()
 assert count(s,'ip_observations')==257 and count(s,'offender_returns')==257
 with s.connect() as d:
  assert {tuple(r) for r in d.execute('SELECT last_seen,expires FROM block_retention')}=={(seen,(dt.datetime.fromisoformat(seen)+dt.timedelta(days=30)).isoformat())}
  assert {r[0] for r in d.execute('SELECT policy_event FROM offender_returns')}=={0}
 assert state(s,'worker_status')['status']=='ok'

@pytest.mark.parametrize('status',['ok','unknown','expired'])
def test_actual_enrich_durable_ASN_busy_then_replay_and_queue(w,tmp_path,monkeypatch,status):
 s=Store(tmp_path/'native');owner(w,s,tmp_path,monkeypatch,fast=False);monkeypatch.setattr(w,'collect',lambda *a,**k:0)
 s.evidence('8.8.8.8','waf','fixture',now(),'http',75)
 future=(dt.datetime.now(UTC)+dt.timedelta(days=1)).isoformat();s.state('crawler_feeds',{'fetched':now(),'expires':future,'data':{}})
 s.cache('8.8.8.8','asn',{'database_build_epoch':0});s.cache('8.8.8.8','crawler',{'verified':False})
 class MM:
  def __enter__(self):return self
  def __exit__(self,*a):pass
  def metadata(self):return types.SimpleNamespace(build_epoch=dt.datetime.now(UTC).timestamp())
  def get(self,*a):pytest.fail('No new lookup for durable input')
 monkeypatch.setattr(w.maxminddb,'open_database',lambda *a:MM())
 expiry=(dt.datetime.now(UTC)-dt.timedelta(hours=1)).isoformat() if status=='expired' else future
 payload={'asn':'64500','origin_fixture':True};origin={'8.8.8.8':{'fetched':future,'expires':expiry,'status':'unknown' if status=='unknown' else 'ok','payload':payload}}
 snapshot=tmp_path/'asn-enrichment.json';snapshot.write_text(json.dumps(origin));before=snapshot.read_bytes();original=s.cache;held=[]
 def cache(address,provider,payload,*a,**k):
  if payload.get('origin_fixture') and not held:
   d=sqlite3.connect(s.path);d.execute('BEGIN IMMEDIATE');held.append(d)
  return original(address,provider,payload,*a,**k)
 monkeypatch.setattr(s,'cache',cache)
 if status!='expired':
  result=w.main();assert result['status']=='deferred' and result['sqlite_code']==5 and not (tmp_path/'asn-queue.json').exists()
  for d in held:d.rollback();d.close()
 monkeypatch.setattr(s,'cache',original);w.main()
 assert snapshot.read_bytes()==before
 queued=json.loads((tmp_path/'asn-queue.json').read_text())['ips'];assert queued==([] if status=='ok' else ['8.8.8.8'])
 assert state(s,'worker_status')['status']=='ok'

@pytest.mark.skipif(os.name=='nt',reason='Actual atomic directory symlink publication is verified on Linux')
@pytest.mark.parametrize('where',['before_swap','after_swap','success_status'])
def test_actual_build_swap_boundary_and_normal_replay(w,tmp_path,monkeypatch,where):
 s=Store(tmp_path/'native');s.evidence('8.8.8.8','waf','fixture',now(),'http',75);s.build(tmp_path/'out');before=(tmp_path/'out/current').resolve()
 owner(w,s,tmp_path,monkeypatch,build=True)
 seen=now()
 def collect(*a,**k):s.evidence('1.1.1.1','waf','fixture',seen,'http',75);return 1
 monkeypatch.setattr(w,'collect',collect);replace=w.os.replace;save=s.state;primary=OSError('fixture publication failure');fired=[False]
 def replacing(src,dst):
  if pathlib.Path(dst)==tmp_path/'out/current' and where=='before_swap':raise primary
  return replace(src,dst)
 def saving(key,value=None):
  if not fired[0] and value is not None and ((where=='after_swap' and key=='latest_build') or (where=='success_status' and key=='ingest_status' and value.get('status')=='ok')):
   fired[0]=True;raise primary
  return save(key,value)
 monkeypatch.setattr(w.os,'replace',replacing);monkeypatch.setattr(s,'state',saving)
 with pytest.raises(OSError) as caught:w.main()
 assert caught.value is primary
 after=(tmp_path/'out/current').resolve();published=where!='before_swap'
 assert (after!=before)==published
 result=state(s,'ingest_status');assert result['publication_boundary']==('after_generation_swap' if published else 'before_generation_swap')
 assert result['publication']==('published_bookkeeping_pending' if published else 'not_confirmed_this_pass')
 assert 'evidence_buckets' not in result and count(s,'evidence')==2
 monkeypatch.setattr(w.os,'replace',replace);monkeypatch.setattr(s,'state',save);w.main()
 assert state(s,'ingest_status')['status']=='ok' and count(s,'evidence')==2
 assert set((tmp_path/'out/current/combined-block.txt').read_text().splitlines())=={'8.8.8.8','1.1.1.1'}

@pytest.mark.parametrize('upstream_failure',[False,True])
def test_history_cleanup_BUSY_preserves_durable_result_restart_and_fetch_budget(tmp_path,monkeypatch,upstream_failure):
 import evidence_history as h
 s=Store(tmp_path/'native');b=Brain(s);at=dt.datetime.now(UTC);cfg={'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'nginx':'*'}};calls=[];held=[]
 def fetch(*a):
  calls.append(1);d=sqlite3.connect(s.path);d.execute('BEGIN IMMEDIATE');held.append(d)
  if upstream_failure:raise TimeoutError('fixture upstream')
  return [],{'status':'ok'}
 assert h.refresh(b,'8.8.8.8',cfg,at,fetch)==('failed' if upstream_failure else 'refreshed')
 for d in held:d.rollback();d.close()
 assert h.refresh(Brain(s),'8.8.8.8',cfg,at,fetch)=='cached' and len(calls)==1
 assert s.state('behavior_history_usage:'+at.date().isoformat())==1
 with s.connect() as d:
  leases=[json.loads(r[0]) for r in d.execute("SELECT value FROM state WHERE key LIKE 'ip_activity_pending:history_query:%'")]
 assert len(leases)==1 and leases[0]['owner']

def test_history_expired_old_owner_cannot_release_reclaimed_and_legacy_claim_compatible(tmp_path):
 from activity import claim_activity,release_activity
 s=Store(tmp_path/'native');assert claim_activity(s,'key',owner='old')=='claimed'
 s.state('ip_activity_pending:key',{'started':(dt.datetime.now(UTC)-dt.timedelta(seconds=91)).isoformat(),'owner':'old'})
 assert claim_activity(s,'key',owner='new')=='claimed' and not release_activity(s,'key','old')
 assert s.state('ip_activity_pending:key')['owner']=='new' and release_activity(s,'key','new')
 assert claim_activity(s,'legacy')=='claimed' and 'owner' not in s.state('ip_activity_pending:legacy')

def test_history_claim_BUSY_no_fetch_or_quota_and_derived_error_not_cached_as_upstream(tmp_path,monkeypatch):
 import evidence_history as h
 s=Store(tmp_path/'native');b=Brain(s);at=dt.datetime.now(UTC);cfg={'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'nginx':'*'}}
 d=sqlite3.connect(s.path);d.execute('BEGIN IMMEDIATE')
 assert h.refresh(b,'8.8.8.8',cfg,at,lambda *a:pytest.fail('Failed claim cannot fetch'))=='deferred'
 d.rollback();d.close();assert s.state('behavior_history_usage:'+at.date().isoformat()) is None
 with b.connect() as db:db.execute("CREATE TRIGGER broken BEFORE INSERT ON history_queries BEGIN SELECT RAISE(ABORT,'fixture'); END")
 with pytest.raises(sqlite3.IntegrityError):h.refresh(b,'8.8.8.8',cfg,at,lambda *a:([],{'status':'ok'}))
 with b.connect() as db:assert db.execute('SELECT count(*) FROM history_queries').fetchone()[0]==0

def test_actual_history_stale_cleanup_retains_new_owner_and_budget_exhaustion_never_fetches(tmp_path):
 import evidence_history as h
 from activity import claim_activity
 s=Store(tmp_path/'native');b=Brain(s);at=dt.datetime.now(UTC);cfg={'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'nginx':'*'}};new_key=[]
 def fetch(*args):
  with s.connect() as d:
   row=d.execute("SELECT key,value FROM state WHERE key LIKE 'ip_activity_pending:history_query:%'").fetchone();lease=json.loads(row['value'])
  lease['started']=(at-dt.timedelta(seconds=91)).isoformat();s.state(row['key'],lease);key=row['key'].removeprefix('ip_activity_pending:');new_key.append(row['key'])
  assert claim_activity(s,key,owner='newer_owner')=='claimed'
  return [],{'status':'ok'}
 assert h.refresh(b,'8.8.8.8',cfg,at,fetch)=='refreshed'
 assert s.state(new_key[0])['owner']=='newer_owner'
 assert h.refresh(Brain(s),'8.8.8.8',cfg,at,lambda *a:pytest.fail('Committed result must win over lease'))=='cached'
 s.state('behavior_history_usage:'+at.date().isoformat(),100)
 assert h.refresh(b,'1.1.1.1',cfg,at,lambda *a:pytest.fail('Exhausted budget cannot fetch'))=='budget'

@pytest.mark.parametrize('error',[OSError('storage IO'),TypeError('storage programming')])
def test_history_event_save_failure_propagates_without_upstream_failure_marker(tmp_path,monkeypatch,error):
 import evidence_history as h
 s=Store(tmp_path/'native');b=Brain(s);cfg={'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'nginx':'*'}};calls=[]
 def fetch(*a):calls.append(1);return [('nginx','fixture',[])],{'status':'ok'}
 def save(*a):raise error
 monkeypatch.setattr(h,'save',save)
 with pytest.raises(type(error)) as caught:h.refresh(b,'8.8.8.8',cfg,dt.datetime.now(UTC),fetch)
 assert caught.value is error and len(calls)==1
 with b.connect() as d:assert d.execute('SELECT count(*) FROM history_queries').fetchone()[0]==0

@pytest.mark.parametrize('error',[OSError('fixture IO'),TypeError('fixture programming'),sqlite3.OperationalError('uncoded locked')])
def test_history_noncontention_cleanup_and_primary_failures_remain_visible(tmp_path,monkeypatch,error):
 import evidence_history as h,activity
 s=Store(tmp_path/'native');b=Brain(s);cfg={'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'nginx':'*'}}
 def broken(*a):raise error
 monkeypatch.setattr(activity,'release_activity',broken)
 with pytest.raises(type(error)) as caught:h.refresh(b,'8.8.8.8',cfg,dt.datetime.now(UTC),lambda *a:([],{'status':'ok'}))
 assert caught.value is error
 primary=TypeError('primary fetch programming error')
 def bad_fetch(*a):raise primary
 with pytest.raises(TypeError) as caught:h.refresh(b,'1.1.1.1',cfg,dt.datetime.now(UTC),bad_fetch)
 assert caught.value is primary

@pytest.mark.skipif(os.name=='nt',reason='Actual existing Linux behavior.lock across separate processes')
def test_actual_behavior_worker_singleflight_outlives_lease_and_fetches_once(tmp_path):
 cfg=tmp_path/'config.json';cfg.write_text(json.dumps({'database':str(tmp_path/'native'),'index_url':'https://fixture.invalid','index_user':'fixture','index_password':'fixture','index_ca':'fixture','source_agents':{'nginx':'*'}}))
 code=r'''
import pathlib,os,time,datetime as dt,socket
socket.socket.connect=lambda *a,**k:(_ for _ in ()).throw(AssertionError('No network in child'))
import behavior_worker as worker,source_handoff,packet_indexing
from behavior_ai import Brain
from evidence_history import refresh
root=pathlib.Path(os.environ['EDL_CONFIG']).parent
def consume(*args):
 quiesce=args[-1]
 while not quiesce.is_set():time.sleep(.005)
source_handoff.consume=consume;packet_indexing.consume=consume
def run(store,**kw):
 cfg=__import__('json').loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text())
 def fetch(*a):
  with open(root/'fetches','a') as f:f.write('fetch\n')
  with store.connect() as d:
   row=d.execute("SELECT key,value FROM state WHERE key LIKE 'ip_activity_pending:history_query:%'").fetchone()
   lease=__import__('json').loads(row['value']);lease['started']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=91)).isoformat()
   d.execute('UPDATE state SET value=? WHERE key=?',(__import__('json').dumps(lease),row['key']))
  (root/'entered').touch();end=time.monotonic()+10
  while not (root/'release').exists():
   if time.monotonic()>end:raise AssertionError('Isolated gate timeout')
   time.sleep(.01)
  return [],{'status':'ok'}
 return {'result':refresh(Brain(store),'8.8.8.8',cfg,dt.datetime.now(dt.timezone.utc),fetch)}
worker.run=run;worker.main()
'''
 env=os.environ.copy();env['EDL_CONFIG']=str(cfg)
 first=subprocess.Popen([sys.executable,'-c',code],cwd=pathlib.Path(__file__).parent,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
 try:
  end=time.monotonic()+10
  while not (tmp_path/'entered').exists():
   if first.poll() is not None:raise AssertionError(first.communicate())
   assert time.monotonic()<end;time.sleep(.01)
  second=subprocess.run([sys.executable,'-c',code],cwd=pathlib.Path(__file__).parent,env=env,capture_output=True,text=True,timeout=8)
  assert second.returncode==0 and (tmp_path/'fetches').read_text().splitlines()==['fetch']
 finally:
  (tmp_path/'release').touch()
  out,err=first.communicate(timeout=10)
 assert first.returncode==0,(out,err)
 assert json.loads(out)['result']=='refreshed' and (tmp_path/'fetches').read_text().splitlines()==['fetch']
