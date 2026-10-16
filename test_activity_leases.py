"""Isolated lease-clock/SQLite contention regressions. No source traffic or live DBs."""
import contextlib,datetime as dt,json,threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from core import Store
import activity

UTC=dt.timezone.utc
REAL_DATETIME=dt.datetime
START=REAL_DATETIME(2026,10,16,12,0,0,999999,tzinfo=UTC)
KEY='ip_activity:synthetic:8.8.8.8'
QUOTA='synthetic-context-quota'

@pytest.fixture
def lease_clock(tmp_path,monkeypatch):
 store=Store(tmp_path/'isolated.sqlite3')
 class Clock(REAL_DATETIME):
  current=START
  calls=0
  @classmethod
  def now(cls,tz=None):
   cls.calls+=1
   return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)
 monkeypatch.setattr(activity.dt,'datetime',Clock)
 return store,Clock

def test_waiting_writer_samples_after_lock_and_sees_new_owner(lease_clock,monkeypatch):
 store,clock=lease_clock;attempted=threading.Event();original=store.connect
 @contextlib.contextmanager
 def observe_begin(*args,**kwargs):
  with original(*args,**kwargs) as db:
   class Connection:
    def execute(self,sql,*parameters):
     if sql=='BEGIN IMMEDIATE':attempted.set()
     return db.execute(sql,*parameters)
   yield Connection()
 monkeypatch.setattr(store,'connect',observe_begin)
 with ThreadPoolExecutor(max_workers=1) as pool:
  with original() as db:
   db.execute('BEGIN IMMEDIATE')
   future=pool.submit(activity.claim_activity,store,KEY,QUOTA,5)
   assert attempted.wait(5),'Contender never attempted BEGIN IMMEDIATE'
   sampled_before_lock=clock.calls
   # Owner commits a lease in the following second while the waiter is blocked.
   clock.current=START+dt.timedelta(milliseconds=250)
   db.execute('INSERT INTO state VALUES(?,?)',('ip_activity_pending:'+KEY,json.dumps({'started':clock.current.isoformat()})))
   db.execute('INSERT INTO state VALUES(?,?)',(QUOTA,'1'))
  result=future.result(timeout=5)
 assert result=='pending'
 assert sampled_before_lock==0 and clock.calls==1
 assert store.state(QUOTA)==1
 assert store.state('ip_activity_pending:'+KEY)['started']==clock.current.isoformat()

def test_second_boundary_uses_same_instant_for_comparison_and_write(lease_clock,monkeypatch):
 store,clock=lease_clock;separate_samples=[]
 def later_now():
  separate_samples.append(True)
  return (START+dt.timedelta(microseconds=1)).isoformat(timespec='seconds')
 monkeypatch.setattr(activity,'now',later_now)
 with ThreadPoolExecutor(max_workers=8) as pool:
  outcomes=list(pool.map(lambda _:activity.claim_activity(store,KEY,QUOTA,8),range(8)))
 assert outcomes.count('claimed')==1 and outcomes.count('pending')==7
 assert store.state(QUOTA)==1
 assert activity.timestamp(store.state('ip_activity_pending:'+KEY)['started'])==START
 assert not separate_samples and clock.calls==8

@pytest.mark.parametrize('age,expected',[(0,'pending'),(89.999999,'pending'),(90,'claimed'),(91,'claimed'),(-86400,'claimed')])
def test_pending_lease_expiry_and_future_clock_recovery(lease_clock,age,expected):
 store,clock=lease_clock
 store.state('ip_activity_pending:'+KEY,{'started':(START-dt.timedelta(seconds=age)).isoformat()})
 store.state(QUOTA,1)
 assert activity.claim_activity(store,KEY,QUOTA,3)==expected
 assert store.state(QUOTA)==(2 if expected=='claimed' else 1)
 if expected=='claimed':assert activity.timestamp(store.state('ip_activity_pending:'+KEY)['started'])==START

@pytest.mark.parametrize('age,expected',[(0,'cached'),(299.999999,'cached'),(300,'claimed'),(-86400,'claimed')])
def test_cache_expiry_keeps_five_minute_boundary(lease_clock,age,expected):
 store,clock=lease_clock;store.state(KEY,{'fetched':(START-dt.timedelta(seconds=age)).isoformat(),'status':'ok','events':[]})
 assert activity.claim_activity(store,KEY,QUOTA,1)==expected
 assert store.state(QUOTA)==(1 if expected=='claimed' else None)

def test_distinct_addresses_share_atomic_quota_and_crash_recovery(lease_clock):
 store,clock=lease_clock
 keys=['ip_activity:synthetic:'+str(i) for i in range(8)]
 with ThreadPoolExecutor(max_workers=8) as pool:
  outcomes=list(pool.map(lambda key:activity.claim_activity(store,key,QUOTA,3),keys))
 assert outcomes.count('claimed')==3 and outcomes.count('budget')==5
 assert store.state(QUOTA)==3
 claimed=[key for key,outcome in zip(keys,outcomes) if outcome=='claimed']
 assert activity.claim_activity(store,claimed[0],QUOTA,3)=='pending'
 clock.current=START+dt.timedelta(seconds=90)
 # Expired/crashed owners do not bypass an exhausted daily budget.
 assert activity.claim_activity(store,claimed[0],QUOTA,3)=='budget' and store.state(QUOTA)==3
 # A later quota period can recover the crashed owner's expired lease once.
 next_quota=QUOTA+':next'
 with ThreadPoolExecutor(max_workers=8) as pool:
  recovered=list(pool.map(lambda _:activity.claim_activity(store,claimed[0],next_quota,3),range(8)))
 assert recovered.count('claimed')==1 and recovered.count('pending')==7
 assert store.state(next_quota)==1

def test_background_failure_backoff_then_success_and_cache(lease_clock):
 from behavior_context import refresh_palo
 store,clock=lease_clock
 cfg={'index_url':'https://synthetic.invalid','index_user':'synthetic','index_password':'fixture-only'}
 store.state('source_configuration',{'index_url':cfg['index_url'],'palo_location':'synthetic-firewall'})
 calls=[]
 def fail(config,address):calls.append('failed');raise TimeoutError('Synthetic unavailable source')
 def success(config,address):
  calls.append('success');return {'status':'ok','fetched':clock.current.isoformat(),'total':0,'events':[]}
 def quota():return 'behavior_palo_usage:'+clock.current.date().isoformat()
 assert refresh_palo(store,cfg,'8.8.8.8',2,fail)=='failed'
 assert store.state(quota())==1
 clock.current=START+dt.timedelta(seconds=3599)
 assert refresh_palo(store,cfg,'8.8.8.8',2,success)=='cached' and calls==['failed']
 clock.current=START+dt.timedelta(seconds=3600)
 assert refresh_palo(store,cfg,'8.8.8.8',2,success)=='refreshed' and calls==['failed','success']
 assert store.state(quota())==2
 clock.current+=dt.timedelta(seconds=299)
 assert refresh_palo(store,cfg,'8.8.8.8',2,success)=='cached'
 clock.current+=dt.timedelta(seconds=1)
 assert refresh_palo(store,cfg,'8.8.8.8',2,success)=='budget' and len(calls)==2
 assert store.describe('8.8.8.8')['score']==0
 with store.connect() as db:assert db.execute('SELECT count(*) FROM block_retention').fetchone()[0]==0


def test_ui_future_cache_and_lease_cannot_suppress_refresh(lease_clock):
 import hashlib
 store,clock=lease_clock
 cfg={'index_url':'https://synthetic.invalid','palo_location':'synthetic-firewall'}
 scope=hashlib.sha256((cfg['index_url']+'|'+cfg['palo_location']).encode()).hexdigest()[:16]
 key='ip_activity:'+scope+':8.8.8.8'
 future=(START+dt.timedelta(days=1)).isoformat()
 store.state(key,{'status':'ok','fetched':future,'events':[]})
 store.state('ip_activity_pending:'+key,{'started':future})
 cache=activity.ActivityCache(store,cfg);cache.pool.shutdown();submissions=[]
 class Pool:
  def submit(self,*args):submissions.append(args)
 cache.pool=Pool()
 assert cache.get('8.8.8.8')['loading'] and len(submissions)==1
 assert activity.timestamp(store.state('ip_activity_pending:'+key)['started'])==START
 assert cache.get('8.8.8.8')['loading'] and len(submissions)==1
