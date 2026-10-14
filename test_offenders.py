import datetime as dt,json,ipaddress,os
import pytest
from core import Store,now
from offenders import Reports,returned,maintain,mark_blocks,backfill_published
UTC=dt.timezone.utc

@pytest.fixture
def store(tmp_path):
 s=Store(tmp_path/'db');maintain(s);return s

def seed_block(s,address='8.8.8.8',age=40,score=75):
 t=(dt.datetime.now(UTC)-dt.timedelta(days=age)).isoformat(timespec='seconds')
 with s.connect() as d:d.execute('INSERT INTO offender_blocks VALUES(?,?,?,?,?)',(address,t,t,t,score))
 return t

def test_new_unblocked_ip_is_not_a_repeat_offender(store):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 assert Reports(store).compute()['repeat_counts']['30']==0
 assert store.describe('8.8.8.8')['score']==50

def test_old_block_plus_new_ordinary_native_visit_is_immediate_candidate(store):
 seed_block(store)
 store.source_activity('8.8.8.8','nginx','web-request',now(),{'activity':'{}'})
 r=store.describe('8.8.8.8')
 assert r['auto_candidate'] and r['score']==100
 assert r['score_breakdown']['previous_block_score']==75
 assert r['score_breakdown']['previous_block_bonus']==25
 assert r['evidence']==[]
 assert len(store.all_scores())==1
 h=Reports(store).compute()['ips']['8.8.8.8']
 assert h['repeat_windows']==[30,60,90,180,365] and h['windows']['30']['observations']==1

def test_fresh_previous_block_reuses_score_without_aged_bonus_and_caps(store):
 seed_block(store,age=1,score=80)
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 assert store.describe('8.8.8.8')['score']==80
 assert store.describe('8.8.8.8')['score_breakdown']['previous_block_bonus']==0

def test_duplicate_forwarding_and_old_snapshot_do_not_add_returns(store):
 baseline=seed_block(store,age=1)
 with store.connect() as d:
  assert not returned(d,'8.8.8.8','nginx','web-request',baseline)
 for _ in range(3):store.source_activity('8.8.8.8','nginx','web-request',now(),{})
 with store.connect() as d:assert d.execute('SELECT count(*) FROM offender_returns').fetchone()[0]==1

def test_history_older_than_a_year_does_not_reblock(store):
 seed_block(store,age=366)
 store.source_activity('8.8.8.8','nginx','web-request',now(),{})
 assert not store.describe('8.8.8.8')['auto_candidate']

def test_windows_have_exact_boundaries_and_count_same_day_returns(store):
 end=dt.datetime.now(UTC).replace(microsecond=0)
 with store.connect() as d:
  for n,days in enumerate([30,60,90,180,365]):
   address='8.8.8.'+str(n+1);t=(end-dt.timedelta(days=days)).isoformat(timespec='seconds')
   d.execute('INSERT INTO offender_returns VALUES(?,?,?,?,?,?,?)',(address,'tpot','Cowrie',t,75,25,0))
  d.execute('INSERT INTO offender_returns VALUES(?,?,?,?,?,?,?)',('8.8.8.1','waf','Coraza',(end-dt.timedelta(hours=1)).isoformat(timespec='seconds'),75,0,0))
 report=Reports(store).compute(at=end)
 assert report['repeat_counts']=={'30':1,'60':2,'90':3,'180':4,'365':5}
 assert report['ips']['8.8.8.1']['windows']['30']['observations']==2

def test_monthly_leader_uses_return_count_and_excludes_previous_month(store):
 end=dt.datetime(2026,10,10,12,tzinfo=UTC)
 with store.connect() as d:
  for a,t in [('8.8.8.8','2026-10-10T01:00:00+00:00'),('8.8.8.8','2026-10-10T02:00:00+00:00'),('9.9.9.9','2026-10-01T01:00:00+00:00'),('9.9.9.9','2026-09-30T02:00:00+00:00')]:d.execute('INSERT INTO offender_returns VALUES(?,?,?,?,?,?,0)',(a,'tpot','Cowrie',t,75,0))
 assert Reports(store).compute(at=end)['top_month']=={'ip':'8.8.8.8','active_days':1,'observations':2}

@pytest.mark.skipif(os.name=='nt',reason='Atomic EDL publication is Linux')
def test_return_policy_preserves_whitelist_and_crawler_protection(store,tmp_path):
 for a in ['8.8.8.8','9.9.9.9','1.1.1.1']:seed_block(store,a)
 store.add_rule('allow','8.8.8.0/24','Dependency',None,'admin')
 store.cache('9.9.9.9','crawler',{'verified':True})
 for a in ['8.8.8.8','9.9.9.9','1.1.1.1']:store.source_activity(a,'nginx','web-request',now(),{})
 m=store.build(tmp_path/'output')
 assert m['counts']['combined-block']==1
 assert (tmp_path/'output/current/combined-block.txt').read_text()=='1.1.1.1\n'
 assert store.describe('1.1.1.1')['retention']['last_source']=='nginx'

def test_only_effective_blocks_are_recorded_and_prefixes_cover_observed_ips(store):
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75)
 mark_blocks(store,store.all_scores(),[ipaddress.ip_network('9.9.9.9')],now())
 with store.connect() as d:
  assert not d.execute('SELECT 1 FROM offender_blocks WHERE ip=?',('8.8.8.8',)).fetchone()
  assert d.execute('SELECT 1 FROM offender_blocks WHERE ip=?',('9.9.9.9',)).fetchone()

def test_palo_return_only_reports_existing_live_block_not_new_scoring(store):
 seed_block(store,age=1)
 start=(dt.datetime.now(UTC)-dt.timedelta(hours=4)).isoformat(timespec='seconds');expiry=(dt.datetime.now(UTC)+dt.timedelta(days=29)).isoformat(timespec='seconds')
 with store.connect() as d:d.execute('INSERT INTO block_retention VALUES(?,?,?,?,?,?,?)',('8.8.8.8',start,start,expiry,'tpot',75,'{}'))
 assert store.renew_block('8.8.8.8',now(),'palo')
 with store.connect() as d:assert d.execute('SELECT policy_event FROM offender_returns').fetchone()[0]==0
 assert Reports(store).compute()['repeat_counts']['30']==1
 assert not store.renew_block('9.9.9.9',now(),'palo')

def test_backfill_requires_verified_effective_membership_and_cannot_add_score(store,tmp_path):
 import hashlib
 generation=tmp_path/'generation-test';generation.mkdir();created=(dt.datetime.now(UTC)-dt.timedelta(days=2)).isoformat(timespec='seconds');data=b'8.8.8.8\n'
 (generation/'combined-block.txt').write_bytes(data)
 (generation/'manifest.json').write_text(json.dumps({'created':created,'counts':{'combined-block':1},'sha256':{'combined-block':hashlib.sha256(data).hexdigest()}}))
 store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 backfill_published(store,tmp_path)
 assert Reports(store).compute()['repeat_counts']['30']==1
 assert store.describe('8.8.8.8')['score']==50
 with store.connect() as d:assert d.execute('SELECT policy_event FROM offender_returns').fetchone()[0]==0
