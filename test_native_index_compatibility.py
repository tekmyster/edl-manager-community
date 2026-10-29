"""Cross-index native ingestion retains event-time and retry semantics."""
import datetime as dt
import json
import os
import ssl
from types import SimpleNamespace

import pytest
from core import Store

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Production worker uses Linux dependencies')


def setup_worker(tmp_path, monkeypatch):
 import worker
 s=Store(tmp_path/'db')
 s.state('source_configuration',{'index_url':'https://index.example.test:9200','sources':{'tpot':'Collector','wazuh':''}})
 cfg={'incremental_ingest':True,'index_url':'https://index.example.test:9200','index_user':'reader','index_password':'test','index_ca':ssl.get_default_verify_paths().cafile}
 return worker,s,cfg


def test_unmapped_index_keeps_native_order_scope_counters_and_reconciliation(tmp_path,monkeypatch):
 worker,s,cfg=setup_worker(tmp_path,monkeypatch)
 real_datetime=dt.datetime
 at=(real_datetime.now(dt.timezone.utc)-dt.timedelta(days=1)).replace(hour=12,minute=0,second=0,microsecond=0)
 class FrozenClock(real_datetime):
  @classmethod
  def now(cls,tz=None):return at if tz else at.replace(tzinfo=None)
 monkeypatch.setattr(worker.dt,'datetime',FrozenClock)
 s.state('native_ingest_cursor',{'through':(at-dt.timedelta(minutes=2)).isoformat(),'reconciled':'2000-01-01T00:00:00+00:00'})
 seen=(at-dt.timedelta(hours=3)).isoformat()
 indexed=(at-dt.timedelta(minutes=1)).isoformat()
 calls=[];late=[False]
 def bucket(address,seen,indexed,agent='Collector'):
  data={'edl_seen_utc':seen,'edl_detector':'Cowrie','edl_qualifying':'yes','edl_path_hashes':'one,two','edl_native_event_count':'7','edl_native_attempt_count':'3','edl_dst_ports':'22','edl_activity_json':json.dumps({'events':[{'seen':seen,'action':'login'}]})}
  return {'key':{'ip':address,'source':'tpot','detector':'Cowrie'},'doc_count':12,'last':{'hits':{'hits':[{'_source':{'data':data,'timestamp':indexed,'agent':{'name':agent}}}]}}}
 original=worker.requests.Session
 class MixedIndex(original):
  def post(self,url,json,timeout,**kwargs):
   if json.get('size'):return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'_shards':{'total':1,'failed':0},'hits':{'hits':[]}})
   calls.append(json)
   assert '/wazuh-alerts-*' in url and '/_search?' in url
   top=json['aggs']['items']['aggs']['last']['top_hits']
   # July index lacks edl_seen_utc; its unmapped shard must not fail the query.
   assert top['sort']==[{'data.edl_seen_utc':{'order':'desc','unmapped_type':'keyword'}},{'timestamp':'desc'}]
   filters=json['query']['bool']['filter']
   assert filters[0]['bool']['should']==[{'bool':{'filter':[{'term':{'data.edl_source':'tpot'}},{'term':{'agent.name':'Collector'}}]}}]
   assert filters[1]=={'terms':{'rule.id':['119900','119902']}}
   assert filters[2]=={'terms':{'data.edl_source':['tpot']}}
   assert any('data.edl_seen_utc' in f.get('range',{}) for f in filters)
   rows=[bucket('8.8.4.4',seen,indexed),bucket('9.9.9.9',seen,indexed,'Other')] if at.strftime('%Y.%m.%d') in url else []
   if late[0] and (at-dt.timedelta(days=1)).strftime('%Y.%m.%d') in url:
    rows.append(bucket('1.1.1.1',(at-dt.timedelta(days=2)).isoformat(),(at-dt.timedelta(days=1)).isoformat()))
   return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'_shards':{'failed':0},'aggregations':{'items':{'buckets':rows}}})
 monkeypatch.setattr(worker.requests,'Session',MixedIndex)
 worker.collect(s,cfg,include_palo=False)
 first=s.state('native_ingest_cursor');assert first['mode']=='bounded_daily_partitions'
 row=s.describe('8.8.4.4');assert row['honeypot_native_events']==3
 assert {r['seen'] for r in row['evidence']}=={seen}
 assert {json.loads(r['details'])['native_event_count'] for r in row['evidence']}=={7}
 assert len(row['evidence'])==2 and len(row['activity'])==1
 assert not s.describe('9.9.9.9')['evidence']
 # Overlap replay cannot duplicate events, grow counters, or renew retention.
 s.state('native_ingest_cursor',first);late[0]=True
 worker.collect(s,cfg,include_palo=False)
 assert s.state('native_ingest_cursor')['mode']=='bounded_daily_partitions'
 assert s.describe('8.8.4.4')['evidence']==row['evidence']
 assert s.describe('8.8.4.4')['honeypot_native_events']==3
 # The new independent recent-day scan should recover the late alert now,
 # while the original historical completion receipt remains untouched.
 early=s.describe('1.1.1.1')
 assert {r['seen'] for r in early['evidence']}=={(at-dt.timedelta(days=2)).isoformat()}
 assert early['honeypot_native_events']==3
 assert s.state('native_ingest_cursor')['reconciled']=='2000-01-01T00:00:00+00:00'
 with s.connect() as db:assert db.execute('SELECT count(*) FROM block_retention').fetchone()[0]==0
 for _ in range(31):worker.collect(s,cfg,include_palo=False)
 assert s.state('native_ingest_cursor')['reconciled']!='2000-01-01T00:00:00+00:00'
 recovered=s.describe('1.1.1.1')
 assert {r['seen'] for r in recovered['evidence']}=={(at-dt.timedelta(days=2)).isoformat()}
 assert recovered['honeypot_native_events']==3


@pytest.mark.parametrize('failure',['http','shard','timeout'])
def test_cross_index_failure_preserves_cursor_and_existing_evidence(tmp_path,monkeypatch,failure):
 import requests
 worker,s,cfg=setup_worker(tmp_path,monkeypatch)
 at=dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
 s.evidence('8.8.4.4','tpot','Cowrie',at,'ssh',10,details={'native_attempt_count':3})
 cursor={'through':at,'reconciled':at,'mode':'incremental','overlap_seconds':600};s.state('native_ingest_cursor',cursor)
 before=s.describe('8.8.4.4')['evidence'];original=worker.requests.Session
 class BrokenIndex(original):
  def post(self,*args,**kwargs):
   def check():
    if failure=='http':raise requests.HTTPError('unmapped index query failed')
   return SimpleNamespace(raise_for_status=check,json=lambda:{'timed_out':failure=='timeout','_shards':{'failed':int(failure=='shard')},'aggregations':{'items':{'buckets':[]}}})
 monkeypatch.setattr(worker.requests,'Session',BrokenIndex)
 worker.collect(s,cfg,include_palo=False)
 assert s.state('native_ingest_coverage')['status']=='partial' and s.state('native_ingest_coverage')['errors']
 assert s.state('native_ingest_cursor')==cursor
 assert s.describe('8.8.4.4')['evidence']==before
