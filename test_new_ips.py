import datetime as dt
from core import Store,now
from new_ips import Reports,record
from test_ui_settings import ui

def test_exact_rolling_arrivals_return_after_year_and_duplicates(tmp_path):
 s=Store(tmp_path/'db');at=dt.datetime.now(dt.timezone.utc).replace(microsecond=0);first=at-dt.timedelta(hours=1)
 def iso(t):return t.isoformat(timespec='seconds')
 events=[('8.8.8.8',first),('8.8.8.8',first),('8.8.8.8',at),('9.9.9.9',first),('9.9.9.9',first-dt.timedelta(days=2)),('1.1.1.1',first),('1.1.1.1',first-dt.timedelta(days=365,seconds=1)),('8.8.4.4',first),('8.8.4.4',first-dt.timedelta(days=365)),('4.2.2.1',at-dt.timedelta(hours=24,seconds=1)),('4.2.2.2',at+dt.timedelta(seconds=1)),('4.2.2.3',at-dt.timedelta(hours=24)),('10.0.0.1',first)]
 with s.connect() as d:
  for address,seen in events:record(d,address,iso(seen))
 r=Reports(s).compute(at);assert {v['ip'] for v in r['rows']}=={'8.8.8.8','1.1.1.1','4.2.2.3'} and r['count']==3
 assert next(v for v in r['rows'] if v['ip']=='8.8.8.8')['new_seen']==iso(first)
 assert not r['coverage']['year_complete']
 # Late-arriving original logs can disprove an apparent new arrival.
 with s.connect() as d:record(d,'8.8.8.8',iso(first-dt.timedelta(days=2)))
 assert Reports(s).compute(at)['count']==2

def test_native_sources_only_and_modal_matches_count(ui):
 app,c,cfg=ui;s=app.store;stamp=now()
 s.evidence('8.8.8.8','tpot','Cowrie',stamp,'ssh',50)
 s.evidence('8.8.8.8','tpot','Cowrie',stamp,'ssh',50)
 s.cache('9.9.9.9','asn',{'asn':123})
 s.add_rule('block','1.1.1.1','Manual only',None,'admin')
 r=c.get('/',base_url='https://localhost');assert 'New IPs' in r.text and '/results/new' in r.text
 r=c.get('/results/new',base_url='https://localhost',headers={'X-EDL-Modal':'1'});assert r.status_code==200 and '/ip/8.8.8.8' in r.text and '/ip/9.9.9.9' not in r.text and '/ip/1.1.1.1' not in r.text
 assert 'New arrival UTC' in r.text and 'tracking is still accumulating' in r.text
 r=c.get('/results/new?m_f_ip=9.9.9.9',base_url='https://localhost');assert 'No matching results' in r.text
 assert Reports(s).compute()['count']==1
 # Source-only activity (without a scoring event) is also an observation.
 s.source_activity('4.2.2.1','nginx','web',stamp,{'path':'/'})
 assert Reports(s).compute()['count']==2
