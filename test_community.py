import datetime as dt
import pytest
from core import Store,now
from setup import initialize
from community_usage import usage
from test_ui_settings import ui

def test_first_install_has_no_seed_data_or_default_password_and_cannot_reset(tmp_path):
 cfg=initialize(tmp_path/'data','Admin','long unique test password',['localhost'],['127.0.0.1/32'],[])
 s=Store(cfg['database']);assert s.all_scores()==[] and not s.active_rules()
 assert all(not v for v in cfg['source_agents'].values()) and cfg['feed_networks']==[]
 assert 'password' not in cfg and 'bootstrap_password' not in cfg
 with pytest.raises(ValueError):initialize(tmp_path/'data','Admin','another long password',['localhost'],[],[])

def test_feed_requires_explicit_source_and_revalidates_content(ui):
 app,c,cfg=ui;s=app.store;s.add_rule('block','8.8.8.8','Test incident',None,'admin');s.build(cfg['output'])
 assert c.get('/feeds/combined-block.txt',base_url='https://localhost').status_code==403
 cfg['feed_networks']=['10.20.30.4/32']
 result=c.get('/feeds/combined-block.txt',base_url='https://localhost',environ_overrides={'REMOTE_ADDR':'10.20.30.4'})
 assert result.status_code==200 and b'8.8.8.8' in result.data and 'must-revalidate' in result.headers['Cache-Control']
 assert c.get('/feeds/combined-block.txt',base_url='https://localhost',environ_overrides={'REMOTE_ADDR':'10.20.30.5'}).status_code==403
 assert c.get('/feeds/combined-block.txt',base_url='https://localhost',environ_overrides={'REMOTE_ADDR':'10.20.30.4'},headers={'If-None-Match':result.headers['ETag']}).status_code==304
 assert c.get('/settings',base_url='https://localhost',environ_overrides={'REMOTE_ADDR':'10.20.30.4'}).status_code==403

def test_usage_deduplicates_sources_and_tracks_bursts_without_changing_policy(tmp_path):
 s=Store(tmp_path/'db');at=dt.datetime(2026,10,14,12,tzinfo=dt.timezone.utc)
 with s.connect() as db:
  for n in range(501):
   address=f'8.8.{n//250}.{n%250+1}'
   db.execute('INSERT INTO ip_observations VALUES(?,?)',(address,'2026-10-14T01:00:00+00:00'))
   db.execute('INSERT INTO ip_observations VALUES(?,?)',(address,'2026-10-14T02:00:00+00:00'))
 assert usage(s,at)['today']==501 and usage(s,at)['burst_days']==1 and not usage(s,at)['license_required']
 with s.connect() as db:db.execute('INSERT INTO community_daily_usage VALUES(?,?)',('2026-10-13',501))
 assert usage(s,at)['license_required']
 s.state('community_use_class','enterprise');assert 'Enterprise use' in usage(s,at)['reasons']
 s.add_rule('block','9.9.9.9','Incident',None,'admin');s.build(tmp_path/'out')
 assert '9.9.9.9' in (tmp_path/'out/current/combined-block.txt').read_text()

def test_enrichment_runs_without_an_asn_database(ui,monkeypatch):
 from worker import enrich
 app,c,cfg=ui;s=app.store
 s.state('crawler_feeds',{'data':{},'expires':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat()})
 monkeypatch.setattr('requests.get',lambda *a,**k:pytest.fail('Unexpected network lookup'))
 assert enrich(s,cfg)==0
 assert 'Community license' in c.get('/settings',base_url='https://localhost').text


def test_rolling_average_threshold_and_peak_ceiling(tmp_path):
 s=Store(tmp_path/'db');at=dt.datetime(2026,10,30,12,tzinfo=dt.timezone.utc)
 usage(s,at)
 with s.connect() as db:
  for n in range(30):db.execute('INSERT INTO community_daily_usage VALUES(?,?)',((at.date()-dt.timedelta(days=n)).isoformat(),501 if n==0 else 500))
 result=usage(s,at);assert result['total']==15001 and result['burst_days']==1 and result['license_required']
 with s.connect() as db:db.execute('UPDATE community_daily_usage SET ips=1001 WHERE day=?',(at.date().isoformat(),))
 assert 'Daily usage exceeds 1,000' in usage(s,at)['reasons']
