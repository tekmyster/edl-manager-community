import datetime as dt
from metric_trends import KEYS,record,trends,interval_chart,values
from test_ui_settings import ui
UTC=dt.timezone.utc

def test_new_ips_are_24_hourly_counts_matching_total():
 from metric_trends import hourly_arrivals
 end=dt.datetime(2026,10,13,0,30,tzinfo=UTC);start=end-dt.timedelta(hours=24)
 rows=[{'new_seen':(start+dt.timedelta(hours=h,minutes=10)).isoformat()} for h in range(24)]
 rows+=[{'new_seen':start.isoformat()},{'new_seen':end.isoformat()}]
 graph=hourly_arrivals({'generated':end.isoformat(),'since':start.isoformat(),'rows':rows})
 assert len(graph['points'])==24 and graph['total']==26
 assert graph['points'][0]['value']==2 and graph['points'][-1]['value']==2
 assert all(p['value']==1 for p in graph['points'][1:-1])
 assert graph['points'][0]['start']==start.isoformat() and graph['points'][-1]['end']==end.isoformat()

def test_empty_new_ip_hours_show_zero_on_zero_baseline():
 from metric_trends import hourly_arrivals
 end=dt.datetime(2026,10,13,tzinfo=UTC)
 graph=hourly_arrivals({'generated':end.isoformat(),'since':(end-dt.timedelta(hours=24)).isoformat(),'rows':[]})
 assert len(graph['points'])==24 and all(p['value']==0 and p['y']==40 for p in graph['points'])

def test_recorded_counts_buckets_and_missing_history(ui):
 app,c,cfg=ui;s=app.store;at=dt.datetime(2026,10,12,12,2,tzinfo=UTC)
 counts=dict.fromkeys(KEYS,10)
 record(s,counts,at);record(s,dict.fromkeys(KEYS,5),at-dt.timedelta(seconds=1))
 with s.connect(commit=False) as d:assert d.execute('SELECT value FROM metric_snapshots WHERE metric="new" ORDER BY at DESC LIMIT 1').fetchone()[0]==10
 r=trends(s,counts,{},at)
 assert r['total']['points'][-1]['value']==10 and r['total']['minimum']==10
 empty=interval_chart([None]*30,at-dt.timedelta(days=30),at,'steps','Daily recorded totals');assert empty['segments']==[] and empty['points']==[]

def test_step_charts_preserve_unknown_days_and_actual_zero():
 at=dt.datetime(2026,10,12,12,tzinfo=UTC)
 graph=interval_chart([None,10,None,0],at-dt.timedelta(days=4),at,'steps','Daily recorded totals')
 assert len(graph['segments'])==2 and [p['value'] for p in graph['points']]==[10,0]
 assert graph['minimum']==0 and graph['bin_count']==4

def test_tiles_have_accessible_graphs_and_keep_result_links(ui):
 app,c,cfg=ui
 html=c.get('/',base_url='https://localhost').text
 assert html.count('class="metric-trend"')==8 and html.count('data-results-modal href=')==13
 assert 'role="img"' in html and 'New IPs per hour' in html and 'History starts today' in html
 assert 'href="/results/new"' in html

def test_monthly_graph_uses_only_the_current_leader(ui):
 app,c,cfg=ui;s=app.store;at=dt.datetime.now(UTC);stamp=at.isoformat()
 from offenders import mark_blocks
 from core import now
 import ipaddress
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 mark_blocks(s,[],[ipaddress.ip_network('8.8.8.8')],stamp)
 with s.connect() as d:
  d.execute('INSERT OR IGNORE INTO offender_returns VALUES(?,?,?,?,?,?,?)',('8.8.8.8','tpot','Cowrie',stamp,50,0,1))
 report={'top_month':{'ip':'8.8.8.8','observations':1},'month_start':at.replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat()}
 r=trends(s,dict.fromkeys(KEYS,0),report,at)
 assert r['top-month']['total']==1 and r['top-month']['caption']=='Returns per day'

def test_daily_repeat_counts_are_distinct_per_interval(ui):
 app,c,cfg=ui;s=app.store;at=dt.datetime.now(UTC)
 with s.connect() as d:
  for n,source in enumerate(['tpot','nginx']):d.execute('INSERT INTO offender_returns VALUES(?,?,?,?,?,?,?)',('8.8.8.8',source,'Sensor',(at-dt.timedelta(minutes=n+1)).isoformat(),75,0,1))
 report={'generated':at.isoformat(),'top_month':None,'month_start':at.replace(day=1,hour=0,minute=0,second=0,microsecond=0).isoformat()}
 graph=trends(s,dict.fromkeys(KEYS,0),report,at)['repeat']
 assert graph['total']==1 and graph['points'][-1]['value']==1 and graph['bin_count']==30
