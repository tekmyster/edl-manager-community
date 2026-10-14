import datetime as dt
from violator_times import attach,format_time
from core import Store,now
from test_ui_settings import ui

def test_times_fill_old_display_snapshots_and_do_not_invent_unknown_dates(tmp_path):
 s=Store(tmp_path/'db');first='2026-01-01T01:02:03+00:00';last='2026-01-03T02:03:04+00:00'
 with s.connect() as d:
  d.execute('INSERT INTO ips(ip,first_seen,last_seen) VALUES(?,?,?)',('8.8.8.8',first,last))
  d.execute('INSERT INTO offender_blocks VALUES(?,?,?,?,?)',('8.8.8.8','2026-01-02T00:00:00+00:00',last,last,100))
 rows=attach(s,[{'ip':'8.8.8.8'},{'ip':'9.9.9.9'}])
 assert rows[0]['first_seen']==first and rows[0]['last_seen']==last and rows[0]['block_recorded']=='2026-01-02T00:00:00+00:00'
 assert rows[0]['block_expires'] is None and all(rows[1][k] is None for k in ('first_seen','last_seen','block_recorded','block_expires'))
 assert format_time('2026-01-01T02:03:04-05:00')=='2026-01-01 07:03:04'

def test_list_modal_dates_and_header_filter_sort_work(ui):
 app,c,cfg=ui;s=app.store
 first=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=2)).isoformat(timespec='seconds');last=now()
 s.evidence('8.8.8.8','tpot','Cowrie',first,'ssh',50,details={'native_attempt_count':1})
 s.evidence('8.8.8.8','tpot','Cowrie',last,'ssh',50,details={'native_attempt_count':2})
 s.build(cfg['output'])
 for path in ['/', '/results/candidate', '/results/total']:
  r=c.get(path,base_url='https://localhost');assert r.status_code==200
  assert 'First seen UTC' in r.text and 'Last seen UTC' in r.text and format_time(first) in r.text and 'Block recorded UTC' in r.text
 r=c.get('/?f_last_seen='+last[:10]+'&sort=first_seen&direction=desc',base_url='https://localhost')
 assert '8.8.8.8' in r.text
 r=c.get('/?f_last_seen=1900-01-01',base_url='https://localhost');assert 'No addresses match' in r.text
 s.add_rule('block','9.9.9.9','Ticket',None,'admin')
 created=next(r['created'] for r in s.active_rules() if r['value']=='9.9.9.9')
 r=c.get('/results/blacklisted',base_url='https://localhost');assert 'Added UTC' in r.text and format_time(created) in r.text
 r=c.get('/ip/8.8.8.8',base_url='https://localhost');assert 'id="observed-times"' in r.text and format_time(first) in r.text
