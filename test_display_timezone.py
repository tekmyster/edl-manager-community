import datetime as dt
from test_ui_settings import ui
from violator_times import format_time

def test_regional_timezone_dst_and_ambiguous_hour():
 assert format_time('2026-01-01T12:00:00+00:00','America/New_York')=='2026-01-01 07:00:00 EST -0500'
 assert format_time('2026-07-01T12:00:00+00:00','America/New_York')=='2026-07-01 08:00:00 EDT -0400'
 assert format_time('2026-11-01T05:30:00+00:00','America/New_York')!=format_time('2026-11-01T06:30:00+00:00','America/New_York')

def test_timezone_persisted_per_account_filters_and_session_settings(ui):
 app,c,cfg=ui;s=app.store
 stamp='2026-01-01T12:00:00+00:00'
 s.evidence('8.8.8.8','tpot','Cowrie',dt.datetime.now(dt.timezone.utc).isoformat(),'ssh',50)
 with s.connect() as d:d.execute('UPDATE ips SET first_seen=? WHERE ip=?',(stamp,'8.8.8.8'))
 r=c.post('/settings/timezone',data={'csrf':'csrf','timezone':'America/New_York'},base_url='https://localhost');assert r.status_code==302
 assert s.state('user_preferences:admin')['timezone']=='America/New_York'
 r=c.get('/ip/8.8.8.8',base_url='https://localhost');assert '2026-01-01 07:00:00 EST -0500' in r.text and 'First seen America/New_York' in r.text
 r=c.get('/?f_first_seen=2026-01-01',base_url='https://localhost');assert '/ip/8.8.8.8' in r.text
 r=c.post('/settings',data={'csrf':'csrf','session_timeout':'3600'},base_url='https://localhost');assert r.status_code==302
 assert s.state('user_preferences:admin')=={'timezone':'America/New_York','session_timeout':3600}
 c.post('/settings/timezone',data={'csrf':'csrf','timezone':'Invalid/Zone'},base_url='https://localhost');assert s.state('user_preferences:admin')['timezone']=='America/New_York'
 fresh=app.test_client()
 with fresh.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 assert '2026-01-01 07:00:00 EST -0500' in fresh.get('/ip/8.8.8.8',base_url='https://localhost').text
 with s.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('other','hash',1))
 with fresh.session_transaction() as session:session.update(user='other',version=1)
 assert 'First seen UTC' in fresh.get('/ip/8.8.8.8',base_url='https://localhost').text
 with s.connect(commit=False) as d:assert d.execute('SELECT first_seen FROM ips WHERE ip=?',('8.8.8.8',)).fetchone()[0]==stamp
