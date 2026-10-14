import datetime as dt,ipaddress,json,os
import pytest
from core import Store,now
from event_history import matching,list_changes,difference,expirations,recover_audit
from test_ui_settings import ui
UTC=dt.timezone.utc

def events(s,ip='8.8.8.8',asn=''):
 return matching(s,ip,asn)['rows']

def nets(*values):return [ipaddress.ip_network(v) for v in values]

def test_operator_notes_actor_range_asn_ipv6_and_disable_are_durable(tmp_path):
 s=Store(tmp_path/'db')
 ident=s.add_rule('allow','8.8.8.0/24','Business owner approved',None,'Alice')
 s.add_rule('block','8.8.8.7-8.8.8.9','Investigation',None,'Bob')
 s.add_rule('allow','AS15169','Crawler owner',None,'Charlie')
 s.add_rule('block','2606:4700:4700::/48','IPv6 review',None,'Bob')
 s.disable_rule(ident,'David');s.disable_rule(ident,'David')
 rows=events(Store(tmp_path/'db'),asn='15169')
 assert len(rows)==4
 assert {r['actor'] for r in rows}=={'Alice','Bob','Charlie','David'}
 assert next(r for r in rows if r['action']=='whitelist.added' and r['actor']=='Alice')['notes']=='Business owner approved'
 assert len(events(s,'8.8.8.10'))==2 and not events(s,'9.9.9.9')
 assert len(events(s,'2606:4700:4700::1111'))==1
 recover_audit(s);assert len(events(s,asn='15169'))==4

def test_rule_and_event_commit_together_or_both_rollback(tmp_path):
 s=Store(tmp_path/'db')
 with s.connect() as d:d.execute("CREATE TRIGGER fail_event BEFORE INSERT ON policy_events WHEN NEW.target='9.9.9.9' BEGIN SELECT RAISE(ABORT,'Event unavailable'); END")
 with pytest.raises(Exception):s.add_rules('allow',['8.8.8.8','9.9.9.9'],'Ticket',None,'admin')
 with s.connect() as d:
  for table in ['rules','audit','policy_events']:assert d.execute('SELECT count(*) FROM '+table).fetchone()[0]==0

def test_existing_audit_recovery_keeps_real_time_and_omits_secrets(tmp_path):
 s=Store(tmp_path/'db');at='2026-01-02T03:04:05+00:00'
 with s.connect() as d:
  d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(at,'Alice','rule.add',json.dumps({'action':'block','id':'old','value':'8.8.8.8','reason':'Saved note','password':'NEVER_COPY'})))
  d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(at,'Alice','password.change','{}'))
 recover_audit(s);recover_audit(s)
 row=events(s)[0];assert row['at']==at and row['notes']=='Saved note'
 with s.connect() as d:assert 'NEVER_COPY' not in json.dumps([dict(r) for r in d.execute('SELECT * FROM policy_events')])

def test_semantic_membership_changes_dont_report_prefix_repacking(tmp_path):
 s=Store(tmp_path/'db');at=now()
 list_changes(s,{'combined-block':nets('8.8.8.0/24')},at,'baseline',initial_baseline=True)
 split=nets('8.8.8.0/25','8.8.8.128/25')
 list_changes(s,{'combined-block':split},at,'repacked')
 assert not events(s)
 list_changes(s,{'combined-block':nets('8.8.8.0/25')},at,'removed','Alice')
 assert not events(s,'8.8.8.8')
 row=events(s,'8.8.8.200')[0];assert row['action']=='list.removed' and row['actor']=='Alice'
 list_changes(s,{'combined-block':nets('8.8.8.0/25')},at,'same','Alice')
 assert len(events(s,'8.8.8.200'))==1
 assert difference(nets('2606:4700::/32'),nets('2606:4700::/33'))==nets('2606:4700:8000::/33')

def test_expiry_is_saved_once_and_survives_a_later_renewal(tmp_path):
 s=Store(tmp_path/'db');expired=(dt.datetime.now(UTC)-dt.timedelta(seconds=1)).isoformat(timespec='seconds')
 ident=s.add_rule('block','8.8.8.8','Temporary incident',None,'Alice')
 with s.connect() as d:
  d.execute('UPDATE rules SET expires=? WHERE id=?',(expired,ident))
  d.execute('INSERT INTO block_retention VALUES(?,?,?,?,?,?,?)',('8.8.8.8',expired,expired,expired,'tpot',75,'{}'))
 expirations(s,now());expirations(s,now())
 assert {r['action'] for r in events(s)}=={'blacklist.added','blacklist.expired','block.expired'}
 with s.connect() as d:d.execute('UPDATE block_retention SET expires=?',((dt.datetime.now(UTC)+dt.timedelta(days=30)).isoformat(),))
 expirations(s,now());assert len(events(s))==3

def test_enrichment_request_is_targeted_and_retained(tmp_path):
 s=Store(tmp_path/'db');s.audit('Alice','enrichment.queue',{'ip':'8.8.8.8'})
 assert events(s)[0]['label']=='Enrichment requested' and not events(s,'9.9.9.9')

@pytest.mark.skipif(os.name=='nt',reason='Atomic Linux publication')
def test_real_publication_logs_exclusion_and_no_rebuild_duplicates(tmp_path):
 s=Store(tmp_path/'db');out=tmp_path/'out';s.build(out)
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',75)
 s.build(out)
 assert any(r['action']=='list.added' and r['list']=='combined-block' for r in events(s))
 s.add_rule('allow','8.8.8.8','Customer issue',None,'Alice');s.build(out,actor='Alice')
 assert any(r['action']=='list.removed' and r['list']=='combined-block' and r['actor']=='Alice' for r in events(s))
 count=len(events(s));s.build(out);assert len(events(s))==count
 assert (out/'current/combined-block.txt').read_text()==''

def test_detail_history_escapes_notes_filters_and_pages(ui):
 app,c,cfg=ui;s=app.store
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 for n in range(31):s.add_rule('allow','8.8.8.8','Ticket '+str(n)+' <script>bad()</script>',None,'Alice')
 r=c.get('/ip/8.8.8.8?e_size=25&e_page=2',base_url='https://localhost')
 assert r.status_code==200 and 'Policy and list history' in r.text and '26–31 of 31 matches' in r.text
 assert '&lt;script&gt;bad()&lt;/script&gt;' in r.text and '<script>bad()</script>' not in r.text
 r=c.get('/ip/8.8.8.8?e_f_notes=Ticket+30',base_url='https://localhost')
 assert '1–1 of 1 matches' in r.text
 assert 'form="event-filters"' in r.text

def test_api_events_requires_token_and_returns_saved_related_events(ui):
 from reporting_api import issue
 app,c,cfg=ui;s=app.store;s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 s.add_rule('allow','8.8.8.0/24','Customer ticket',None,'Alice')
 assert c.get('/api/v1/ips/8.8.8.8/events',base_url='https://localhost').status_code==401
 token=issue(s,'Events',30,'admin')
 r=c.get('/api/v1/ips/8.8.8.8/events',base_url='https://localhost',headers={'Authorization':'Bearer '+token})
 assert r.status_code==200 and r.json['total']==1 and r.json['data'][0]['notes']=='Customer ticket'
 assert token not in r.text and 'details' not in r.json['data'][0]
