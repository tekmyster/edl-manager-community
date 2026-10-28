"""Disposable policy timelines; no production events or verdicts are injected."""
import datetime as dt
import ipaddress
import json
import os
import hashlib

import pytest

from core import Store
from permanent_policy import active, confirm, observe, reverse, view
from offenders import maintain

UTC = dt.timezone.utc
START = dt.datetime(2025, 1, 1, tzinfo=UTC)
ADDRESS = '8.8.8.8'


@pytest.fixture
def timeline(tmp_path, monkeypatch):
    real = dt.datetime
    class Clock(real):
        current = START
        @classmethod
        def now(cls, tz=None):
            return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)
    monkeypatch.setattr(dt, 'datetime', Clock)
    return Store(tmp_path/'native.sqlite3'), Clock


def proof(detector='sensitive-path-probe', record_id=None):
    return {'detector':detector,'native_pipeline':'tekmyster-edl30-v1','native_qualifying':True,
            'native_record_id':record_id or hashlib.sha256(detector.encode()).hexdigest()}


def seed(store, address=ADDRESS, at=START):
    event = {'id': 'native-baseline-event', 'source': 'tpot', 'sensor': 'Cowrie', 'seen': at.isoformat(),
             'strength':75,'details':proof('Cowrie:command-input')}
    row = {'ip': address, 'auto_candidate': True, 'verified_crawler': False, 'score': 75, 'evidence': [event]}
    confirm(store, [row], [ipaddress.ip_network(address)], at.isoformat(), 'generation-unit-fixture', 'fixture-digest')


def hit(store, clock, day, address=ADDRESS, arrived=None, source='nginx', event_id=None):
    event = START + dt.timedelta(days=day)
    clock.current = START + dt.timedelta(days=arrived if arrived is not None else day)
    before=view(store,address)
    store.evidence(address,source,'sensitive-path-probe',event.isoformat(),'http',50,
                   details=proof(record_id=event_id or hashlib.sha256((source+event.isoformat()).encode()).hexdigest()))
    return view(store,address)!=before


def ingest_offense(store, clock, day, address=ADDRESS, detector='sensitive-path-probe', source='nginx', qualifying='yes', **extra):
    from worker import ingest_source
    clock.current=START+dt.timedelta(days=day)
    native=clock.current.isoformat()
    data={'edl_seen_utc':native,'edl_pipeline':'tekmyster-edl30-v1','edl_event_id':hashlib.sha256((source+detector+native).encode()).hexdigest(),
          'edl_qualifying':qualifying,'edl_activity_json':json.dumps({'events':[{'id':'native-'+str(day),'seen':native,'action':'sensitive path request'}]}),**extra}
    return ingest_source(store,{'ip':address,'source':source,'detector':detector},data,native,1)


@pytest.mark.parametrize('days,periods,earned', [
    ([0, 1, 29.999], [], False), ([30, 59.999], [1], False),
    ([30, 60, 89.999], [1, 2], False), ([30, 60, 90], [1, 2, 3], True),
    ([45, 75, 110], [1, 2, 3], True), ([30, 90, 120], [1, 3, 4], False),
    ([30, 90, 120, 150], [1, 3, 4, 5], True),
])
def test_nonoverlapping_boundaries_and_gap_reset(timeline, days, periods, earned):
    store, clock = timeline
    seed(store)
    for day in days: hit(store, clock, day)
    result = view(store, ADDRESS)
    assert [r['period'] for r in result['milestones']] == periods
    assert bool(result['earned']) == earned
    assert bool(active(store)) == earned


def test_many_hits_duplicates_and_collection_refresh_count_once(timeline):
    store, clock = timeline
    seed(store)
    for _ in range(4):
        for day in (32, 33, 48, 59): hit(store, clock, day)
    result = view(store, ADDRESS)
    assert result['streak'] == 1 and not result['earned']
    assert len(result['milestones']) == 1
    assert len([a for a in result['audit'] if a['action'] == 'milestone']) == 1
    assert result['milestones'][0]['seen'] == (START+dt.timedelta(days=32)).isoformat(timespec='seconds')


def test_late_out_of_order_events_fill_gap_using_native_time(timeline):
    store, clock = timeline
    seed(store)
    hit(store, clock, 31)
    hit(store, clock, 95)
    assert not active(store)
    hit(store, clock, 66, arrived=95)
    assert view(store, ADDRESS)['earned'] == (START + dt.timedelta(days=95)).isoformat()
    hit(store, clock, 91, arrived=105)
    result = view(store, ADDRESS)
    assert result['earned'] == (START + dt.timedelta(days=91)).isoformat()
    assert result['audit'][0]['action'] == 'earned_date_corrected'
    assert result['audit'][0]['details']['previous'].startswith('2025-04-06')


def test_future_unknown_ai_and_palo_cannot_earn(timeline):
    store, clock = timeline
    seed(store)
    for day in (30, 60, 90):
        for source in ('palo', 'ai', 'cluster', 'misp'):
            assert not hit(store, clock, day, source=source)
    assert not hit(store, clock, 90, arrived=89)
    with store.connect() as d:
        assert not observe(d, ADDRESS, 'nginx', 'request', (START+dt.timedelta(days=90)).isoformat(), 'model-event', 'assessment')
    assert not active(store)
    assert view(store, ADDRESS)['milestones'] == []


def test_disabled_sources_cannot_extend_monthly_history(timeline):
    store, clock = timeline
    seed(store)
    store.state('source_configuration', {'index_url': 'https://configured.invalid', 'sources': {'nginx': False}})
    for day in (30, 60, 90): assert not hit(store, clock, day)
    assert view(store, ADDRESS)['milestones'] == []


def test_baseline_requires_confirmed_native_exact_membership(timeline):
    store, clock = timeline
    row = {'ip': ADDRESS, 'score': 75, 'auto_candidate': False, 'verified_crawler': False, 'evidence': []}
    for auto, verified, source in [(False, False, 'tpot'), (True, True, 'tpot'), (True, False, 'palo')]:
        row.update(auto_candidate=auto, verified_crawler=verified, evidence=[{'source':source}])
        confirm(store,[row],[ipaddress.ip_network(ADDRESS)],START.isoformat(),'generation-fixture','digest')
    row.update(auto_candidate=True, verified_crawler=False, evidence=[])
    confirm(store,[row],[ipaddress.ip_network(ADDRESS)],START.isoformat(),'generation-fixture','digest')
    assert view(store, ADDRESS) is None
    seed(store)
    before = view(store, ADDRESS)
    seed(store, at=START+dt.timedelta(days=20))
    assert view(store, ADDRESS) == before
    assert view(store, '8.8.8.9') is None


def test_persistence_cleanup_and_reversal_are_durable(timeline):
    store, clock = timeline
    seed(store)
    for day in (30, 60, 90): hit(store, clock, day)
    earned = active(store)[ADDRESS]
    clock.current = START + dt.timedelta(days=800)
    maintain(store)
    reopened = Store(store.path)
    assert active(reopened)[ADDRESS] == earned
    assert len(view(reopened, ADDRESS)['milestones']) == 3
    reverse(reopened, ADDRESS, 'Reviewed ownership change', 'administrator')
    reverse(reopened, ADDRESS, 'Duplicate submission', 'administrator')
    for day in (30, 60, 90, 810, 840, 870): hit(reopened, clock, day, arrived=900)
    reopened = Store(store.path)
    assert not active(reopened)
    result = view(reopened, ADDRESS)
    assert result['earned'] == earned and result['reversal_actor'] == 'administrator'
    assert len([a for a in result['audit'] if a['action']=='reversed']) == 1
    assert len(result['milestones']) == 3
    with reopened.connect() as d:
        assert d.execute("SELECT count(*) FROM policy_events WHERE action='permanent.reversed'").fetchone()[0] == 1


@pytest.mark.parametrize('reason', ['', ' ', 'x'*1001])
def test_reversal_requires_explicit_reason(timeline, reason):
    store, clock = timeline
    seed(store)
    for day in (30, 60, 90): hit(store, clock, day)
    with pytest.raises(ValueError): reverse(store, ADDRESS, reason, 'admin')
    assert active(store)


@pytest.mark.skipif(os.name=='nt', reason='Linux atomic publication and real served feed')
def test_real_native_ingestion_baseline_and_served_feed_survive_cleanup(timeline, tmp_path):
    from app import create_app
    store, clock = timeline
    output = tmp_path/'output'
    # Real native scoring -> actual atomic publication -> baseline provenance.
    ingest_offense(store,clock,0,source='tpot',detector='Cowrie:command-input')
    manifest = store.build(output)
    baseline = view(store, ADDRESS)
    assert baseline['provenance']['combined_block_sha256'] == manifest['sha256']['combined-block']
    assert baseline['provenance']['evidence'][0]['id']
    for day in (31, 61, 91):
        clock.current=START+dt.timedelta(days=day)
        ingest_offense(store,clock,day)
        ingest_offense(store,clock,day)
        store.build(output)
    assert active(store)
    # Expire ordinary data; permanent policy must remain without score inflation.
    clock.current=START+dt.timedelta(days=800)
    maintain(store)
    with store.connect() as d:
        d.execute('DELETE FROM evidence');d.execute('DELETE FROM source_activity')
        d.execute('DELETE FROM block_retention');d.execute('DELETE FROM offender_returns')
        d.execute('DELETE FROM offender_blocks');d.execute('DELETE FROM ips')
    reopened=Store(store.path)
    assert reopened.all_scores()[0]['score']==0
    m=reopened.build(output)
    assert m['counts']['combined-block']==1 and m['counts']['scored-block']==0
    cfg={'database':store.path,'output':str(output),'providers_file':str(tmp_path/'providers'),'session_secret':'isolated-test','hosts':['localhost']}
    app=create_app(cfg);app.testing=True
    with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','test-only',1))
    client=app.test_client()
    with client.session_transaction() as session:
        session.update(user='admin',version=1,csrf='test-csrf',expires_at=clock.current.timestamp()+3600)
    response=client.get('/lists/combined-block.txt',base_url='https://localhost')
    assert response.status_code==200 and response.text==ADDRESS+'\n'
    detail=client.get('/ip/'+ADDRESS,base_url='https://localhost')
    assert detail.status_code==200 and 'Permanent block' in detail.text
    assert 'earned' in detail.text and 'native-baseline-event' not in detail.text
    assert client.post('/ip/'+ADDRESS+'/permanent-reversal',base_url='https://localhost',data={'reason':'review'}).status_code==400
    anon=app.test_client()
    assert anon.post('/ip/'+ADDRESS+'/permanent-reversal',base_url='https://localhost',data={'reason':'review'}).status_code!=200
    response=client.post('/ip/'+ADDRESS+'/permanent-reversal',base_url='https://localhost',data={'csrf':'test-csrf','reason':'Ownership reviewed'})
    assert response.status_code==302
    app.store.build(output)
    assert client.get('/lists/combined-block.txt',base_url='https://localhost').text==''
    assert 'Administrator reversal' in client.get('/ip/'+ADDRESS,base_url='https://localhost').text


@pytest.mark.skipif(os.name=='nt', reason='Linux atomic publication')
def test_permanent_exact_addresses_protection_and_reversal_preserve_native_policy(timeline, tmp_path):
    from table_layout import policy_rows
    store, clock = timeline
    addresses=['8.8.8.8','8.8.8.9','9.9.9.9','1.1.1.1']
    for address in addresses:
        seed(store,address)
        for day in (30,60,90):hit(store,clock,day,address)
    store.add_rule('allow','9.9.9.0/24','Protected dependency',None,'admin')
    store.cache('1.1.1.1','crawler',{'verified':True})
    output=tmp_path/'output';m=store.build(output)
    assert (output/'current/combined-block.txt').read_text()=='8.8.8.8\n8.8.8.9\n'
    rows={r['ip']:r for r in policy_rows(store,store.all_scores(),store.active_rules())}
    assert rows['9.9.9.9']['policy']==rows['1.1.1.1']['policy']=='Allowed'
    assert rows[ADDRESS]['policy']=='Denied' and 'Permanent' in rows[ADDRESS]['policy_reason']
    assert m['permanent_policy']['active_exact_ips']==4 and m['permanent_policy']['published_exact_ips']==2
    reverse(store,ADDRESS,'Reviewed','admin')
    clock.current=START+dt.timedelta(days=91)
    store.evidence(ADDRESS,'tpot','Cowrie',clock.current.isoformat(),'ssh',75)
    store.build(output)
    # Reversal only revokes permanent status, not an independent native score.
    assert ADDRESS in (output/'current/combined-block.txt').read_text()
    assert store.describe(ADDRESS)['auto_candidate']


def test_ingestion_rejects_expired_collection_and_keeps_late_native_event_time(timeline):
    store, clock = timeline
    seed(store)
    for day in (31,91):
        clock.current=START+dt.timedelta(days=day)
        hit(store,clock,day)
    clock.current=START+dt.timedelta(days=92)
    # Late by 27 days is inside the existing native ingestion horizon.
    store.evidence(ADDRESS,'waf','coraza-interruption',(START+dt.timedelta(days=65)).isoformat(),'http',50,details=proof('coraza-interruption'))
    assert active(store)[ADDRESS]==(START+dt.timedelta(days=91)).isoformat()
    saved=view(store,ADDRESS)
    store.evidence(ADDRESS,'waf','coraza-interruption',(START+dt.timedelta(days=60)).isoformat(),'http',50,details=proof('coraza-interruption'))
    assert view(store,ADDRESS)==saved # older than native horizon: not admitted


def test_monthly_state_rolls_back_with_native_ingestion(timeline):
    import sqlite3
    store, clock = timeline
    seed(store)
    clock.current=START+dt.timedelta(days=31)
    store._worker_connection=sqlite3.connect(store.path)
    store._batch_evidence=True
    try:
        store.evidence(ADDRESS,'nginx','sensitive-path-probe',clock.current.isoformat(),'http',50,details=proof())
        with sqlite3.connect(store.path) as independent:
            assert independent.execute('SELECT count(*) FROM permanent_milestones').fetchone()[0]==0
        store._worker_connection.rollback()
    finally:
        store._worker_connection.close();store._worker_connection=None
        store._batch_evidence=False
    assert view(store,ADDRESS)['milestones']==[]
    with store.connect() as d:assert d.execute('SELECT count(*) FROM evidence').fetchone()[0]==0


@pytest.mark.skipif(os.name=='nt', reason='Linux atomic publication')
def test_ai_only_publications_and_repeated_analysis_never_start_native_baseline(tmp_path):
    from test_behavior_scoring import fixture
    from behavior_scoring import apply
    store, brain, packet, assessment, expiry=fixture(tmp_path)
    for _ in range(3):
        assert apply(store,[store.describe(ADDRESS)])[0]['native_score']==70
        manifest=store.build(tmp_path/'lists')
        assert manifest['ai_scoring']['ai_only_ips']==[ADDRESS]
        assert view(store,ADDRESS) is None
    config=store.state('behavior_settings');config['scoring_enabled']=False
    store.state('behavior_settings',config)
    store.build(tmp_path/'lists')
    assert view(store,ADDRESS) is None and not active(store)
    assert store.describe(ADDRESS)['score']==70


def test_policy_screen_has_readable_states_and_accessible_reversal(tmp_path, timeline):
    from app import create_app
    at=dt.datetime.now(UTC)
    baseline=at-dt.timedelta(days=112)
    cfg={'database':str(tmp_path/'db'),'output':str(tmp_path/'lists'),'providers_file':str(tmp_path/'providers'),'session_secret':'test-only','hosts':['localhost']}
    app=create_app(cfg);client=app.test_client()
    with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','test-only',1))
    with client.session_transaction() as session:session.update(user='admin',version=1,csrf='test-only',expires_at=at.timestamp()+3600)
    url='/ip/'+ADDRESS
    assert 'No confirmed native baseline recorded' in client.get(url,base_url='https://localhost').text
    seed(app.store,at=baseline)
    response=client.get(url,base_url='https://localhost')
    assert response.status_code==200
    assert 'No qualifying monthly repeats recorded' in response.text
    for day in (31,62,93):
        when=(baseline+dt.timedelta(days=day)).isoformat()
        timeline[1].current=baseline+dt.timedelta(days=day)
        # Historical fixture insertion exercises the actual persisted-evidence gate.
        with app.store.connect() as d:
            d.execute('INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)',('fixture-'+str(day),ADDRESS,'waf','coraza-interruption',when,'http',50,'',json.dumps(proof('coraza-interruption',hashlib.sha256(when.encode()).hexdigest()))))
            observe(d,ADDRESS,'waf','coraza-interruption',when,'fixture-'+str(day),'evidence')
    timeline[1].current=at
    html=client.get(url,base_url='https://localhost').text
    assert 'Earned:' in html and 'Permanent block' in html
    assert 'tabindex="0" role="region" aria-label="Monthly repeat milestones"' in html
    assert 'aria-label="Permanent repeat policy help"' in html
    assert 'name="reason" rows="3" maxlength="1000" required' in html
    assert 'action="/ip/'+ADDRESS+'/permanent-reversal"' in html
    assert '<pre' not in html
    app.store.add_rule('allow',ADDRESS,'Dependency',None,'admin')
    assert 'Publication suppressed by whitelist' in client.get(url,base_url='https://localhost').text
    reverse(app.store,ADDRESS,'Reviewed <unsafe>','admin')
    html=client.get(url,base_url='https://localhost').text
    assert 'Reviewed &lt;unsafe&gt;' in html and 'Reversed by admin' in html
    assert '<button>Reverse permanent block</button>' not in html


@pytest.mark.parametrize('details,strength', [
    ({},75), ({'native_qualifying':True},75), (proof(),0),
    ({**proof(),'native_qualifying':False},75),
    ({**proof(),'deterministic_qualifying':False},75),
    ({**proof(),'detector':'web-request'},75),
    ({**proof(),'native_pipeline':'arbitrary-source'},75),
    ({**proof(),'native_record_id':''},75),
])
def test_ambiguous_or_nonqualifying_evidence_cannot_start_baseline_or_earn(timeline,details,strength):
    store,clock=timeline
    for day in (0,31,61,91):
        clock.current=START+dt.timedelta(days=day)
        store.evidence(ADDRESS,'nginx','sensitive-path-probe',clock.current.isoformat(),'http',strength,details=details)
        row=store.describe(ADDRESS);row['auto_candidate']=True
        confirm(store,[row],[ipaddress.ip_network(ADDRESS)],clock.current.isoformat(),'generation-negative-fixture','digest')
        assert view(store,ADDRESS) is None
    seed(store)
    for day in (31,61,91):
        clock.current=START+dt.timedelta(days=day)
        store.evidence(ADDRESS,'nginx','sensitive-path-probe',clock.current.isoformat(),'http',strength,details=details)
    assert view(store,ADDRESS)['milestones']==[] and not active(store)


@pytest.mark.parametrize('details',[{}, {'deterministic_qualifying':False}, {'deterministic_qualifying':True}, proof()])
def test_direct_source_activity_cannot_bypass_offense_gate(timeline,details):
    store,clock=timeline
    seed(store)
    for day in (31,61,91):
        clock.current=START+dt.timedelta(days=day)
        store.source_activity(ADDRESS,'nginx','sensitive-path-probe',clock.current.isoformat(),details)
    assert not active(store) and view(store,ADDRESS)['milestones']==[]


@pytest.mark.skipif(os.name=='nt', reason='Actual Linux worker ingestion')
@pytest.mark.parametrize('qualifying,detector',[('no','web-request'),('yes','web-request'),('', 'sensitive-path-probe'),('yes','unrecognized-detector')])
def test_actual_worker_nonoffense_activity_does_not_earn_but_native_return_is_unchanged(timeline,tmp_path,qualifying,detector):
    store,clock=timeline
    ingest_offense(store,clock,0,source='tpot',detector='Cowrie:command-input')
    store.build(tmp_path/'output')
    assert view(store,ADDRESS)
    for day in (31,61,91):
        ingest_offense(store,clock,day,detector=detector,qualifying=qualifying)
        assert store.describe(ADDRESS)['auto_candidate'] # existing broad return floor retained
        store.build(tmp_path/'output')
    assert not active(store) and view(store,ADDRESS)['milestones']==[]
    with store.connect() as d:assert d.execute('SELECT count(*) FROM source_activity').fetchone()[0]>0


@pytest.mark.skipif(os.name=='nt', reason='Actual Linux worker ingestion')
def test_actual_honeypot_counter_refresh_and_replayed_attempt_id_are_not_new_offenses(timeline,tmp_path):
    store,clock=timeline
    ingest_offense(store,clock,0,source='tpot',detector='Cowrie:command-input')
    store.build(tmp_path/'output')
    attempt_time=(START+dt.timedelta(days=31)).isoformat()
    sample={'id':'genuine-attempt-1','seen':attempt_time,'action':'cowrie.login.failed'}
    for day in (31,61,91):
        ingest_offense(store,clock,day,source='tpot',detector='Cowrie',edl_native_attempt_count='99999',
                       edl_activity_json=json.dumps({'events':[sample,{'id':'bookkeeping-'+str(day),'seen':(START+dt.timedelta(days=day)).isoformat(),'action':'cowrie.session.closed'}]}))
    assert [r['period'] for r in view(store,ADDRESS)['milestones']]==[1]
    # Even changing a previously identified attempt's time cannot move it into another period.
    for day in (61,91):
        ingest_offense(store,clock,day,source='tpot',detector='Cowrie',edl_activity_json=json.dumps({'events':[{**sample,'seen':(START+dt.timedelta(days=day)).isoformat()}]}))
    assert not active(store)
    # Distinct genuinely new identified attempts do earn subsequent periods.
    for day in (61,91):
        ingest_offense(store,clock,day,source='tpot',detector='Cowrie',edl_native_attempt_count='1',edl_activity_json=json.dumps({'events':[{**sample,'id':'genuine-attempt-'+str(day),'seen':(START+dt.timedelta(days=day)).isoformat()}]}))
    assert active(store)
    assert view(store,ADDRESS)['milestones'][-1]['event_id']=='genuine-attempt-91'


@pytest.mark.skipif(os.name=='nt', reason='Actual Linux worker ingestion')
def test_actual_detector_refresh_and_reused_record_id_cannot_earn_later_periods(timeline,tmp_path):
    from worker import ingest_source
    store,clock=timeline
    ingest_offense(store,clock,0,source='tpot',detector='Cowrie:command-input')
    store.build(tmp_path/'output')
    ingest_offense(store,clock,31)
    native=(START+dt.timedelta(days=31)).isoformat()
    record_id=hashlib.sha256(('nginx'+'sensitive-path-probe'+native).encode()).hexdigest()
    for day in (61,91):
        clock.current=START+dt.timedelta(days=day)
        data={'edl_seen_utc':native,'edl_pipeline':'tekmyster-edl30-v1','edl_event_id':hashlib.sha256(str(day).encode()).hexdigest(),'edl_qualifying':'yes'}
        ingest_source(store,{'ip':ADDRESS,'source':'nginx','detector':'sensitive-path-probe'},data,clock.current.isoformat(),99999)
        # Reuse the exact native source record but change its alleged event time.
        ingest_offense(store,clock,day,edl_event_id=record_id)
    assert [r['period'] for r in view(store,ADDRESS)['milestones']]==[1]
    assert not active(store)


@pytest.mark.skipif(os.name=='nt', reason='Actual Linux native publication')
def test_published_generic_native_block_does_not_establish_permanent_baseline(timeline,tmp_path):
    store,clock=timeline
    store.evidence(ADDRESS,'tpot','Cowrie',START.isoformat(),'ssh',75,details={'native_attempt_count':99999})
    output=tmp_path/'output'
    store.build(output)
    assert ADDRESS in (output/'current/combined-block.txt').read_text()
    assert store.describe(ADDRESS)['score']==100
    assert view(store,ADDRESS) is None


@pytest.mark.skipif(os.name=='nt', reason='Actual Linux worker collection')
def test_selected_native_wazuh_alert_provenance_through_collect(timeline,tmp_path,monkeypatch):
    import ssl
    from types import SimpleNamespace
    import worker
    store,clock=timeline
    store.state('source_configuration',{'index_url':'https://index.example.test','sources':{'wazuh':'*'},'palo_location':''})
    cfg={'index_url':'https://index.example.test','index_ca':ssl.get_default_verify_paths().cafile,'index_user':'test','index_password':'test'}
    original=worker.requests.Session
    class NativeAlerts(original):
        def post(self,url,json,timeout,**kwargs):
            assert timeout==(3,8) and kwargs=={'stream':True}
            sources=json['aggs']['items']['composite']['sources']
            buckets=[]
            if any('rule' in item for item in sources):
                buckets=[{'key':{'ip':ADDRESS,'rule':'123456'},'doc_count':1,'last':{'hits':{'hits':[{'_id':'alert-'+clock.current.isoformat(),'_source':{'timestamp':clock.current.isoformat(),'rule':{'id':'123456','level':12,'description':'Exploit detected','groups':['ids']}}}]}}}]
            return SimpleNamespace(raise_for_status=lambda:None,json=lambda:{'_shards':{'failed':0},'aggregations':{'items':{'buckets':buckets}}})
    monkeypatch.setattr(worker.requests,'Session',NativeAlerts)
    for day in (0,31,61,91):
        clock.current=START+dt.timedelta(days=day)
        worker.collect(store,cfg,include_palo=False)
        store.build(tmp_path/'output')
    result=view(store,ADDRESS)
    assert result['earned'] and all(m['source']=='wazuh' and m['event_id'].startswith('alert-') for m in result['milestones'])
    assert result['provenance']['evidence'][0]['qualified_events'][0]['proof']['rule']['id']=='123456'
