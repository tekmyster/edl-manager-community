"""Disposable policy timelines; no production events or verdicts are injected."""
import datetime as dt
import ipaddress
import json
import os

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


def seed(store, address=ADDRESS, at=START):
    event = {'id': 'native-baseline-event', 'source': 'tpot', 'sensor': 'Cowrie', 'seen': at.isoformat()}
    row = {'ip': address, 'auto_candidate': True, 'verified_crawler': False, 'score': 75, 'evidence': [event]}
    confirm(store, [row], [ipaddress.ip_network(address)], at.isoformat(), 'generation-unit-fixture', 'fixture-digest')


def hit(store, clock, day, address=ADDRESS, arrived=None, source='nginx', event_id=None):
    event = START + dt.timedelta(days=day)
    clock.current = START + dt.timedelta(days=arrived if arrived is not None else day)
    with store.connect() as d:
        return observe(d, address, source, 'request', event.isoformat(), event_id or 'event-' + str(day), 'evidence')


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
    assert result['milestones'][0]['event_id'] == 'event-32'


def test_late_out_of_order_events_fill_gap_using_native_time(timeline):
    store, clock = timeline
    seed(store)
    for day in (95, 31): hit(store, clock, day, arrived=100)
    assert not active(store)
    hit(store, clock, 65, arrived=100)
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
    store.evidence(ADDRESS, 'tpot', 'Cowrie', START.isoformat(), 'ssh', 75)
    manifest = store.build(output)
    baseline = view(store, ADDRESS)
    assert baseline['provenance']['combined_block_sha256'] == manifest['sha256']['combined-block']
    assert baseline['provenance']['evidence'][0]['id']
    for day in (31, 61, 91):
        clock.current=START+dt.timedelta(days=day)
        store.source_activity(ADDRESS,'nginx','web-request',clock.current.isoformat(),{})
        store.source_activity(ADDRESS,'nginx','web-request',clock.current.isoformat(),{'refresh':True})
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
        store.source_activity(ADDRESS,'nginx','web-request',clock.current.isoformat(),{})
    clock.current=START+dt.timedelta(days=92)
    # Late by 27 days is inside the existing native ingestion horizon.
    store.evidence(ADDRESS,'waf','Coraza',(START+dt.timedelta(days=65)).isoformat(),'http',0)
    assert active(store)[ADDRESS]==(START+dt.timedelta(days=91)).isoformat()
    saved=view(store,ADDRESS)
    store.evidence(ADDRESS,'waf','Coraza',(START+dt.timedelta(days=60)).isoformat(),'http',0)
    assert view(store,ADDRESS)==saved # older than native horizon: not admitted


def test_monthly_state_rolls_back_with_native_ingestion(timeline):
    import sqlite3
    store, clock = timeline
    seed(store)
    clock.current=START+dt.timedelta(days=31)
    store._worker_connection=sqlite3.connect(store.path)
    store._batch_evidence=True
    try:
        store.source_activity(ADDRESS,'nginx','web-request',clock.current.isoformat(),{})
        with sqlite3.connect(store.path) as independent:
            assert independent.execute('SELECT count(*) FROM permanent_milestones').fetchone()[0]==0
        store._worker_connection.rollback()
    finally:
        store._worker_connection.close();store._worker_connection=None
        store._batch_evidence=False
    assert view(store,ADDRESS)['milestones']==[]
    with store.connect() as d:assert d.execute('SELECT count(*) FROM source_activity').fetchone()[0]==0


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


def test_policy_screen_has_readable_states_and_accessible_reversal(tmp_path):
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
        with app.store.connect() as d:observe(d,ADDRESS,'waf','Coraza',(baseline+dt.timedelta(days=day)).isoformat(),'event-'+str(day),'evidence')
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
