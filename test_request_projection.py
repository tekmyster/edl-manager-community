"""Requested read-model scope and freshness; no inference or truth fixtures."""
import contextlib,datetime as dt
import analytics_store as ledger
import production_analytics as analytics
from behavior_ai import Brain
from core import Store

def test_dashboard_omits_only_unrendered_provider_details(tmp_path,monkeypatch):
    b=Brain(Store(tmp_path/'native'));at=dt.datetime.now(dt.timezone.utc)
    ledger.event(b.store,'misp','local_query','8.8.8.8',at-dt.timedelta(minutes=1))
    a=ledger.Attempt(b.store,'packet');a.start();a.finish('accepted',{'input_tokens':5,'output_tokens':2})
    at=dt.datetime.now(dt.timezone.utc);full=analytics.summary(b,at=at);queries=[];original=analytics.connect
    @contextlib.contextmanager
    def traced(*a,**kw):
        with original(*a,**kw) as db:
            db.set_trace_callback(queries.append)
            try:yield db
            finally:db.set_trace_callback(None)
    monkeypatch.setattr(analytics,'connect',traced)
    tiles=analytics.summary(b,at=at,include_providers=False)
    assert tiles['providers']==tiles['cache_snapshot']==[]
    assert {k:v for k,v in tiles.items() if k not in ('providers','cache_snapshot')}=={k:v for k,v in full.items() if k not in ('providers','cache_snapshot')}
    assert not any('FROM counters' in q for q in queries)
    assert full['providers'][1]['unique_local']==1 and full['providers'][1]['counts']['local_query']==1
    # No measurement cache: the next read sees the new completed dispatch.
    a=ledger.Attempt(b.store,'next');a.start();a.finish('rejected',{'input_tokens':3,'output_tokens':1})
    next_read=analytics.summary(b,include_providers=False)
    assert next_read['requests']==tiles['requests']+1 and next_read['day_tokens']==tiles['day_tokens']+4

def test_projected_dashboard_still_reports_ledger_read_failure(tmp_path):
    b=Brain(Store(tmp_path/'native'))
    with ledger.connect(b.store,True) as db:db.execute('DROP TABLE requests')
    assert analytics.summary(b,include_providers=False)['error']

def test_expired_ignored_source_identity_payload_is_not_newly_decoded(tmp_path):
    s=Store(tmp_path/'native');seen=dt.datetime.now(dt.timezone.utc).isoformat()
    s.evidence('8.8.8.8','waf','fixture',seen,'http',50)
    with s.connect() as db:db.execute("INSERT INTO cache VALUES('8.8.8.8','source_type','failed','not-json','2000-01-01','2000-01-02')")
    assert s.describe('8.8.8.8')['score']==50

def test_arrival_read_does_not_wait_for_native_writer_and_retention_still_runs(tmp_path):
    import sqlite3,threading,time
    from new_ips import Reports,record
    s=Store(tmp_path/'native');at=dt.datetime.now(dt.timezone.utc)
    with s.connect() as db:
        record(db,'8.8.8.8',(at-dt.timedelta(days=367)).isoformat(timespec='seconds'))
        record(db,'8.8.8.8',(at-dt.timedelta(minutes=1)).isoformat(timespec='seconds'))
    held=threading.Event();release=threading.Event()
    def writer():
        with sqlite3.connect(s.path) as db:
            db.execute('BEGIN IMMEDIATE');held.set();release.wait(2);db.rollback()
    thread=threading.Thread(target=writer);thread.start();assert held.wait(2)
    try:
        start=time.monotonic();report=Reports(s).compute(at)
        assert time.monotonic()-start<1 and report['count']==1
        with s.connect(commit=False) as db:assert db.execute('SELECT count(*) FROM ip_observations').fetchone()[0]==2
    finally:release.set();thread.join(3)
    # Regular Store initialization owns the same unchanged retention cutoff.
    Store(s.path)
    with s.connect(commit=False) as db:assert db.execute('SELECT count(*) FROM ip_observations').fetchone()[0]==1
