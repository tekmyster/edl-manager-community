import datetime as dt
import json
import os

import pytest

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux worker')


@pytest.fixture
def store(tmp_path):
    from core import Store
    return Store(tmp_path/'test.sqlite3')


class Response:
    def __init__(self, body): self.body = body
    def raise_for_status(self): pass
    def json(self): return self.body


class Session:
    def __init__(self, total): self.total = total; self.calls = []
    def post(self, url, json, timeout):
        self.calls.append(json)
        start = (json['page']-1)*1000
        return Response({'response': {'Attribute': [{'value': '8.8.8.8', 'id': str(i), 'to_ids': False, 'Event': {'info': 'Context'}} for i in range(start, min(start+1000, self.total))]}})


def test_complete_misp_snapshot_can_cross_old_50k_limit():
    import worker
    session = Session(55001)
    result = worker.misp_attributes(session, 'https://example.org')
    assert len(result) == 55001 and len(session.calls) == 56
    assert result[-1]['id'] == '55000' and result[-1]['to_ids'] is False
    assert all(q['enforceWarninglist'] is True and q['deleted'] is False and q['timestamp'] == '30d' for q in session.calls)


def test_misp_bound_rejects_full_100k_without_returning_partial_data():
    import worker
    session = Session(100000)
    with pytest.raises(ValueError, match='volume guard'): worker.misp_attributes(session, 'https://example.org')
    assert len(session.calls) == 100


def test_managed_expiry_is_enforced_even_if_import_scheduler_stops():
    import worker
    def attribute(expiry):
        return {'value': '8.8.8.8', 'to_ids': False, 'comment': 'Local managed IP context; expires='+expiry+'; source example', 'Event': {'info': 'Example [local managed IP context]'}}
    future = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat(timespec='seconds')
    session = Session(0)
    session.post = lambda *args, **kwargs: Response({'response': {'Attribute': [attribute('2000-01-01T00:00:00+00:00'), attribute(future)]}})
    attrs = worker.misp_attributes(session, 'https://example.org')
    assert len(attrs) == 1 and attrs[0]['expires'] == future and attrs[0]['to_ids'] is False


def test_managed_context_cannot_become_actionable_or_lose_expiry():
    import worker
    session = Session(0)
    session.post = lambda *args, **kwargs: Response({'response': {'Attribute': [{'value': '8.8.8.8', 'to_ids': True, 'Event': {'info': 'Example [local managed IP context]'}}]}})
    with pytest.raises(ValueError, match='policy mismatch'): worker.misp_attributes(session, 'https://example.org')


@pytest.mark.parametrize('body', [{}, {'response': {}}, {'response': None}, {'response': {'Attribute': ['bad']}}, {'response': {'Attribute': [{'value': '8.8.8.8', 'Event': None}]}}, {'response': {'Attribute': [{'value': '8.8.8.8', 'Event': {'info': None}}]}}])
def test_bad_misp_response_cannot_become_successful_empty_snapshot(body):
    import worker
    session = Session(0)
    session.post = lambda *args, **kwargs: Response(body)
    with pytest.raises(ValueError): worker.misp_attributes(session, 'https://example.org')


def test_failed_second_page_retains_prior_snapshot_and_scores(store, tmp_path, monkeypatch):
    import worker
    class Database:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, address): return {'autonomous_system_number': 15169}
        def metadata(self): return type('Metadata', (), {'build_epoch': dt.datetime.now(dt.timezone.utc).timestamp()})()
    monkeypatch.setattr(worker.maxminddb, 'open_database', lambda path: Database())
    expiry = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=1)).isoformat()
    store.evidence('8.8.4.4', 'nginx', 'sensitive-path-probe', worker.now(), 'http', 50)
    store.state('crawler_feeds', {'fetched': worker.now(), 'expires': expiry, 'providers': {}})
    prior = {'fetched': '2026-01-01T00:00:00+00:00', 'expires': '2026-01-01T00:01:00+00:00', 'generation': 'prior', 'attributes': []}
    store.state('misp_snapshot', prior)
    store.cache('8.8.4.4', 'misp', {'matches': 1, 'snapshot_generation': 'prior'})
    calls = []
    def post(self, url, json, timeout):
        calls.append(json['page'])
        if json['page'] == 2: raise worker.requests.Timeout('test outage')
        return Response({'response': {'Attribute': [{'value': '8.8.4.4', 'id': '1', 'to_ids': True}]*1000}})
    monkeypatch.setattr(worker.requests.Session, 'post', post)
    keys = tmp_path/'keys.json'; keys.write_text('{"misp":"test-only-key"}')
    cfg = {'providers_file': str(keys), 'database': str(store.path), 'asn_database': 'unused', 'crawler_feed_file': str(tmp_path/'missing.json'), 'misp_url': 'https://example.org', 'misp_ca': True}
    worker.enrich(store, cfg)
    assert calls == [1, 2] and store.state('misp_snapshot') == prior
    assert store.cached('8.8.4.4', 'misp')['status'] == 'failed'
    assert store.describe('8.8.4.4')['score'] == 50


def test_managed_context_caps_snapshot_and_ip_cache_expiry(store, tmp_path, monkeypatch):
    import worker
    class Database:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, address): return {'autonomous_system_number': 15169}
        def metadata(self): return type('Metadata', (), {'build_epoch': dt.datetime.now(dt.timezone.utc).timestamp()})()
    monkeypatch.setattr(worker.maxminddb, 'open_database', lambda path: Database())
    expiry = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=30)).isoformat(timespec='seconds')
    store.evidence('8.8.4.4', 'nginx', 'sensitive-path-probe', worker.now(), 'http', 50)
    store.state('crawler_feeds', {'fetched': worker.now(), 'expires': expiry, 'providers': {}})
    attribute = {'value': '8.8.4.4', 'id': '1', 'to_ids': False, 'comment': 'Local managed IP context; expires='+expiry+'; source test', 'Event': {'info': 'Test [local managed IP context]'}}
    monkeypatch.setattr(worker.requests.Session, 'post', lambda *args, **kwargs: Response({'response': {'Attribute': [attribute]}}))
    keys = tmp_path/'keys.json'; keys.write_text('{"misp":"test-only-key"}')
    cfg = {'providers_file': str(keys), 'database': str(store.path), 'asn_database': 'unused', 'crawler_feed_file': str(tmp_path/'missing.json'), 'misp_url': 'https://example.org', 'misp_ca': True}
    worker.enrich(store, cfg)
    cached = store.cached('8.8.4.4', 'misp')
    assert store.state('misp_snapshot')['expires'] == expiry and cached['expires'] <= expiry
    payload = json.loads(cached['payload'])
    assert payload['context_matches'] == 1 and payload['matches'] == 0 and payload['score_contribution'] == 0
    assert store.describe('8.8.4.4')['score'] == 50
