import datetime as dt
import ipaddress
import json

import pytest

import misp_feed_sync as sync


AT = dt.datetime(2026, 10, 16, 12, tzinfo=dt.timezone.utc)


def config(**overrides):
    source = {'id': 'example', 'name': 'Example feed', 'url': 'https://example.org/ips', 'ttl_hours': 48}
    source.update(overrides)
    return {'sources': [source]}


def fetched(raw):
    return lambda source: (raw, {'http_status': 200, 'content_type': 'text/plain'})


def unavailable(source):
    raise TimeoutError('source unavailable')


def test_ranges_are_lossless_cidrs_without_expanding_hosts():
    values, comments = sync.parse_feed(b'# source\n8.8.4.1 - 8.8.4.6\n8.8.8.0/24\n8.8.8.1/24\n')
    ranges = [ipaddress.ip_network(v) for v in values if v != '8.8.8.0/24']
    assert sum(n.num_addresses for n in ranges) == 6
    assert {str(a) for n in ranges for a in n} == {f'8.8.4.{i}' for i in range(1, 7)}
    assert values.count('8.8.8.0/24') == 1 and comments == 1


@pytest.mark.parametrize('raw', [b'10.0.0.1', b'8.0.0.0/4', b'8.8.8.8 - 10.0.0.1', b'127.0.0.1', b'224.0.0.1', b'2001:db8::1', b'<html>8.8.8.8</html>', b'upstream error', b''])
def test_nonpublic_and_invalid_content_is_rejected(raw):
    with pytest.raises(ValueError): sync.parse_feed(raw)


def test_empty_feed_requires_explicit_policy_and_comment_marker():
    with pytest.raises(ValueError): sync.parse_feed(b'# empty today')
    assert sync.parse_feed(b'# empty today', allow_empty=True) == ([], 1)
    with pytest.raises(ValueError): sync.parse_feed(b'\n', allow_empty=True)
    with pytest.raises(ValueError): sync.parse_feed(b'8.8.8.8', 'text/html')


@pytest.mark.parametrize('overrides', [{'to_ids': True}, {'ttl_hours': 0}, {'ttl_hours': 169}, {'id': '../bad'}, {'url': 'https://user:password@example.org/ips'}, {'url': 'https://example.org/ips?api_key=redacted'}])
def test_configuration_rejects_unsafe_sources(overrides):
    with pytest.raises(ValueError): sync.validate_config(config(**overrides))


def test_duplicate_sources_cannot_be_counted_twice():
    cfg = config(); cfg['sources'].append(dict(cfg['sources'][0], id='other'))
    with pytest.raises(ValueError): sync.validate_config(cfg)


def test_snapshots_are_local_context_with_stable_identity_and_collection_time(tmp_path):
    first = tmp_path/'first'; second = tmp_path/'second'
    sync.stage(config(), first, fetcher=fetched(b'8.8.8.8\n8.8.8.8'), at=AT)
    later = AT + dt.timedelta(hours=1)
    sync.stage(config(), second, first, fetched(b'8.8.8.8'), later)
    a = json.loads((first/'example/event.json').read_text())['Event']
    b = json.loads((second/'example/event.json').read_text())['Event']
    assert a['uuid'] == b['uuid'] and a['Attribute'][0]['uuid'] == b['Attribute'][0]['uuid']
    assert len(a['Attribute']) == 1 and a['distribution'] == 0 and a['published'] is False
    attr = b['Attribute'][0]
    assert attr['to_ids'] is False and attr['distribution'] == 0
    assert int(attr['timestamp']) == int(later.timestamp())
    assert 'native observation time unavailable' in attr['comment']
    assert 'https://example.org/ips' in attr['comment']


def test_outage_holds_original_timestamps_and_provenance_then_revokes_at_ttl(tmp_path):
    good = tmp_path/'good'; held = tmp_path/'held'; expired = tmp_path/'expired'
    original = sync.stage(config(), good, fetcher=fetched(b'8.8.8.8'), at=AT)['sources'][0]
    status = sync.stage(config(), held, good, unavailable, AT+dt.timedelta(hours=1))
    prior = status['sources'][0]
    assert status['required_failures'] == 1 and prior['status'] == 'held_last_good'
    assert prior['raw_sha256'] == original['raw_sha256'] and prior['expires'] == original['expires']
    assert (held/'example/event.json').read_bytes() == (good/'example/event.json').read_bytes()
    status = sync.stage(config(), expired, held, unavailable, AT+dt.timedelta(hours=48))
    assert status['sources'][0]['status'] == 'expired_revoke'
    assert json.loads((expired/'example/event.json').read_text())['Event']['Attribute'] == []


def test_source_id_cannot_be_reassigned_leaving_old_indicators_active(tmp_path):
    sync.stage(config(), tmp_path/'old', fetcher=fetched(b'8.8.8.8'), at=AT)
    with pytest.raises(ValueError, match='reassigned'):
        sync.stage(config(url='https://example.org/replacement'), tmp_path/'new', tmp_path/'old', unavailable, AT)


def test_source_cannot_disappear_from_reconciliation_without_retirement(tmp_path):
    cfg = config(); cfg['sources'].append(dict(cfg['sources'][0], id='second', url='https://example.org/second'))
    sync.stage(cfg, tmp_path/'old', fetcher=fetched(b'8.8.8.8'), at=AT)
    with pytest.raises(ValueError, match='Retire old source'):
        sync.stage(config(), tmp_path/'new', tmp_path/'old', fetched(b'8.8.8.8'), AT)


def test_optional_unavailable_and_healthy_empty_have_distinct_honest_states(tmp_path):
    failed = sync.stage(config(optional=True), tmp_path/'failed', fetcher=unavailable, at=AT)
    empty = sync.stage(config(allow_empty=True), tmp_path/'empty', fetcher=fetched(b'# no entries'), at=AT)
    assert failed['sources'][0]['status'] == 'unavailable' and failed['required_failures'] == 0
    assert empty['sources'][0]['status'] == 'healthy_empty'
    assert failed['sources'][0]['count'] == empty['sources'][0]['count'] == 0


@pytest.mark.parametrize('legacy_null_state', [False, True])
def test_repeated_never_successful_source_preserves_unavailable_health_and_other_refreshes(tmp_path, legacy_null_state):
    import urllib.error
    cfg = config(optional=True)
    cfg['sources'].append(dict(cfg['sources'][0], id='healthy', url='https://example.org/healthy', optional=False))
    def fetcher(source):
        if source['id'] == 'example': raise urllib.error.HTTPError(source['url'], 403, 'Forbidden', None, None)
        return b'9.9.9.9', {'http_status': 200, 'content_type': 'text/plain'}
    previous = tmp_path/'first'
    sync.stage(cfg, previous, fetcher=fetcher, at=AT)
    if legacy_null_state:
        path = previous/'example/source.json'; record = json.loads(path.read_text())
        record.update(status='expired_revoke', last_success=None, expires=None)
        path.write_text(json.dumps(record))
    for cycle in range(1, 4):
        current = tmp_path/str(cycle)
        result = sync.stage(cfg, current, previous, fetcher, AT+dt.timedelta(hours=cycle))
        failed, healthy = result['sources']
        assert result['required_failures'] == 0
        assert failed['status'] == 'unavailable' and failed['http_status'] == 403 and failed['count'] == 0
        assert failed.get('last_success') is None and failed.get('expires') is None
        assert json.loads((current/'example/event.json').read_text())['Event']['Attribute'] == []
        assert healthy['status'] == 'ok' and healthy['count'] == 1
        assert healthy['last_success'] == sync.stamp(AT+dt.timedelta(hours=cycle))
        previous = current


def test_repeated_required_unavailable_source_reports_failure_without_aborting_batch(tmp_path):
    previous = tmp_path/'first'
    sync.stage(config(), previous, fetcher=unavailable, at=AT)
    for cycle in range(1, 4):
        current = tmp_path/str(cycle)
        result = sync.stage(config(), current, previous, unavailable, AT+dt.timedelta(hours=cycle))
        assert result['required_failures'] == 1 and result['sources'][0]['status'] == 'unavailable'
        previous = current


def test_never_successful_source_can_recover_then_hold_its_real_last_good_snapshot(tmp_path):
    cfg = config(optional=True)
    sync.stage(cfg, tmp_path/'failed', fetcher=unavailable, at=AT)
    recovered = sync.stage(cfg, tmp_path/'recovered', tmp_path/'failed', fetched(b'8.8.8.8'), AT+dt.timedelta(hours=1))
    held = sync.stage(cfg, tmp_path/'held', tmp_path/'recovered', unavailable, AT+dt.timedelta(hours=2))
    assert recovered['sources'][0]['status'] == 'ok' and recovered['sources'][0]['count'] == 1
    assert held['sources'][0]['status'] == 'held_last_good'
    assert held['sources'][0]['last_success'] == recovered['sources'][0]['last_success']
    assert held['sources'][0]['expires'] == recovered['sources'][0]['expires']
    assert (tmp_path/'held/example/event.json').read_bytes() == (tmp_path/'recovered/example/event.json').read_bytes()


def test_byte_and_indicator_limits_are_enforced(monkeypatch):
    monkeypatch.setattr(sync, 'MAX_BYTES', 3)
    with pytest.raises(ValueError, match='byte guard'): sync.parse_feed(b'8.8.8.8')
    monkeypatch.setattr(sync, 'MAX_BYTES', 100)
    monkeypatch.setattr(sync, 'MAX_ENTRIES', 1)
    with pytest.raises(ValueError, match='indicator guard'): sync.parse_feed(b'8.8.8.8\n9.9.9.9')


def test_cli_stages_without_import_by_default(tmp_path, monkeypatch, capsys):
    cfg = tmp_path/'config.json'; cfg.write_text(json.dumps(config()))
    monkeypatch.setattr(sync, 'stage', lambda cfg, dest, previous: {'required_failures': 0})
    monkeypatch.setattr(sync, 'import_snapshot', lambda *args, **kwargs: pytest.fail('Import requires explicit selection'))
    monkeypatch.setattr('sys.argv', ['misp_feed_sync.py', '--config', str(cfg), '--output', str(tmp_path/'output')])
    assert sync.main() == 0
    assert (tmp_path/'output').is_dir()


def test_cli_cannot_replace_unrelated_directories(tmp_path, monkeypatch):
    cfg = tmp_path/'config.json'; cfg.write_text(json.dumps(config()))
    target = tmp_path/'existing'; target.mkdir(); (target/'keep').write_text('existing data')
    monkeypatch.setattr('sys.argv', ['misp_feed_sync.py', '--config', str(cfg), '--output', str(target)])
    with pytest.raises(ValueError, match='outside managed snapshot'): sync.main()
    assert (target/'keep').read_text() == 'existing data'
