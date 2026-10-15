import datetime as dt
import json
import pytest
from core import Store, now
from behavior_ai import Brain, DEFAULTS, config_id, settings, PROMPT_VERSION
from behavior_scoring import contribution, apply


def fixture(tmp_path):
    s = Store(tmp_path / 'manager.sqlite3')
    s.evidence('8.8.8.8', 'waf', 'WAF', now(), 'exploit', 70)
    samples = [{'id': str(i), 'seen': now(), 'path': path, 'method': 'GET', 'port': 443, 'action': 'request'}
               for i, path in enumerate(['/login/admin', '/server/config'])]
    s.source_activity('8.8.8.8', 'nginx', 'HTTP', now(), {'activity': {'events': samples}, 'deterministic_qualifying': False})
    b = Brain(s)
    ident, packet, _ = b.packet(s.describe('8.8.8.8'))
    events = [e['id'] for e in packet['events'] if e.get('independent_evidence')]
    assessment = {'classification': 'malicious', 'maliciousness_confidence': .95,
                  'findings': [{'evidence_ids': events}], 'contradictory_evidence': [], 'metadata': {'model': 'test','prompt_version':PROMPT_VERSION}}
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    s.state('behavior_settings', {**DEFAULTS, 'enabled': True, 'model_enabled': True, 'scoring_enabled': True,
                                  'model': 'test', 'max_bump': 10})
    with b.connect() as d:
        d.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',
                  ('assessment', ident, config_id(settings(s))+'-test', now(), expiry, 'completed', json.dumps(assessment), '', 8))
    return s, b, packet, assessment, expiry


def test_pilot_publication_does_not_poison_retention_or_repeat_history(tmp_path):
    s, b, packet, assessment, expiry = fixture(tmp_path)
    out = tmp_path / 'out'
    native = s.describe('8.8.8.8')
    assert native['score'] == 70
    effective = apply(s, [native])[0]
    assert effective['score'] == 79.5 and effective['native_score'] == 70
    assert apply(s,[effective])[0]['score']==79.5
    assert apply(s, [s.describe('8.8.8.8')])[0]['score'] == 79.5
    manifest = s.build(out)
    assert '8.8.8.8' in (out / 'current' / 'combined-block.txt').read_text()
    assert manifest['ai_scoring']['ai_only_ips'] == ['8.8.8.8']
    with s.connect() as d:
        assert d.execute('SELECT count(*) FROM block_retention').fetchone()[0] == 0
        assert d.execute('SELECT count(*) FROM offender_blocks').fetchone()[0] == 0
    cfg = s.state('behavior_settings');cfg['scoring_enabled'] = False;s.state('behavior_settings', cfg)
    s.build(out)
    assert not (out / 'current' / 'combined-block.txt').read_text()
    assert s.describe('8.8.8.8')['score'] == 70


@pytest.mark.parametrize('change', ['expired', 'benign', 'low_confidence', 'counted', 'duplicate', 'crawler', 'contradiction'])
def test_pilot_abstains_on_unsupported_or_protected_activity(tmp_path, change):
    s, b, packet, assessment, expiry = fixture(tmp_path)
    row = s.describe('8.8.8.8')
    if change == 'expired':expiry = '2020-01-01T00:00:00+00:00'
    if change == 'benign':assessment['classification'] = 'benign'
    if change == 'low_confidence':assessment['maliciousness_confidence'] = .89
    if change == 'counted':
        row['evidence'].append({'source': 'nginx', 'sensor': 'HTTP'})
    if change == 'duplicate':
        events = [e for e in packet['events'] if e.get('independent_evidence')]
        events[1].update({k: events[0][k] for k in ('seen', 'path', 'method', 'port')})
    if change == 'crawler':row['verified_crawler'] = True
    if change == 'contradiction':assessment['contradictory_evidence'] = [{'summary': 'Verified benign context'}]
    assert contribution(packet, assessment, row, expiry) == 0


def test_expiry_and_provider_outage_fall_back_to_native(tmp_path):
    s, b, packet, assessment, expiry = fixture(tmp_path)
    with b.connect() as d:d.execute("UPDATE assessments SET expires='2020-01-01T00:00:00+00:00'")
    assert apply(s, [s.describe('8.8.8.8')])[0]['score'] == 70
    out = tmp_path / 'out';s.build(out)
    assert not (out / 'current' / 'combined-block.txt').read_text()
    with b.connect() as d:d.execute('DROP TABLE assessments')
    assert apply(s, [s.describe('8.8.8.8')])[0]['score'] == 70


def test_whitelist_blocks_ai_adjustment(tmp_path):
 s,b,packet,assessment,expiry=fixture(tmp_path)
 s.add_rule('allow','8.8.8.8','Known service',None,'admin')
 assert apply(s,[s.describe('8.8.8.8')])[0]['score']==70
 out=tmp_path/'out';s.build(out)
 assert not (out/'current'/'combined-block.txt').read_text()


def test_overlay_is_idempotent_below_threshold(tmp_path):
 s,b,packet,assessment,expiry=fixture(tmp_path)
 with s.connect() as d:d.execute('UPDATE evidence SET strength=60')
 first=apply(s,[s.describe('8.8.8.8')])[0]
 assert first['score']==69.5
 assert apply(s,[first])[0]['score']==69.5
 cfg=s.state('behavior_settings');cfg['scoring_enabled']=False;s.state('behavior_settings',cfg)
 assert apply(s,[first])[0]['score']==60
