"""Exact-IP native repeat policy, independent of rolling reports and AI history.

Only a newly confirmed native publication starts a baseline. Period 1 is
[baseline + 30 days, baseline + 60 days); period 0 never earns a milestone.
After a gap a new run needs three consecutive periods. Late native events may
fill a gap; arrival order never substitutes for event time. No legacy backfill.
"""
import datetime as dt
import hashlib
import json
import re

UTC = dt.timezone.utc
PERIOD = dt.timedelta(days=30)
SOURCES = frozenset(('tpot', 'owapot', 'nginx', 'waf', 'crowdsec', 'wazuh'))
SCHEMA = '''
CREATE TABLE IF NOT EXISTS permanent_cases(
 ip TEXT PRIMARY KEY, baseline TEXT NOT NULL, provenance TEXT NOT NULL,
 streak INTEGER NOT NULL DEFAULT 0, last_period INTEGER NOT NULL DEFAULT 0,
 earned TEXT, reversed TEXT, reversal_reason TEXT, reversal_actor TEXT);
CREATE TABLE IF NOT EXISTS permanent_milestones(
 ip TEXT NOT NULL, period INTEGER NOT NULL, event_id TEXT NOT NULL,
 seen TEXT NOT NULL, source TEXT NOT NULL, sensor TEXT NOT NULL, origin TEXT NOT NULL,
 PRIMARY KEY(ip,period));
CREATE TABLE IF NOT EXISTS permanent_audit(
 id INTEGER PRIMARY KEY, ip TEXT NOT NULL, recorded TEXT NOT NULL,
 action TEXT NOT NULL, actor TEXT NOT NULL, details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS permanent_audit_ip ON permanent_audit(ip,id);
CREATE TABLE IF NOT EXISTS permanent_event_ids(
 ip TEXT NOT NULL, source TEXT NOT NULL, event_id TEXT NOT NULL, seen TEXT NOT NULL,
 evidence_id TEXT NOT NULL, PRIMARY KEY(ip,source,event_id));
'''


def qualifying_events(row):
    """Conservative positive qualification, not the broad native return floor.

    Proof is populated from the existing worker's selected source records. A
    source label, strength, counter, or arbitrary activity snapshot is not proof.
    Unknown detector/sample semantics intentionally abstain.
    """
    try:
        details = json.loads(row['details']) if isinstance(row['details'], str) else row['details']
        source, sensor, seen = row['source'], row['sensor'], row['seen']
        if (source not in SOURCES or row['strength'] <= 0 or
                details.get('native_qualifying') is not True or
                details.get('deterministic_qualifying') is False):
            return []
        record_id = details.get('native_record_id')
        if not isinstance(record_id, str) or not record_id or len(record_id) > 256:
            return []
        detector = details.get('detector', '')
        proof = {'evidence_id': row['id'], 'record_id': record_id,
                 'pipeline': details.get('native_pipeline'), 'detector': detector}
        if details.get('native_pipeline') == 'tekmyster-edl30-v1':
            # The sensor's record ID is a digest of its normalized native input.
            if not re.fullmatch('[0-9a-f]{64}', record_id):
                return []
            direct = ((source, detector) in {('nginx', 'sensitive-path-probe'), ('waf', 'coraza-interruption')}
                      or source == 'crowdsec' and detector.startswith('crowdsec-ban:') and
                         len(detector) > len('crowdsec-ban:') and 'manual' not in detector.lower()
                      or source == 'tpot' and detector in ('Cowrie:command-input', 'Cowrie:failed-login'))
            if sensor != detector.split(':')[0]:
                return []
            if direct:
                # Counter/path refresh may change the record digest. Identity uses
                # the detector's native offense time, never refresh time/digest.
                identity = hashlib.sha256(json.dumps([source, detector, seen], separators=(',', ':')).encode()).hexdigest()
                return [{'id': identity, 'seen': seen, 'proof': {**proof, 'kind': 'qualified detector event'}}]
            if source == 'tpot' and detector == sensor == 'Cowrie':
                # Aggregate last_seen/counters can advance on session bookkeeping.
                # Only identified native attempt samples earn periods, at sample time.
                actions = {'cowrie.session.connect', 'cowrie.login.failed', 'cowrie.login.success',
                           'cowrie.command.input', 'cowrie.session.file_download', 'cowrie.session.file_upload'}
                result = []
                for sample in details.get('native_offense_samples', [])[:24]:
                    if not isinstance(sample, dict) or sample.get('action') not in actions:
                        continue
                    ident = sample.get('id'); event = dt.datetime.fromisoformat(sample.get('seen', '').replace('Z', '+00:00'))
                    parent = dt.datetime.fromisoformat(seen)
                    if (not isinstance(ident, str) or not ident or len(ident) > 256 or event.tzinfo is None or
                            not parent - PERIOD <= event <= parent):
                        continue
                    result.append({'id': ident, 'seen': event.astimezone(UTC).isoformat(timespec='seconds'),
                                   'proof': {**proof, 'kind': 'identified honeypot attempt', 'action': sample['action']}})
                return result
        elif source == 'wazuh' and details.get('native_pipeline') == 'wazuh-qualified-alert-v1':
            rule = details.get('native_rule', {})
            desc = str(details.get('description', '')).lower()
            groups = rule.get('groups', [])
            auth = any(t in desc for t in ('brute force', 'authentication failed', 'login failed', 'invalid user')) or any('authentication_fail' in g for g in groups)
            attack = any(t in desc for t in ('exploit', 'malware', 'sql injection', 'command injection', 'web attack', 'attack detected'))
            ids = any(g in ('ids', 'suricata') for g in groups) and int(rule.get('level', 0)) >= 12
            if (int(rule.get('level', 0)) >= 8 and sensor == 'rule:' + str(rule.get('id')) and
                    not any(t in desc for t in ('success', '404', 'not found', '400 error', 'edl', 'flow event')) and
                    (attack or ids or auth and int(details.get('records', 0)) >= 5)):
                return [{'id': record_id, 'seen': seen, 'proof': {**proof, 'kind': 'qualified native Wazuh alert', 'rule': rule}}]
    except (ValueError, TypeError, KeyError, AttributeError):
        return []
    return []


def source_provenance(data, source=None, detector=None):
    """Copy only bounded, nonsecret native qualification fields from the sensor."""
    if (data.get('edl_pipeline') != 'tekmyster-edl30-v1' or data.get('edl_qualifying') != 'yes' or
            not isinstance(data.get('edl_event_id'), str) or not re.fullmatch('[0-9a-f]{64}', data['edl_event_id'])):
        return {}
    try:
        activity = json.loads(data.get('edl_activity_json', '{}'))
        samples = [{k: sample.get(k, '') for k in ('id', 'seen', 'action')}
                   for sample in activity.get('events', [])[:24] if isinstance(sample, dict)]
    except (ValueError, TypeError, AttributeError):
        samples = []
    return {'native_pipeline': data['edl_pipeline'], 'native_qualifying': True,
            'native_record_id': data['edl_event_id'],
            **({'native_offense_samples': samples} if source == 'tpot' and detector == 'Cowrie' else {})}


def identity_keys(event_id, proof):
    keys = ['event:' + event_id]
    if proof['kind'] != 'identified honeypot attempt':
        keys.append('record:' + proof['record_id'])
    return keys


def audit(d, address, action, details, actor='System'):
    from core import now
    d.execute('INSERT INTO permanent_audit(ip,recorded,action,actor,details) VALUES(?,?,?,?,?)',
              (address, now(), action, actor, json.dumps(details, sort_keys=True)))


def confirm(store, rows, nets, created, generation, digest):
    """Called only after atomic publication; no manual/AI/subnet-only baselines."""
    from offenders import contains
    matches = contains(nets)
    with store.connect() as d:
        known = {r[0] for r in d.execute('SELECT ip FROM permanent_cases')}
        for row in rows:
            if row['ip'] in known:
                continue
            if not row['auto_candidate'] or row['verified_crawler'] or not matches(row['ip']):
                continue
            native = [(e, qualifying_events(e)) for e in row['evidence']]
            published = dt.datetime.fromisoformat(created)
            native = [(e, [v for v in events if published - PERIOD <= dt.datetime.fromisoformat(v['seen']) <= published])
                      for e, events in native]
            native = [(e, events) for e, events in native if events]
            if not native:
                continue
            provenance = {'generation': generation, 'combined_block_sha256': digest,
                          'native_score': row['score'],
                          'evidence': [{**{k: e[k] for k in ('id', 'source', 'sensor', 'seen')},
                                        'qualified_events': events} for e, events in native]}
            result = d.execute('INSERT OR IGNORE INTO permanent_cases(ip,baseline,provenance) VALUES(?,?,?)',
                               (row['ip'], created, json.dumps(provenance, sort_keys=True)))
            if result.rowcount:
                for evidence, events in native:
                    for event in events:
                        for key in identity_keys(event['id'], event['proof']):
                            d.execute('INSERT OR IGNORE INTO permanent_event_ids VALUES(?,?,?,?,?)',
                                      (row['ip'], evidence['source'], key, event['seen'], evidence['id']))
                audit(d, row['ip'], 'baseline', {'baseline': created, **provenance})


def observe(d, address, source, sensor, seen, event_id, origin):
    """Read persisted native evidence and admit only positively qualified events."""
    if source not in SOURCES or origin != 'evidence':
        return False
    row = d.execute('SELECT * FROM evidence WHERE id=? AND ip=? AND source=? AND sensor=? AND seen=?',
                    (event_id, address, source, sensor, seen)).fetchone()
    if not row:
        return False
    configured = d.execute("SELECT value FROM state WHERE key='source_configuration'").fetchone()
    if configured:
        config = json.loads(configured[0])
        if not config.get('index_url') or not config.get('sources', {}).get(source):
            return False
    changed = False
    for event in qualifying_events(row):
        changed = _milestone(d, address, source, sensor, event['seen'], event['id'], event['proof']) or changed
    return changed


def _milestone(d, address, source, sensor, seen, event_id, proof):
    case = d.execute('SELECT * FROM permanent_cases WHERE ip=?', (address,)).fetchone()
    if not case or case['reversed']:
        return False
    event = dt.datetime.fromisoformat(seen)
    if not dt.datetime.now(UTC) - PERIOD <= event <= dt.datetime.now(UTC):
        return False
    period = (event - dt.datetime.fromisoformat(case['baseline'])) // PERIOD
    if period < 1:
        return False
    # A replayed native ID with a changed collection/counter time cannot move
    # an already seen attempt into another monthly period.
    for key in identity_keys(event_id, proof):
        previous_id = d.execute('SELECT seen FROM permanent_event_ids WHERE ip=? AND source=? AND event_id=?',
                                (address, source, key)).fetchone()
        if previous_id and previous_id['seen'] != seen:
            return False
    for key in identity_keys(event_id, proof):
        d.execute('INSERT OR IGNORE INTO permanent_event_ids VALUES(?,?,?,?,?)',
                  (address, source, key, seen, proof['evidence_id']))
    previous = d.execute('SELECT * FROM permanent_milestones WHERE ip=? AND period=?',
                         (address, period)).fetchone()
    if previous and (previous['seen'], previous['event_id']) <= (seen, event_id):
        return False
    d.execute('INSERT OR REPLACE INTO permanent_milestones VALUES(?,?,?,?,?,?,?)',
              (address, period, event_id, seen, source, sensor, 'evidence'))
    audit(d, address, 'milestone', {'period': period, 'event_id': event_id, 'seen': seen,
                                  'source': source, 'sensor': sensor, 'origin': 'evidence', 'qualification': proof,
                                  'replaces': dict(previous) if previous else None})
    streak = 0
    last = 0
    earned = None
    for row in d.execute('SELECT period,seen FROM permanent_milestones WHERE ip=? ORDER BY period', (address,)):
        streak = streak + 1 if row['period'] == last + 1 else 1
        last = row['period']
        if streak >= 3 and earned is None:
            earned = row['seen']
    d.execute('UPDATE permanent_cases SET streak=?,last_period=?,earned=? WHERE ip=?',
              (streak, last, earned, address))
    if earned and earned != case['earned']:
        audit(d, address, 'earned' if not case['earned'] else 'earned_date_corrected',
              {'earned': earned, 'previous': case['earned'], 'reason': 'Three consecutive monthly native repeat periods'})
    return True


def active(store):
    with store.connect(commit=False) as d:
        return {r['ip']: r['earned'] for r in d.execute('SELECT ip,earned FROM permanent_cases WHERE earned IS NOT NULL AND reversed IS NULL')}


def view(store, address):
    with store.connect(commit=False) as d:
        row = d.execute('SELECT * FROM permanent_cases WHERE ip=?', (address,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data['provenance'] = json.loads(row['provenance'])
        data['milestones'] = [dict(r) for r in d.execute('SELECT * FROM permanent_milestones WHERE ip=? ORDER BY period', (address,))]
        for item in data['milestones']:
            start = dt.datetime.fromisoformat(row['baseline']) + item['period'] * PERIOD
            item.update(start=start.isoformat(timespec='seconds'), end=(start + PERIOD).isoformat(timespec='seconds'))
        data['audit'] = [{**dict(r), 'details': json.loads(r['details'])} for r in d.execute('SELECT * FROM permanent_audit WHERE ip=? ORDER BY id DESC LIMIT 50', (address,))]
    data['status'] = 'Reversed' if row['reversed'] else 'Permanent block' if row['earned'] else 'Tracking monthly repeats'
    data['reason'] = ('Administrator reversed this policy; saved events cannot re-enable it.' if row['reversed'] else
                      'Three consecutive monthly native repeat periods after a confirmed native block.' if row['earned'] else
                      f"{row['streak']} consecutive monthly repeat period(s) recorded; three are required. A missing period resets the run.")
    return data


def reverse(store, address, reason, actor):
    from core import ip, now
    address = str(ip(address))
    reason = reason.strip()
    if not reason or len(reason) > 1000:
        raise ValueError('Enter a reversal reason of 1–1,000 characters.')
    with store.connect() as d:
        row = d.execute('SELECT * FROM permanent_cases WHERE ip=?', (address,)).fetchone()
        if not row or not row['earned']:
            raise ValueError('This address has no earned permanent block.')
        if row['reversed']:
            return
        at = now()
        d.execute('UPDATE permanent_cases SET reversed=?,reversal_reason=?,reversal_actor=? WHERE ip=?', (at, reason, actor, address))
        audit(d, address, 'reversed', {'reason': reason, 'earned': row['earned']}, actor)
        details = {'ip': address, 'reason': reason, 'earned': row['earned']}
        record = d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',
                           (at, actor, 'permanent.reversed', json.dumps(details)))
        from event_history import insert
        insert(d, 'audit:' + str(record.lastrowid), at, actor, 'permanent.reversed', 'ip', address, details)
