"""Exact-IP native repeat policy, independent of rolling reports and AI history.

Only a newly confirmed native publication starts a baseline. Period 1 is
[baseline + 30 days, baseline + 60 days); period 0 never earns a milestone.
After a gap a new run needs three consecutive periods. Late native events may
fill a gap; arrival order never substitutes for event time. No legacy backfill.
"""
import datetime as dt
import hashlib
import json

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
'''


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
            native = [e for e in row['evidence'] if e['source'] in SOURCES]
            prior = row.get('prior_return')
            if not native and not (prior and prior['source'] in SOURCES and prior['policy_event']):
                continue
            provenance = {'generation': generation, 'combined_block_sha256': digest,
                          'native_score': row['score'],
                          'evidence': [{k: e[k] for k in ('id', 'source', 'sensor', 'seen')} for e in native],
                          'native_return': prior}
            result = d.execute('INSERT OR IGNORE INTO permanent_cases(ip,baseline,provenance) VALUES(?,?,?)',
                               (row['ip'], created, json.dumps(provenance, sort_keys=True)))
            if result.rowcount:
                audit(d, row['ip'], 'baseline', {'baseline': created, **provenance})


def observe(d, address, source, sensor, seen, event_id, origin):
    """Save one earliest representative event per monthly period in native tx.

    IDs identify normalized native evidence or source activity, never collection
    refresh times, model assessments or Palo drops. No scoring/TTL writes here.
    """
    if source not in SOURCES or origin not in ('evidence', 'source_activity'):
        return False
    configured = d.execute("SELECT value FROM state WHERE key='source_configuration'").fetchone()
    if configured:
        config = json.loads(configured[0])
        if not config.get('index_url') or not config.get('sources', {}).get(source):
            return False
    case = d.execute('SELECT * FROM permanent_cases WHERE ip=?', (address,)).fetchone()
    if not case or case['reversed']:
        return False
    event = dt.datetime.fromisoformat(seen)
    if event > dt.datetime.now(UTC):
        return False
    period = (event - dt.datetime.fromisoformat(case['baseline'])) // PERIOD
    if period < 1:
        return False
    previous = d.execute('SELECT * FROM permanent_milestones WHERE ip=? AND period=?',
                         (address, period)).fetchone()
    if previous and (previous['seen'], previous['event_id']) <= (seen, event_id):
        return False
    d.execute('INSERT OR REPLACE INTO permanent_milestones VALUES(?,?,?,?,?,?,?)',
              (address, period, event_id, seen, source, sensor, origin))
    audit(d, address, 'milestone', {'period': period, 'event_id': event_id, 'seen': seen,
                                  'source': source, 'sensor': sensor, 'origin': origin,
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


def activity_id(address, source, sensor, seen):
    return hashlib.sha256(json.dumps(['source_activity', address, source, sensor, seen],
                                     separators=(',', ':')).encode()).hexdigest()


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
