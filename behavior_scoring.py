"""Bounded, expiring AI score contributions; native scoring remains authoritative."""
import datetime as dt
import json
import math
import pathlib
import sqlite3

UTC = dt.timezone.utc
MAXIMUM = 10
MIN_CONFIDENCE = .9


def contribution(packet, assessment, row, expires, at=None, maximum=MAXIMUM):
    """Require fresh, distinct observations not already credited by native scoring."""
    at = at or dt.datetime.now(UTC)
    if type(maximum) not in (int,float) or not math.isfinite(maximum):return 0
    if row.get('verified_crawler') or row['score'] >= 75:
        return 0
    if assessment.get('classification') != 'malicious' or assessment.get('contradictory_evidence'):
        return 0
    confidence = assessment.get('maliciousness_confidence')
    if type(confidence) not in (int, float) or not math.isfinite(confidence) or not MIN_CONFIDENCE <= confidence <= 1:
        return 0
    try:
        expiry = dt.datetime.fromisoformat(expires)
        if expiry.tzinfo is None or expiry <= at:
            return 0
    except (ValueError, TypeError):
        return 0
    if row.get('cache', {}).get('greynoise', {}).get('classification') == 'benign':
        return 0
    counted = {(e['source'], e['sensor']) for e in row.get('evidence', []) if e['source'] != 'palo'}
    cited = {ident for finding in assessment.get('findings', []) for ident in finding.get('evidence_ids', [])}
    observations = set()
    for event in packet.get('events', []):
        if event['id'] not in cited or event.get('independent_evidence') is not True:
            continue
        if event.get('source') == 'palo' or (event.get('source'), event.get('sensor')) in counted:
            continue
        try:
            seen = dt.datetime.fromisoformat(event['seen'])
            if seen.tzinfo is None or not at - dt.timedelta(hours=24) <= seen <= at + dt.timedelta(minutes=5):
                continue
        except (ValueError, TypeError, KeyError):
            continue
        # Copies of one request in multiple logs cannot become two observations.
        observations.add((event['seen'], event.get('path'), event.get('method'), event.get('port')))
    if len(observations) < 2:
        return 0
    return round(min(MAXIMUM, max(0, maximum)) * confidence, 2)


def apply(store, rows):
    """Overlay one current assessment per IP, with no writes to native history."""
    normalized=[]
    for original in rows:
        if 'native_score' not in original:
            normalized.append(original);continue
        native=original['native_score'];row={**original,'score':native,'auto_candidate':native>=75 and not original.get('verified_crawler')}
        for key in ('native_score','ai_bump','ai_assessment_id','ai_expires'):row.pop(key,None)
        row['score_breakdown']={k:v for k,v in row.get('score_breakdown',{}).items() if k!='ai_behavior_bonus'}
        row['review_notes']=[v for v in row.get('review_notes',[]) if not v.startswith('AI pilot:')]
        if native<75 and 'Score is below the 75% automatic block threshold' not in row.get('holds',[]):row['holds']=row.get('holds',[])+['Score is below the 75% automatic block threshold']
        normalized.append(row)
    rows=normalized
    cfg = store.state('behavior_settings') or {}
    if not all(cfg.get(k) for k in ('enabled', 'model_enabled', 'scoring_enabled')):
        return rows
    path = pathlib.Path(store.path).parent / 'behavior.sqlite3'
    if not path.exists():
        return rows
    from behavior_ai import config_id,settings,PROMPT_VERSION
    prefix=config_id(settings(store))+'-%'
    try:
        db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=2)
        db.row_factory = sqlite3.Row
        try:
            candidates = {r['ip']: dict(r) for r in db.execute('''
                SELECT p.ip,p.content,a.id,a.result,a.expires,a.created
                FROM current_packets c JOIN packets p ON p.id=c.packet_id
                JOIN assessments a ON a.packet_id=p.id
                WHERE a.status='completed' AND a.expires>?
                AND a.config_id LIKE ? AND a.rowid=(SELECT max(b.rowid) FROM assessments b WHERE b.packet_id=p.id AND b.config_id LIKE ?)
            ''', (dt.datetime.now(UTC).isoformat(),prefix,prefix))}
        finally:
            db.close()
    except (OSError, sqlite3.Error):
        return rows
    from table_layout import policy_rows
    rules=store.active_rules()
    allowed={r['ip'] for r in policy_rows(store,rows,rules) if r['policy']=='Allowed'} if rules else set()
    result = []
    at = dt.datetime.now(UTC)
    configuration = store.state('source_configuration')
    enabled = ({k for k, v in configuration.get('sources', {}).items() if v} if configuration.get('index_url') else set()) if configuration else None
    for row in rows:
        saved = candidates.get(row['ip'])
        bump = 0
        if saved and row['ip'] not in allowed:
            try:
                packet, assessment = json.loads(saved['content']), json.loads(saved['result'])
                created = dt.datetime.fromisoformat(saved['created'])
                if assessment.get('metadata',{}).get('model')!=cfg.get('model') or assessment.get('metadata',{}).get('prompt_version')!=PROMPT_VERSION or packet.get('version') != 'behavior-3' or not at - dt.timedelta(hours=24) <= created <= at:
                    result.append(row);continue
                if enabled is not None:
                    packet['events'] = [e for e in packet['events'] if e['source'] in enabled]
                bump = contribution(packet, assessment, row, saved['expires'], at, cfg.get('max_bump') or 0)
            except (ValueError, TypeError, KeyError):
                bump = 0
        if not bump:
            result.append(row);continue
        effective = round(min(100, row['score'] + bump), 2)
        holds = [h for h in row.get('holds', []) if h != 'Score is below the 75% automatic block threshold' or effective < 75]
        result.append({**row, 'native_score': row['score'], 'ai_bump': bump, 'ai_assessment_id': saved['id'],
                       'ai_expires': min(saved['expires'], (created + dt.timedelta(hours=24)).isoformat()),
                       'score': effective, 'auto_candidate': effective >= 75 and not row.get('verified_crawler'),
                       'holds': holds, 'score_breakdown': {**row.get('score_breakdown', {}), 'ai_behavior_bonus': bump},
                       'review_notes': row.get('review_notes', []) + ['AI pilot: fresh behavior outside native scoring +' + str(bump)]})
    return result
