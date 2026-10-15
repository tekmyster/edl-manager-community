"""Read-only operational measurements from saved AI assessments."""
import datetime as dt
import json
import math


def metrics(brain, period='24h', at=None):
    at = at or dt.datetime.now(dt.timezone.utc)
    periods = {'24h': (24, 3600), '7d': (7, 86400), '30d': (30, 86400)}
    if period not in periods:
        raise ValueError('Choose a supported time range.')
    count, seconds = periods[period]
    start = at - dt.timedelta(seconds=count * seconds)
    bins = [{'start': (start + dt.timedelta(seconds=i * seconds)).isoformat(),
             'end': (start + dt.timedelta(seconds=(i + 1) * seconds)).isoformat(),
             'completed': 0, 'failed': 0, 'superseded': 0, 'input': 0, 'output': 0,
             'known_tokens': 0, 'unknown_tokens': 0, 'durations': []} for i in range(count)]
    with brain.connect() as db:
        rows = db.execute('SELECT created,status,result,latency FROM assessments WHERE created>=? AND created<? ORDER BY created',
                          (start.isoformat(), at.isoformat())).fetchall()
        cached = db.execute("SELECT coalesce(sum(count),0) FROM analysis_counters WHERE kind='cached' AND hour>=? AND hour<?",
                            (start.isoformat(), at.isoformat())).fetchone()[0]
    durations, success_times, models = [], [], set()
    malicious = benign = inconclusive = 0
    for row in rows:
        try:
            when = dt.datetime.fromisoformat(row['created'])
            index = int((when - start).total_seconds() // seconds)
            value = json.loads(row['result'])
        except (ValueError, TypeError):
            continue
        if not 0 <= index < count:
            continue
        bucket = bins[index]
        status = row['status'] if row['status'] in ('completed', 'failed') else 'superseded'
        bucket[status] += 1
        elapsed = row['latency']
        if isinstance(elapsed, (int, float)) and math.isfinite(elapsed) and elapsed >= 0:
            durations.append(elapsed)
            bucket['durations'].append(elapsed)
            if status == 'completed':
                success_times.append(elapsed)
        metadata = value.get('metadata', {}) if isinstance(value, dict) else {}
        pair = (metadata.get('input_tokens'), metadata.get('output_tokens'))
        if all(type(n) is int and n >= 0 for n in pair):
            bucket['input'] += pair[0]
            bucket['output'] += pair[1]
            bucket['known_tokens'] += 1
        else:
            bucket['unknown_tokens'] += 1
        model = metadata.get('model')
        if isinstance(model, str):
            models.add(model[:120])
        if status == 'completed':
            classification = value.get('classification')
            malicious += classification == 'malicious'
            benign += classification == 'benign'
            inconclusive += classification == 'inconclusive'
    for bucket in bins:
        values = bucket.pop('durations')
        bucket['latency'] = round(sum(values) / len(values), 2) if values else None
        bucket['requests'] = bucket['completed'] + bucket['failed'] + bucket['superseded']
        bucket['tokens'] = bucket['input'] + bucket['output']
    totals = {key: sum(b[key] for b in bins) for key in
              ('completed', 'failed', 'superseded', 'requests', 'input', 'output', 'known_tokens', 'unknown_tokens')}
    ordered = sorted(durations)
    totals.update(tokens=totals['input'] + totals['output'], cached=cached,
                  success_rate=round(100 * totals['completed'] / totals['requests'], 1) if totals['requests'] else None,
                  average_seconds=round(sum(success_times) / len(success_times), 2) if success_times else None,
                  p95_seconds=round(ordered[math.ceil(len(ordered) * .95) - 1], 2) if ordered else None,
                  malicious=malicious, benign=benign, inconclusive=inconclusive)
    # SVG coordinates share a disciplined plot area. Missing latency remains a gap.
    peaks = {'tokens': max(1, max(b['tokens'] for b in bins)),
             'requests': max(1, max(b['requests'] for b in bins)),
             'latency': max(1, max((b['latency'] or 0) for b in bins))}
    for i, b in enumerate(bins):
        b['x'] = round(48 + (i + .5) * 624 / count, 2)
        b['width'] = round(min(36, 624 / count * .65), 2)
        for name in ('input', 'output', 'completed', 'failed', 'superseded'):
            peak = peaks['tokens' if name in ('input', 'output') else 'requests']
            b[name + '_height'] = round(140 * b[name] / peak, 2)
        b['latency_y'] = round(166 - 140 * b['latency'] / peaks['latency'], 2) if b['latency'] is not None else None
    segments, points = [], []
    for b in bins:
        if b['latency_y'] is None:
            if points: segments.append(' '.join(points)); points = []
        else:
            points.append(f"{b['x']},{b['latency_y']}")
    if points: segments.append(' '.join(points))
    return {'period': period, 'start': start.isoformat(), 'end': at.isoformat(), 'bins': bins,
            'totals': totals, 'peaks': peaks, 'latency_segments': segments, 'models': sorted(models),
            'active_scoring': False, 'applied_points': 0}
