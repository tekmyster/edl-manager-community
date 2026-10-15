import datetime as dt
import json
import pytest
from core import Store
from behavior_ai import Brain
from behavior_metrics import metrics


def test_metrics_preserve_failed_tokens_and_missing_history(tmp_path):
    b = Brain(Store(tmp_path / 'manager.sqlite3'))
    at = dt.datetime(2026, 10, 15, 12, tzinfo=dt.timezone.utc)
    when = (at - dt.timedelta(minutes=30)).isoformat()
    with b.connect() as d:
        for ident, status, result, latency in [
            ('ok', 'completed', {'classification': 'malicious', 'metadata': {'input_tokens': 100, 'output_tokens': 50}}, 8),
            ('fail', 'failed', {'metadata': {'input_tokens': 100, 'output_tokens': 1800}}, 25),
            ('old', 'failed', {}, 10),
            ('new', 'superseded', {'metadata': {'input_tokens': 10, 'output_tokens': 10}}, 12)]:
            d.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',
                      (ident, 'packet', 'cfg', when, when, status, json.dumps(result), '', latency))
        d.execute('INSERT INTO analysis_counters VALUES(?,?,?)', (when, 'cached', 4))
    result = metrics(b, at=at)
    totals = result['totals']
    assert len(result['bins']) == 24
    assert totals['tokens'] == 2070 and totals['unknown_tokens'] == 1
    assert totals['average_seconds'] == 8 and totals['p95_seconds'] == 25
    assert totals['completed'] == 1 and totals['failed'] == 2 and totals['superseded'] == 1
    assert totals['success_rate'] == 25 and totals['cached'] == 4
    assert sum(v['tokens'] for v in result['bins']) == totals['tokens']
    assert result['bins'][0]['latency'] is None
    assert result['applied_points'] == 0 and not result['active_scoring']


def test_metrics_empty_ranges_and_output_render(tmp_path):
    from flask import Flask, render_template
    b = Brain(Store(tmp_path / 'manager.sqlite3'))
    app = Flask(__name__)
    app.jinja_env.filters['recorded_time'] = lambda v: v or '—'
    with app.test_request_context('/'):
        for period, count in [('24h', 24), ('7d', 7), ('30d', 30)]:
            result = metrics(b, period)
            assert len(result['bins']) == count
            assert result['totals']['average_seconds'] is None
            page = render_template('behavior_metrics.html', metrics=result)
            assert 'No model requests' in page and 'Interval details' in page
            assert page.count('<svg ') == 4
            assert 'NaN' not in page and 'raw JSON' not in page
    with pytest.raises(ValueError):metrics(b, 'invalid')
