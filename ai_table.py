"""Read-only, batched IP table annotations; never inference or scoring writes."""
import contextlib
import datetime as dt
import math
import pathlib
import sqlite3
from behavior_ai import settings,config_id,timestamp

FIELDS=('ai_assessment','ai_contribution','ai_coverage')
LABELS={'accepted':'Accepted model output','rejected':'Rejected output','failed':'Request failed','expired':'Expired assessment','pending':'Awaiting assessment','model_off':'Model off','not_indexed':'Not indexed','unavailable':'Unavailable'}


def decorate(store,rows,visible,at=None):
    at=at or dt.datetime.now(dt.timezone.utc)
    cfg=settings(store);target=pathlib.Path(store.path).resolve().with_name('behavior.sqlite3')
    saved={};unavailable=False;addresses=list(dict.fromkeys(r['ip'] for r in rows))
    if target.exists() and addresses:
        try:
            with contextlib.closing(sqlite3.connect(target.as_uri()+'?mode=ro',uri=True,timeout=.25)) as db:
                db.row_factory=sqlite3.Row;db.execute('BEGIN')
                for offset in range(0,len(addresses),400):
                    batch=addresses[offset:offset+400]
                    sql='''SELECT c.ip,p.id packet_id,p.created packet_indexed,
                        CASE WHEN json_valid(p.content) THEN json_extract(p.content,'$.coverage') END coverage,
                        CASE WHEN json_valid(p.content) AND json_type(p.content,'$.events')='array' THEN json_array_length(p.content,'$.events') END observed,
                        a.id assessment_id,a.status,a.expires,a.created assessed,a.error,
                        CASE WHEN json_valid(a.result) THEN json_extract(a.result,'$.classification') END classification
                        FROM current_packets c JOIN packets p ON p.id=c.packet_id
                        LEFT JOIN assessments a ON a.rowid=(SELECT x.rowid FROM assessments x WHERE x.packet_id=p.id AND x.config_id LIKE ? ORDER BY x.created DESC,x.rowid DESC LIMIT 1)
                        WHERE c.ip IN ('''+','.join('?' for _ in batch)+')'
                    for value in db.execute(sql,[config_id(cfg)+'-%',*batch]):saved[value['ip']]=dict(value)
        except (sqlite3.Error,OSError):unavailable=True;saved={}
    result=[]
    for original in rows:
        row=dict(original);value=saved.get(row['ip']);status='unavailable' if unavailable else 'not_indexed'
        label=LABELS[status];coverage='Unavailable' if unavailable else 'Not indexed';coverage_state='unknown' if unavailable else 'not_indexed'
        if value:
            status='model_off' if not (cfg['enabled'] and cfg['model_enabled']) else 'pending'
            if value['status']:
                expiry=timestamp(value['expires'])
                if not expiry:status='unavailable'
                elif expiry<=at:status='expired'
                elif value['status']=='completed':status='accepted'
                elif value['status']=='failed':status='rejected' if value['error']=='invalid_assessment' else 'failed'
            label=LABELS[status]
            if status in ('accepted','expired') and value['status']=='completed' and value['classification'] in ('benign','malicious','inconclusive'):
                label+=' · '+value['classification']
            count=value['observed']
            if value['coverage']=='saved_samples' and type(count) is int:
                coverage=f'Saved samples · {count:,} observations';coverage_state='sampled'
            else:coverage='Coverage unavailable';coverage_state='unknown'
        elif not unavailable and not (cfg['enabled'] and cfg['model_enabled']):
            status='model_off';label=LABELS[status]
        points=row.get('ai_bump',0)
        if row.get('history_only') or type(points) not in (int,float) or not math.isfinite(points) or points<0:points=None
        contribution='Unavailable for history' if points is None else f'{points:g} points applied'
        row.update(ai_assessment=label,ai_assessment_status=status,ai_packet_id=value['packet_id'] if value else None,
                   ai_assessed=value['assessed'] if value else None,ai_coverage=coverage,ai_coverage_status=coverage_state,
                   ai_contribution=contribution,ai_contribution_value=points)
        row['ai_search']=' '.join(str(row[k]) for k in FIELDS if k in visible)
        result.append(row)
    return result
