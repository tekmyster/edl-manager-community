"""Bounded recovery from saved assessments; never invent a dispatch or verdict.

The behavior worker retries a rowid page after a busy analytics write. New
receipts contain observed dispatch/completion times. Older metadata may repair
an existing real dispatch, leaving its unknown exact completion time null.
"""
import datetime as dt
import json
import math
import re
import sqlite3

from analytics_store import connect, warning


def receipt(row):
    from behavior_ai import timestamp
    try:meta=json.loads(row['metadata'] or '{}')
    except (ValueError,TypeError):return None
    if not isinstance(meta,dict):return None
    ident=meta.get('request_id')
    if not isinstance(ident,str) or not re.fullmatch(r'[a-f0-9]{32}',ident):return None
    state=meta.get('request_transport_state')
    if state not in ('accepted','rejected','failed'):
        if row['status']=='completed':state='accepted'
        elif meta.get('validation_diagnostic'):state='rejected'
        else:return None
    start=meta.get('request_started_at');finish=meta.get('request_finished_at')
    start=start if timestamp(start) else None
    if start and timestamp(start)<dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=35):return None
    finish=finish if timestamp(finish) and start and timestamp(finish)>=timestamp(start) else None
    def number(key,integer=False):
        v=meta.get(key)
        return v if type(v) in ((int,) if integer else (int,float)) and math.isfinite(v) and v>=0 else None
    return (ident,row['packet_id'],start,finish,state,number('first_content_seconds'),
            number('input_tokens',True),number('output_tokens',True),number('request_seconds'))


def recover(brain,limit=50):
    """At most 50 assessment metadata rows and one 25ms analytics transaction.

    Both databases use short independent connections. Commit the analytics page
    before its behavior cursor; a crash between commits is safe to replay.
    Nothing on this path changes assessments, reviews, usage or scheduling.
    """
    limit=max(1,min(50,limit));result={'scanned':0,'bound':50,'recovered':0,'partial':False}
    try:
        with sqlite3.connect(str(brain.path),timeout=.025) as db:
            db.row_factory=sqlite3.Row
            row=db.execute("SELECT value FROM retention_state WHERE name='telemetry_cursor'").fetchone()
            saved_cursor=row[0] if row else None
            try:marker=json.loads(saved_cursor) if saved_cursor else {}
            except (ValueError,TypeError):marker={}
            if not isinstance(marker,dict):marker={}
            cursor=marker.get('rowid',0)
            if type(cursor) is not int or cursor<0:cursor=0
            previous=db.execute('SELECT id FROM assessments WHERE rowid=?',(cursor,)).fetchone() if cursor else None
            # Retention may delete the watermark and SQLite can reuse rowids.
            # Identity loss restarts the bounded scan; idempotence prevents
            # double counting, and a compare-and-swap avoids a racing rewind.
            if cursor and (not previous or previous[0]!=marker.get('id')):cursor=0
            rows=db.execute("SELECT rowid,id,packet_id,created,status,json_extract(CASE WHEN json_valid(result) THEN result ELSE '{}' END,'$.metadata') metadata FROM assessments WHERE rowid>? ORDER BY rowid LIMIT ?",(cursor,limit)).fetchall()
        result['scanned']=len(rows)
        if not rows:return result
        values=[(row,v) for row in rows if (v:=receipt(row))]
        if values:
            with connect(brain.store,True) as db:
                for source,value in values:
                    ident,packet,start,finish,state,first,inp,out,total=value
                    old=db.execute('SELECT packet,started,state,finished FROM requests WHERE id=?',(ident,)).fetchone()
                    # A historical assessment cannot supply a missing dispatch.
                    if old is None and start is None:continue
                    if old is not None and (old['packet']!=packet or (start and old['started']!=start)):continue
                    if old is not None and (old['finished'] is not None or old['state']!='pending'):continue
                    if old is None:
                        db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)',value)
                        db.execute("INSERT INTO coverage VALUES('ai',?) ON CONFLICT(name) DO UPDATE SET started=min(coverage.started,excluded.started)",(start,))
                    else:
                        db.execute("UPDATE requests SET finished=?,state=?,first_seconds=?,input_tokens=?,output_tokens=?,total_seconds=? WHERE id=? AND state='pending' AND finished IS NULL",(finish,state,first,inp,out,total,ident))
                    db.execute('INSERT OR IGNORE INTO request_recovery VALUES(?,?,?)',(ident,source['id'],source['created']))
                    result['recovered']+=1
        with sqlite3.connect(str(brain.path),timeout=.025) as db:
            next_cursor=json.dumps({'rowid':rows[-1]['rowid'],'id':rows[-1]['id']},sort_keys=True)
            db.execute("INSERT INTO retention_state VALUES('telemetry_cursor',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value WHERE value=?",(next_cursor,saved_cursor))
            result['partial']=bool(db.execute('SELECT 1 FROM assessments WHERE rowid>? LIMIT 1',(rows[-1]['rowid'],)).fetchone())
        return result
    except (sqlite3.Error,OSError,ValueError,TypeError) as exc:
        warning('ai_recover',exc)
        # On a failed analytics transaction the page is retried, not discarded.
        result.update(recovered=0,partial=True,status='retry')
        return result
