"""Private, durable completed-result journal; never reissue inference to retry a save.

The journal contains only the already validated assessment (or bounded failure
metadata), not prompts, credentials, provider bodies or source configuration.
It is removed only after the whole assessment/job/backoff transaction commits.
"""
import contextlib
import hashlib
import itertools
import json
import logging
import math
import os
import pathlib
import sqlite3
import stat
import tempfile
import time


def contention(exc):
    code=getattr(exc,'sqlite_errorcode',None)
    return isinstance(exc,sqlite3.OperationalError) and type(code) is int and code>=0 and code&255 in (5,6)


def retry_busy(operation):
    """250ms retry window, with each rolled-back connection closed by the caller."""
    end=time.monotonic()+.25
    while True:
        try:return operation()
        except sqlite3.OperationalError as exc:
            remaining=end-time.monotonic()
            if not contention(exc) or remaining<=0:raise
            time.sleep(min(.005,remaining))


def private_directory(p,create=False):
    if create:p.mkdir(mode=0o700,exist_ok=True)
    if p.exists():
        if p.is_symlink() or not p.is_dir():raise ValueError('Invalid assessment journal directory')
        if os.name=='posix' and (p.stat().st_uid!=os.geteuid() or stat.S_IMODE(p.stat().st_mode)&0o077):
            raise ValueError('Assessment journal directory must be private')
        if create:sync_directory(p.parent)
    return p


def directory(brain,create=False):
    return private_directory(pathlib.Path(brain.path).with_suffix('.pending-assessments'),create)


def review_directory(brain,create=False):
    return private_directory(directory(brain,create)/'review',create)


def review_key(brain,p,create=False):
    return private_directory(review_directory(brain,create)/p.stem,create)


def location(brain,ident,cid):
    name=hashlib.sha256(json.dumps([ident,cid]).encode()).hexdigest()+'.json'
    return directory(brain)/name


def sync_directory(p):
    if os.name=='posix':
        fd=os.open(p,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)


def read(p):
    if p.is_symlink():raise ValueError('Invalid assessment journal file')
    with p.open('rb') as f:body=f.read(1048577)
    if len(body)>1048576:raise ValueError('Assessment journal record too large')
    v=json.loads(body)
    if not isinstance(v,dict) or set(v)!={'version','row','owner','backoff_key','backoff_previous','backoff_at'} or type(v['version']) is not int or v['version']!=1:
        raise ValueError('Invalid assessment journal record')
    row=v['row']
    if not isinstance(row,list) or len(row)!=9 or any(not isinstance(x,str) for x in row[:8]) or row[5] not in ('completed','failed'):
        raise ValueError('Invalid assessment journal row')
    if type(row[8]) not in (int,float) or not math.isfinite(row[8]) or row[8]<0:
        raise ValueError('Invalid assessment journal latency')
    if not isinstance(v['owner'],str) or not isinstance(v['backoff_key'],str) or v['backoff_previous'] is not None and not isinstance(v['backoff_previous'],str):
        raise ValueError('Invalid assessment journal ownership')
    if type(v['backoff_at']) not in (int,float) or not math.isfinite(v['backoff_at']):raise ValueError('Invalid assessment journal time')
    expected=hashlib.sha256(json.dumps(row[1:3]).encode()).hexdigest()+'.json'
    if p.name!=expected:raise ValueError('Invalid assessment journal identity')
    return v


def publish(p,body):
    parent=p.parent
    if len(body)>1048576:raise ValueError('Assessment journal record too large')
    staging=private_directory(private_directory(parent/'review',True)/'_staging',True)
    fd,name=tempfile.mkstemp(prefix='.result-',dir=staging)
    temp=pathlib.Path(name)
    try:
        with os.fdopen(fd,'wb') as f:f.write(body);f.flush();os.fsync(f.fileno())
        # Link a complete fsynced record exclusively; never overwrite a result.
        try:os.link(temp,p)
        except FileExistsError:
            if p.is_symlink():raise ValueError('Invalid assessment journal file')
            with p.open('rb') as f:existing=f.read(1048577)
            if existing!=body:raise ValueError('Conflicting pending assessment')
        sync_directory(parent)
    finally:temp.unlink(missing_ok=True)
    return p


def reserve(brain,ident,cid,owner,assessment,request):
    directory(brain,True)
    p=location(brain,ident,cid).with_suffix('.inflight')
    return publish(p,json.dumps({'owner':owner,'packet':ident,'config':cid,'assessment':assessment,'request':request}).encode())


def stage(brain,value):
    directory(brain,True)
    return publish(location(brain,*value['row'][1:3]),json.dumps(value,allow_nan=False).encode())


def clear_reservation(p,owner):
    marker=p.with_suffix('.inflight')
    for attempt in range(3):
        if marker.is_symlink():raise ValueError('Invalid assessment dispatch marker')
        try:
            with marker.open('rb') as f:body=f.read(4097)
        except FileNotFoundError:return
        if len(body)>4096:raise ValueError('Invalid assessment dispatch marker')
        if json.loads(body).get('owner')!=owner:return
        try:marker.unlink(missing_ok=True);return
        except PermissionError:
            # Windows may briefly report a peer's deletion as access denied.
            # Reopen and recheck ownership before retrying; never change ACLs.
            if attempt==2:raise
            time.sleep(.005)


def resolve_dispatch(brain,marker):
    if marker.is_symlink():raise ValueError('Invalid assessment dispatch marker')
    try:
        with marker.open('rb') as f:body=f.read(4097)
    except FileNotFoundError:return None
    if len(body)>4096:raise ValueError('Invalid assessment dispatch marker')
    value=json.loads(body)
    if not isinstance(value,dict) or set(value)!={'owner','packet','config','assessment','request'} or any(not isinstance(v,str) for v in value.values()):
        raise ValueError('Invalid assessment dispatch marker')
    if marker!=location(brain,value['packet'],value['config']).with_suffix('.inflight'):
        raise ValueError('Invalid assessment dispatch identity')
    def saved():
        with contextlib.closing(sqlite3.connect(str(brain.path),timeout=.025)) as db:
            row=db.execute('SELECT packet_id,config_id,status FROM assessments WHERE id=?',(value['assessment'],)).fetchone()
            job=db.execute('SELECT id,state,lease FROM jobs WHERE packet_id=? AND config_id=?',(value['packet'],value['config'])).fetchone()
            return row,job
    try:row,job=retry_busy(saved)
    except sqlite3.OperationalError as exc:
        if not contention(exc):raise
        logging.warning('Behavior assessment persistence deferred sqlite_code=%s',exc.sqlite_errorcode)
        return 'persistence_deferred'
    if not row:
        if job and job[0]==value['owner'] and job[1]=='running' and job[2]>time.time():return 'leased_or_exhausted'
        return 'persistence_review_required'
    if tuple(row[:2])!=(value['packet'],value['config']) or row[2] not in ('completed','failed','superseded'):
        raise ValueError('Conflicting saved dispatch identity')
    clear_reservation(marker.with_suffix('.json'),value['owner']);sync_directory(marker.parent)
    return row[2]


def retain_review(brain,p):
    """Durably retain opaque evidence outside the bounded pending work scan."""
    if p.is_symlink():raise ValueError('Invalid assessment journal file')
    try:
        with p.open('rb') as f:body=f.read(1048577)
    except FileNotFoundError:return
    if len(body)>1048576:raise ValueError('Assessment journal record too large')
    target_parent=review_key(brain,p,True)
    target=target_parent/(hashlib.sha256(body).hexdigest()+p.suffix)
    attention=review_directory(brain)/'attention'
    try:
        fd=os.open(attention,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError:
        if attention.is_symlink() or not attention.is_file():raise ValueError('Invalid assessment review indicator')
    else:
        with os.fdopen(fd,'wb') as f:f.write(b'Retained inference evidence requires review.\n');f.flush();os.fsync(f.fileno())
        sync_directory(attention.parent)
    try:os.link(p,target)
    except FileExistsError:
        if target.is_symlink():raise ValueError('Invalid assessment review file')
        with target.open('rb') as f:prior=f.read(1048577)
        if prior!=body:raise ValueError('Conflicting assessment review evidence')
    except FileNotFoundError:
        if not target.is_file():raise
    # No evidence is discarded: the new link and its private parent are durable
    # before removing the pending link. Same-content replay is idempotent.
    sync_directory(target_parent)
    p.unlink(missing_ok=True);sync_directory(p.parent)


class Cancelled(Exception):pass


def persist(brain,p,should_stop=None):
    try:value=read(p)
    except FileNotFoundError:return 'persistence_deferred'
    frozen=value['row']
    attempts=0
    def save():
        nonlocal attempts
        if attempts and should_stop and should_stop():raise Cancelled()
        attempts+=1
        with contextlib.closing(sqlite3.connect(str(brain.path),timeout=.025)) as db,db:
            db.row_factory=sqlite3.Row;db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM assessments WHERE id=?',(frozen[0],)).fetchone()
            if old:
                if any(old[i]!=frozen[i] for i in range(9) if i!=5) or old['status'] not in (frozen[5],'superseded'):
                    raise ValueError('Conflicting saved assessment')
                return old['status']
            packet=db.execute('SELECT ip FROM packets WHERE id=?',(frozen[1],)).fetchone()
            if not packet:raise ValueError('Pending assessment packet unavailable')
            owned=db.execute("SELECT 1 FROM jobs WHERE id=? AND packet_id=? AND config_id=? AND state='running'",(value['owner'],frozen[1],frozen[2])).fetchone()
            if not owned:return 'lease_lost'
            current=db.execute('SELECT packet_id FROM current_packets WHERE ip=?',(packet['ip'],)).fetchone()
            row=list(frozen)
            if not owned or current and current[0]!=frozen[1]:row[5]='superseded'
            db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',row)
            if owned:
                db.execute("UPDATE jobs SET state=?,lease=0,updated=? WHERE id=? AND state='running'",(row[5],frozen[3],value['owner']))
                if frozen[7] not in ('invalid_assessment','output_limit'):
                    prior=db.execute('SELECT value FROM retention_state WHERE name=?',(value['backoff_key'],)).fetchone()
                    previous=prior[0] if prior else None
                    # An older saved result must not overwrite a newer provider guard.
                    if previous==value['backoff_previous']:
                        failures=min(5,(json.loads(previous).get('failures',0) if previous else 0)+1) if frozen[7] else 0
                        until=value['backoff_at']+min(900,30*2**failures) if failures else 0
                        db.execute('INSERT OR REPLACE INTO retention_state VALUES(?,?)',(value['backoff_key'],json.dumps({'failures':failures,'until':until})))
            return row[5] if owned else 'lease_lost'
    try:status=retry_busy(save)
    except Cancelled:return 'persistence_deferred'
    except sqlite3.OperationalError as exc:
        if not contention(exc):raise
        logging.warning('Behavior assessment persistence deferred sqlite_code=%s',exc.sqlite_errorcode)
        return 'persistence_deferred'
    if status=='lease_lost':
        retain_review(brain,p)
        marker=p.with_suffix('.inflight')
        try:
            with marker.open('rb') as f:owner=json.loads(f.read(4097)).get('owner')
        except FileNotFoundError:owner=None
        if owner==value['owner']:retain_review(brain,marker)
        logging.warning('Behavior assessment persistence requires review reason=lease_lost')
        return status
    # Also safe after a crash between commit and unlink: the same ID is checked.
    clear_reservation(p,value['owner'])
    p.unlink(missing_ok=True);sync_directory(p.parent)
    return status


def recover(brain,should_stop=None):
    parent=directory(brain);out={'scanned':0,'dispatch_markers_scanned':0,'entries_scanned':0,'saved':0,'deferred':False,'review_required':0,'uncertain_dispatches':0,'bound_per_kind':50,'entry_bound':51,'review_retained':False}
    if not parent.exists():return out
    out['review_retained']=(review_directory(brain)/'attention').is_file()
    # One known review subdirectory plus at most 50 pending files. Never filter
    # an unbounded directory stream looking for 50 matching filename suffixes.
    work=0
    with os.scandir(parent) as entries:
        for entry in itertools.islice(entries,51):
            out['entries_scanned']+=1
            if entry.name=='review':continue
            if work==50:break
            if should_stop and should_stop():out['deferred']=True;break
            p=pathlib.Path(entry.path)
            if not p.exists() and not p.is_symlink():continue
            work+=1
            if entry.name.endswith('.inflight'):
                out['dispatch_markers_scanned']+=1
                result=p.with_suffix('.json')
                if result.exists() or result.is_symlink():p=result
                else:
                    status=resolve_dispatch(brain,p)
                    if status=='persistence_deferred':out['deferred']=True;break
                    if status=='persistence_review_required':
                        retain_review(brain,p);out['uncertain_dispatches']+=1;out['review_retained']=True
                    continue
            elif not entry.name.endswith('.json'):raise ValueError('Unexpected assessment journal entry')
            out['scanned']+=1
            status=persist(brain,p,should_stop)
            if status=='persistence_deferred':out['deferred']=True;break
            if status=='lease_lost':out['review_required']+=1;out['review_retained']=True;continue
            out['saved']+=1
    if out['uncertain_dispatches']:
        logging.warning('Behavior assessment persistence requires review reason=dispatch_outcome_unknown')
    return out
