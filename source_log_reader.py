"""Complete compressed inputs before consumption; retain deferred-file cursors.

Compressed bytes are snapshotted to a temporary spool (1 MiB memory rollover threshold),
then validated through EOF/CRC before any record reaches the consumer. Only one
compressed file is spooled at a time. Plain logs retain incremental text offsets.
"""
import contextlib
import gzip
import io
import os
import pathlib
import tempfile
import zlib
import dataclasses
import hashlib
import time
import copy

_CHUNK = 1024 * 1024


class DeferredInput(Exception):
    def __init__(self, path, reason):
        self.path = str(path)
        self.reason = reason
        super().__init__(f'{self.path}: {reason}')


def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


@contextlib.contextmanager
def _prepared(path, before, old, admission=None):
    try:
        raw = path.open('rb')
    except OSError as exc:
        raise DeferredInput(path, 'Input could not be opened; retry required.') from exc
    with raw:
        opened = os.fstat(raw.fileno())
        if _identity(opened) != _identity(before):
            raise DeferredInput(path, 'Input changed before reading; retry required.')
        if path.suffix != '.gz':
            with io.TextIOWrapper(raw, encoding='utf-8', errors='replace') as stream:
                offset = old.get('offset', 0) if old.get('inode') == opened.st_ino and old.get('offset', 0) <= opened.st_size else 0
                if offset:
                    stream.seek(offset)
                yield stream, opened
            return
        # Copy only the observed compressed size: a writer cannot extend this
        # read indefinitely. No consumer effects occur until validation ends.
        with tempfile.SpooledTemporaryFile(max_size=_CHUNK) as snapshot:
            try:
                remaining = opened.st_size
                while remaining:
                    if admission:admission.check()
                    block = raw.read(min(_CHUNK, remaining))
                    if not block:
                        raise DeferredInput(path, 'Compressed input changed while reading; retry required.')
                    snapshot.write(block)
                    if admission:admission.charge(len(block))
                    remaining -= len(block)
                if _identity(os.fstat(raw.fileno())) != _identity(opened) or _identity(path.stat()) != _identity(opened):
                    raise DeferredInput(path, 'Compressed input changed while reading; retry required.')
                snapshot.seek(0)
                with gzip.GzipFile(fileobj=snapshot, mode='rb') as checked:
                    expanded=0
                    for block in iter(lambda:checked.read(_CHUNK),b''):
                        expanded+=len(block)
                        if admission:
                            admission.charge(len(block))
                            admission.check()
                            if expanded>admission.limits.expanded_bytes:raise DeferredInput(path,'Expanded archive exceeds bounded admission; historical cursor retained.')
            except (EOFError, gzip.BadGzipFile, zlib.error) as exc:
                raise DeferredInput(path, 'Compressed input is incomplete or damaged; retry required.') from exc
            except OSError as exc:
                raise DeferredInput(path, 'Compressed input could not be read; retry required.') from exc
            snapshot.seek(0)
            with io.TextIOWrapper(gzip.GzipFile(fileobj=snapshot, mode='rb'), encoding='utf-8', errors='replace') as stream:
                if old.get('partial') and old.get('inode')==opened.st_ino and old.get('mtime')==opened.st_mtime and old.get('size')==opened.st_size:
                    stream.seek(old.get('offset',0))
                yield stream, opened


def collect_log_inputs(paths, files, consume, *, cutoff, limits=None, start_after=None):
    """Update cursors only for consumed complete files; return explicit coverage.

`consume(path, line)` retains the caller's parsing/qualification semantics.
Malformed records remain the caller's decision. Consumer failures propagate.
Failed compressed inputs contribute no partial records and keep prior state.
"""
    if limits is not None:return collect_bounded(paths,files,consume,cutoff=cutoff,limits=limits,start_after=start_after)
    coverage = {'status': 'complete', 'completed': 0, 'unchanged': 0, 'outside_retention': 0, 'deferred': []}
    for value in paths:
        path = pathlib.Path(value)
        old = files.get(str(path), {})
        try:
            if old.get('record_debt') or old.get('opaque_pending') or old.get('continuity_debt') or old.get('delivery_offset') is not None:
                raise DeferredInput(path,'Bounded delivery protocol requires bounded reader; all cursors/debt retained.')
            try:
                before = path.stat()
            except OSError as exc:
                raise DeferredInput(path, 'Input metadata is unavailable; retry required.') from exc
            if before.st_mtime < cutoff:
                coverage['outside_retention'] += 1
                continue
            if path.suffix == '.gz' and old.get('inode') == before.st_ino and old.get('mtime') == before.st_mtime and old.get('size') == before.st_size and not old.get('partial'):
                coverage['unchanged'] += 1
                continue
            with _prepared(path, before, old) as (stream, observed):
                for line in iter(stream.readline, ''):
                    consume(path, line)
                final = stream.tell()
            # Use the opened inode, never a replacement now at the same path.
            files[str(path)] = {**old,'inode': observed.st_ino, 'offset': final, 'mtime': observed.st_mtime, 'size': observed.st_size,**({'partial':False} if 'partial' in old else {})}
            coverage['completed'] += 1
            if old.get('legacy_prefix_unverified') or old.get('prior_generations'):
                coverage['status']='partial';coverage.setdefault('historical_debt',[]).append({'path':str(path),'reason':'Retained legacy/generation continuity debt requires review.'})
        except DeferredInput as exc:
            coverage['status'] = 'partial'
            coverage['deferred'].append({'path': exc.path, 'reason': exc.reason})
    return coverage

@dataclasses.dataclass(frozen=True)
class InputLimits:
    seconds:float=5
    input_bytes:int=64*1024**2
    file_bytes:int=32*1024**2
    records:int=4096
    record_bytes:int=1024**2
    compressed_bytes:int=1024**2
    expanded_bytes:int=4*1024**2
    validation_bytes:int=16*1024**2
    files:int=256

class _Admission:
    def __init__(self,limits):
        if any(v<=0 for v in dataclasses.asdict(limits).values()):raise ValueError('Positive input bounds required')
        self.limits=limits;self.deadline=time.monotonic()+limits.seconds;self.validation_bytes=0
    def check(self):
        if time.monotonic()>=self.deadline:raise DeferredInput('', 'Input work budget exhausted; checkpoint retained.')
    def charge(self,n):
        self.validation_bytes+=n
        if self.validation_bytes>self.limits.validation_bytes:raise DeferredInput('','Archive validation admission exhausted; cursor retained.')

def _anchor(path,offset):
    # A complete line's UTF8 cookie is a byte position. Never reinterpret an
    # opaque legacy cookie; its preexisting continuity debt remains explicit.
    if type(offset) is not int or offset<0 or offset>path.stat().st_size:return None
    with path.open('rb') as f:
        head=f.read(min(offset,4096));f.seek(max(0,offset-4096));tail=f.read(min(offset,4096))
    return {'offset':offset,'head':hashlib.sha256(head).hexdigest(),'tail':hashlib.sha256(tail).hexdigest()}


class SliceChanged(DeferredInput):
    def __init__(self,path,receipt):
        super().__init__(path,'Admitted bytes changed during consumption; prior checkpoint and continuity debt retained.')
        self.receipt=receipt


def _slice(path,binary,observed,lane,consume,coverage,admission,through=None):
    """Capture bounded bytes before callbacks; acknowledge only that capture.

    An opaque record has its own delivery frontier. The ordinary offset stops
    before the first unresolved record. Only a verified newline releases later
    records, and range/hash receipts keep that omission explicitly unresolved.
    No source payload is stored in the checkpoint.
    """
    limits=admission.limits;lane=copy.deepcopy(lane)
    start=lane.get('delivery_offset',lane.get('offset',0))
    if type(start) is not int or start<0:raise DeferredInput(path,'Unsupported legacy byte cookie; cursor retained for review.')
    admitted=min(limits.file_bytes,limits.input_bytes-coverage['input_bytes'])
    if path.suffix!='.gz':admitted=min(admitted,max(0,observed.st_size-start))
    binary.seek(0);head=binary.read(4096)
    binary.seek(max(0,start-4096));preceding=binary.read(min(start,4096))
    binary.seek(start);data=binary.read(admitted)
    at_eof=start+len(data)==observed.st_size if path.suffix!='.gz' else len(data)<admitted
    coverage['input_bytes']+=len(data)
    capture={'device':observed.st_dev,'inode':observed.st_ino,'size':observed.st_size,'mtime_ns':observed.st_mtime_ns,'ctime_ns':observed.st_ctime_ns,'start':start,'end':start+len(data),'sha256':hashlib.sha256(data).hexdigest(),'offset_space':'expanded_bytes' if path.suffix=='.gz' else 'source_bytes'}
    pending=lane.get('opaque_pending');debts=lane.setdefault('record_debt',[]);position=0
    while position<len(data) and coverage['records']<limits.records and time.monotonic()<admission.deadline:
        absolute=start+position
        if through is not None and absolute>=through:break
        newline=data.find(b'\n',position);end=len(data) if newline<0 else newline+1
        length=end-position
        if pending is None and newline>=0 and length<=limits.record_bytes:
            consume(path,data[position:end].decode('utf-8',errors='replace'));coverage['records']+=1
            position=end
            if debts or 'delivery_offset' in lane:lane['delivery_offset']=start+position
            else:lane['offset']=start+position
            continue
        if pending is None:
            # A small incomplete tail may still become a normal record. A
            # slice-end fragment gets a fresh full admission next invocation.
            if newline<0 and length<=limits.record_bytes and (at_eof or position>0):break
            if len(debts)>=64:break
            pending={'start':absolute,'through':absolute,'source':{k:capture[k] for k in ('device','inode','size','mtime_ns','ctime_ns','offset_space')},'segments':[],'chain_sha256':hashlib.sha256(b'').hexdigest(),'status':'unresolved_record','boundary_verified':False}
            lane.setdefault('offset',absolute)
        if len(pending['segments'])>=4096:break
        segment={'start':absolute,'end':start+end,'sha256':hashlib.sha256(data[position:end]).hexdigest()}
        pending['segments'].append(segment)
        pending['chain_sha256']=hashlib.sha256(bytes.fromhex(pending['chain_sha256'])+str(segment['start']).encode()+b':'+str(segment['end']).encode()+b':'+bytes.fromhex(segment['sha256'])).hexdigest()
        pending['through']=start+end;position=end;lane['delivery_offset']=start+position
        if newline>=0:
            pending['boundary_verified']=True;pending['end']=start+end;debts.append(pending);pending=None
    if pending is not None:lane['opaque_pending']=pending
    else:lane.pop('opaque_pending',None)
    final=lane.get('delivery_offset',lane.get('offset',start))
    def captured_anchor(offset):
        if not start<=offset<=start+len(data):return None
        tail=(preceding+data[:offset-start])[-min(offset,4096):] if offset else b''
        return {'offset':offset,'head':hashlib.sha256(head[:min(offset,4096)]).hexdigest(),'tail':hashlib.sha256(tail).hexdigest()}
    if path.suffix!='.gz':
        lane['delivery_anchor']=captured_anchor(final)
        if lane.get('offset',start)>=start:lane['anchor']=captured_anchor(lane.get('offset',start))
    # Validation is independent of the stream's prefetched buffer. Never
    # construct a successful anchor from bytes replaced by a callback.
    try:
        after=path.stat()
        if after.st_dev!=observed.st_dev or after.st_ino!=observed.st_ino or after.st_size<observed.st_size:raise ValueError('generation')
        if path.suffix=='.gz':
            if _identity(after)!=_identity(observed) or after.st_ctime_ns!=observed.st_ctime_ns:raise ValueError('compressed mutation')
        else:
            with path.open('rb',buffering=0) as verified:
                checked=os.fstat(verified.fileno())
                if checked.st_dev!=observed.st_dev or checked.st_ino!=observed.st_ino:raise ValueError('opened generation')
                if verified.read(len(head))!=head:raise ValueError('head')
                verified.seek(max(0,start-4096))
                if verified.read(len(preceding))!=preceding:raise ValueError('preceding boundary')
                verified.seek(start)
                if hashlib.sha256(verified.read(len(data))).hexdigest()!=capture['sha256']:raise ValueError('admitted range')
    except (OSError,ValueError) as exc:raise SliceChanged(path,capture) from exc
    eof=(final==observed.st_size if path.suffix!='.gz' else final==start+len(data) and len(data)<admitted)
    return lane,eof and not pending

def collect_bounded(paths,files,consume,*,cutoff,limits,start_after=None):
    admission=_Admission(limits);paths=sorted({pathlib.Path(p) for p in paths},key=str)
    if len(paths)>limits.files:raise ValueError('Input inventory exceeds bounded admission')
    # Fair cyclic work across existing inputs, including old plain rotations.
    # Large/unverified archives remain explicit debt, never a fabricated EOF.
    plain=[p for p in paths if p.suffix!='.gz'];compressed=[p for p in paths if p.suffix=='.gz']
    if start_after in map(str,plain):
        i=next(i for i,p in enumerate(plain) if str(p)==start_after)+1;plain=plain[i:]+plain[:i]
    ordered=plain+compressed
    coverage=dict(status='complete',completed=0,unchanged=0,outside_retention=0,deferred=[],input_bytes=0,records=0,next_path=start_after,historical_debt=[])
    def defer(path,reason):coverage['status']='partial';coverage['deferred'].append(dict(path=str(path),reason=reason))
    for p in ordered:
        old=files.get(str(p),{});old_prior=list(old.get('prior_generations',[]))
        if old_prior:coverage['historical_debt'].append(dict(path=str(p),reason='Prior generation receipts retained; mapping/completeness is not certified.'))
        if old.get('legacy_prefix_unverified'):coverage['historical_debt'].append(dict(path=str(p),reason='Existing legacy prefix lacks a capture anchor; not retroactively certified.'))
        if old.get('continuity_debt') or old.get('record_debt') or old.get('opaque_pending') or (old.get('prefix_reconcile') or {}).get('record_debt') or (old.get('prefix_reconcile') or {}).get('opaque_pending'):
            coverage['historical_debt'].append(dict(path=str(p),reason='Unresolved byte ranges or in-slice continuity receipts retained; source completeness is not certified.'))
        try:
            admission.check();before=p.stat()
            if len(old.get('continuity_debt',[]))>=64:defer(p,'Continuity receipt admission reached; preserve all receipts for review.');continue
            if before.st_mtime<cutoff:coverage['outside_retention']+=1;continue
            same=old.get('inode')==before.st_ino
            if p.suffix=='.gz' and same and old.get('mtime')==before.st_mtime and old.get('size')==before.st_size and not old.get('partial'):
                coverage['unchanged']+=1;continue
            if coverage['input_bytes']>=limits.input_bytes or coverage['records']>=limits.records:defer(p,'Per-pass input admission exhausted; checkpoint retained.');continue
            if p.suffix=='.gz' and before.st_size>limits.compressed_bytes:defer(p,'Archive exceeds bounded validation admission; original bytes/cursor remain historical debt.');continue
            # Refuse observed rewrites at an anchored consumed prefix. No
            # truncate/reset shortcut is used to make a damaged cursor advance.
            if same and p.suffix!='.gz' and old.get('anchor') and _anchor(p,old['offset'])!=old['anchor']:
                defer(p,'Consumed prefix changed; retain cursor and require continuity review.');continue
            unverified=bool(same and p.suffix!='.gz' and (old.get('legacy_prefix_unverified') or old.get('offset',0) and not old.get('anchor')))
            generation_changed=bool(old) and (not same or p.suffix!='.gz' and not unverified and before.st_size<old.get('offset',0) or p.suffix=='.gz' and (old.get('mtime')!=before.st_mtime or old.get('size')!=before.st_size))
            if generation_changed and len(old_prior)>=64:defer(p,'Prior generation receipt bound reached; retain all receipts.');continue
            prior=old_prior+([{k:v for k,v in old.items() if k!='prior_generations'}] if generation_changed else [])
            if prior and generation_changed:coverage['historical_debt'].append(dict(path=str(p),reason='Prior generation receipts retained; mapping/completeness is not certified.'))
            if unverified:coverage['historical_debt'].append(dict(path=str(p),reason='Existing legacy prefix is preserved without claiming retrospective continuity.'))
            resume={} if generation_changed else old
            prefix=dict(old.get('prefix_reconcile',{'offset':0,'through':old.get('offset',0)})) if unverified and same else None
            prefix_pending=bool(prefix and prefix.get('delivery_offset',prefix['offset'])<prefix['through'])
            use_prefix=prefix_pending and (old.get('next_lane','prefix')=='prefix' or old.get('offset',0)>before.st_size)
            if use_prefix:
                if prefix.get('anchor') and _anchor(p,prefix['offset'])!=prefix['anchor']:
                    defer(p,'Reconciliation prefix changed; both checkpoints retained.');continue
                resume={**old,'offset':prefix['offset']}
            logical_anchor_before=_anchor(p,old.get('offset',0)) if use_prefix else None
            lane=prefix if use_prefix else resume
            if lane.get('delivery_anchor') and _anchor(p,lane.get('delivery_offset',lane.get('offset',0)))!=lane['delivery_anchor']:
                defer(p,'Delivery frontier changed; retain unresolved ranges and both cursors.');continue
            with _prepared(p,before,resume,admission) as (stream,observed):
                if p.suffix!='.gz':
                    with p.open('rb',buffering=0) as binary:
                        if _identity(os.fstat(binary.fileno()))!=_identity(observed):raise DeferredInput(p,'Input changed before capture; checkpoint retained.')
                        updated,complete=_slice(p,binary,observed,lane,consume,coverage,admission,prefix['through'] if use_prefix else None)
                else:
                    updated,complete=_slice(p,stream.buffer,observed,lane,consume,coverage,admission)
            final=updated.get('delivery_offset',updated.get('offset',0))
            logical_offset=old.get('offset',0) if use_prefix else updated.get('offset',0)
            # The updated forward lane already includes preserved unknown
            # fields. Merging old active keys back would resurrect a completed
            # opaque_pending record and swallow a later appended valid line.
            base=dict(old) if use_prefix or generation_changed else {}
            if generation_changed:
                for name in ('anchor','delivery_anchor','delivery_offset','opaque_pending','record_debt','continuity_debt'):base.pop(name,None)
            row={**base,**({} if use_prefix else updated),**dict(inode=observed.st_ino,offset=logical_offset,mtime=observed.st_mtime,size=observed.st_size,partial=not complete,prior_generations=prior)}
            if generation_changed:
                # Continuity debt belongs to the retained prior generation.
                # Never carry its in-flight prefix cursor into a new inode.
                for name in ('legacy_prefix_unverified','legacy_receipt','prefix_reconcile','next_lane'):row.pop(name,None)
            if p.suffix!='.gz' and use_prefix:row['anchor']=logical_anchor_before
            if unverified:
                row['legacy_prefix_unverified']=True
                row.setdefault('legacy_receipt',{k:v for k,v in old.items() if k not in ('prior_generations','prefix_reconcile')})
                if use_prefix:prefix=updated
                row['prefix_reconcile']=prefix;row['next_lane']='forward' if use_prefix else 'prefix'
                if prefix and prefix.get('delivery_offset',prefix['offset'])<prefix['through']:complete=False;row['partial']=True
            if row.get('record_debt') or row.get('opaque_pending') or row.get('continuity_debt') or (row.get('prefix_reconcile') or {}).get('record_debt') or (row.get('prefix_reconcile') or {}).get('opaque_pending'):
                coverage['historical_debt'].append(dict(path=str(p),reason='Unresolved record/continuity receipt retained; delivery progress does not acknowledge its evidence.'))
                complete=False;row['partial']=True
            files[str(p)]=row
            if p.suffix!='.gz':coverage['next_path']=str(p)
            if complete:coverage['completed']+=1
            else:defer(p,'Bounded slice committed; remaining retained input is pending.')
        except SliceChanged as exc:
            debt=list(old.get('continuity_debt',[]))
            if len(debt)<64:debt.append(exc.receipt)
            files[str(p)]={**old,'inode':before.st_ino,'offset':old.get('offset',0),'continuity_debt':debt,'partial':True}
            defer(p,exc.reason)
        except (OSError,DeferredInput) as exc:defer(p,exc.reason if isinstance(exc,DeferredInput) else 'Input unavailable; prior cursor retained.')
    if coverage['historical_debt']:coverage['status']='partial'
    coverage['validation_bytes']=admission.validation_bytes
    return coverage
