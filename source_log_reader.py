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
import struct
from receipt_pages import ReceiptPageError, refuse_paged_debt, lanes as receipt_lanes

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
        raw = path.open('rb', buffering=0)
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
        if admission is not None:
            with _validated_archive(path, raw, opened, admission) as snapshot:
                with io.TextIOWrapper(snapshot, encoding='utf-8', errors='replace') as stream:
                    if old.get('partial') and old.get('inode')==opened.st_ino and old.get('mtime')==opened.st_mtime and old.get('size')==opened.st_size:
                        stream.seek(old.get('offset',0))
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


def _gzip_payload(data):
    """Parse a bounded in-memory gzip header; source bytes were already admitted."""
    if len(data)<10 or data[:3]!=b'\x1f\x8b\x08' or data[3]&0xe0:
        raise gzip.BadGzipFile('Invalid gzip header')
    flags=data[3];position=10
    if flags&4:
        if position+2>len(data):raise EOFError('Truncated gzip extra length')
        length=struct.unpack_from('<H',data,position)[0];position+=2+length
    for flag in (8,16):
        if flags&flag:
            end=data.find(b'\0',position)
            if end<0:raise EOFError('Truncated gzip header string')
            position=end+1
    if position>len(data):raise EOFError('Truncated gzip header')
    if flags&2:
        if position+2>len(data):raise EOFError('Truncated gzip header CRC')
        if struct.unpack_from('<H',data,position)[0] != zlib.crc32(data[:position])&0xffff:
            raise gzip.BadGzipFile('Invalid gzip header CRC')
        position+=2
    return data[position:]


@contextlib.contextmanager
def _validated_archive(path, raw, opened, admission):
    """Validate bounded gzip members before callbacks; no speculative extra byte."""
    if opened.st_size > admission.limits.compressed_bytes:
        raise DeferredInput(path, 'Archive exceeds bounded validation admission; cursor retained.')
    admission.require(opened.st_size)
    compressed = bytearray()
    try:
        remaining = opened.st_size
        while remaining:
            block = admission.read(raw, min(_CHUNK, remaining))
            if not block:
                raise DeferredInput(path, 'Compressed input changed while reading; retry required.')
            compressed.extend(block);remaining -= len(block)
        if _identity(os.fstat(raw.fileno())) != _identity(opened) or _identity(path.stat()) != _identity(opened):
            raise DeferredInput(path, 'Compressed input changed while reading; retry required.')
        with tempfile.SpooledTemporaryFile(max_size=_CHUNK) as expanded:
            data = bytes(compressed);produced = 0;members = 0
            while data:
                admission.check()
                if members and not data.strip(b'\0'):
                    break  # gzip permits zero padding after its final member.
                data=_gzip_payload(data);decoder = zlib.decompressobj(-zlib.MAX_WBITS);crc=0;member_size=0
                while not decoder.eof:
                    admission.check()
                    maximum = min(65536, admission.remaining, admission.limits.expanded_bytes-produced)
                    if maximum <= 0:
                        raise DeferredInput(path, 'Archive expanded/validation admission exhausted; cursor retained.')
                    try:block = decoder.decompress(data, maximum)
                    except zlib.error:
                        # zlib may discard partial output when raising. Retire its entire
                        # pre-admitted output allowance so later files cannot reuse it.
                        admission.charge(maximum);admission.validation_error_reserved_bytes+=maximum
                        raise
                    admission.charge(len(block));produced += len(block);expanded.write(block)
                    crc=zlib.crc32(block,crc);member_size+=len(block)
                    following = decoder.unconsumed_tail
                    if decoder.eof:
                        trailer=decoder.unused_data
                        if len(trailer)<8:raise EOFError('Truncated gzip trailer')
                        expected_crc,expected_size=struct.unpack_from('<II',trailer)
                        if expected_crc!=crc&0xffffffff or expected_size!=member_size&0xffffffff:
                            raise gzip.BadGzipFile('Gzip CRC/size mismatch')
                        data=trailer[8:];members += 1;break
                    if not following and not block:
                        raise DeferredInput(path, 'Compressed input is incomplete or damaged; retry required.')
                    data = following
            if not members:
                raise DeferredInput(path, 'Compressed input is incomplete or damaged; retry required.')
            if _identity(os.fstat(raw.fileno())) != _identity(opened) or _identity(path.stat()) != _identity(opened):
                raise DeferredInput(path, 'Compressed input changed during validation; retry required.')
            expanded.seek(0)
            yield expanded
    except (EOFError, gzip.BadGzipFile, zlib.error) as exc:
        raise DeferredInput(path, 'Compressed input is incomplete or damaged; retry required.') from exc



def collect_log_inputs(paths, files, consume, *, cutoff, limits=None, start_after=None, receipt_store=None, rotation_pairs=(), commit_guard=None):
    """Update cursors only for consumed complete files; return explicit coverage.

`consume(path, line)` retains the caller's parsing/qualification semantics.
Malformed records remain the caller's decision. Consumer failures propagate.
Failed compressed inputs contribute no partial records and keep prior state.
"""
    if limits is not None:return collect_bounded(paths,files,consume,cutoff=cutoff,limits=limits,start_after=start_after,receipt_store=receipt_store,rotation_pairs=rotation_pairs,commit_guard=commit_guard)
    if rotation_pairs or commit_guard is not None:raise ValueError('Rotation pairs require bounded collection')
    if any('generation_origin' in lane for lane in receipt_lanes(files)):
        raise ReceiptPageError('Observed rotation generations require bounded compatible reader')
    refuse_paged_debt(files)
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
        self.recovery=False;self.phase='input';self.input_closed=False;self.checkpoint_deadline=None;self.whole_deadline=time.monotonic()+180;self.input_finished=None;self.checkpoint_started=None
        self.limits=limits;self.deadline=time.monotonic()+limits.seconds;self.work_deadline=self.deadline-limits.seconds*.5;self.validation_bytes=0;self.validation_error_reserved_bytes=0;self.rotation_captures=None;self.rotation_recheck_bytes=0
    def check(self):
        now=time.monotonic()
        if now>=self.whole_deadline:raise DeferredInput('', 'Whole execution budget exhausted; checkpoint retained.')
        deadline=self.deadline if self.phase=='input' else self.checkpoint_deadline
        if now>=deadline:raise DeferredInput('', ('Input' if self.phase=='input' else 'Checkpoint')+' work budget exhausted; checkpoint retained.')
    def check_input(self):
        if self.input_closed:raise DeferredInput('', 'Source input is closed; no new callbacks permitted.')
        self.check()
    def begin_checkpoint(self,recovery=False):
        if self.phase=='checkpoint':
            self.check();return
        if not recovery:self.check_input()
        now=time.monotonic()
        if not recovery and now>=self.deadline:raise DeferredInput('', 'Input work budget exhausted; checkpoint retained.')
        if now>=self.whole_deadline:raise DeferredInput('', 'Whole execution budget exhausted; checkpoint retained.')
        self.recovery=recovery;self.input_closed=True;self.input_finished=now;self.checkpoint_started=now
        self.phase='checkpoint';self.checkpoint_deadline=min(now+45,self.whole_deadline)
        self.check()
    def budgets(self):
        return {'phase':self.phase,'source_phase_performed':not self.recovery,
            'source_elapsed_seconds':None if self.recovery else (time.monotonic() if self.input_finished is None else self.input_finished)-(self.deadline-self.limits.seconds),
            'source_seconds':self.limits.seconds,'checkpoint_seconds':45,'whole_seconds':180,
            'source_deadline':self.deadline,'source_closed_at':self.input_finished,
            'checkpoint_started':self.checkpoint_started,'checkpoint_deadline':self.checkpoint_deadline,
            'whole_deadline':self.whole_deadline,
            'checkpoint_elapsed_seconds':0 if self.checkpoint_started is None else time.monotonic()-self.checkpoint_started}
    @property
    def remaining(self):
        return self.limits.validation_bytes-self.validation_bytes
    def require(self,n):
        self.check()
        if n<0 or n>self.remaining:raise DeferredInput('','Archive validation admission exhausted; cursor retained.')
    def charge(self,n):
        if n<0 or n>self.remaining:raise DeferredInput('','Archive validation admission exhausted; cursor retained.')
        self.validation_bytes+=n
    def read(self,stream,n):
        self.require(n)
        data=stream.read(n)
        self.charge(len(data))
        return data


def _anchor(path,offset,admission=None):
    # A complete line's UTF8 cookie is a byte position. Never reinterpret an
    # opaque legacy cookie; its preexisting continuity debt remains explicit.
    if type(offset) is not int or offset<0 or offset>path.stat().st_size:return None
    with path.open('rb') as f:
        read=f.read if admission is None else lambda size:admission.read(f,size)
        head=read(min(offset,4096));f.seek(max(0,offset-4096));tail=read(min(offset,4096))
    return {'offset':offset,'head':hashlib.sha256(head).hexdigest(),'tail':hashlib.sha256(tail).hexdigest()}


class SliceChanged(DeferredInput):
    def __init__(self,path,receipt):
        super().__init__(path,'Admitted bytes changed during consumption; prior checkpoint and continuity debt retained.')
        self.receipt=receipt


def _capture_digest(stream,length,admission):
    if admission.rotation_recheck_bytes+length>admission.limits.input_bytes:
        raise DeferredInput('', 'Capture revalidation admission exhausted; checkpoint retained.')
    digest=hashlib.sha256()
    while length:
        admission.check();part=stream.read(min(_CHUNK,length))
        if not part:raise DeferredInput('', 'Captured input truncated; checkpoint retained.')
        admission.rotation_recheck_bytes+=len(part);length-=len(part);digest.update(part)
    return digest.hexdigest()


def _slice(path,binary,observed,lane,consume,coverage,admission,through=None,receipt_store=None):
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
    if admission.rotation_captures is not None:
        # Reserve four later checks for every captured range: after callbacks,
        # after durable staging, before output and before checkpoint replace.
        reserved=4*sum(c['end']-c['start'] for _,c in admission.rotation_captures)
        admitted=min(admitted,max(0,(limits.input_bytes-admission.rotation_recheck_bytes-reserved)//5))
    if path.suffix!='.gz':admitted=min(admitted,max(0,observed.st_size-start))
    prefix_read=binary.read if path.suffix=='.gz' else lambda size:admission.read(binary,size)
    binary.seek(0);head=prefix_read(4096)
    binary.seek(max(0,start-4096));preceding=prefix_read(min(start,4096))
    binary.seek(start);data=binary.read(admitted)
    at_eof=start+len(data)==observed.st_size if path.suffix!='.gz' else len(data)<admitted
    coverage['input_bytes']+=len(data)
    capture={'device':observed.st_dev,'inode':observed.st_ino,'size':observed.st_size,'mtime_ns':observed.st_mtime_ns,'ctime_ns':observed.st_ctime_ns,'start':start,'end':start+len(data),'sha256':hashlib.sha256(data).hexdigest(),'offset_space':'expanded_bytes' if path.suffix=='.gz' else 'source_bytes'}
    if 'record_debt_pages' in lane:
        if receipt_store is None:raise ReceiptPageError('Compatible receipt store required before consuming input')
        receipt_store.check_source(lane['record_debt_pages'], observed, 'expanded_bytes' if path.suffix=='.gz' else 'source_bytes')
    pending=lane.get('opaque_pending');debts=lane.setdefault('record_debt',[]);position=0
    while position<len(data) and coverage['records']<limits.records and time.monotonic()<admission.work_deadline:
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
            if len(debts)>=64:
                if receipt_store is None:break
                reference=receipt_store.append(lane.get('record_debt_pages'),debts[:16],observed,
                                               'expanded_bytes' if path.suffix=='.gz' else 'source_bytes')
                lane['record_debt_pages']=reference
                del debts[:16]
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
    lane['unresolved_record_count']=len(debts)+(lane.get('record_debt_pages') or {}).get('count',0)+(1 if pending is not None else 0)
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
                if admission.read(verified,len(head))!=head:raise ValueError('head')
                verified.seek(max(0,start-4096))
                if admission.read(verified,len(preceding))!=preceding:raise ValueError('preceding boundary')
                verified.seek(start)
                if _capture_digest(verified,len(data),admission)!=capture['sha256']:raise ValueError('admitted range')
    except (OSError,ValueError) as exc:raise SliceChanged(path,capture) from exc
    if admission.rotation_captures is not None:admission.rotation_captures.append((str(path),capture))
    eof=(final==observed.st_size if path.suffix!='.gz' else final==start+len(data) and len(data)<admitted)
    return lane,eof and not pending

@dataclasses.dataclass(frozen=True)
class RotationPair:
    """Explicit copytruncate current/retained pair; never an inferred glob policy."""
    current: object
    retained: object


def _rotation_anchors(row):
    anchors=[]
    for lane in (row, row.get('prefix_reconcile',{})):
        if not isinstance(lane,dict):raise DeferredInput('', 'Malformed rotation cursor; retain generation.')
        for name in ('anchor','delivery_anchor'):
            value=lane.get(name)
            if value is None:continue
            if (not isinstance(value,dict) or set(value)!={'offset','head','tail'}
                    or type(value['offset']) is not int or value['offset']<=0
                    or any(not isinstance(value[k],str) or len(value[k])!=64
                           or any(c not in '0123456789abcdef' for c in value[k]) for k in ('head','tail'))):
                raise DeferredInput('', 'Unsupported rotation anchor; retain generation.')
            if value not in anchors:anchors.append(value)
    return anchors


def _rotation_anchor(path,offset,admission):
    admission.check();before=path.stat()
    if type(offset) is not int or offset<0 or offset>before.st_size:return None
    with path.open('rb',buffering=0) as f:
        opened=os.fstat(f.fileno())
        if _identity(opened)!=_identity(before):raise DeferredInput(path,'Rotation source changed while opening.')
        head=admission.read(f,min(offset,4096));f.seek(max(0,offset-4096));tail=admission.read(f,min(offset,4096))
        after=os.fstat(f.fileno())
        if _identity(after)!=_identity(before) or after.st_ctime_ns!=before.st_ctime_ns:
            raise DeferredInput(path,'Rotation source changed during association.')
    return {'offset':offset,'head':hashlib.sha256(head).hexdigest(),'tail':hashlib.sha256(tail).hexdigest()}


def _retained_count(row):
    pending=[row];count=0
    while pending:
        value=pending.pop();prior=value.get('prior_generations',[])
        if not isinstance(prior,list) or any(not isinstance(v,dict) for v in prior):
            raise DeferredInput('', 'Malformed retained generations; preserve all history.')
        count+=len(prior)
        if count>=64:raise DeferredInput('', 'Prior generation receipt bound reached; retain all receipts.')
        pending.extend(prior)
    return count


def _rotation_plan(paths,files,pairs,admission):
    paths=set(map(pathlib.Path,paths));used=set();plans=[];blocked={}
    for pair in pairs:
        if not isinstance(pair,RotationPair):raise ValueError('Explicit RotationPair required')
        current,retained=pathlib.Path(pair.current),pathlib.Path(pair.retained)
        if (current==retained or current.parent!=retained.parent or retained.name!=current.name+'.1'
                or current.suffix=='.gz' or {current,retained}&used):
            raise ValueError('Distinct configured plain current/.1 pair required')
        used.update((current,retained))
        if not {current,retained}<=paths:continue
        old=[files.get(str(p),{}) for p in (current,retained)]
        if not all(old):continue
        try:
            admission.check();observed=[p.stat() for p in (current,retained)]
            # A recorded physical shrink is mandatory, never an oversized legacy cookie.
            if type(old[0].get('size')) is not int or old[0]['size']<0:
                raise DeferredInput(current,'Missing physical generation size; retain cursor.')
            if observed[0].st_size>=old[0]['size']:continue
            for row,st in zip(old,observed):
                if (type(row.get('inode')) is not int or row['inode']!=st.st_ino
                        or type(row.get('size')) is not int or row['size']<0
                        or type(row.get('mtime')) not in (int,float) or not st.st_mtime>row['mtime']):
                    raise DeferredInput(current,'Unproven configured rotation; retain both generations.')
                _retained_count(row)
            anchors=[_rotation_anchors(row) for row in old]
            if not all(anchors):raise DeferredInput(current,'Rotation lacks retained byte anchors; preserve both cursors.')
            if all(_rotation_anchor(current,x['offset'],admission)==x for x in anchors[0]):
                raise DeferredInput(current,'Shrink without changed captured prefix; retain generation.')
            if all(_rotation_anchor(retained,x['offset'],admission)==x for x in anchors[1]):
                raise DeferredInput(retained,'Retained file is not a changed generation; retain both cursors.')
            # Candidate matching is only policy corroboration. Never resume its old offset.
            candidates=[]
            for candidate in sorted(paths,key=str):
                suffix=candidate.name[len(current.name)+1:] if candidate.name.startswith(current.name+'.') else ''
                if candidate.parent!=current.parent or not suffix.isdigit():continue
                if all(_rotation_anchor(candidate,x['offset'],admission)==x for x in anchors[0]):candidates.append(candidate)
            if candidates!=[retained]:raise DeferredInput(current,'Missing or ambiguous retained rotation candidate; hold pair.')
            snapshots=[]
            for path,st in zip((current,retained),observed):
                head=_rotation_anchor(path,min(st.st_size,4096),admission)
                after=path.stat()
                if _identity(after)!=_identity(st) or after.st_ctime_ns!=st.st_ctime_ns:
                    raise DeferredInput(path,'Rotation association metadata changed; retain both cursors.')
                snapshots.append({'path':str(path),'device':st.st_dev,'inode':st.st_ino,'size':st.st_size,
                                  'mtime_ns':st.st_mtime_ns,'ctime_ns':st.st_ctime_ns,'head_anchor':head})
            lineage=hashlib.sha256(json_bytes({'policy':'explicit-copytruncate-pair-v1',
                       'observed':snapshots,'previous':old})).hexdigest()
            plans.append({'paths':(current,retained),'old':old,'snapshots':snapshots,'lineage':lineage})
        except (OSError,DeferredInput) as exc:
            for path in (current,retained):blocked[str(path)]=exc.reason if isinstance(exc,DeferredInput) else 'Rotation input unavailable; retain pair.'
    work=dict(files)
    for plan in plans:
        for path,row,snapshot in zip(plan['paths'],plan['old'],plan['snapshots']):
            work[str(path)]={'inode':snapshot['inode'],'offset':0,'size':snapshot['size'],
                'mtime':snapshot['mtime_ns']/1e9,'prior_generations':[copy.deepcopy(row)],'partial':True,
                'generation_origin':{'format':'explicit-copytruncate-pair-v1','lineage':plan['lineage'],
                    'observed':snapshot,'peer':str(plan['paths'][1] if path==plan['paths'][0] else plan['paths'][0]),
                    'historical_equivalence_verified':False,'started_at_beginning':True}}
    return work,plans,blocked


def json_bytes(value):
    import json
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def _rotation_stable(plans,admission):
    # An append can race stat/open without invalidating captured bytes. Retry
    # the WHOLE strict validation, including every captured-range digest, only
    # after proven same-inode growth. Never merely accept changed metadata.
    while True:
        admission.check();observed={}
        for plan in plans:
            snapshot=plan['snapshots'][0];path=pathlib.Path(snapshot['path']);st=path.stat()
            observed[str(path)]=(st.st_dev,st.st_ino,st.st_size,snapshot['device'],snapshot['inode'])
        try:return _rotation_stable_once(plans,admission)
        except DeferredInput as exc:
            before=observed.get(exc.path)
            if (before is None or exc.reason not in ('Rotation source changed while opening.',
                    'Rotation source changed during association.')
                    or getattr(admission,'rotation_stable_retry_count',0)>=2):raise
            after=pathlib.Path(exc.path).stat()
            if ((after.st_dev,after.st_ino)!=before[:2]
                    or (after.st_dev,after.st_ino)!=before[3:]
                    or after.st_size<=before[2]):raise
            admission.check()
            admission.rotation_stable_retry_count=getattr(admission,'rotation_stable_retry_count',0)+1


def _rotation_stable_once(plans,admission):
    for plan in plans:
        for number,snapshot in enumerate(plan['snapshots']):
            path=pathlib.Path(snapshot['path']);now=path.stat()
            identity=(now.st_dev,now.st_ino)
            if identity!=(snapshot['device'],snapshot['inode']) or now.st_size<snapshot['size']:
                raise DeferredInput(path,'Rotation generation replaced/truncated before commit; retain both cursors.')
            changed=(now.st_mtime_ns,now.st_ctime_ns)!=(snapshot['mtime_ns'],snapshot['ctime_ns'])
            if changed and (number==1 or now.st_size==snapshot['size']):
                raise DeferredInput(path,'Rotation generation rewritten before commit; retain both cursors.')
            if number==0:
                # Append-only writers may continue, but growth must not hide a rewrite
                # of this invocation's captured bytes after buffered callbacks.
                for captured_path,capture in admission.rotation_captures or ():
                    if captured_path!=str(path):continue
                    length=capture['end']-capture['start']
                    if admission.rotation_recheck_bytes+length>admission.limits.input_bytes:
                        raise DeferredInput(path,'Rotation capture revalidation admission exhausted; hold pair.')
                    digest=hashlib.sha256()
                    with path.open('rb',buffering=0) as verified:
                        if (os.fstat(verified.fileno()).st_dev,os.fstat(verified.fileno()).st_ino)!=(snapshot['device'],snapshot['inode']):
                            raise DeferredInput(path,'Rotation opened generation changed; hold pair.')
                        verified.seek(capture['start']);remaining=length
                        while remaining:
                            admission.check();part=verified.read(min(_CHUNK,remaining))
                            if not part:raise DeferredInput(path,'Rotation capture truncated; hold pair.')
                            admission.rotation_recheck_bytes+=len(part);remaining-=len(part);digest.update(part)
                    if digest.hexdigest()!=capture['sha256']:
                        raise DeferredInput(path,'Rotation captured range changed; hold pair.')
            if _rotation_anchor(path,snapshot['head_anchor']['offset'],admission)!=snapshot['head_anchor']:
                raise DeferredInput(path,'Rotation generation prefix changed before commit; retain both cursors.')


class GenerationCommitGuard:
    """Recheck a planned pair immediately before the entry's atomic state replace.

    The original source20s closes before a single checkpoint45s phase. Shared
    validation and bounded capture recheck admissions stay in force. Output already appended on a failed state commit is
    retried with identical native IDs under the entry's existing deduplication.
    """
    def __init__(self,whole_deadline=None):
        self.whole_deadline=time.monotonic()+180 if whole_deadline is None else whole_deadline
        self.plans=None;self.receipt={'armed':False}
    def arm(self,plans,admission):
        if self.plans is not None:raise ValueError('Generation commit guard may arm once')
        self.plans,self.admission=plans,admission
        admission.whole_deadline=min(admission.whole_deadline,self.whole_deadline)
    def check(self):
        if time.monotonic()>=self.whole_deadline:raise DeferredInput('', 'Whole execution budget exhausted; checkpoint retained.')
        if self.plans is not None:self.admission.check()
    def begin_checkpoint(self):
        if self.plans is None:raise ValueError('Close armed source input before checkpoint')
        self.admission.begin_checkpoint()
    def budgets(self):
        return self.admission.budgets()
    def validate(self):
        if self.plans is None:return
        self.check()
        try:_rotation_stable(self.plans,self.admission)
        except DeferredInput:
            raise
        except OSError as exc:
            raise ReceiptPageError('Generation validation unavailable before atomic state commit; retain original state') from exc
        self.receipt={'armed':True,'validated_before_atomic_state_replace':True,
            'final_validation_bytes':self.admission.validation_bytes,
            'validation_error_reserved_bytes':self.admission.validation_error_reserved_bytes,
            'final_rotation_capture_recheck_bytes':self.admission.rotation_recheck_bytes,
            'phase_budgets':self.budgets()}


def _collect_generation_safe(paths,files,consume,*,cutoff,limits,start_after,admission,receipt_store,rotation_pairs,commit_guard=None):
    work,plans,blocked=_rotation_plan(paths,files,rotation_pairs,admission)
    if not plans:
        # Revalidate durable associations before their first ordinary record pass,
        # including offset-zero sources which do not yet have a delivery anchor.
        active=[]
        for pair in rotation_pairs:
            if any(str(p) in blocked for p in (pair.current,pair.retained)):continue
            snapshots=[]
            for path in map(pathlib.Path,(pair.current,pair.retained)):
                origin=files.get(str(path),{}).get('generation_origin')
                if origin is None:break
                snapshots.append(origin['observed'])
            if len(snapshots)==2:active.append({'snapshots':snapshots})
        _rotation_stable(active,admission)
        admission.rotation_captures=[] if active else None
        work=dict(files)
        # Four later prefix checks (after callbacks, after staging, before
        # output, before replace) share the same original validation allowance.
        # Archives cannot spend this reserved work and starve a valid checkpoint.
        reserve=8*sum(min(v['head_anchor']['offset'],4096) for plan in active for v in plan['snapshots'])
        admission.require(reserve)
        original_limits=admission.limits
        admission.limits=dataclasses.replace(original_limits,validation_bytes=original_limits.validation_bytes-reserve)
        try:
            result=_collect_bounded(paths,work,consume,cutoff=cutoff,limits=limits,start_after=start_after,
                                admission=admission,receipt_store=receipt_store,blocked=blocked)
        finally:admission.limits=original_limits
        _rotation_stable(active,admission)
        result['validation_bytes']=admission.validation_bytes
        result['rotation_capture_recheck_bytes']=admission.rotation_recheck_bytes
        files.clear();files.update(work)
        if commit_guard is not None:commit_guard.arm(active,admission)
        return result
    # Association is its own transaction. No records or callbacks are admitted:
    # old cursors remain whole historical objects, new active offsets are zero.
    # The entry rechecks this association after its durable state staging write.
    try:
        _rotation_stable(plans,admission)
        if receipt_store is not None:receipt_store.verify_files(work)
    except (OSError,DeferredInput) as exc:
        return {'status':'partial','deferred':[{'path':'rotation-pair','reason':str(exc)}],
                'historical_debt':[{'path':'rotation-pair','reason':'Original generations retained.'}],
                'records':0,'input_bytes':0,'validation_bytes':admission.validation_bytes,
                'generation_transition':'deferred_no_callbacks_or_state_commit'}
    files.clear();files.update(work)
    if commit_guard is not None:commit_guard.arm(plans,admission)
    return {'status':'partial','completed':0,'unchanged':0,'outside_retention':0,
        'deferred':[], 'records':0,'input_bytes':0,'next_path':start_after,
        'historical_debt':[{'path':'rotation-pair','reason':'Prior generations retained; historical equivalence not certified.'}],
        'generation_transition':'associated_at_zero_records_deferred',
        'generation_transitions':[{'lineage':p['lineage'],'paths':list(map(str,p['paths'])),
          'from_beginning':True,'historical_equivalence_verified':False} for p in plans],
        'validation_bytes':admission.validation_bytes,'rotation_capture_recheck_bytes':admission.rotation_recheck_bytes}


def collect_bounded(paths,files,consume,*,cutoff,limits,start_after=None,receipt_store=None,rotation_pairs=(),commit_guard=None):
    paths=tuple(paths);rotation_pairs=tuple(rotation_pairs)
    if commit_guard is not None and not isinstance(commit_guard,GenerationCommitGuard):raise ValueError('Explicit GenerationCommitGuard required')
    if len(set(map(pathlib.Path,paths)))>limits.files or len(rotation_pairs)>limits.files//2:
        raise ValueError('Input/rotation inventory exceeds bounded admission')
    admission=_Admission(limits)
    if commit_guard is not None:admission.whole_deadline=min(admission.whole_deadline,commit_guard.whole_deadline)
    original_consume=consume
    def consume(*args,**kwargs):
        admission.check_input()
        result=original_consume(*args,**kwargs)
        admission.check_input()
        return result
    if receipt_store is None:
        refuse_paged_debt(files)
        result=_collect_generation_safe(paths,files,consume,cutoff=cutoff,limits=limits,start_after=start_after,admission=admission,receipt_store=None,rotation_pairs=rotation_pairs,commit_guard=commit_guard)
        if commit_guard is not None and commit_guard.plans is None:commit_guard.arm([],admission)
        return result
    with receipt_store.invocation(admission.check):
        receipt_store.verify_files(files)
        result=_collect_generation_safe(paths,files,consume,cutoff=cutoff,limits=limits,start_after=start_after,
                                admission=admission,receipt_store=receipt_store,rotation_pairs=rotation_pairs,commit_guard=commit_guard)
        if commit_guard is not None and commit_guard.plans is None:commit_guard.arm([],admission)
        result['receipt_page_io_bytes']=receipt_store.io_bytes
        return result


def _collect_bounded(paths,files,consume,*,cutoff,limits,start_after,admission,receipt_store=None,blocked=None):
    paths=sorted({pathlib.Path(p) for p in paths},key=str)
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
        if blocked and str(p) in blocked:defer(p,blocked[str(p)]);continue
        old=files.get(str(p),{});old_prior=list(old.get('prior_generations',[]))
        if old_prior:coverage['historical_debt'].append(dict(path=str(p),reason='Prior generation receipts retained; mapping/completeness is not certified.'))
        if old.get('legacy_prefix_unverified'):coverage['historical_debt'].append(dict(path=str(p),reason='Existing legacy prefix lacks a capture anchor; not retroactively certified.'))
        if old.get('record_debt_pages') or old.get('continuity_debt') or old.get('record_debt') or old.get('opaque_pending') or (old.get('prefix_reconcile') or {}).get('record_debt_pages') or (old.get('prefix_reconcile') or {}).get('record_debt') or (old.get('prefix_reconcile') or {}).get('opaque_pending'):
            coverage['historical_debt'].append(dict(path=str(p),reason='Unresolved byte ranges or in-slice continuity receipts retained; source completeness is not certified.'))
        try:
            admission.check()
            if time.monotonic()>=admission.work_deadline:raise DeferredInput(p,'Record work budget exhausted; commit reserve retained.')
            before=p.stat()
            if len(old.get('continuity_debt',[]))>=64:defer(p,'Continuity receipt admission reached; preserve all receipts for review.');continue
            if before.st_mtime<cutoff:coverage['outside_retention']+=1;continue
            same=old.get('inode')==before.st_ino
            if p.suffix=='.gz' and same and old.get('mtime')==before.st_mtime and old.get('size')==before.st_size and not old.get('partial'):
                coverage['unchanged']+=1;continue
            if coverage['input_bytes']>=limits.input_bytes or coverage['records']>=limits.records:defer(p,'Per-pass input admission exhausted; checkpoint retained.');continue
            if p.suffix=='.gz' and before.st_size>limits.compressed_bytes:defer(p,'Archive exceeds bounded validation admission; original bytes/cursor remain historical debt.');continue
            # Refuse observed rewrites at an anchored consumed prefix. No
            # truncate/reset shortcut is used to make a damaged cursor advance.
            if same and p.suffix!='.gz' and old.get('anchor') and _anchor(p,old['offset'],admission)!=old['anchor']:
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
                if prefix.get('anchor') and _anchor(p,prefix['offset'],admission)!=prefix['anchor']:
                    defer(p,'Reconciliation prefix changed; both checkpoints retained.');continue
                resume={**old,'offset':prefix['offset']}
            logical_anchor_before=_anchor(p,old.get('offset',0),admission) if use_prefix else None
            lane=prefix if use_prefix else resume
            if lane.get('delivery_anchor') and _anchor(p,lane.get('delivery_offset',lane.get('offset',0)),admission)!=lane['delivery_anchor']:
                defer(p,'Delivery frontier changed; retain unresolved ranges and both cursors.');continue
            with _prepared(p,before,resume,admission) as (stream,observed):
                if p.suffix!='.gz':
                    with p.open('rb',buffering=0) as binary:
                        if _identity(os.fstat(binary.fileno()))!=_identity(observed):raise DeferredInput(p,'Input changed before capture; checkpoint retained.')
                        updated,complete=_slice(p,binary,observed,lane,consume,coverage,admission,prefix['through'] if use_prefix else None,receipt_store=receipt_store)
                else:
                    updated,complete=_slice(p,stream.buffer,observed,lane,consume,coverage,admission,receipt_store=receipt_store)
            final=updated.get('delivery_offset',updated.get('offset',0))
            logical_offset=old.get('offset',0) if use_prefix else updated.get('offset',0)
            # The updated forward lane already includes preserved unknown
            # fields. Merging old active keys back would resurrect a completed
            # opaque_pending record and swallow a later appended valid line.
            base=dict(old) if use_prefix or generation_changed else {}
            if generation_changed:
                for name in ('anchor','delivery_anchor','delivery_offset','opaque_pending','record_debt','record_debt_pages','unresolved_record_count','continuity_debt'):base.pop(name,None)
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
            if row.get('record_debt_pages') or row.get('record_debt') or row.get('opaque_pending') or row.get('continuity_debt') or (row.get('prefix_reconcile') or {}).get('record_debt_pages') or (row.get('prefix_reconcile') or {}).get('record_debt') or (row.get('prefix_reconcile') or {}).get('opaque_pending'):
                coverage['historical_debt'].append(dict(path=str(p),reason='Unresolved record/continuity receipt retained; delivery progress does not acknowledge its evidence.'))
                complete=False;row['partial']=True
            files[str(p)]=row
            if p.suffix!='.gz':coverage['next_path']=str(p)
            if complete:coverage['completed']+=1
            else:defer(p,'Bounded slice committed; remaining retained input is pending.')
        except SliceChanged as exc:
            if old.get('generation_origin'):
                raise ReceiptPageError('Associated source changed during callbacks; retain original state') from exc
            debt=list(old.get('continuity_debt',[]))
            if len(debt)<64:debt.append(exc.receipt)
            files[str(p)]={**old,'inode':before.st_ino,'offset':old.get('offset',0),'continuity_debt':debt,'partial':True}
            defer(p,exc.reason)
        except (OSError,DeferredInput) as exc:defer(p,exc.reason if isinstance(exc,DeferredInput) else 'Input unavailable; prior cursor retained.')
    if coverage['historical_debt']:coverage['status']='partial'
    coverage['unresolved_record_references']=sum(len(v.get('record_debt',[]))+(v.get('record_debt_pages') or {}).get('count',0)+(1 if v.get('opaque_pending') else 0) for v in receipt_lanes(files))
    coverage['unresolved_count_scope']='Retained lane references, including prior/legacy copies; not unique event or attack counts.'
    if coverage['unresolved_record_references']:coverage['status']='partial'
    coverage['validation_bytes']=admission.validation_bytes
    coverage['validation_error_reserved_bytes']=admission.validation_error_reserved_bytes
    coverage['rotation_capture_recheck_bytes']=admission.rotation_recheck_bytes
    return coverage
