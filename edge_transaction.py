"""Private local staging for a bounded edge pass, with exact crash replay.

Only sanitized native output and the normal state checkpoint are staged. A ready
marker is published only after both files are durable and source guards pass.
Recovery repeats the exact output plan (native event IDs deduplicate it), then
commits that exact checkpoint. No source records are reread or relabelled.
"""
import hashlib
import json
import os
import pathlib
import time
from source_log_reader import GenerationCommitGuard, _Admission, InputLimits
from receipt_pages import ReceiptPageError, ReceiptPages

CHUNK=65536
MAX_STATE=256*1024**2
MAX_OUTPUT=64*1024**2


def directory_sync(folder):
    fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def digest(path,maximum,check):
    check();before=path.stat();value=hashlib.sha256();size=0
    if before.st_size>maximum:raise ReceiptPageError('Edge staging admission exceeded')
    with path.open('rb') as saved:
        while True:
            check();chunk=saved.read(CHUNK)
            if not chunk:break
            value.update(chunk);size+=len(chunk)
        after=os.fstat(saved.fileno())
    current=path.stat()
    identity=lambda st:(st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
    if identity(before)!=identity(after) or identity(after)!=identity(current):
        raise ReceiptPageError('Edge staging changed; retain transaction')
    return {'sha256':value.hexdigest(),'bytes':size}


class EdgeTransaction:
    def __init__(self,statefile,output,guard):
        self.statefile=pathlib.Path(statefile);self.output=pathlib.Path(output);self.guard=guard
        self.stage=self.statefile.with_suffix('.output-stage')
        self.saved=self.statefile.with_suffix('.tmp')
        self.ready=self.statefile.with_suffix('.ready')

    def open_output(self):
        # Only uncommitted staging is overwritten; a ready transaction must be
        # recovered before entering collection, never replaced with another pass.
        if self.ready.exists():raise ReceiptPageError('Recover ready edge transaction before collection')
        return self.stage.open('w',encoding='utf-8')

    def commit(self,state):
        self.guard.begin_checkpoint()
        self.guard.check()
        # The default C-backed encoder has the same JSON semantics as the old
        # default JSONEncoder.iterencode stream. Encoding is one bounded-input
        # call: it cannot be interrupted, and its whole cost belongs to the
        # checkpoint deadline. A late return cannot write or acknowledge a state.
        # Accepted ASCII-escaped output retains at most MAX_STATE characters;
        # the service's unchanged RSS/AS limits also bound transient allocation.
        encoded=json.dumps(state)
        self.guard.check()
        if len(encoded)>MAX_STATE:
            raise ReceiptPageError('Edge checkpoint staging admission exceeded')
        with self.saved.open('w',encoding='utf-8') as saved:
            for start in range(0,len(encoded),CHUNK):
                self.guard.check();saved.write(encoded[start:start+CHUNK])
            self.guard.check();saved.flush();os.fsync(saved.fileno())
        del encoded
        metadata={'format':'edge-ready-v1',
            'state':digest(self.saved,MAX_STATE,self.guard.check),
            'output':digest(self.stage,MAX_OUTPUT,self.guard.check),
            'plans':[{'snapshots':p['snapshots']} for p in self.guard.plans or []],
            'captures':self.guard.admission.rotation_captures or []}
        self.guard.validate()
        marker=self.ready.with_suffix('.ready-tmp')
        raw=json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()
        if len(raw)>1024**2:raise ReceiptPageError('Edge recovery metadata admission exceeded')
        with marker.open('wb') as saved:
            saved.write(raw);saved.flush();os.fsync(saved.fileno())
        self.guard.check();os.replace(marker,self.ready);directory_sync(self.ready.parent)
        self.finish(metadata)

    def finish(self,metadata):
        self.guard.validate()
        # Preserve a killed append fragment and delimit it before exact replay.
        if self.output.exists() and self.output.stat().st_size:
            with self.output.open('rb') as saved:
                saved.seek(-1,os.SEEK_END);incomplete=saved.read(1)!=b'\n'
            if incomplete:
                with self.output.open('ab') as saved:saved.write(b'\n');saved.flush();os.fsync(saved.fileno())
        with self.stage.open('rb') as source,self.output.open('ab') as output:
            while True:
                self.guard.check();chunk=source.read(CHUNK)
                if not chunk:break
                output.write(chunk)
            output.flush();os.fsync(output.fileno())
        self.guard.validate()
        # The marker stays until the checkpoint is durable. A crash after replace
        # is recognized by the same state digest; output is safe to replay again.
        if self.saved.exists():os.replace(self.saved,self.statefile)
        directory_sync(self.statefile.parent)
        self.guard.check()
        self.ready.unlink();directory_sync(self.statefile.parent)
        self.stage.unlink(missing_ok=True)
        self.guard.check()
        self.guard.receipt['phase_budgets']=self.guard.budgets()


def recover_edge_transaction(statefile,output,whole_deadline=None):
    guard=GenerationCommitGuard(whole_deadline)
    recovery_started=time.monotonic()
    statefile=pathlib.Path(statefile);ready=statefile.with_suffix('.ready')
    if not ready.exists():return False
    admission=_Admission(InputLimits(seconds=20,records=16384))
    admission.whole_deadline=min(admission.whole_deadline,guard.whole_deadline)
    admission.begin_checkpoint(recovery=True)
    admission.checkpoint_started=recovery_started;admission.checkpoint_deadline=min(recovery_started+45,admission.whole_deadline)
    admission.check()
    if ready.stat().st_size>1024**2:raise ReceiptPageError('Edge recovery metadata admission exceeded')
    metadata=json.loads(ready.read_text(encoding='utf-8'))
    if metadata.get('format')!='edge-ready-v1':raise ReceiptPageError('Unsupported edge transaction')
    admission.check()
    admission.rotation_captures=metadata['captures'];guard.arm(metadata['plans'],admission)
    transaction=EdgeTransaction(statefile,output,guard)
    selected=transaction.saved if transaction.saved.exists() else statefile
    if digest(selected,MAX_STATE,guard.check)!=metadata['state'] or digest(transaction.stage,MAX_OUTPUT,guard.check)!=metadata['output']:
        raise ReceiptPageError('Edge prepared transaction hash mismatch; retain checkpoint')
    with selected.open(encoding='utf-8') as saved:state=json.load(saved)
    guard.check()
    with ReceiptPages(statefile.parent/'receipt-pages').invocation(guard.check) as store:store.verify_files(state['files'])
    transaction.finish(metadata)
    print(json.dumps({'mode':'edge','prepared_transaction_recovered':True,'generation_commit_validation':guard.receipt}))
    return True
