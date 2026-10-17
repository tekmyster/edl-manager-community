"""Local operational ledger. No prompts, provider bodies, secrets or external writes.

Hourly per-IP provider counters and individual AI transport attempts are retained
35 days. Telemetry failure never stops native ingestion or policy evaluation.
"""
import contextlib
import datetime as dt
import json
import logging
import pathlib
import sqlite3
import uuid
import threading
import weakref

UTC = dt.timezone.utc
_ready = set()
_pruned = {}
_handles_lock = threading.Lock()
SCHEMA = '''
CREATE TABLE IF NOT EXISTS coverage(name TEXT PRIMARY KEY,started TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS counters(hour TEXT NOT NULL,provider TEXT NOT NULL,kind TEXT NOT NULL,ip TEXT NOT NULL,n INTEGER NOT NULL,last TEXT NOT NULL,PRIMARY KEY(hour,provider,kind,ip));
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,packet TEXT NOT NULL,started TEXT NOT NULL,finished TEXT,state TEXT NOT NULL,first_seconds REAL,input_tokens INTEGER,output_tokens INTEGER,total_seconds REAL);
CREATE INDEX IF NOT EXISTS requests_started ON requests(started);
CREATE TABLE IF NOT EXISTS request_recovery(id TEXT PRIMARY KEY,assessment_id TEXT NOT NULL,saved_at TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS request_recovery_delete AFTER DELETE ON requests BEGIN DELETE FROM request_recovery WHERE id=OLD.id; END;
'''


def stamp(at=None):
    return (at or dt.datetime.now(UTC)).astimezone(UTC).isoformat(timespec='microseconds')


def path(store):
    return pathlib.Path(store.path).resolve().with_name('analytics.sqlite3')


def warning(operation, exc):
    # Exception text can contain paths or supplied values. Fixed operation names
    # and numeric SQLite/OS codes are enough to distinguish busy/read-only/etc.
    code = getattr(exc, 'sqlite_errorcode', None)
    errno = getattr(exc, 'errno', None)
    logging.warning('Analytics persistence failed operation=%s sqlite_code=%s os_errno=%s',
                    operation, code if type(code) is int else None,
                    errno if type(errno) is int else None)


@contextlib.contextmanager
def connect(store, write=False):
    target = path(store)
    if write:
        # Keep the WAL open across frequent cache reads. Closing its last handle
        # per read would force checkpoints and dominate enrichment runtime.
        if not hasattr(store,'_analytics_handles'):
            with _handles_lock:
                if not hasattr(store,'_analytics_handles'):
                    store._analytics_handles={}
                    weakref.finalize(store,lambda handles:[c.close() for c in handles.values()],store._analytics_handles)
        owner=threading.get_ident()
        db=store._analytics_handles.get(owner)
        if db is None:
            db=sqlite3.connect(str(target),timeout=.025,check_same_thread=False)
            db.row_factory=sqlite3.Row
            try:
                db.execute('PRAGMA synchronous=NORMAL')
                store._analytics_handles[owner]=db
            except Exception:
                db.close()
                raise
    else:
        db=sqlite3.connect(target.as_uri()+'?mode=ro',uri=True,timeout=.25)
        db.row_factory=sqlite3.Row
    pruned_day = None
    try:
        if write and str(target) not in _ready:
            # Existing schemas need no DDL/write lock on each worker startup.
            # Concurrent fresh initializers remain bounded by the same 25ms busy
            # timeout; an unsuccessful initializer can try again at completion.
            if db.execute('PRAGMA journal_mode').fetchone()[0].lower() != 'wal':
                db.execute('PRAGMA journal_mode=WAL')
            names={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE name IN ('coverage','counters','requests','requests_started','request_recovery','request_recovery_delete')")}
            if len(names) != 6:db.executescript(SCHEMA)
            _ready.add(str(target))
        if write:
            day = stamp()[:10]
            if _pruned.get(str(target)) != day:
                cut = stamp(dt.datetime.now(UTC)-dt.timedelta(days=35))
                db.execute('DELETE FROM counters WHERE hour<?', (cut,))
                db.execute('DELETE FROM requests WHERE started<?', (cut,))
                db.execute("INSERT OR REPLACE INTO coverage VALUES('pruned',?)", (day,))
                pruned_day = day
        yield db
        if write:
            db.commit()
            if pruned_day is not None:_pruned[str(target)] = pruned_day
    except Exception as exc:
        if write:
            try:db.rollback()
            finally:
                code=getattr(exc,'sqlite_errorcode',0) or 0
                if isinstance(exc,sqlite3.Error) and code & 255 not in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
                    # Do not retain an unusable/read-only handle indefinitely.
                    store._analytics_handles.pop(owner,None)
                    db.close()
                    _ready.discard(str(target))
                    _pruned.pop(str(target),None)
        raise
    finally:
        if not write:db.close()


def event(store, provider, kind, address='', at=None, n=1):
    events(store, [(provider,kind,address,n)],at)


def events(store, records, at=None):
    when = stamp(at)
    try:
        with connect(store, True) as db:
            db.executemany('INSERT OR IGNORE INTO coverage VALUES(?,?)', [(p,when) for p in {r[0] for r in records}])
            db.executemany('INSERT OR IGNORE INTO coverage VALUES(?,?)', [(p+':'+k,when) for p,k,_,_ in records])
            db.executemany('INSERT INTO counters VALUES(?,?,?,?,?,?) ON CONFLICT(hour,provider,kind,ip) DO UPDATE SET n=n+excluded.n,last=excluded.last',
                          [(when[:13]+':00:00.000000+00:00',p,k,a,n,when) for p,k,a,n in records])
    except (sqlite3.Error, OSError) as exc:
        warning('counters', exc)


class Attempt:
    def __init__(self, store, packet):
        self.store, self.packet, self.id = store, packet, uuid.uuid4().hex
        self.started = None
        self._outcome = None

    def coverage(self, db):
        db.execute("INSERT INTO coverage VALUES('ai',?) ON CONFLICT(name) DO UPDATE SET started=min(coverage.started,excluded.started)", (self.started,))

    def start(self):
        if self.started is None:self.started = stamp()
        try:
            with connect(self.store, True) as db:
                self.coverage(db)
                db.execute("INSERT OR IGNORE INTO requests(id,packet,started,state) VALUES(?,?,?,'pending')", (self.id,self.packet,self.started))
            return True
        except (sqlite3.Error, OSError) as exc:
            warning('ai_start', exc)
            return False

    def finish(self, state, metadata):
        # No start means no known dispatch: never manufacture history. Freeze the
        # first observed completion before I/O, including when persistence fails.
        if self.started is None:return False
        def number(key, integer=False):
            value=metadata.get(key)
            import math
            return value if type(value) in ((int,) if integer else (int,float)) and math.isfinite(value) and value>=0 else None
        if self._outcome is None:
            self._outcome = (stamp(),state,number('first_content_seconds'),number('input_tokens',True),number('output_tokens',True),number('request_seconds'))
        metadata.update(request_started_at=self.started,request_finished_at=self._outcome[0],request_transport_state=self._outcome[1])
        try:
            with connect(self.store, True) as db:
                self.coverage(db)
                # Recover this actual in-memory dispatch when its INSERT failed.
                # Completed records are immutable on duplicate/retried finishes.
                db.execute('''INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET finished=excluded.finished,state=excluded.state,
                    first_seconds=excluded.first_seconds,input_tokens=excluded.input_tokens,
                    output_tokens=excluded.output_tokens,total_seconds=excluded.total_seconds
                    WHERE requests.finished IS NULL''',
                    (self.id,self.packet,self.started,*self._outcome))
            return True
        except (sqlite3.Error, OSError) as exc:
            warning('ai_finish', exc)
            return False
