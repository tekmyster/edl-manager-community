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

_CHUNK = 1024 * 1024


class DeferredInput(Exception):
    def __init__(self, path, reason):
        self.path = str(path)
        self.reason = reason
        super().__init__(f'{self.path}: {reason}')


def _identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns


@contextlib.contextmanager
def _prepared(path, before, old):
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
                    block = raw.read(min(_CHUNK, remaining))
                    if not block:
                        raise DeferredInput(path, 'Compressed input changed while reading; retry required.')
                    snapshot.write(block)
                    remaining -= len(block)
                if _identity(os.fstat(raw.fileno())) != _identity(opened) or _identity(path.stat()) != _identity(opened):
                    raise DeferredInput(path, 'Compressed input changed while reading; retry required.')
                snapshot.seek(0)
                with gzip.GzipFile(fileobj=snapshot, mode='rb') as checked:
                    while checked.read(_CHUNK):
                        pass
            except (EOFError, gzip.BadGzipFile, zlib.error) as exc:
                raise DeferredInput(path, 'Compressed input is incomplete or damaged; retry required.') from exc
            except OSError as exc:
                raise DeferredInput(path, 'Compressed input could not be read; retry required.') from exc
            snapshot.seek(0)
            with io.TextIOWrapper(gzip.GzipFile(fileobj=snapshot, mode='rb'), encoding='utf-8', errors='replace') as stream:
                yield stream, opened


def collect_log_inputs(paths, files, consume, *, cutoff):
    """Update cursors only for consumed complete files; return explicit coverage.

`consume(path, line)` retains the caller's parsing/qualification semantics.
Malformed records remain the caller's decision. Consumer failures propagate.
Failed compressed inputs contribute no partial records and keep prior state.
"""
    coverage = {'status': 'complete', 'completed': 0, 'unchanged': 0, 'outside_retention': 0, 'deferred': []}
    for value in paths:
        path = pathlib.Path(value)
        old = files.get(str(path), {})
        try:
            try:
                before = path.stat()
            except OSError as exc:
                raise DeferredInput(path, 'Input metadata is unavailable; retry required.') from exc
            if before.st_mtime < cutoff:
                coverage['outside_retention'] += 1
                continue
            if path.suffix == '.gz' and old.get('inode') == before.st_ino and old.get('mtime') == before.st_mtime and old.get('size') == before.st_size:
                coverage['unchanged'] += 1
                continue
            with _prepared(path, before, old) as (stream, observed):
                for line in iter(stream.readline, ''):
                    consume(path, line)
                final = stream.tell()
            # Use the opened inode, never a replacement now at the same path.
            files[str(path)] = {'inode': observed.st_ino, 'offset': final, 'mtime': observed.st_mtime, 'size': observed.st_size}
            coverage['completed'] += 1
        except DeferredInput as exc:
            coverage['status'] = 'partial'
            coverage['deferred'].append({'path': exc.path, 'reason': exc.reason})
    return coverage
