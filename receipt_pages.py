"""Bounded, immutable metadata pages for unresolved native record receipts.

A manifest authenticates file identities/metadata without traversing old page
bodies on every source pass. Every newly published or reused body is checked in
full. Published bodies are read-only, never replaced, and never garbage-collected.
"""
import contextlib
import functools
import copy
import hashlib
import json
import itertools
import os
from pathlib import Path
import re
import stat
import uuid

FORMAT = 'edl-unresolved-receipts-v1'
MAX_PAGE = 8 * 1024**2
MAX_BYTES = 128 * 1024**2
MAX_ENTRIES = 512
MAX_IO = 32 * 1024**2
MAX_RECEIPTS = 16
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'(?:[0-9a-f]{64}\.json|\.stage-[0-9a-f]{32})\Z')

class ReceiptPageError(RuntimeError):
    """Fail the producer before output/state publication; preserve all debt."""


def _io_errors(method):
    @functools.wraps(method)
    def bounded(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except OSError as exc:
            # Do not let the reader's ordinary unavailable-input handler hide
            # a partially completed metadata publication as a routine defer.
            raise ReceiptPageError('Receipt storage IO failed; retain prior durable state') from exc
    return bounded


def canonical(value, *, limit=MAX_PAGE, check=lambda: None):
    # Reject pathological metadata before the encoder/deep-copy can allocate
    # an unbounded tree or a very large quoted string. No values are coerced.
    stack = [(iter((value,)), 0)]
    nodes = 0
    while stack:
        iterator, depth = stack[-1]
        try:
            item = next(iterator)
        except StopIteration:
            stack.pop()
            continue
        nodes += 1
        if nodes % 256 == 0:
            check()
        if nodes > 1000000 or depth > 64:
            raise ReceiptPageError('Receipt JSON structure admission exceeded')
        if isinstance(item, str) and len(item) > limit:
            raise ReceiptPageError('Receipt string admission exceeded')
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ReceiptPageError('Receipt object keys must remain strings')
            stack.append((iter(itertools.chain.from_iterable(item.items())), depth + 1))
        elif isinstance(item, (list, tuple)):
            stack.append((iter(item), depth + 1))
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    parts, size = [], 0
    for text in encoder.iterencode(value):
        check()
        raw = text.encode('utf-8')
        size += len(raw)
        if size > limit:
            raise ReceiptPageError('Receipt canonical byte admission exceeded')
        parts.append(raw)
    return b''.join(parts)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptPageError('Duplicate page JSON member')
        value[key] = item
    return value


def _integer(value, minimum=0):
    return type(value) is int and value >= minimum


def _hex(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def lanes(files):
    """Only known cursor containers, never emitted caches or unknown fields."""
    if not isinstance(files, dict):
        raise ReceiptPageError('Invalid file cursor map')
    pending = [(value, 0) for value in files.values()]
    visited = 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 16384 or depth > 64 or not isinstance(value, dict):
            raise ReceiptPageError('Cursor container admission exceeded')
        yield value
        for key in ('prefix_reconcile', 'legacy_receipt'):
            if key in value and value[key] is not None:
                pending.append((value[key], depth + 1))
        prior = value.get('prior_generations', [])
        if not isinstance(prior, list) or len(prior) > 64:
            raise ReceiptPageError('Prior generation admission exceeded')
        pending.extend((item, depth + 1) for item in prior)


def refuse_paged_debt(files):
    if any('record_debt_pages' in value for value in lanes(files)):
        raise ReceiptPageError('Page-backed receipts require a compatible reader; hold producer')


class ReceiptPages:
    def __init__(self, directory, *, max_bytes=MAX_BYTES,
                 max_entries=MAX_ENTRIES, max_page=MAX_PAGE, max_io=MAX_IO, _fault=None):
        if not (0 < max_bytes <= MAX_BYTES and 0 < max_entries <= MAX_ENTRIES
                and 0 < max_page <= MAX_PAGE and 0 < max_io <= MAX_IO):
            raise ValueError('Page bounds may only be reduced')
        self.path = Path(directory).absolute()
        self.max_bytes, self.max_entries, self.max_page = max_bytes, max_entries, max_page
        self.max_io, self.io_bytes = max_io, 0
        self.fd = None
        self.check = lambda: None
        self.charge = lambda size: None
        self.fault = _fault or (lambda point: None)
        self.checked = set()

    @contextlib.contextmanager
    def invocation(self, check, charge=None):
        if self.fd is not None:
            raise ReceiptPageError('Overlapping page-store invocation')
        if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
            raise ReceiptPageError('Secure directory operations unavailable')
        self.check = check
        self.io_bytes = 0
        external_charge = charge or (lambda size: None)
        def page_charge(size):
            self.check()
            if self.io_bytes + size > self.max_io:
                raise ReceiptPageError('Per-invocation receipt IO admission exceeded')
            self.io_bytes += size
            external_charge(size)
        self.charge = page_charge
        try:
            self.check()
            try:
                self.path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            self.root = os.fstat(self.fd)
            parent_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            if self.root.st_uid != os.geteuid() or stat.S_IMODE(self.root.st_mode) != 0o700:
                raise ReceiptPageError('Page directory ownership/mode mismatch')
            self.checked = set()
            self.inventory()
            yield self
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            raise ReceiptPageError('Receipt page operation failed; retain prior state') from exc
        finally:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None

    @_io_errors
    def inventory(self):
        self.check()
        current = os.stat(self.path, follow_symlinks=False)
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o700
                or (current.st_dev, current.st_ino) != (self.root.st_dev, self.root.st_ino)):
            raise ReceiptPageError('Page directory substituted')
        entries, links, total = {}, {}, 0
        with os.scandir(self.fd) as iterator:
            for entry in iterator:
                self.check()
                if len(entries) >= self.max_entries or not NAME.fullmatch(entry.name):
                    raise ReceiptPageError('Page entry admission exceeded/unknown entry')
                st = entry.stat(follow_symlinks=False)
                mode = stat.S_IMODE(st.st_mode)
                expected_modes = (0o400, 0o600) if entry.name.startswith('.stage-') else (0o400,)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                        or st.st_dev != self.root.st_dev or mode not in expected_modes
                        or not 0 <= st.st_size <= self.max_page):
                    raise ReceiptPageError('Unsafe or unbounded page entry')
                entries[entry.name] = st
                inode = (st.st_dev, st.st_ino)
                links[inode] = links.get(inode, 0) + 1
                total += st.st_size  # Count every name, even hard-linked crash leftovers.
                if total > self.max_bytes:
                    raise ReceiptPageError('Page byte quota exceeded, including orphans')
        if any(st.st_nlink != links[(st.st_dev, st.st_ino)] for st in entries.values()):
            raise ReceiptPageError('Page has an unowned external hard link')
        self.entries, self.total = entries, total
        return entries

    @staticmethod
    def descriptor(digest, st, receipt_count, previous):
        return dict(hash=digest, device=st.st_dev, inode=st.st_ino,
                    size=st.st_size, mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns,
                    links=st.st_nlink, receipts=receipt_count, previous=previous)

    @_io_errors
    def read(self, digest):
        if not _hex(digest):
            raise ReceiptPageError('Invalid content address')
        name = digest + '.json'
        self.inventory()
        expected = self.entries.get(name)
        if expected is None:
            raise ReceiptPageError('Missing receipt page')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            before = os.fstat(fd)
            if self.descriptor(digest, before, 0, None) != self.descriptor(digest, expected, 0, None):
                raise ReceiptPageError('Page substituted while opening')
            data = bytearray()
            while True:
                self.check()
                part = os.read(fd, min(65536, self.max_page + 1 - len(data)))
                if not part:
                    break
                self.charge(len(part))
                data.extend(part)
                if len(data) > self.max_page:
                    raise ReceiptPageError('Page read admission exceeded')
            after = os.fstat(fd)
            path_stat = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if (self.descriptor(digest, before, 0, None) != self.descriptor(digest, after, 0, None)
                    or self.descriptor(digest, after, 0, None) != self.descriptor(digest, path_stat, 0, None)):
                raise ReceiptPageError('Page changed during validation')
        finally:
            os.close(fd)
        raw = bytes(data)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ReceiptPageError('Receipt page hash mismatch')
        try:
            value = json.loads(raw, object_pairs_hook=_pairs,
                               parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ReceiptPageError('Malformed receipt page') from exc
        if canonical(value, limit=self.max_page, check=self.check) != raw:
            raise ReceiptPageError('Noncanonical receipt page')
        self.page_schema(value)
        return value, after

    @staticmethod
    def identity_schema(identity):
        if (not isinstance(identity, dict)
                or set(identity) != {'device', 'inode', 'offset_space', 'generation'}
                or not _integer(identity['device']) or not _integer(identity['inode'], 1)
                or identity['offset_space'] not in ('source_bytes', 'expanded_bytes')
                or not _hex(identity['generation'])):
            raise ReceiptPageError('Invalid source generation identity')

    @staticmethod
    def receipt_schema(receipt, identity):
        if not isinstance(receipt, dict):
            raise ReceiptPageError('Invalid full receipt')
        source = receipt.get('source')
        if (not isinstance(source, dict)
                or any(source.get(key) != identity[key] for key in ('device', 'inode', 'offset_space'))
                or type(source.get('device')) is not int or type(source.get('inode')) is not int):
            raise ReceiptPageError('Receipt source generation mismatch')
        segments = receipt.get('segments')
        if (not _integer(receipt.get('start')) or not _integer(receipt.get('end'))
                or receipt['end'] <= receipt['start'] or type(receipt.get('through')) is not int
                or receipt.get('through') != receipt['end']
                or receipt.get('boundary_verified') is not True
                or receipt.get('status') != 'unresolved_record'
                or not isinstance(segments, list) or not 1 <= len(segments) <= 4096):
            raise ReceiptPageError('Invalid complete unresolved receipt')
        end, chain = receipt['start'], hashlib.sha256(b'').digest()
        for segment in segments:
            if (not isinstance(segment, dict) or type(segment.get('start')) is not int
                    or not _integer(segment.get('end')) or segment['start'] != end
                    or segment['end'] <= end or not _hex(segment.get('sha256'))):
                raise ReceiptPageError('Invalid receipt segment')
            end = segment['end']
            chain = hashlib.sha256(chain + str(segment['start']).encode() + b':'
                                   + str(end).encode() + b':' + bytes.fromhex(segment['sha256'])).digest()
        if end != receipt['end'] or chain.hex() != receipt.get('chain_sha256'):
            raise ReceiptPageError('Receipt chain/boundary mismatch')

    def page_schema(self, page):
        if not isinstance(page, dict) or set(page) != {'format', 'identity', 'previous', 'receipts'}:
            raise ReceiptPageError('Unsupported page schema')
        if page['format'] != FORMAT:
            raise ReceiptPageError('Unsupported page format')
        self.identity_schema(page['identity'])
        previous = page['previous']
        if previous is not None and (not isinstance(previous, dict)
                or set(previous) != {'tip', 'count', 'pages'} or not _hex(previous['tip'])
                or not _integer(previous['count'], 1) or not _integer(previous['pages'], 1)):
            raise ReceiptPageError('Invalid previous page link')
        receipts = page['receipts']
        if not isinstance(receipts, list) or not 1 <= len(receipts) <= MAX_RECEIPTS:
            raise ReceiptPageError('Page receipt admission exceeded')
        for receipt in receipts:
            self.check()
            self.receipt_schema(receipt, page['identity'])

    @_io_errors
    def verify(self, ref):
        if (not isinstance(ref, dict)
                or set(ref) != {'format', 'identity', 'tip', 'count', 'pages', 'bytes', 'manifest'}
                or ref['format'] != FORMAT or not _hex(ref['tip'])
                or not _integer(ref['count'], 1) or not _integer(ref['pages'], 1)
                or not _integer(ref['bytes'], 1) or not isinstance(ref['manifest'], list)
                or not 1 <= len(ref['manifest']) <= self.max_entries
                or ref['pages'] != len(ref['manifest'])):
            raise ReceiptPageError('Invalid page-backed debt reference')
        self.identity_schema(ref['identity'])
        self.inventory()
        previous, count, size, addresses = None, 0, 0, set()
        for item in ref['manifest']:
            self.check()
            if (not isinstance(item, dict) or not _hex(item.get('hash'))
                    or item['hash'] in addresses or item.get('previous') != previous
                    or not _integer(item.get('receipts'), 1) or item['receipts'] > MAX_RECEIPTS):
                raise ReceiptPageError('Invalid receipt manifest')
            st = self.entries.get(item['hash'] + '.json')
            if st is None or item != self.descriptor(item['hash'], st, item['receipts'], previous):
                raise ReceiptPageError('Missing, changed or substituted historical page')
            previous = item['hash'];addresses.add(previous)
            count += item['receipts'];size += item['size']
        if (previous != ref['tip'] or count != ref['count'] or size != ref['bytes']):
            raise ReceiptPageError('Receipt manifest totals mismatch')
        key = hashlib.sha256(canonical(ref, check=self.check)).hexdigest()
        if key not in self.checked:
            page, st = self.read(ref['tip'])
            expected_previous = None if len(ref['manifest']) == 1 else dict(
                tip=ref['manifest'][-2]['hash'], count=count-ref['manifest'][-1]['receipts'], pages=ref['pages']-1)
            if (page['identity'] != ref['identity'] or page['previous'] != expected_previous
                    or len(page['receipts']) != ref['manifest'][-1]['receipts']):
                raise ReceiptPageError('Page/reference link mismatch')
            self.checked.add(key)

    def verify_files(self, files):
        for lane in lanes(files):
            self.check()
            if 'record_debt_pages' in lane:
                self.verify(lane['record_debt_pages'])

    @_io_errors
    def check_source(self, ref, observed, offset_space):
        self.verify(ref)
        identity = ref['identity']
        if (identity['device'], identity['inode'], identity['offset_space']) != (
                observed.st_dev, observed.st_ino, offset_space):
            raise ReceiptPageError('Active source generation differs from page reference')

    @_io_errors
    def append(self, ref, receipts, observed, offset_space):
        self.check()
        if ref is not None:
            self.verify(ref)
            identity = ref['identity']
        else:
            if not receipts or not isinstance(receipts[0].get('source'), dict):
                raise ReceiptPageError('Cannot infer missing receipt identity')
            source = receipts[0]['source']
            identity = {key:source.get(key) for key in ('device', 'inode', 'offset_space')}
            identity['generation'] = hashlib.sha256(canonical(dict(
                source_origin=source, first_start=receipts[0].get('start'),
                first_chain=receipts[0].get('chain_sha256')), check=self.check)).hexdigest()
        self.identity_schema(identity)
        if (identity['device'], identity['inode'], identity['offset_space']) != (
                observed.st_dev, observed.st_ino, offset_space):
            raise ReceiptPageError('Active source identity differs from paged debt')
        previous = None if ref is None else {key:ref[key] for key in ('tip', 'count', 'pages')}
        page = dict(format=FORMAT, identity=identity, previous=previous, receipts=receipts)
        self.page_schema(page)
        raw = canonical(page, limit=self.max_page, check=self.check)
        if len(raw) > self.max_page:
            raise ReceiptPageError('Full receipts exceed bounded page admission')
        digest = hashlib.sha256(raw).hexdigest()
        self.inventory()
        if digest + '.json' in self.entries:
            existing, st = self.read(digest)
            if canonical(existing, limit=self.max_page, check=self.check) != raw:
                raise ReceiptPageError('Conflicting content address')
        else:
            if self.total + 2*len(raw) > self.max_bytes or len(self.entries) + 2 > self.max_entries:
                raise ReceiptPageError('Page quota reservation failed, including staging/orphans')
            if self.io_bytes + 3*len(raw) > self.max_io:
                raise ReceiptPageError('Insufficient bounded IO for complete page publication')
            name = '.stage-' + uuid.uuid4().hex
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=self.fd)
            try:
                self.fault('after_stage_create')
                view = memoryview(raw)
                while view:
                    self.check();chunk = view[:65536];self.charge(len(chunk))
                    written = os.write(fd, chunk)
                    if written <= 0:
                        raise ReceiptPageError('Short receipt page write')
                    view = view[written:]
                self.fault('after_stage_write');os.fsync(fd);self.fault('after_file_fsync')
                os.fchmod(fd, 0o400);os.fsync(fd)
                self.fault('after_mode_fsync')
                stage_stat = os.fstat(fd)
            finally:
                os.close(fd)
            # Read back the exclusive staging object before publication.
            checkfd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
            try:
                opened = os.fstat(checkfd)
                if self.descriptor(digest, opened, 0, None) != self.descriptor(digest, stage_stat, 0, None):
                    raise ReceiptPageError('Staging page substituted')
                body = bytearray()
                while len(body) < len(raw):
                    self.check();part = os.read(checkfd, min(65536,len(raw)-len(body)))
                    if not part:break
                    self.charge(len(part));body.extend(part)
                if bytes(body) != raw or os.fstat(checkfd).st_size != len(raw):
                    raise ReceiptPageError('Staging receipt readback mismatch')
                os.fsync(checkfd)
                after_read = os.fstat(checkfd)
                current_stage = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if (self.descriptor(digest, after_read, 0, None) != self.descriptor(digest, stage_stat, 0, None)
                        or self.descriptor(digest, current_stage, 0, None) != self.descriptor(digest, stage_stat, 0, None)):
                    raise ReceiptPageError('Staging page changed during readback')
            finally:
                os.close(checkfd)
            self.fault('after_readback')
            try:
                os.link(name, digest+'.json', src_dir_fd=self.fd, dst_dir_fd=self.fd,
                        follow_symlinks=False)
            except FileExistsError:
                existing, st = self.read(digest)
                if canonical(existing, limit=self.max_page, check=self.check) != raw:raise ReceiptPageError('Publication conflict')
            self.fault('after_publish_link');os.fsync(self.fd)
            self.fault('after_publish_dir_fsync')
            # Only this invocation's exclusive stage is removed after durable
            # publication. Previous crash leftovers are retained and charged.
            os.unlink(name, dir_fd=self.fd);self.fault('after_stage_unlink');os.fsync(self.fd)
            self.fault('after_stage_cleanup_fsync')
            existing, st = self.read(digest)
            if canonical(existing, limit=self.max_page, check=self.check) != raw:raise ReceiptPageError('Published receipt mismatch')
        # Persist the published inode's final link/mode metadata too, before
        # its stat anchors can enter durable state. This is also required when
        # reusing an orphan whose previous publisher died before directory fsync.
        sealed_fd = os.open(digest+'.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            sealed = os.fstat(sealed_fd)
            if self.descriptor(digest, sealed, 0, None) != self.descriptor(digest, st, 0, None):
                raise ReceiptPageError('Published inode changed before durability seal')
            os.fsync(sealed_fd)
        finally:
            os.close(sealed_fd)
        os.fsync(self.fd)
        current = os.stat(digest+'.json', dir_fd=self.fd, follow_symlinks=False)
        if self.descriptor(digest, current, 0, None) != self.descriptor(digest, st, 0, None):
            raise ReceiptPageError('Published inode changed during durability seal')
        self.fault('after_published_inode_fsync')
        manifest = ([] if ref is None else copy.deepcopy(ref['manifest']))
        manifest.append(self.descriptor(digest, st, len(receipts), None if ref is None else ref['tip']))
        new = dict(format=FORMAT, identity=copy.deepcopy(identity), tip=digest,
                   count=(0 if ref is None else ref['count'])+len(receipts), pages=len(manifest),
                   bytes=(0 if ref is None else ref['bytes'])+len(raw), manifest=manifest)
        # This exact body has already passed full hash/schema/byte checks.
        # Authenticate the new manifest without reading its tip a second time.
        self.checked.add(hashlib.sha256(canonical(new, check=self.check)).hexdigest())
        self.verify(new);self.fault('before_reference_return')
        return new
