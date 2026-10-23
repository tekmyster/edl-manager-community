import copy
import gzip
import json
import os
import pathlib

import pytest

from source_log_reader import collect_log_inputs


def collect(paths, state, received):
    return collect_log_inputs(paths, state, lambda path, line: received.append(json.loads(line)), cutoff=0)


@pytest.mark.parametrize('damage', ['truncated', 'crc'])
def test_bad_gzip_has_no_consumer_effect_or_cursor_loss_and_other_input_completes(tmp_path, damage):
    bad = tmp_path/'archive.log.1.gz'
    complete = gzip.compress(b'{"id":"archive","count":7}\n')
    broken = complete[:-4] if damage == 'truncated' else complete[:-8] + bytes([complete[-8] ^ 1]) + complete[-7:]
    bad.write_bytes(broken)
    current = tmp_path/'current.log'
    current.write_text('{"id":"current","count":3}\n')
    previous = {'inode': 42, 'offset': 123, 'size': 100, 'mtime': 1}
    state = {str(bad): previous.copy()}
    received = []
    coverage = collect([bad, current], state, received)
    assert received == [{'id': 'current', 'count': 3}]
    assert state[str(bad)] == previous
    assert coverage['status'] == 'partial' and coverage['completed'] == 1
    assert coverage['deferred'] == [{'path': str(bad), 'reason': 'Compressed input is incomplete or damaged; retry required.'}]
    # A repaired file is retried without emitting its valid prefix twice.
    bad.write_bytes(complete)
    coverage = collect([bad, current], state, received)
    assert coverage['status'] == 'complete'
    assert received == [{'id': 'current', 'count': 3}, {'id': 'archive', 'count': 7}]
    collect([bad, current], state, received)
    assert len(received) == 2


def test_concatenated_gzip_member_is_atomic_until_last_member_is_complete(tmp_path):
    path = tmp_path/'archive.log.gz'
    first = gzip.compress(b'{"id":1}\n')
    second = gzip.compress(b'{"id":2}\n')
    path.write_bytes(first+second[:-5])
    state, received = {}, []
    assert collect([path], state, received)['status'] == 'partial'
    assert not state and not received
    path.write_bytes(first+second)
    assert collect([path], state, received)['status'] == 'complete'
    assert received == [{'id': 1}, {'id': 2}]
    assert collect([path], state, received)['unchanged'] == 1
    assert len(received) == 2


def test_rotation_during_snapshot_defers_without_consuming_or_advancing(tmp_path, monkeypatch):
    path = tmp_path/'archive.log.gz'
    path.write_bytes(gzip.compress(b'{"id":"old"}\n'))
    replacement = tmp_path/'replacement.gz'
    replacement.write_bytes(gzip.compress(b'{"id":"new"}\n'))
    original_stat = pathlib.Path.stat
    calls = 0

    def rotating_stat(p, *args, **kwargs):
        nonlocal calls
        if p == path:
            calls += 1
            if calls == 2:
                try:
                    os.replace(replacement, path)
                except PermissionError:
                    # Windows can deny rename of an open file; exercise its
                    # real in-place replacement path instead.
                    path.write_bytes(replacement.read_bytes())
        return original_stat(p, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, 'stat', rotating_stat)
    state, received = {}, []
    coverage = collect([path], state, received)
    assert coverage['status'] == 'partial'
    assert coverage['deferred'][0]['path'] == str(path)
    assert not state and not received
    assert collect([path], state, received)['status'] == 'complete'
    assert received == [{'id': 'new'}]


def test_validated_snapshot_does_not_acknowledge_later_compressed_append(tmp_path):
    path = tmp_path/'archive.log.gz'
    path.write_bytes(gzip.compress(b'{"id":1}\n'))
    initial_size = path.stat().st_size
    state, received = {}, []

    def append_after_validation(p, line):
        received.append(json.loads(line))
        with p.open('ab') as f:
            f.write(gzip.compress(b'{"id":2}\n'))

    collect_log_inputs([path], state, append_after_validation, cutoff=0)
    assert received == [{'id': 1}]
    assert state[str(path)]['size'] == initial_size < path.stat().st_size
    # Changed gzip files replay from the start, as before. Caller event-ID
    # suppression owns deduplication; the reader must not skip the new member.
    assert collect([path], state, received)['unchanged'] == 0
    assert received[-2:] == [{'id': 1}, {'id': 2}]


def test_plain_utf8_append_and_same_name_replacement_preserve_offsets(tmp_path):
    path = tmp_path/'current.log'
    path.write_text('{"id":"Î±"}\n', encoding='utf-8')
    state, received = {}, []
    collect([path], state, received)
    with path.open('a', encoding='utf-8') as f:
        f.write('{"id":"ðŸ™‚"}\n')
    collect([path], state, received)
    replacement = tmp_path/'next.log'
    replacement.write_text('{"id":"replacement"}\n')
    os.replace(replacement, path)
    collect([path], state, received)
    assert received == [{'id': 'Î±'}, {'id': 'ðŸ™‚'}, {'id': 'replacement'}]


def test_retention_and_consumer_failure_are_not_misreported_as_full_reads(tmp_path):
    old = tmp_path/'old.log.gz'
    old.write_bytes(b'not gzip')
    state, received = {}, []
    assert collect_log_inputs([old], state, lambda *args: received.append(args), cutoff=old.stat().st_mtime+1)['outside_retention'] == 1
    assert not state and not received
    current = tmp_path/'current.log.gz'
    current.write_bytes(gzip.compress(b'{"id":1}\n'))
    before = copy.deepcopy(state)

    def broken_consumer(*args):
        raise RuntimeError('consumer failed')

    with pytest.raises(RuntimeError, match='consumer failed'):
        collect_log_inputs([current], state, broken_consumer, cutoff=0)
    assert state == before


def test_missing_input_is_explicit_and_prior_state_is_preserved(tmp_path):
    missing = tmp_path/'missing.log.gz'
    prior = {'offset': 99, 'inode': 1, 'size': 9, 'mtime': 1}
    state = {str(missing): prior.copy()}
    coverage = collect([missing], state, [])
    assert coverage['status'] == 'partial'
    assert coverage['deferred'][0]['path'] == str(missing)
    assert state[str(missing)] == prior


def test_large_compressed_input_preserves_content_after_disk_spooling(tmp_path):
    # Incompressible synthetic content exercises the bounded-memory disk path.
    payload = os.urandom(2 * 1024 * 1024).hex()
    path = tmp_path/'archive.log.gz'
    path.write_bytes(gzip.compress((json.dumps({'id': 'large', 'payload': payload})+'\n').encode()))
    assert path.stat().st_size > 1024 * 1024
    state, received = {}, []
    assert collect([path], state, received)['status'] == 'complete'
    assert received == [{'id': 'large', 'payload': payload}]
    assert collect([path], state, received)['unchanged'] == 1
    assert len(received) == 1
