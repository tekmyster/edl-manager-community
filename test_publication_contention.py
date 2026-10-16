"""Competing real publishers and committed ingestion in disposable Linux stores."""
import hashlib
import json
import multiprocessing
import os
import pathlib
import sqlite3
import time

import pytest

from core import Store, now

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux worker and atomic symlink publication')


def paused_publisher(database, output, entered, release):
    store = Store(database)
    score = store.all_scores

    def pause_after_snapshot():
        rows = score()
        entered.set()
        if not release.wait(15):
            raise RuntimeError('Test publisher was not released')
        return rows

    store.all_scores = pause_after_snapshot
    store.build(output)


def assert_generation(output):
    generation = (output / 'current').resolve(strict=True)
    manifest = json.loads((generation / 'manifest.json').read_text())
    for name, count in manifest['counts'].items():
        data = (generation / (name + '.txt')).read_bytes()
        assert hashlib.sha256(data).hexdigest() == manifest['sha256'][name]
        assert len(data.decode().splitlines()) == count
    assert json.loads((generation / 'dashboard.json').read_text())['created'] == manifest['created']
    return generation


@pytest.mark.parametrize('mode', ['--ingest-only', '--enrich-only'])
@pytest.mark.parametrize('owner_crashes', [False, True])
def test_committed_ingestion_survives_competing_publisher_and_next_cycle_publishes(tmp_path, monkeypatch, caplog, mode, owner_crashes):
    import worker
    import source_types

    database = tmp_path / 'db'
    output = tmp_path / 'out'
    store = Store(database)
    store.add_rule('block', '9.9.9.9', 'Existing reviewed block', None, 'test')
    store.add_rule('allow', '1.1.1.1', 'Protected customer', None, 'test')
    store.build(output)
    original = assert_generation(output)
    cfg = {'database': str(database), 'output': str(output)}
    config = tmp_path / 'config.json'
    config.write_text(json.dumps(cfg))
    monkeypatch.setenv('EDL_CONFIG', str(config))
    monkeypatch.setattr('sys.argv', ['worker.py', mode])
    monkeypatch.setattr(source_types, 'refresh', lambda s: None)
    monkeypatch.setattr(worker, 'enrich', lambda s, cfg: 0)
    ctx = multiprocessing.get_context('spawn')
    entered, release = ctx.Event(), ctx.Event()
    owner = ctx.Process(target=paused_publisher, args=(str(database), str(output), entered, release))
    owner.start()
    try:
        assert entered.wait(10), 'Actual publisher did not reach its snapshot'
        owning_request = store.state('publication_request')['id']
        generation_count = len(list(output.glob('generation-*')))
        seen = now()

        def collect(s, cfg, **kwargs):
            # Exercise the worker's persistent batched connection, cursor and
            # genuine scoring path, with no external telemetry or live DB.
            for address in ['8.8.8.8', '1.1.1.1']:
                s.evidence(address, 'waf', 'test-waf', seen, 'http', 75)
            s.state('native_ingest_cursor', {'through': seen, 'mode': 'test'})
            return 2

        monkeypatch.setattr(worker, 'collect', collect)
        started = time.monotonic()
        worker.main()
        assert time.monotonic() - started < 5
        status_key = 'ingest_status' if mode == '--ingest-only' else 'worker_status'
        status = store.state(status_key)
        assert status['status'] == 'publication_pending'
        assert status['publication'] == 'pending' and status['generation'] is None
        assert 'Publication deferred' in caplog.text
        assert store.state('native_ingest_cursor')['through'] == seen
        with store.connect() as db:
            assert db.execute('SELECT count(*) FROM evidence').fetchone()[0] == 2
        pending = store.state('publication_request')
        assert pending['id'] != owning_request
        # The contender cannot enter _build or disturb the live last-good set.
        assert len(list(output.glob('generation-*'))) == generation_count
        assert assert_generation(output) == original
        if owner_crashes:
            owner.terminate()
        else:
            release.set()
        owner.join(10)
        assert not owner.is_alive()
        if not owner_crashes:
            assert owner.exitcode == 0
            assert store.state('publication_completed')['request_id'] == owning_request
            # The older publisher cannot acknowledge the new pending request.
            assert store.state('publication_request')['id'] == pending['id']
            assert '8.8.8.8' not in (assert_generation(output) / 'combined-block.txt').read_text()
        else:
            assert assert_generation(output) == original
        # Natural periodic retry consumes the committed data even if its source
        # is now unavailable. No replay, cursor rewind or AI call is required.
        monkeypatch.setattr(worker, 'collect', lambda *args, **kwargs: 0)
        worker.main()
        status = store.state(status_key)
        assert status['status'] == 'ok' and status['publication'] == 'published'
        current = assert_generation(output)
        assert current != original
        assert set((current / 'combined-block.txt').read_text().splitlines()) == {'8.8.8.8', '9.9.9.9'}
        assert store.state('publication_completed')['request_id'] == store.state('publication_request')['id']
        assert store.state('publication_request')['requested'] == pending['requested']
        assert store.state('native_ingest_cursor')['through'] == seen
    finally:
        # A killed process can leave an Event's internal lock inconsistent.
        # Never touch that Event after deliberately terminating its waiter.
        if owner.is_alive():
            release.set()
            owner.join(5)
        if owner.is_alive():
            owner.terminate()
        owner.join(10)


def test_build_commits_batched_evidence_before_lock_and_never_maintains_as_waiter(tmp_path, monkeypatch):
    from filelock import FileLock
    import offenders

    store = Store(tmp_path / 'db')
    output = tmp_path / 'out'
    output.mkdir()
    store._worker_connection = sqlite3.connect(store.path)
    store._batch_evidence = True
    try:
        store.evidence('8.8.8.8', 'waf', 'test-waf', now(), 'http', 75)
        assert store._worker_connection.in_transaction
        with FileLock(str(output / 'build.lock')):
            monkeypatch.setattr(offenders, 'maintain', lambda s: pytest.fail('Waiter ran maintenance'))
            assert store.build(output, defer_if_busy=True) is None
            assert not store._worker_connection.in_transaction
            with sqlite3.connect(store.path, timeout=.1) as other:
                assert other.execute('SELECT count(*) FROM evidence').fetchone()[0] == 1
                other.execute("INSERT INTO state VALUES ('other-writer','true')")
    finally:
        store._worker_connection.close()
        store._worker_connection = None


def test_real_build_failure_remains_failure_with_pending_request_and_last_good(tmp_path, monkeypatch):
    store = Store(tmp_path / 'db')
    output = tmp_path / 'out'
    store.build(output)
    original = assert_generation(output)
    completed = store.state('publication_completed')
    real = store._build

    def fail(*args, **kwargs):
        raise OSError('Isolated publication failure')

    monkeypatch.setattr(store, '_build', fail)
    with pytest.raises(OSError, match='Isolated publication failure'):
        store.build(output, defer_if_busy=True)
    assert store.state('publication_completed') == completed
    assert store.state('publication_request')['id'] != completed['request_id']
    assert assert_generation(output) == original
    monkeypatch.setattr(store, '_build', real)
    store.build(output, defer_if_busy=True)
    assert store.state('publication_completed')['request_id'] == store.state('publication_request')['id']
    assert assert_generation(output) != original
