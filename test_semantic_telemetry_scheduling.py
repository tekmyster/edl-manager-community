"""Offline role, real SQLite contention and queue fairness regressions."""
import copy
import datetime as dt
import json
import sqlite3
import time

import pytest
from core import Store
from behavior_ai import Brain,validate_result
from behavior_generation import offers,decode,example
from behavior_grounding import GroundingError,contract,example as canonical
from behavior_scheduling import richness,index,backfill,schedule
from behavior_telemetry import recover
import analytics_store as ledger
from test_source_observations import linked_packet


def positive(packet):
    packet['context']=[{'id':'positive','kind':'intelligence','provider':'crawler',
        'status':'ok','verified':True,'cache_fresh':True,'expires':'2099-01-01T00:00:00+00:00'}]
    return packet


@pytest.mark.parametrize('status',['301','404','200',''])
def test_more_probes_are_facts_not_opposing_evidence(status):
    p=linked_packet();p['events'][1].update(path='/.env.swp',method='GET',status=status,action='sensitive-path-probe')
    tables,_=offers(p,[],{});wire=example(p)
    assert not tables['counterevidence']
    probe=next(v for v in contract(p,{})['facts'] if '/.env.swp' in v['summary'])
    result=canonical(p);result['contradictory_evidence']=[probe]
    with pytest.raises(GroundingError,match='positive opposing context'):validate_result(result,p,[],{})
    wire['contradictory_evidence']=[next(k for k,v in tables['facts'].items() if v==probe)]
    with pytest.raises(ValueError):decode(wire,p,[],{})
    assert decode(example(p),p,[],{})['contradictory_evidence']==[]


def test_positive_context_has_separate_role_scope_and_cannot_be_used_twice():
    p=positive(linked_packet());tables,_=offers(p,[],{});wire=example(p)
    assert set(tables['facts']).isdisjoint(tables['counterevidence'])
    assert all(len(k)<=32 for table in tables.values() for k in table)
    wire['findings']=[];wire['contradictory_evidence']=list(tables['counterevidence'])
    result=decode(wire,p,[],{});validate_result(result,p,[],{})
    assert result['contradictory_evidence'][0]['evidence_ids']==['positive']
    wire['findings']=[next(k for k,v in tables['facts'].items() if v==result['contradictory_evidence'][0])]
    with pytest.raises(ValueError):decode(wire,p,[],{})


@pytest.mark.parametrize('change',[{'cache_fresh':False},{'verified':False},{'expires':'2000-01-01T00:00:00+00:00'}])
def test_stale_unverified_context_is_not_counterevidence(change):
    p=positive(linked_packet());p['context'][0].update(change)
    assert not offers(p,[],{})[0]['counterevidence']


def saved(brain,ident,packet,metadata,status='completed'):
    when='2026-10-17T19:08:57+00:00'
    with brain.connect() as db:
        db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',
                   (ident,packet,'fixture',when,when,status,json.dumps({'metadata':metadata}),'',3.651241))


META={'request_id':'b028bf3ea16e4055bf8215f59af9e054','first_content_seconds':1.0915374499745667,
      'input_tokens':2981,'output_tokens':181,'request_seconds':3.651241}


def test_known_legacy_pending_completion_recovers_without_inventing_times_or_rows(tmp_path):
    b=Brain(Store(tmp_path/'native'));meta=dict(META)
    with ledger.connect(b.store,True) as db:
        db.execute("INSERT INTO requests(id,packet,started,state) VALUES(?,?,?,'pending')",(meta['request_id'],'packet','2026-10-17T19:08:53.548300+00:00'))
    saved(b,'actual-saved','packet',meta);saved(b,'missing-dispatch','other',{**meta,'request_id':'a'*32})
    with b.connect() as db:before=list(db.execute('SELECT * FROM assessments'))
    assert recover(b)['recovered']==1
    with ledger.connect(b.store) as db:
        rows=list(db.execute('SELECT * FROM requests'));assert len(rows)==1
        row=rows[0];assert row['state']=='accepted' and row['finished'] is None
        assert row['started']=='2026-10-17T19:08:53.548300+00:00'
        assert (row['first_seconds'],row['input_tokens'],row['output_tokens'],row['total_seconds'])==(meta['first_content_seconds'],2981,181,3.651241)
    with b.connect() as db:assert list(db.execute('SELECT * FROM assessments'))==before
    assert recover(Brain(b.store))['recovered']==0
    from production_analytics import summary
    report=summary(b,at=dt.datetime(2026,10,17,20,tzinfo=dt.timezone.utc))
    assert report['outcomes']=={'accepted':1} and report['completion_time_unknown']==1
    # Both distinct observed completions retain tokens; only one known dispatch.
    assert report['day_tokens']==2*(2981+181) and report['historical_completions']==1
    from app import create_app
    app=create_app({'database':str(b.store.path),'output':str(tmp_path/'output'),'providers_file':str(tmp_path/'keys'),'session_secret':'test-only','hosts':['localhost']})
    app.testing=True;client=app.test_client()
    with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('fixture','hash',1))
    with client.session_transaction() as session:session.update(user='fixture',version=1,expires_at=time.time()+3600,csrf='test-only')
    response=client.get('/analytics',base_url='https://localhost');assert response.status_code==200
    assert b'Recovered completion timing: 1 without exact finish times.' in response.data
    assert b'Token charts use saved assessment times.' in response.data
    import os,pathlib
    if os.environ.get('INTELLIGENCE_UI_EXPORT'):
        folder=pathlib.Path(os.environ['INTELLIGENCE_UI_EXPORT']);folder.mkdir(exist_ok=True)
        (folder/'recovered-analytics.html').write_bytes(response.data)
    earlier=summary(b,at=dt.datetime(2026,10,17,19,8,56,tzinfo=dt.timezone.utc))
    assert earlier['outcomes']=={'pending':1} and earlier['first_samples']==0 and earlier['day_tokens']==0


def test_busy_completion_recovers_after_object_loss_and_process_style_restart(tmp_path,caplog):
    b=Brain(Store(tmp_path/'native'));attempt=ledger.Attempt(b.store,'packet');assert attempt.start()
    lock=sqlite3.connect(ledger.path(b.store));lock.execute('BEGIN IMMEDIATE')
    meta=dict(META);meta['request_id']=attempt.id
    try:
        begin=time.monotonic();assert not attempt.finish('accepted',meta)
        assert time.monotonic()-begin<.5
        exact_finish=attempt._outcome[0];saved(b,'durable','packet',meta)
        begin=time.monotonic();assert recover(b)['status']=='retry';assert time.monotonic()-begin<.5
        with b.connect() as db:assert not db.execute("SELECT 1 FROM retention_state WHERE name='telemetry_cursor'").fetchone()
    finally:lock.rollback();lock.close()
    del attempt
    assert recover(Brain(Store(b.store.path)))['recovered']==1
    with ledger.connect(b.store) as db:
        row=db.execute('SELECT * FROM requests').fetchone();assert row['finished']==exact_finish and row['state']=='accepted'
    assert 'operation=ai_finish sqlite_code=5' in caplog.text and 'operation=ai_recover sqlite_code=5' in caplog.text
    assert 'packet' not in caplog.text and meta['request_id'] not in caplog.text


def test_failed_start_and_finish_recover_only_from_actual_durable_receipt(tmp_path):
    b=Brain(Store(tmp_path/'native'))
    with ledger.connect(b.store,True):pass
    lock=sqlite3.connect(ledger.path(b.store));lock.execute('BEGIN IMMEDIATE')
    attempt=ledger.Attempt(b.store,'packet');meta=dict(META);meta['request_id']=attempt.id
    try:
        assert not attempt.start();assert not attempt.finish('rejected',meta)
        saved(b,'durable','packet',meta,'failed')
    finally:lock.rollback();lock.close()
    assert recover(b)['recovered']==1
    with ledger.connect(b.store) as db:
        row=db.execute('SELECT * FROM requests').fetchone()
        assert row['started']==meta['request_started_at'] and row['finished']==meta['request_finished_at'] and row['state']=='rejected'


def test_recovery_is_bounded_and_never_overwrites_completed_or_foreign_packet(tmp_path):
    b=Brain(Store(tmp_path/'native'));a=ledger.Attempt(b.store,'original');a.id=META['request_id'];a.start();a.finish('rejected',{})
    with ledger.connect(b.store) as db:before=[tuple(r) for r in db.execute('SELECT * FROM requests')]
    for i in range(52):saved(b,str(i),'foreign',dict(META))
    assert recover(b,500)['scanned']==50 and recover(b)['scanned']==2
    with ledger.connect(b.store) as db:assert [tuple(r) for r in db.execute('SELECT * FROM requests')]==before


def test_unknown_or_invalid_metadata_does_not_block_recovery_cursor(tmp_path):
    b=Brain(Store(tmp_path/'native'))
    for i,meta in enumerate((None,[],{'request_id':'PRIVATE-CREDENTIAL'},dict(META))):saved(b,str(i),'p',meta)
    assert recover(b)['scanned']==4 and recover(b)['scanned']==0
    with ledger.connect(b.store) as db:assert not db.execute('SELECT 1 FROM requests').fetchone()


def put(db,p,queued,address):
    db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(p['packet_id'],address,queued,json.dumps(p),'[]',0))
    db.execute('INSERT INTO current_packets VALUES(?,?)',(address,p['packet_id']))
    index(db,p['packet_id']);db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',(address,p['packet_id'],queued))


def test_coherent_session_beats_recent_generic_paths_without_losing_fairness(tmp_path):
    b=Brain(Store(tmp_path/'native'));p=linked_packet();p['packet_id']='coherent'
    original=copy.deepcopy(p);when='2026-10-17T18:30:20+00:00'
    with b.connect() as db:
        for i in range(160):
            generic={'packet_id':'generic'+str(i),'events':[{'id':str(i)+'-'+str(k),'seen':'2026-10-17T19:00:00+00:00','path':'/probe/'+str(k),'method':'GET','action':'sensitive path request'} for k in range(4)]}
            put(db,generic,'2026-10-17T18:00:00+00:00','generic'+str(i))
        put(db,p,when,'coherent-address')
        before=list(db.execute('SELECT id,created,content FROM packets'))
        chosen=schedule(db)
        assert chosen[0]['packet_id'].startswith('generic') and chosen[1]['packet_id']=='coherent'
        assert len(chosen)==100 and list(db.execute('SELECT id,created,content FROM packets'))==before
        excluded={(r['ip'],r['packet_id']) for r in chosen}
        assert schedule(db,excluded=excluded)[0]['packet_id'] not in {r['packet_id'] for r in chosen}
    assert p==original and richness(p)>richness(generic)


@pytest.mark.parametrize('mutation',[
    lambda p:p['events'].pop(0),
    lambda p:p['events'][1]['source_observation'].update(session_ref='0'*64),
    lambda p:p['events'][2]['source_observation'].update(semantic='shell_input'),
    lambda p:p['events'][2]['source_observation'].update(semantic='interactive_input'),
    lambda p:p['events'][2]['provenance'].update(upstream_id=p['events'][1]['provenance']['upstream_id']),
])
def test_missing_conflicted_or_repeated_session_reports_have_no_sequence_bonus(mutation):
    p=linked_packet();before=richness(p);mutation(p);assert richness(p)<=2<before


def test_existing_priority_reindex_is_versioned_bounded_and_restartable(tmp_path):
    b=Brain(Store(tmp_path/'native'));p=linked_packet()
    with b.connect() as db:
        for i in range(205):put(db,{**p,'packet_id':str(i)},'2026-10-17T18:00:00+00:00',str(i))
        db.execute('DELETE FROM packet_scheduling_v2_ready');db.execute('UPDATE packet_scheduling SET richness=2')
    assert backfill(b)['scanned']==200
    with b.connect() as db:
        assert db.execute("SELECT richness FROM packet_scheduling WHERE packet_id='204'").fetchone()[0]>2
        assert db.execute("SELECT richness FROM packet_scheduling WHERE packet_id='0'").fetchone()[0]==2
        plan=' '.join(r[3] for r in db.execute('EXPLAIN QUERY PLAN SELECT rowid,id FROM packets WHERE rowid<? ORDER BY rowid DESC LIMIT 200',(999,)))
        assert 'INTEGER PRIMARY KEY' in plan and 'TEMP B-TREE' not in plan
    assert backfill(Brain(b.store))['scanned']==5 and not backfill(b)['partial']
