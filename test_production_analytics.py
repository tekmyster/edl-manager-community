"""Mechanics and authorization fixtures only, never model-quality evidence."""
import datetime as dt
import json
import sqlite3
import time
import pytest
from core import Store
from behavior_ai import Brain,DEFAULTS,infer,ModelOutputError
from analytics_store import event,connect,stamp,Attempt,path
from production_analytics import summary,investigations
from test_behavior_backend_telemetry import request_fixture

UTC=dt.timezone.utc
AT=dt.datetime(2026,10,17,14,30,tzinfo=UTC)


def attempt(b,ident,started,finished,state='accepted',first=2,inp=10,out=5):
    with connect(b.store,True) as d:
        d.execute("INSERT OR IGNORE INTO coverage VALUES('ai',?)",(stamp(started),))
        d.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)',(ident,'packet',stamp(started),stamp(finished) if finished else None,state,first,inp,out,8))


def test_dispatch_completion_windows_unknowns_and_legacy_dedup(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    attempt(b,'old',AT-dt.timedelta(hours=1),AT-dt.timedelta(minutes=29),first=None)
    attempt(b,'new',AT-dt.timedelta(minutes=5),AT-dt.timedelta(minutes=4),state='rejected',first=1.25)
    attempt(b,'future',AT,AT+dt.timedelta(seconds=5))
    with b.connect() as d:
        for ident,meta in [('legacy',{'input_tokens':100,'output_tokens':25}),('linked',{'request_id':'new','input_tokens':10,'output_tokens':5}),('unknown',{})]:
            d.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',(ident,'p','cfg',stamp(AT-dt.timedelta(minutes=4)),stamp(AT),'completed',json.dumps({'metadata':meta}),'',999))
    data=summary(b,'America/New_York',AT)
    assert data['hour_requests']==1 and data['hour_outcomes']=={'rejected':1}
    assert data['first_seconds']==1.25 and data['first_samples']==1
    assert data['day_tokens']==155 and data['day_known']==3 and data['day_unknown']==1
    assert sum(r['tokens'] for r in data['bins'])==155
    assert data['bins'][0]['first_seconds'] is None and len(data['bins'])==24
    assert data['historical_completions']==2
    assert not data['bins'][0]['covered']


def test_timezone_midnight_dst_and_exclusive_end(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    at=dt.datetime(2026,11,1,6,30,tzinfo=UTC)  # second 01:30 in New York
    attempt(b,'first',at-dt.timedelta(hours=1),at-dt.timedelta(minutes=59))
    attempt(b,'second',at-dt.timedelta(minutes=10),at-dt.timedelta(minutes=9))
    data=summary(b,'America/New_York',at)
    assert parse_hour(data['hour_start'])==dt.datetime(2026,11,1,6,tzinfo=UTC)
    assert parse_hour(data['day_start'])==dt.datetime(2026,11,1,4,tzinfo=UTC)
    assert data['hour_requests']==1 and data['day_attempts']==2
    assert data['bins'][-2]['label']=='01:00 -0400' and data['bins'][-1]['label']=='01:00 -0500'


def parse_hour(value):return dt.datetime.fromisoformat(value)


def test_cache_counts_unique_ips_outbound_and_negative_reads(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    for kind in ['hit','hit','negative_hit','miss','stale','cached_error','outbound','usable']:
        event(b.store,'greynoise',kind,'8.8.8.8',AT-dt.timedelta(minutes=5))
    event(b.store,'misp','local_query','9.9.9.9',AT-dt.timedelta(minutes=5))
    event(b.store,'misp','imports',at=AT-dt.timedelta(minutes=5),n=100)
    data=summary(b,at=AT);gn=data['providers'][0];misp=data['providers'][1]
    assert gn['reads']==6 and gn['hits']==3 and gn['hit_ratio']==50
    assert gn['unique_ips']==gn['unique_usable']==gn['unique_outbound']==1
    assert misp['counts']['imports']==100 and misp['unique_local']==1 and not misp['outbound_started']


@pytest.mark.parametrize('provider',['greynoise','misp'])
@pytest.mark.parametrize('final_miss',[False,True])
def test_provider_aggregate_reconciles_multiple_hours_and_empty_final_bucket(tmp_path,provider,final_miss):
    b=Brain(Store(tmp_path/'manager'))
    records=[(6,'hit',3),(5,'negative_hit',2),(3,'hit',1),
             (4,'miss',2),(2,'stale',1),(1,'cached_error',1)]
    if final_miss:records.append((0,'miss',1))
    for hours,kind,count in records:
        event(b.store,provider,kind,'8.8.8.8',AT-dt.timedelta(hours=hours,minutes=5),n=count)
    p=next(p for p in summary(b,at=AT)['providers'] if p['name']==provider)
    assert p['hits']==6 and p['reads']==10+final_miss
    assert p['hit_ratio']==round(600/(10+final_miss),1)
    assert p['hits']==sum(b['hits'] for b in p['timeline'])
    assert p['reads']==sum(b['total'] for b in p['timeline'])
    assert p['reads']-p['hits']==sum(b['misses'] for b in p['timeline'])
    assert p['timeline'][-1]['hits']==0
    assert p['timeline'][-1]['total']==int(final_miss)


def test_supervisor_three_earlier_hits_and_current_miss_are_seventy_five_percent(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    event(b.store,'greynoise','hit','8.8.8.8',AT-dt.timedelta(hours=2),n=3)
    event(b.store,'greynoise','miss','8.8.8.8',AT-dt.timedelta(minutes=5))
    p=summary(b,at=AT)['providers'][0]
    assert (p['hits'],p['reads'],p['hit_ratio'])==(3,4,75)
    assert sum(b['hits'] for b in p['timeline'])==3


@pytest.mark.parametrize('terminator',[b'',b'\n',b'\r\n'])
@pytest.mark.parametrize('byte_chunks',[False,True])
def test_complete_nonstreaming_fallback_never_becomes_first_content_timing(tmp_path,terminator,byte_chunks):
    from test_behavior_ai import result
    packet,_,_=request_fixture(tmp_path,{})
    body=json.dumps({'model':'test','done':True,'message':{'content':json.dumps(result(packet))},
                     'prompt_eval_count':123,'eval_count':45}).encode()+terminator
    closed=[]
    class Response:
        status_code=200
        def iter_content(self,n):
            if byte_chunks:
                for i in range(len(body)):yield body[i:i+1]
            else:yield body
        def close(self):closed.append(True)
    b=Brain(Store(tmp_path/'manager'));tracker=Attempt(b.store,packet['packet_id'])
    value,meta=infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',lambda *a,**kw:Response(),tracker)
    assert value['classification']=='inconclusive' and closed==[True]
    assert meta['first_content_seconds'] is None and meta['request_seconds']>=0
    assert (meta['input_tokens'],meta['output_tokens'])==(123,45)
    with connect(b.store) as d:
        row=d.execute('SELECT * FROM requests').fetchone()
        assert row['state']=='accepted' and row['first_seconds'] is None
        assert (row['input_tokens'],row['output_tokens'])==(123,45)


def test_empty_interim_frame_then_final_only_content_has_unknown_first_content_time(tmp_path):
    from test_behavior_ai import result
    packet,_,_=request_fixture(tmp_path,{})
    frames=[{'model':'test','done':False,'message':{'content':''}},
            {'model':'test','done':True,'message':{'content':json.dumps(result(packet))}}]
    class Response:
        status_code=200
        def iter_content(self,n):
            for frame in frames:yield (json.dumps(frame)+'\n').encode()
        def close(self):pass
    value,meta=infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',lambda *a,**kw:Response())
    assert value['classification']=='inconclusive' and meta['first_content_seconds'] is None


def test_stream_measures_first_content_and_validates_final_output(tmp_path):
    from test_behavior_ai import result
    packet,_,_=request_fixture(tmp_path,{})
    full=json.dumps(result(packet));parts=[full[:50],full[50:]];calls=[]
    class Response:
        status_code=200
        def iter_content(self,n):
            assert n==1
            yield (json.dumps({'model':'test','message':{'content':''},'done':False})+'\n').encode()
            for part in parts:
                time.sleep(.01)
                yield (json.dumps({'model':'test','message':{'content':part},'done':False})+'\n').encode()
            yield (json.dumps({'model':'test','message':{'content':''},'done':True,'prompt_eval_count':11,'eval_count':9})+'\n').encode()
        def close(self):calls.append('closed')
    def send(*args,**kw):
        assert kw['json']['stream'] is True and kw['stream'] is True and kw['allow_redirects'] is False
        return Response()
    b=Brain(Store(tmp_path/'manager'));tracker=Attempt(b.store,packet['packet_id'])
    value,meta=infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',send,tracker)
    assert value['classification']=='inconclusive' and calls==['closed']
    assert 0<meta['first_content_seconds']<meta['request_seconds']
    with connect(b.store) as d:
        row=d.execute('SELECT * FROM requests').fetchone()
        assert row['state']=='accepted' and row['input_tokens']==11 and row['first_seconds']==meta['first_content_seconds']


@pytest.mark.parametrize('tail',['truncated','foreign','bad_content','extra_after_done','over_limit'])
def test_stream_never_accepts_partial_or_foreign_output(tmp_path,tail):
    packet,_,_=request_fixture(tmp_path,{})
    class Response:
        status_code=200
        def iter_content(self,n):
            yield (json.dumps({'model':'test','message':{'content':'{'},'done':False})+'\n').encode()
            if tail=='foreign':yield b'{"model":"other","done":true}\n'
            if tail=='bad_content':yield b'{"model":"test","message":{"content":3},"done":true}\n'
            if tail=='extra_after_done':yield b'{"model":"test","done":true}\n{"model":"test","done":true}\n'
            if tail=='over_limit':yield b'x'*131073
        def close(self):pass
    b=Brain(Store(tmp_path/'manager'));tracker=Attempt(b.store,packet['packet_id'])
    with pytest.raises((ValueError,TypeError,KeyError)):
        infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'test'},packet,[],{},'',lambda *a,**kw:Response(),tracker)
    with connect(b.store) as d:assert d.execute('SELECT state FROM requests').fetchone()[0] in ('failed','rejected')


def test_uncollected_history_is_unknown_and_read_only(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    data=summary(b,at=AT)
    assert not path(b.store).exists() and data['coverage']=={} and not data['error']
    assert data['first_seconds'] is None and not any(v['covered'] for v in data['bins'])


def test_analytics_management_auth_and_render(tmp_path):
    from app import create_app
    app=create_app({'database':str(tmp_path/'db'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'test-secret','hosts':['localhost']})
    app.testing=True;c=app.test_client()
    with app.store.connect() as d:d.execute('INSERT INTO users VALUES(?,?,?)',('admin','hash',1))
    for route in ['/','/analytics','/analytics/data']:
        assert c.get(route,base_url='https://localhost').status_code==302
    with c.session_transaction() as s:s.update(user='admin',version=1,expires_at=time.time()+3600,csrf='csrf')
    for route in ['/','/analytics','/analytics/data']:
        r=c.get(route,base_url='https://localhost');assert r.status_code==200,r.data[:1000]
        if route=='/analytics/data':assert r.headers['Cache-Control']=='no-store'
        else:
            assert b'AI requests this hour' in r.data and b'Average first response today' in r.data
            assert b'Unavailable' in r.data and b'data-tip=' in r.data
        assert c.get(route,base_url='https://localhost',environ_overrides={'REMOTE_ADDR':'8.8.8.8'}).status_code==403
    assert c.post('/analytics/data',data={'csrf':'csrf'},base_url='https://localhost').status_code==405


def test_observation_ids_are_deduplicated_and_gaps_remain_explicit(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    when=stamp(AT-dt.timedelta(minutes=10))
    content={'events':[{'id':'original-one','seen':when,'client_type':'HTTP tool','provenance':{'original_id':'source-one'}},{'id':'unknown','seen':when}]}
    with b.connect() as d:
        for ident in ['first','rebuilt']:
            d.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,'8.8.8.8',when,json.dumps(content),'[]',0))
    data=investigations(b,stamp(AT-dt.timedelta(hours=23)),stamp(AT))
    assert data['events']==2 and data['unknown']==1 and dict(data['features'])=={'HTTP tool':1,'Unknown':1}
    assert sum(r['total'] for r in data['feature_timeline'])==2


def test_ledger_contains_no_provider_content_or_credentials(tmp_path):
    b=Brain(Store(tmp_path/'manager'));a=Attempt(b.store,'packet')
    a.start();a.finish('rejected',{'input_tokens':10,'output_tokens':2,'first_content_seconds':1,'request_seconds':3,'secret':'DO_NOT_STORE','prompt':'DO_NOT_STORE'})
    with connect(b.store) as d:
        saved=' '.join(str(tuple(r)) for r in d.execute('SELECT * FROM requests'))
    assert 'DO_NOT_STORE' not in saved


def test_retention_does_not_prune_native_or_review_data(tmp_path):
    import analytics_store
    b=Brain(Store(tmp_path/'manager'));b.store.evidence('8.8.8.8','waf','test',stamp(),'http',50)
    with connect(b.store,True) as d:
        d.execute("INSERT INTO counters VALUES('2000-01-01T00:00:00+00:00','misp','hit','8.8.8.8',1,'2000-01-01T00:00:00+00:00')")
    analytics_store._pruned.clear();event(b.store,'misp','hit','8.8.8.8')
    with connect(b.store) as d:assert not d.execute("SELECT 1 FROM counters WHERE hour LIKE '2000%'").fetchone()
    with b.store.connect() as d:assert d.execute('SELECT count(*) FROM evidence').fetchone()[0]==1


def test_gateway_stream_is_incremental_and_rejects_incomplete_extra_or_large():
    from io import BytesIO
    from model_gateway import stream_lines
    first=b'{"model":"test","message":{"content":"hello"},"done":false}\n'
    final=b'{"model":"test","message":{"content":""},"done":true}\n'
    response=BytesIO(first+final)
    stream=stream_lines(response,'test')
    assert next(stream)==first and response.tell()==len(first)
    assert list(stream)==[final]
    for body in [first,first+final+first,b'x'*131073]:
        with pytest.raises(ValueError):list(stream_lines(BytesIO(body),'test'))


def test_fractional_timezone_keeps_provider_and_ai_intervals_aligned(tmp_path):
    b=Brain(Store(tmp_path/'manager'))
    event(b.store,'misp','hit','8.8.8.8',AT-dt.timedelta(minutes=5))
    data=summary(b,'Asia/Kathmandu',AT)
    assert data['bins'][-1]['label']=='19:45 +0545'
    assert data['providers'][1]['timeline'][-1]['hits']==1
    assert sum(r['hits'] for r in data['providers'][1]['timeline'])==data['providers'][1]['hits']


def test_legacy_seconds_and_new_fractional_timestamps_share_exact_boundaries(tmp_path):
    b=Brain(Store(tmp_path/'manager'));start=AT.replace(hour=0,minute=0)
    with b.connect() as d:
        for ident,when in [('start',start.isoformat()),('end',AT.isoformat())]:
            d.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',(ident,'packet','cfg',when,when,'completed',json.dumps({'metadata':{'input_tokens':10,'output_tokens':5}}),'',99))
            d.execute('INSERT INTO analysis_counters VALUES(?,?,?)',(when,'cached',1))
    data=summary(b,at=AT)
    assert data['day_tokens']==15 and data['historical_completions']==1 and data['cached']==1


def test_relative_database_configuration_remains_portable(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    b=Brain(Store('data/manager.sqlite3'))
    event(b.store,'misp','local_query','8.8.8.8',AT-dt.timedelta(minutes=5))
    data=summary(b,at=AT)
    assert data['providers'][1]['unique_local']==1 and not data['error']
    assert path(b.store)==tmp_path/'data/analytics.sqlite3'
