"""Recovered completion cohorts and authenticated HTML; isolated SQLite only."""
import datetime as dt
import json
import time
from html.parser import HTMLParser

import pytest
from analytics_store import connect,stamp
from behavior_ai import Brain
from core import Store
from production_analytics import summary

UTC=dt.timezone.utc
AT=dt.datetime(2026,10,17,20,tzinfo=UTC)
WINDOW=dt.datetime(2026,10,16,21,tzinfo=UTC)
DISPATCH=WINDOW-dt.timedelta(seconds=10)


def seed(brain,dispatch,saved,state='accepted',recovery=True):
    ident='1'*32;packet='fixture-'+state
    with connect(brain.store,True) as db:
        db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)',
                   (ident,packet,stamp(dispatch),None,state,1.0915374499745667,2981,181,3.651241))
        if recovery:db.execute('INSERT INTO request_recovery VALUES(?,?,?)',(ident,'saved',saved))
    with brain.connect() as db:
        db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',
                   ('saved',packet,'fixture',saved,saved,'completed',json.dumps({'classification':'inconclusive','metadata':{'request_id':ident,'input_tokens':2981,'output_tokens':181}}),'',3.651241))
    return ident,packet


@pytest.mark.parametrize('offset,expected',[(0,3162),(.000001,3162),(2,3162),(-.000001,0),(-1,0)])
@pytest.mark.parametrize('fractional',[False,True])
def test_proxy_boundary_cohort_preserves_known_dispatch_and_counts_tokens_once(tmp_path,offset,expected,fractional):
    b=Brain(Store(tmp_path/'native'))
    saved=WINDOW+dt.timedelta(seconds=offset)
    saved_text=saved.isoformat(timespec='microseconds' if fractional else 'seconds')
    ident,_=seed(b,DISPATCH,saved_text)
    data=summary(b,at=AT)
    assert data['day_tokens']==0  # This is yesterday's completion, not today's.
    assert sum(v['tokens'] for v in data['bins'])==expected
    assert data['historical_completions']==0
    assert data['completion_time_unknown']==int(bool(expected))
    # Dispatch preceded the plotted range; completion inclusion adds no request.
    assert data['requests']==data['day_attempts']==0 and data['outcomes']=={}
    assert sum(v['requests'] for v in data['bins'])==0
    if expected:
        assert len(data['recent'])==1
        assert data['recent'][0]['started']==stamp(DISPATCH) and data['recent'][0]['finished'] is None
    with connect(b.store) as db:
        r=db.execute('SELECT * FROM requests WHERE id=?',(ident,)).fetchone()
        assert r['started']==stamp(DISPATCH) and r['finished'] is None


@pytest.mark.parametrize('offset,terminal',[(0,False),(-1,True),(1,False)])
def test_saved_proxy_end_is_exclusive_and_future_state_is_masked(tmp_path,offset,terminal):
    b=Brain(Store(tmp_path/'native'))
    ident,_=seed(b,AT-dt.timedelta(seconds=20),(AT+dt.timedelta(seconds=offset)).isoformat(timespec='seconds'))
    data=summary(b,at=AT)
    assert data['requests']==1 and data['historical_completions']==0
    assert data['completion_time_unknown']==int(terminal)
    assert data['day_tokens']==(3162 if terminal else 0)
    assert data['recent'][0]['state']==('accepted' if terminal else 'pending')
    assert (data['recent'][0]['first_seconds'] is not None)==terminal
    assert data['recent'][0]['finished'] is None
    later=summary(b,at=AT+dt.timedelta(seconds=2))
    assert later['day_tokens']==3162 and later['completion_time_unknown']==1


def test_before_and_after_old_dispatch_proxy_snapshot(tmp_path):
    b=Brain(Store(tmp_path/'native'));saved=WINDOW+dt.timedelta(seconds=2)
    seed(b,DISPATCH,saved.isoformat(timespec='seconds'))
    for instant,terminal in ((saved-dt.timedelta(microseconds=1),False),(saved,False),(saved+dt.timedelta(microseconds=1),True)):
        data=summary(b,at=instant)
        assert data['requests']==1  # This earlier snapshot includes the real dispatch.
        assert data['recent'][0]['state']==('accepted' if terminal else 'pending')
        assert data['day_tokens']==(3162 if terminal else 0)
        assert data['historical_completions']==0 and data['completion_time_unknown']==int(terminal)


def test_database_without_recovery_table_is_read_compatible_and_unmodified(tmp_path):
    b=Brain(Store(tmp_path/'native'))
    seed(b,AT-dt.timedelta(seconds=20),(AT-dt.timedelta(seconds=10)).isoformat(),recovery=False)
    with connect(b.store,True) as db:
        db.execute('DROP TRIGGER request_recovery_delete');db.execute('DROP TABLE request_recovery')
    with connect(b.store) as db:before=list(db.iterdump())
    data=summary(b,at=AT)
    assert not data['error'] and data['requests']==1 and data['completion_time_unknown']==0
    with connect(b.store) as db:
        assert list(db.iterdump())==before
        assert not db.execute("SELECT 1 FROM sqlite_master WHERE name='request_recovery'").fetchone()


class Rows(HTMLParser):
    def __init__(self):super().__init__();self.rows=[];self.row=None;self.cell=None
    def handle_starttag(self,tag,attrs):
        if tag=='tr':self.row=[]
        if tag=='td' and self.row is not None:self.cell=[]
    def handle_data(self,data):
        if self.cell is not None:self.cell.append(data)
    def handle_endtag(self,tag):
        if tag=='td' and self.cell is not None:
            self.row.append(' '.join(''.join(self.cell).split()));self.cell=None
        if tag=='tr' and self.row is not None:self.rows.append(self.row);self.row=None


@pytest.mark.parametrize('state',['accepted','rejected','failed','pending'])
def test_authenticated_recent_request_labels_terminal_unknown_times_truthfully(tmp_path,state):
    from app import create_app
    app=create_app({'database':str(tmp_path/'native'),'output':str(tmp_path/'out'),'providers_file':str(tmp_path/'keys'),'session_secret':'test-only','hosts':['localhost']})
    app.testing=True;b=Brain(app.store);now=dt.datetime.now(UTC)
    seed(b,now-dt.timedelta(seconds=20),(now-dt.timedelta(seconds=10)).isoformat(),state=state)
    client=app.test_client();assert client.get('/analytics',base_url='https://localhost').status_code==302
    with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('fixture','hash',1))
    with client.session_transaction() as s:s.update(user='fixture',version=1,expires_at=time.time()+3600,csrf='test-only')
    response=client.get('/analytics',base_url='https://localhost');assert response.status_code==200
    parsed=Rows();parsed.feed(response.get_data(as_text=True))
    row=next(r for r in parsed.rows if len(r)==6 and r[2]==state and r[-1]=='Saved packet')
    assert row[1]==('Pending / interrupted' if state=='pending' else 'Time unknown')
