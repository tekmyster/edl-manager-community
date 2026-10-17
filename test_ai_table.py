"""Optional read-only AI columns preserve table/account/native contracts."""
import datetime as dt
import json
import sqlite3
from pathlib import Path
import pytest
from werkzeug.datastructures import MultiDict
from behavior_ai import Brain,DEFAULTS,config_id
from ai_table import decorate,FIELDS
from table_layout import layout,DEFAULT,ALL
from test_ui_settings import ui

UTC=dt.timezone.utc


def seed(store):
    cfg={**DEFAULTS,'enabled':True,'model_enabled':True,'model':'fixture','scoring_enabled':False}
    store.state('behavior_settings',cfg);brain=Brain(store);at=dt.datetime.now(UTC)
    for i,(address,status,classification,age) in enumerate([('8.8.8.8','completed','benign',1),('9.9.9.9','failed','malicious',1),('1.1.1.1','completed','malicious',-1),('4.2.2.1',None,None,1)]):
        store.evidence(address,'waf','Fixture',at.isoformat(),'http',50)
        ident,packet,_=brain.packet(store.describe(address))
        if status:
            with brain.connect() as db:db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',(str(i),ident,config_id(cfg)+'-fixture',at.isoformat(),(at+dt.timedelta(hours=age)).isoformat(),status,json.dumps({'classification':classification,'maliciousness_confidence':1}),'invalid_assessment' if status=='failed' else '',1))
    return brain


def dump(database):
    with database.connect() as db:return list(db.iterdump())


def test_labels_current_config_expiry_and_actual_contribution_without_native_writes(ui):
    app,_,_=ui;brain=seed(app.store);native,before=dump(app.store),dump(brain)
    rows=[{'ip':'8.8.8.8','ai_bump':2.25},{'ip':'9.9.9.9'},{'ip':'1.1.1.1'},{'ip':'4.2.2.1'},{'ip':'5.5.5.5'},{'ip':'6.6.6.6','history_only':True}]
    saved=decorate(app.store,rows,set(FIELDS))
    assert [v['ai_assessment_status'] for v in saved]==['accepted','rejected','expired','pending','not_indexed','not_indexed']
    assert saved[0]['ai_contribution_value']==2.25 and saved[0]['ai_assessment']=='Accepted model output · benign'
    assert saved[2]['ai_contribution_value']==0  # model confidence1/malicious does not invent points
    assert 'malicious' not in saved[1]['ai_assessment']
    assert saved[-1]['ai_contribution_value'] is None
    assert saved[0]['ai_coverage'].startswith('Saved samples · ')
    assert 'accuracy' not in saved[0]['ai_search']
    assert dump(app.store)==native and dump(brain)==before
    # A foreign model configuration is never presented as the current assessment.
    cfg=app.store.state('behavior_settings');cfg['model']='other';app.store.state('behavior_settings',cfg)
    assert decorate(app.store,rows[:1],set(FIELDS))[0]['ai_assessment_status']=='pending'


def test_unavailable_database_and_unindexed_never_invent_coverage(ui,monkeypatch):
    app,_,_=ui
    path=Path(app.store.path).parent/'behavior.sqlite3'
    # No read-model call creates/initializes a missing behavior database.
    if path.exists():path.unlink()
    value=decorate(app.store,[{'ip':'8.8.8.8'}],set(FIELDS))[0]
    assert value['ai_assessment_status']=='model_off' and value['ai_coverage']=='Not indexed'
    assert not path.exists()
    seed(app.store)
    original=sqlite3.connect
    def denied(*a,**kw):
        if 'behavior.sqlite3' in str(a[0]):raise sqlite3.OperationalError('isolated fixture')
        return original(*a,**kw)
    with monkeypatch.context() as patch:
        patch.setattr('ai_table.sqlite3.connect',denied)
        assert decorate(app.store,[{'ip':'8.8.8.8'}],set(FIELDS))[0]['ai_assessment_status']=='unavailable'


def test_optional_layout_defaults_legacy_order_and_account_roundtrip_filters_paging(ui):
    app,c,_=ui;seed(app.store)
    order,visible=layout({},dict.fromkeys(ALL))
    assert order==list(ALL) and visible==set(DEFAULT)
    _,visible=layout({'order':['ip','policy'],'visible':['ip','policy']},dict.fromkeys(ALL))
    assert not visible.intersection(FIELDS)
    html=c.get('/',base_url='https://localhost').text
    assert 'name="f_ai_assessment"' not in html
    sequence=['ip','ai_coverage','policy','ai_assessment','ai_contribution']
    data=MultiDict([('csrf','csrf'),('return_query','sort=ai_assessment&f_ai_assessment=accepted')]+[('column_order',v) for v in sequence]+[('visible_columns',v) for v in sequence])
    reply=c.post('/settings/columns',data=data,base_url='https://localhost');assert reply.status_code==302
    html=c.get(reply.location,base_url='https://localhost').text
    table=html.split('id="ip-evidence"')[1].split('<table>')[1]
    assert table.index('AI evidence coverage')<table.index('Policy')<table.index('AI assessment')<table.index('AI contribution')
    assert '1–1 of 1 matches' in html and 'Accepted model output' in html
    assert '/behavior/observations/' in table
    assert '1–1 of 1 matches' in c.get('/?q=benign',base_url='https://localhost').text
    assert '1–1 of 1 matches' in c.get('/?f_ai_assessment=rejected',base_url='https://localhost').text
    assert '4 matches' in c.get('/?f_ai_contribution=none&f_ai_coverage=sampled',base_url='https://localhost').text
    # Search follows the selected fields; hidden AI filters/sorts are discarded.
    data=MultiDict([('csrf','csrf'),('column_order','ip'),('visible_columns','ip')])
    c.post('/settings/columns',data=data,base_url='https://localhost')
    html=c.get('/?f_ai_assessment=rejected&sort=ai_assessment',base_url='https://localhost').text
    assert '4 matches' in html and 'name="f_ai_assessment"' not in html
    assert app.store.state('user_preferences:admin')['ip_columns']['visible']==['ip']
    other=app.test_client()
    with app.store.connect() as db:db.execute('INSERT INTO users VALUES(?,?,?)',('other','hash',1))
    with other.session_transaction() as session:session.update(user='other',version=1,expires_at=dt.datetime.now(UTC).timestamp()+3600,csrf='csrf')
    assert 'name="f_ai_coverage"' not in other.get('/',base_url='https://localhost').text
    c.post('/settings/columns',data={'csrf':'csrf','restore':'1'},base_url='https://localhost')
    assert 'name="f_ai_assessment"' not in c.get('/',base_url='https://localhost').text
    assert c.post('/settings/columns',data={'csrf':'csrf','column_order':'ai_injected'},base_url='https://localhost').status_code==400
def test_ai_filters_sort_and_paging_operate_on_complete_result_before_page(ui):
    app,c,_=ui
    app.store.state('behavior_settings',{**DEFAULTS,'enabled':True,'model_enabled':True,'model':'fixture'})
    for i in range(1,31):app.store.evidence('6.6.6.'+str(i),'waf','Fixture',dt.datetime.now(UTC).isoformat(),'http',50)
    data=MultiDict([('csrf','csrf')]+[('column_order',k) for k in ['ip',*FIELDS]]+[('visible_columns',k) for k in ['ip',*FIELDS]])
    assert c.post('/settings/columns',data=data,base_url='https://localhost').status_code==302
    html=c.get('/?f_ai_assessment=not_indexed&size=25&page=2&sort=ai_contribution',base_url='https://localhost').text
    assert '26–30 of 30 matches' in html and html.count('data-select-ip=')==5
    assert 'f_ai_assessment=not_indexed' in html and 'aria-label="IP evidence table"' in html
    assert 'No addresses match these filters.' in c.get('/?f_ai_assessment=accepted',base_url='https://localhost').text
