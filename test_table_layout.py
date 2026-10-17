import datetime as dt
from werkzeug.datastructures import MultiDict
from table_layout import policy_rows,layout,DEFAULT
from test_ui_settings import ui
from core import now

def test_policy_precedence_and_fresh_asn_rules(ui):
 app,c,cfg=ui;s=app.store
 for action,ip in [('block','8.8.8.8'),('allow','8.8.8.8'),('block','9.9.9.9')]:s.add_rule(action,ip,'Ticket',None,'admin')
 rows=[{'ip':'8.8.8.8','auto_candidate':True},{'ip':'9.9.9.9','auto_candidate':False,'verified_crawler':True},{'ip':'1.1.1.1','auto_candidate':False},{'ip':'4.2.2.1','auto_candidate':True}]
 r=policy_rows(s,rows,s.active_rules());assert [x['policy'] for x in r]==['Allowed','Allowed','Evaluating','Denied']
 s.add_rule('block','8.8.8.8','Emergency',None,'admin',True)
 assert policy_rows(s,rows,s.active_rules())[0]['policy']=='Denied'
 s.add_rule('block','AS123','ASN ticket',None,'admin')
 s.cache('1.1.1.1','asn',{'asn':'123','database_build_epoch':dt.datetime.now(dt.timezone.utc).timestamp()})
 assert policy_rows(s,rows,s.active_rules())[2]['policy']=='Denied'
 s.cache('1.1.1.1','asn',{'asn':'123','database_build_epoch':dt.datetime.now(dt.timezone.utc).timestamp()-31*86400})
 assert policy_rows(s,rows,s.active_rules())[2]['policy']=='Evaluating'

def test_layout_saved_per_account_and_hidden_sort_is_safe(ui):
 app,c,cfg=ui;s=app.store;s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 s.state('user_preferences:admin',{'session_timeout':3600,'timezone':'UTC'})
 payload=MultiDict([('csrf','csrf'),('column_order','last_seen'),('column_order','ip'),('column_order','policy'),('visible_columns','last_seen'),('visible_columns','policy')])
 assert c.post('/settings/columns',data=payload,base_url='https://localhost').status_code==302
 assert s.state('user_preferences:admin')['session_timeout']==3600 and s.state('user_preferences:admin')['timezone']=='UTC'
 html=c.get('/?sort=score&f_score=100',base_url='https://localhost').text
 table=html.split('id="ip-evidence"')[1].split('<table>')[1]
 assert table.index('IP address')<table.index('Last seen UTC')<table.index('Policy') and 'No addresses match' not in html
 assert 'name="f_score"' not in html and 'Active policy rules' not in html
 assert c.post('/settings/columns',data={'csrf':'csrf','column_order':'injected'},base_url='https://localhost').status_code==400
 assert c.post('/settings/columns',data={'column_order':'ip'},base_url='https://localhost').status_code==400
 fresh=app.test_client()
 with fresh.session_transaction() as session:session.update(user='admin',version=1,expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+3600,csrf='csrf')
 assert 'name="f_score"' not in fresh.get('/',base_url='https://localhost').text
 c.post('/settings/columns',data={'csrf':'csrf','restore':'1'},base_url='https://localhost')
 assert 'name="f_score"' in c.get('/',base_url='https://localhost').text
 assert layout({},dict.fromkeys(DEFAULT))[0]==list(DEFAULT)
 r=c.get('/results/policy',base_url='https://localhost');assert r.status_code==200
