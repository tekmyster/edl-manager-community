from test_ui_settings import ui
from core import now

def test_live_filter_integration_and_server_results(ui):
 app,c,cfg=ui
 app.store.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 app.store.add_rule('allow','9.9.9.9','Dependency',None,'admin')
 html=c.get('/',base_url='https://localhost').text
 assert 'live-filters.js' in html
 assert 'form="evidence-filters"' in html
 allowed=c.get('/?f_policy=Allowed&page=1',base_url='https://localhost').text.split('<tbody>')[1].split('</tbody>')[0]
 assert '/ip/9.9.9.9' in allowed and '/ip/8.8.8.8' not in allowed
 evaluating=c.get('/?f_policy=Evaluating&f_ip=8.8.8.8',base_url='https://localhost').text.split('<tbody>')[1].split('</tbody>')[0]
 assert '/ip/8.8.8.8' in evaluating and '/ip/9.9.9.9' not in evaluating
 assert c.get('/static/live-filters.js',base_url='https://localhost').status_code==200
