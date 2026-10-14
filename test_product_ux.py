from test_ui_settings import ui
from core import now

def test_consistent_policy_and_display_labels_keep_feed_contracts(ui):
 app,c,cfg=ui;s=app.store
 s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 s.add_rule('allow','8.8.8.8','Dependency',None,'admin')
 s.build(cfg['output'])
 html=c.get('/',base_url='https://localhost').text
 assert '/lists/combined-block.txt' in html and 'Combined blocks' in html
 assert 'rule.add' not in html and 'Rule added' in html
 assert '<details class="rule-editor">' in html and '<details class="bulk-editor">' in html
 detail=c.get('/ip/8.8.8.8',base_url='https://localhost').text
 assert 'policy-allowed' in detail and 'Review hold' not in detail
 for route in ['/','/ip/8.8.8.8','/settings']:
  html=c.get(route,base_url='https://localhost').text
  assert 'Skip to content' in html and '<main id="main-content" tabindex="-1">' in html and '<pre' not in html
 assert 'AbuseIPDB API key' in c.get('/settings',base_url='https://localhost').text
 modal=c.get('/results/policy?m_f_action=allow',base_url='https://localhost',headers={'X-EDL-Modal':'1'}).text
 assert '<option value="allow" selected>Whitelist</option>' in modal
 assert '/rules/' in modal and 'Disable' in modal
 assert '<h2>Policy overrides</h2>' not in modal

def test_ui_errors_are_actionable_preserve_status_and_hide_diagnostics(ui):
 app,c,cfg=ui
 bad=c.post('/rules',data={'value':'8.8.8.8'},base_url='https://localhost')
 assert bad.status_code==400 and 'Refresh the page' in bad.text and 'Invalid CSRF token' not in bad.text
 assert c.get('/missing',base_url='https://localhost').status_code==404
 assert 'Page not found' in c.get('/missing',base_url='https://localhost').text
 bad=c.post('/settings',data={'csrf':'csrf','session_timeout':'invalid'},base_url='https://localhost')
 assert bad.status_code==400 and 'System settings' in bad.text
