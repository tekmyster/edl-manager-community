import re
from test_ui_settings import ui

def test_help_and_context_links_are_authenticated_and_complete(ui):
 app,c,cfg=ui
 html=c.get('/help',base_url='https://localhost').text
 assert 'Community Edition' in html and '10.99.' not in html and '<script>' not in html
 anchors=set(re.findall(r'id="([^"]+)"',html))
 for route in ['/','/settings']:
  page=c.get(route,base_url='https://localhost').text
  assert set(re.findall(r'href="/help#([^"]+)"',page))<=anchors
 assert app.test_client().get('/help',base_url='https://localhost').status_code==302
