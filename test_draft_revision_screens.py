"""Authenticated fixture render checks; optional static export for pixel inspection."""
import os,pathlib,re,json
import pytest
import behavior_ai as ai,behavior_tokens
from behavior_pipeline_job import run
from test_pipeline_support import setup,close,SyntheticCounter,Reply,choices

@pytest.mark.parametrize('populated',[False,True])
def test_request_and_assessment_screens_do_not_expose_provisional_evidence(tmp_path,monkeypatch,populated):
 from test_ui_settings import ui
 app,client,config=ui.__wrapped__(tmp_path)
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 s,b,cfg,packets=setup(config['database'])
 try:
  if populated:
   status=run(b,packets[0]['packet_id'],packets[0],set(),cfg,requester=lambda u,**kw:Reply(kw['json'],choices(kw['json'])))
   assert status=='completed' and status.request_units==2
  for route,name in [('/behavior','settings'),('/behavior/metrics','metrics')]:
   response=client.get(route,base_url='https://localhost');assert response.status_code==200
   html=response.data.decode('utf-8','strict')
   assert all(value not in html for value in ('draft_binding','provisional_answer','draft_wire_sha256','input_binding','client_sources','Traceback','PRIVATE'))
   if name=='settings':assert 'reserves two requests' in html and 'one assessment timeout' in html
   if name=='metrics':assert 'Each assessment plans two requests' in html
   destination=os.environ.get('EDL_UI_EXPORT')
   if destination:
    # Same rendered HTML and CSS, no server and no network resource loading.
    # Scripts are omitted only in this inert pixel-inspection artifact.
    def stylesheet(match):
     css=pathlib.Path(app.static_folder)/match.group(1)
     return '<style>'+css.read_text()+'</style>'
    inert=re.sub(r'<link rel="stylesheet" href="/static/([^?\"]+)(?:\?[^\"]*)?">',stylesheet,html)
    inert=re.sub(r'<script\b[^>]*>.*?</script>','',inert,flags=re.S)
    target=pathlib.Path(destination);target.mkdir(exist_ok=True)
    edition=os.environ.get('EDL_UI_EDITION','fixture')
    (target/(edition+'-'+name+('-populated' if populated else '-empty')+'.html')).write_text(inert)
 finally:close(s);close(app.store)
