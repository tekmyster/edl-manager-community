"""Neutral history mechanics through original runtime constructors, not model quality."""
import copy,json
import pytest
import behavior_ai as ai,behavior_generation as gen,behavior_revision as rev,behavior_grounding as gr
import behavior_tokens as tokens,behavior_synthesis as sy,behavior_representation as rep
from behavior_pipeline import Pipeline
from test_pipeline_support import SyntheticCounter,choices
from test_observable_synthesis import event,packet


def build(monkeypatch,path='/manual',oldpath='/manual',oldtime='2026-05-03T02:01:00+00:00'):
 monkeypatch.setattr(tokens,'load',lambda cfg:SyntheticCounter())
 p=packet(event('current',seen='2026-08-19T16:10:00+00:00',method='HEAD',path=path,status=204,source='Nacre',sensor='edge'))
 old=event('earlier',seen=oldtime,method='HEAD',path=oldpath,status=404,source='Kestrel',sensor='archive',parameter_names=['cursor'],provenance={'collector':'retained source','time_basis':'native event','detail':'sample'})
 c=[{'candidate_id':'prior-window','current_events':copy.deepcopy(p['events']),'historical_events':[old],'similarity':.991}]
 before=copy.deepcopy((p,c));plan=Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},p,c,{})
 return p,c,before,plan


@pytest.mark.parametrize('path,oldpath',[('/manual','/manual'),('/manual','/unrelated'),('/','/'),('/robots.txt','/robots.txt')])
@pytest.mark.parametrize('oldtime',['2026-05-03T02:01:00+00:00','2025-01-01T23:59:59+00:00'])
def test_neutral_history_survives_operator_abstention_independent_of_overlap(monkeypatch,path,oldpath,oldtime):
 p,c,before,plan=build(monkeypatch,path,oldpath,oldtime);tables,_=gen.offers(p,c,{});key=next(iter(tables['history']))
 raw=choices(plan.request,groups='selected');raw['historical_observations']={key:'detail'}
 can=plan.decode(raw);assert can['actor_correlation']==[] and can['classification']=='inconclusive'
 fact=tables['history'][key];assert fact in can['historical_observations'] and fact['evidence_ids']==['earlier']
 assert all(v in fact['summary'] for v in (oldtime,'HEAD',oldpath,'404','Kestrel','archive','retained source','native event','NAT','proxies','address reassignment','cursor'))
 assert '16:10:00' not in fact['summary'] and '0.991' not in fact['summary']
 ai.validate_result(can,p,c,{})
 final=plan._revision('SYNTHETIC-HISTORY',json.dumps(raw),can,sy.presentation(can,p['events']))
 logical=rep.expand(json.loads(final.request['messages'][1]['content']));shown=logical['provisional_answer']['rendered']
 assert fact in shown['historical_observations'] and rev.restore_facts(logical['offered']['history'],shown)==tables['history']
 assert logical['candidates'][0]['historical_events']==c[0]['historical_events']
 wire=choices(final.request);wire['historical_observations']={key:'detail'};out=final.decode(wire)
 assert out.get('historical_observations')==[fact] and out['actor_correlation']==[]
 assert (p,c)==before
 for form in ({},{key:'omit'}):
  wire['historical_observations']=form;assert not final.decode(wire).get('historical_observations')
 del wire['historical_observations'];assert not final.decode(wire).get('historical_observations')
 assert plan.request['options']==final.request['options']=={'temperature':0,'num_predict':1800,'num_ctx':8192}


def test_history_does_not_supply_verdict_support_or_opposing_context(monkeypatch):
 p,c,_,plan=build(monkeypatch);wire=choices(plan.request);key=next(iter(gen.offers(p,c,{})[0]['history']))
 wire['historical_observations']={key:'detail'};can=plan.decode(wire)
 for field,change in [('classification','malicious'),('classification','benign')]:
  bad=copy.deepcopy(can);bad[field]=change
  with pytest.raises(ValueError):ai.validate_result(bad,p,c,{})
 bad=copy.deepcopy(can);bad['contradictory_evidence']=bad['historical_observations'];bad['historical_observations']=[]
 with pytest.raises(ValueError):ai.validate_result(bad,p,c,{})
 for mutate in (lambda v:v['historical_observations'][0].update(summary='Same operator returned'),lambda v:v['historical_observations'][0].update(evidence_ids=['current']),lambda v:v['historical_observations'].append(copy.deepcopy(v['historical_observations'][0]))):
  bad=copy.deepcopy(can);mutate(bad)
  with pytest.raises(ValueError):ai.validate_result(bad,p,c,{})
 for value in ({'foreign':'detail'},{key:'support'},{key:'counterevidence'},[key]):
  wire['historical_observations']=value
  with pytest.raises(ValueError):plan.decode(wire)


def test_original_relationship_and_current_choices_still_independent(monkeypatch):
 p,c,_,plan=build(monkeypatch);tables,_=gen.offers(p,c,{})
 assert tables['relations']
 w=choices(plan.request);r=next(iter(tables['relations']));w['actor_correlation']=[{'choice_id':r,'confidence':0}]
 out=plan.decode(w);assert out['actor_correlation'] and not out['findings']
 w['historical_observations']={k:'detail' for k in tables['history']};assert plan.decode(w)['actor_correlation']==out['actor_correlation']
 w['actor_correlation']=[];assert plan.decode(w)['actor_correlation']==[]
 old=gen.offers(p,[],{})[0]
 for kind in ('facts','counterevidence','attack','d3fend','automation','intent'):assert tables[kind]==old[kind]


def test_neutral_history_uses_owned_durable_draft_two_charges_one_publication_and_cache(tmp_path,monkeypatch):
 from behavior_pipeline_job import run
 from behavior_pipeline import request_digest
 from test_pipeline_support import setup,close,Reply
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(tokens,'load',lambda cfg:SyntheticCounter())
 s,b,cfg,packets=setup(tmp_path/'history-runtime');p=packets[0]
 old=event('old-neutral',seen='2026-04-01T04:03:02+00:00',method='HEAD',path='/reference',status=404,source='Kestrel',sensor='archive',provenance={'collector':'retained','time_basis':'native event','detail':'sample'})
 c=[{'candidate_id':'prior-window','current_events':copy.deepcopy(p['events'][:1]),'historical_events':[old]}];calls=[]
 def send(url,**kw):
  request=kw['json'];calls.append(copy.deepcopy(request));w=choices(request,groups='selected')
  w['historical_observations']={k:'detail' for k in request['format']['properties']['historical_observations']['properties']}
  return Reply(request,w)
 def rows(table):
  with b.connect() as db:return [dict(x) for x in db.execute('SELECT * FROM '+table)]
 try:
  status=run(b,p['packet_id'],p,set(),cfg,candidates=c,requester=send)
  assert status=='completed' and status.request_units==len(calls)==2
  assert sum(x['requests'] for x in rows('usage'))==2 and rows('pipeline_reservations')[0]['held']==0
  assert [x['state'] for x in rows('pipeline_stages')]==['accepted','accepted'] and len(rows('assessments'))==1
  draft=rows('pipeline_drafts')[0];receipt=json.loads(draft['receipt']);can=json.loads(draft['canonical'])
  assert receipt['draft_canonical_sha256']==request_digest(can) and any('old-neutral' in x['evidence_ids'] for x in can['historical_observations'])
  assert json.loads(draft['revision_request'])==calls[1]
  saved=json.loads(rows('assessments')[0]['result']);assert saved['actor_correlation']==[]
  assert any('2026-04-01T04:03:02' in x['summary'] and '/reference' in x['summary'] for x in saved['historical_observations'])
  assert run(b,p['packet_id'],p,set(),cfg,candidates=c,requester=send)=='cached' and len(calls)==2
 finally:close(s)


def test_history_citations_cannot_change_pilot_points_even_with_current_id_overlap():
 import datetime as dt
 from behavior_scoring import contribution
 at=dt.datetime(2026,8,19,16,10,tzinfo=dt.timezone.utc)
 p=packet(*[event('overlap-'+str(i),seen=at.isoformat(),method='GET',path='/'+str(i),port='443',independent_evidence=True) for i in range(2)])
 a={'classification':'malicious','maliciousness_confidence':1,'contradictory_evidence':[],'findings':[]}
 row={'score':0,'evidence':[]};expires=(at+dt.timedelta(hours=1)).isoformat()
 assert contribution(p,a,row,expires,at)==0
 a['historical_observations']=[{'summary':'Neutral old source','evidence_ids':[e['id']]} for e in p['events']]
 assert contribution(p,a,row,expires,at)==0
 a['findings']=[{'summary':'Original current source','evidence_ids':[e['id']]} for e in p['events']]
 expected=contribution(p,a,row,expires,at);assert expected==10
 a.pop('historical_observations');assert contribution(p,a,row,expires,at)==expected


def test_existing_evidence_panel_and_frozen_feedback_retain_neutral_history(monkeypatch):
 from pathlib import Path
 from jinja2 import Environment,FileSystemLoader,select_autoescape
 from behavior_feedback import observations
 p,c,_,plan=build(monkeypatch);w=choices(plan.request);w['historical_observations']={k:'detail' for k in gen.offers(p,c,{})[0]['history']};can=plan.decode(w)
 env=Environment(loader=FileSystemLoader(Path(__file__).parent/'templates'),autoescape=select_autoescape(['html']))
 template=env.get_template('behavior_historical_observations.html');html=template.render(history_assessment=can)
 assert all(v in html for v in ('Historical observations','2026-05-03T02:01:00','/manual','404','Kestrel','retained source','native event','earlier'))
 assert 'historical_observations' not in html and 'draft_binding' not in html
 snapshot={'assessment':can,'packet':p,'comparisons':[{'details':c[0]}]}
 assert observations(snapshot)==c[0]['historical_events']
 bad=copy.deepcopy(can);bad['historical_observations'][0]['summary']='<script>untrusted</script>'
 assert '<script>' not in template.render(history_assessment=bad)
 assert template.render(history_assessment={'findings':[]}).strip()==''
