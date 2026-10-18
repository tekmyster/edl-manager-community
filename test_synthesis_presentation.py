"""Regression boundaries for compact summaries and known request identity."""
import copy,itertools,json,re
import pytest
from behavior_synthesis import offers,decode,render,clusters,project,presentation
from behavior_generation import example,decode as generation_decode
from behavior_ai import validate_result
from test_observable_synthesis import event,packet,choose


def stress_packet():
 p=packet();p['packet_id']='bounded-summary'
 for i in range(8):p['events'].append(event('nav'+str(i),seen='2026-10-18T12:00:0'+str(i)+'+00:00',method='GET',path='/'+'a'*60+str(i),status=404,client_claim={'label':'Example client'}))
 from behavior_synthesis import DISCOVERY
 for i in range(8):p['events'].append(event('d'+str(i),seen='2026-10-19T12:00:0'+str(i)+'+00:00',method='GET',path=sorted(DISCOVERY)[i%len(DISCOVERY)],status=404,client_claim={'label':'Example client'}))
 return p


def test_supervisor_three_legal_group_boundary_is_valid_compact_and_keeps_every_selected_tuple():
 p=stress_packet();table=offers(p);assert len(table)==3;wire=example(p);wire['observable_synthesis']={k:v['interpretations'][-1] for k,v in table.items()};value=generation_decode(wire,p,[],{});validate_result(value,p,[],{})
 assert len(value['observable_synthesis'])==3 and len(value['analysis_summary'])<=700
 assert all(e['id'] not in value['analysis_summary'] for e in p['events']) and '+00:00' not in value['analysis_summary']
 display=presentation(value,p['events']);assert len(display['details'])==3
 for stored,detail in zip(value['observable_synthesis'],display['details']):
  assert len(detail['rows'])==len(stored['source_tuples'])
  assert [{k:v for k,v in row.items() if k!='number'} for row in detail['rows']]==stored['source_tuples']


@pytest.mark.parametrize('kind,action,extra',[('http','request',{'method':'GET','path':'/.env','status':404}),('auth','cowrie.login.failed',{}),('deny','drop',{'port':'22'})])
def test_known_upstream_identity_crossing_second_is_one_group_and_distinct_ids_remain_distinct(kind,action,extra):
 a=event('a',action,seen='2026-10-18T12:00:00.999+00:00',provenance={'detail':'sample','upstream_id':'same-request'},**extra);b=event('b',action,seen='2026-10-18T12:00:01.001+00:00',provenance={'detail':'sample','upstream_id':'same-request'},**extra)
 assert len(clusters([project(a),project(b)],kind))==1
 b['provenance']['upstream_id']='distinct-request';b['seen']=a['seen'];assert len(clusters([project(a),project(b)],kind))==2


def test_supervisor_same_known_request_does_not_offer_repeated_probe_even_across_rounding_boundary():
 p=packet(event('a',seen='2026-10-18T12:00:00.999+00:00',method='GET',path='/.env',status=404,provenance={'detail':'sample','upstream_id':'same-source-request-id'}),event('b',seen='2026-10-18T12:00:01.001+00:00',method='GET',path='/.env',status=404,provenance={'detail':'sample','upstream_id':'same-source-request-id'}))
 assert all('repeated_sensitive_path_probe' not in v['interpretations'] for v in offers(p).values())
 p['events'][1]['sensor']='mirrored';assert len(clusters([project(e) for e in p['events']],'http'))==1
 assert all('repeated_sensitive_path_probe' not in v['interpretations'] for v in offers(p).values())
 p['events'][1]['provenance']['upstream_id']='different-request';p['events'][1]['seen']=p['events'][0]['seen'];assert any('repeated_sensitive_path_probe' in v['interpretations'] for v in offers(p).values())


def test_unknown_request_identity_rounding_boundary_is_not_independent_repeat_evidence():
 p=packet(event('a',seen='2026-10-18T12:00:00.999+00:00',method='GET',path='/.env',status=404),event('b',seen='2026-10-18T12:00:01.001+00:00',method='GET',path='/.env',status=404))
 assert len(clusters([project(e) for e in p['events']],'http'))==2
 assert all('repeated_sensitive_path_probe' not in v['interpretations'] for v in offers(p).values())


def test_request_identity_reused_for_an_update_does_not_create_multiday_client_or_denial_recurrence():
 p=packet(event('a','drop',port='22',client_claim={'label':'Example client'},provenance={'detail':'sample','upstream_id':'same'}),event('b','drop',seen='2026-10-19T12:00:00+00:00',port='22',client_claim={'label':'Example client'},provenance={'detail':'sample','upstream_id':'same'}))
 assert not any(v['kind'] in ('client_recurrence','denied_recurrence') for v in offers(p).values())


def test_conflicting_representations_keep_all_individual_source_statuses_and_destination_scope():
 a=event('a',method='GET',path='/.env',status=404,provenance={'detail':'sample','upstream_id':'same'});b=copy.deepcopy(a);b.update(id='b',status=200,seen='2026-10-18T12:00:01+00:00');p=packet(a,b);items=decode(choose(p,'resource_discovery'),p);detail=presentation({'classification':'inconclusive','observable_synthesis':items},p['events'])['details'][0]
 assert {r['status'] for r in detail['rows']}=={'404','200'} and 'HTTP 404' in detail['account'] and 'HTTP 200' in detail['account']
 b['destination']={'scope':'public','address':'8.8.8.8'};a['destination']={'scope':'public','address':'1.1.1.1'};assert len(clusters([project(a),project(b)],'http'))==2


def test_legacy_without_structured_synthesis_is_unchanged_and_presentation_is_read_only():
 original={'classification':'inconclusive','analysis_summary':'Original saved text'};before=copy.deepcopy(original);assert presentation(original,[]) is None and original==before
 p=stress_packet();wire=example(p);wire['observable_synthesis']={k:v['interpretations'][-1] for k,v in offers(p).items()};value=generation_decode(wire,p,[],{});before=copy.deepcopy(value);presentation(value,p['events']);assert value==before


def test_disclosure_renders_all_bound_rows_readable_citations_and_escapes_source_text():
 from flask import Flask,render_template
 from html.parser import HTMLParser
 from pathlib import Path
 repo=Path(__file__).parent
 app=Flask(__name__,template_folder=str(repo/'templates'))
 app.jinja_env.filters['behavior_source']=lambda x:x
 p=stress_packet()
 wire=example(p);wire['observable_synthesis']={k:v['interpretations'][-1] for k,v in offers(p).items()}
 value=generation_decode(wire,p,[],{});display=presentation(value,p['events'])
 display['details'][0]['rows'][0]['client_label']='<script>alert(1)</script>'
 with app.test_request_context():html=render_template('behavior_synthesis.html',synthesis=display,citation_prefix='case-current-')
 class Elements(HTMLParser):
  def __init__(self):super().__init__();self.elements=[]
  def handle_starttag(self,tag,attrs):self.elements.append((tag,dict(attrs)))
 parsed=Elements();parsed.feed(html)
 details=next(a for tag,a in parsed.elements if a.get('class')=='behavior-synthesis-details')
 assert 'open' not in details
 links=[a for tag,a in parsed.elements if tag=='a' and 'data-behavior-citation' in a]
 assert len(links)==sum(len(x['source_tuples']) for x in value['observable_synthesis'])
 assert all(a['aria-label'].startswith('Open saved observation ') and a['href'].startswith('#case-current-') for a in links)
 assert all(e['seen'] in html for group in value['observable_synthesis'] for e in group['source_tuples'])
 assert '<script>alert(1)</script>' not in html and '&lt;script&gt;alert(1)&lt;/script&gt;' in html
 assert all(a['tabindex']=='0' for tag,a in parsed.elements if a.get('role')=='region')
