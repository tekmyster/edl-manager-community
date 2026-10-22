"""Literal optional report replacements, not selection or truth enforcement."""
import copy,json,itertools
import pytest
import behavior_generation as gen,behavior_synthesis as sy,behavior_revision as rev,behavior_representation as rep,behavior_ai as ai,behavior_tokens
from test_observable_synthesis import event,packet
from test_pipeline_support import SyntheticCounter,choices
from behavior_pipeline import Pipeline


def reports():
 return packet(event('policy-a','policy-denied:[identifier]',source='edge',sensor='policy',seen='2026-08-01T03:04:05+00:00',provenance={'detail':'summary'}),
 event('policy-b','policy-denied:[identifier]',source='edge',sensor='policy',seen='2026-08-01T03:04:08+00:00',provenance={'detail':'summary'}),
 event('rule-a','Monitor rule 782',source='monitor',sensor='rule:782',seen='2026-08-01T03:04:08.001+00:00',provenance={'detail':'summary'}),
 event('handshake','protocol.client.exchange',source='tpot',sensor='Protocol',seen='2026-08-01T03:04:08.002+00:00'))


def test_summary_reports_and_unfamiliar_handshake_have_literal_optional_account():
 p=reports();before=copy.deepcopy(p);groups=sy.offers(p)
 chosen={k:'reported_source_occurrences' for k in groups};items=sy.decode(chosen,p)
 value=gen.example(p);value['observable_synthesis']=chosen;value['observations']={};can=gen.decode(value,p,[],{})
 detail=sy.presentation(can,p['events'])['details'][0]
 assert detail['rows']==[dict(sy.project_report(e),number=i+1) for i,e in enumerate(p['events'])]
 for row in detail['rows']:assert row['seen'] in detail['account'] and row['action'] in detail['account']
 assert 'policy-denied:[identifier]' in detail['account'] and 'Monitor rule 782' in detail['account']
 assert 'do not prove a shared session, independent events, attacks or current enforcement' in detail['uncertainty']
 assert p==before and not can['findings'] and can['classification']=='inconclusive'
 # Presence, empty metadata, one source or matching times does not imply truth.
 for e in p['events']:assert e['id'] in {r['event_id'] for g in items for r in g['source_tuples']}


def test_original_account_identity_rows_and_unknown_choices_are_preserved():
 from test_source_occurrence_accounts import sparse
 p=sparse();old=sy.offers(p);p['events'].extend(reports()['events']);new=sy.offers(p)
 assert all(new[k]==v for k,v in old.items() if set(v['evidence_ids'])=={'first','close-first','later','close-later'})
 empty=gen.example(p);empty['observations']={};empty['observable_synthesis']={k:'omit' for k in new}
 assert gen.decode(empty,p,[],{})['observable_synthesis']==[]
 label=next(k for k,v in gen.offers(p,[],{})[0]['facts'].items() if v['evidence_ids']==['label'])
 empty['observations']={label:'detail'};assert gen.decode(empty,p,[],{})['findings']


@pytest.mark.parametrize('times',[['2026-08-01T03:04:05+00:00'],['2026-08-01T03:04:05+00:00']*2])
def test_singleton_and_equal_time_rule_reports_assert_no_distinctness(times):
 p=packet(*(event(str(i),'Report rule 909',sensor='rule:909',seen=t,provenance={'detail':'summary'}) for i,t in enumerate(times)))
 w=gen.example(p);w['observations']={};w['observable_synthesis']={k:('reported_source_occurrences' if g['kind']=='source_occurrences' else 'omit') for k,g in sy.offers(p).items()};can=gen.decode(w,p,[],{});detail=sy.presentation(can,p['events'])['details'][0]
 assert len(detail['rows'])==len(times)
 assert not any(t in can['analysis_summary'].lower() for t in ('distinct','separate','repeated','sequence'))
 assert 'independent events' in detail['uncertainty']


def test_codec_preserves_exact_date_spelling_markers_and_old_payloads():
 literal={'text_parts':['not','joined']};value={'packet':{'events':[{'data':literal},{'data':{'text_literal':[['x',1]]}}]},'offered':{'facts':{}},'synthesis_options':{'g':{'reported_account':'~prefix 2026-08-01T03:04:05.000000+00:00 | 2026-08-01T03:04:05+00:00','kind':'test'}}}
 original=copy.deepcopy(value);packed=rep.factor_selection(value)
 assert packed['encoding']=='compact-string-2' and rep.expand(packed)==original and value==original
 old={'encoding':'compact-string-1','symbols':{},'input':{'data':literal}}
 assert rep.expand(old)=={'data':literal}
 with pytest.raises(ValueError):rep.expand({'encoding':'compact-string-2','symbols':{},'input':{'text_parts':[1]}})


def test_owned_draft_can_replace_reports_without_forcing_any_choice(monkeypatch):
 monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter());p=reports();plan=Pipeline({**ai.DEFAULTS,'model':'synthetic','tokenizer_sha256':'0'*64},p,[],{})
 draft=choices(plan.request,purpose='detail',groups='omit');can=plan.decode(draft);final=plan._revision('synthetic-report-parent',json.dumps(draft),can,sy.presentation(can,p['events']))
 logical=rep.expand(json.loads(final.request['messages'][1]['content']));shown=logical['provisional_answer']['rendered']
 assert rev.restore_facts(logical['offered']['facts'],shown)==gen.prepare(p,[],{})[1]['offered']['facts']
 assert rev.restore_accounts(logical['synthesis_options'],shown)==gen.prepare(p,[],{})[1]['synthesis_options']
 selected=choices(final.request,purpose=None,groups='selected');out=final.decode(selected);details=sy.presentation(out,p['events'])['details']
 for e in p['events']:assert any(e['action'] in d['account'] and sy.project_report(e)['seen'] in d['account'] for d in details)
 assert not out['findings']
 for comparison,purpose in itertools.product(rev.COMPARISONS,('omit','detail','support')):
  w=choices(final.request,groups='omit',purpose='detail');k=next(iter(w['observations']));w['observations']={k:{'comparison':comparison,'purpose':purpose}};result=final.decode(w)
  assert bool(result['findings'])==(purpose!='omit') and not result['observable_synthesis']


def test_new_report_accounts_traverse_durable_two_charge_publication(tmp_path,monkeypatch):
 import behavior_ai as ai
 from behavior_pipeline_job import run
 from test_pipeline_support import setup,close,Reply
 monkeypatch.setattr(ai,'local_endpoint',lambda _:None);monkeypatch.setattr(behavior_tokens,'load',lambda cfg:SyntheticCounter())
 store,brain,cfg,packets=setup(tmp_path/'reports.sqlite3');p=reports();p['packet_id']=packets[0]['packet_id'];calls=[]
 try:
  with brain.connect() as db:db.execute('UPDATE packets SET content=? WHERE id=?',(json.dumps(p),p['packet_id']))
  def send(url,**kw):calls.append(kw['json']);return Reply(kw['json'],choices(kw['json'],groups='selected'))
  result=run(brain,p['packet_id'],p,set(),cfg,requester=send)
  assert result=='completed' and len(calls)==result.request_units==2
  with brain.connect() as db:
   stages=[dict(r) for r in db.execute('SELECT * FROM pipeline_stages')];draft=dict(db.execute('SELECT * FROM pipeline_drafts').fetchone());final=dict(db.execute('SELECT * FROM pipeline_finals').fetchone());saved=[dict(r) for r in db.execute('SELECT * FROM assessments')]
   assert sum(r['requests'] for r in db.execute('SELECT * FROM usage'))==2 and sum(r['held'] for r in db.execute('SELECT * FROM pipeline_reservations'))==0
  assert [r['state'] for r in stages]==['accepted','accepted'] and len(saved)==1 and saved[0]['status']=='completed'
  assert json.loads(draft['revision_request'])==calls[1]
  details=sy.presentation(json.loads(final['canonical']),p['events'])['details']
  for e in p['events']:assert any(e['action'] in d['account'] and sy.project_report(e)['seen'] in d['account'] for d in details)
  assert run(brain,p['packet_id'],p,set(),cfg,requester=send)=='cached' and len(calls)==2
 finally:close(store)


def test_redacted_placeholder_alone_is_not_an_action_account():
 p=packet(event('placeholder','[identifier]',source='collector',sensor='[identifier]',provenance={'detail':'summary'}))
 assert not any(g['kind']=='source_occurrences' for g in sy.offers(p).values())
 assert any(g['kind']=='insufficient_detail' for g in sy.offers(p).values())
