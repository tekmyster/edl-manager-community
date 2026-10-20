"""Prompt-only factual-coverage experiment; mocked outputs do not measure utility."""
import copy
import behavior_ai as ai
import behavior_generation as gen
from behavior_synthesis import offers, render
from test_source_observations import linked_packet
from test_generation_choices import transport


def empty_wire(packet):
 wire=gen.example(packet)
 wire['observations']={key:'omit' for key in wire['observations']}
 return wire


def test_neutral_preference_keeps_all_omit_unknown_and_inconclusive_valid():
 packet=linked_packet();wire=empty_wire(packet)
 (result,metadata),requests=transport(packet,wire)
 assert result['observable_synthesis']==result['findings']==result['actor_correlation']==[]
 assert result['classification']=='inconclusive'
 assert result['automation']==result['intent']=={'classification':'unknown','confidence':0}
 ai.validate_result(result,packet,[],{})
 assert metadata['prompt_version']=='behavior-3.23'
 assert metadata['generation_schema_version']==gen.VERSION=='grounded-groups-9'
 assert requests[0]['messages'][0]['content']==gen.INSTRUCTION


def test_neutral_session_account_needs_no_intent_verdict_or_support_pair():
 packet=linked_packet();before=copy.deepcopy(packet);wire=empty_wire(packet)
 group=next(key for key,value in offers(packet).items() if value['kind']=='session_sequence')
 wire['observable_synthesis'][group]='reported_session_sequence'
 (result,_),_=transport(packet,wire)
 assert packet==before and result['findings']==[]
 assert result['classification']=='inconclusive' and result['intent']==result['automation']=={'classification':'unknown','confidence':0}
 assert result['observable_synthesis'][0]['evidence_ids']==[e['id'] for e in packet['events']]
 assert 'execution' in render(result['observable_synthesis'],packet)
 ai.validate_result(result,packet,[],{})


def test_prompt_only_version_gets_fresh_job_preserves_old_assessment(tmp_path,monkeypatch):
 from core import Store,now
 from test_behavior_ai import result
 store=Store(tmp_path/'native')
 store.evidence('8.8.8.8','tpot','fixture',now(),'ssh',50)
 brain=ai.Brain(store);ident,packet,features=brain.packet(store.describe('8.8.8.8'))
 native_before=store.describe('8.8.8.8');calls=[]
 def fake(*args):
  calls.append(ai.PROMPT_VERSION)
  return result(packet),{'prompt_version':ai.PROMPT_VERSION,'generation_schema_version':ai.GENERATION_SCHEMA_VERSION}
 monkeypatch.setattr(ai,'infer',fake)
 cfg={**ai.DEFAULTS,'model_enabled':True,'daily_budget':None}
 monkeypatch.setattr(ai,'PROMPT_VERSION','behavior-3.21')
 assert ai.model_job(brain,ident,packet,features,cfg,candidates=[])=='completed'
 with brain.connect() as db:
  old=tuple(db.execute('SELECT * FROM assessments').fetchone())
 monkeypatch.setattr(ai,'PROMPT_VERSION','behavior-3.23')
 assert ai.GENERATION_SCHEMA_VERSION=='grounded-groups-9'
 assert ai.model_job(brain,ident,packet,features,cfg,candidates=[])=='completed'
 assert ai.model_job(brain,ident,packet,features,cfg,candidates=[])=='cached'
 with brain.connect() as db:
  rows=[tuple(row) for row in db.execute('SELECT * FROM assessments')]
 assert old in rows and len(rows)==2 and calls==['behavior-3.21','behavior-3.23']
 assert len({row[2] for row in rows})==2
 native_after=store.describe('8.8.8.8')
 assert native_before['score']==native_after['score'] and native_before['retention']==native_after['retention']
