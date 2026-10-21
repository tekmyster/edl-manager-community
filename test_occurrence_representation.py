"""Input joins and reversible encoding are mechanics, never a quality oracle."""
import copy,json
import pytest
import behavior_generation as gen
import behavior_representation as rep
import behavior_revision as rev
import behavior_synthesis as sy
from test_source_observations import linked_packet

def test_lossless_compact_codec_retains_literals_types_and_separate_keys():
 statement='The same fixed statement remains a separate offered occurrence.'
 value={'offered':{'facts':{'a':{'summary':statement,'evidence_ids':['first-occurrence-id-1234567890'],'missing':None},'b':{'summary':statement,'evidence_ids':['later-occurrence-id-1234567890'],'different':[]}}},
 'source':{'symbol_ref':'literal-marker','object_literal':[['x',None]],'strings':['~0','~~0','~s0','~~','~not-a-ref','',statement]},'ids':['first-occurrence-id-1234567890','later-occurrence-id-1234567890']}
 before=copy.deepcopy(value);encoded=rep.factor_selection(value)
 assert rep.expand(json.loads(json.dumps(encoded)))==value==before
 assert encoded['input']['offered']['facts']['a'][1]==statement
 assert encoded['input']['offered']['facts']['b'][1]==statement
 assert encoded['input']['offered']['facts']['a']!=encoded['input']['offered']['facts']['b']
 assert statement not in encoded['symbols'].values()

@pytest.mark.parametrize('bad',[[-1,'value'],[True,'value'],[1,'value'],[0],None])
def test_invalid_fact_shapes_fail_closed(bad):
 v=rep.factor_selection({'offered':{'facts':{'a':{'summary':'value'}}}})
 v['input']['offered']['facts']['a']=bad
 with pytest.raises(ValueError):rep.expand(v)

def test_unknown_compact_reference_rejected_and_old_codec_preserved():
 v=rep.factor_selection({'a':'~s999'});assert rep.expand(v)=={'a':'~s999'}
 v['input']['a']='~s999'
 with pytest.raises(ValueError):rep.expand(v)
 original={'symbol_ref':'literal','v':['repeated long string of source evidence']*2}
 assert rep.expand(rep.factor(original))==original

def test_occurrence_join_does_not_extend_a_selected_account():
 packet=linked_packet();later=copy.deepcopy(packet['events'][0]);later.update(id='later-connection',seen='2026-10-17T10:05:00+00:00')
 packet['events'].append(later);tables,_=gen.offers(packet,[],{});facts=gen.annotated_facts(packet,tables)
 key=next(k for k,v in facts.items() if v['evidence_ids']==['later-connection'])
 assert facts[key]['occurrences']==[[later['seen'],[]]]
 for f in facts.values():
  assert f['allowed_roles']==['omit','detail','support']
  assert len(f['occurrences'])==len(f['evidence_ids'])
  for ident,(seen,rows) in zip(f['evidence_ids'],f['occurrences']):
   event=next(e for e in packet['events'] if e['id']==ident)
   assert event['seen']==seen
   for g,r in rows:assert list(sy.offers(packet).values())[g]['source_tuples'][r]['event_id']==ident
 wire=gen.example(packet);wire['observations']={key:'detail'}
 assert gen.decode(wire,packet,[],{})['findings']==[tables['facts'][key]]
 wire['observations']={}
 assert gen.decode(wire,packet,[],{})['findings']==[]

def test_unknown_or_ambiguous_source_time_is_not_invented():
 packet=linked_packet();tables,_=gen.offers(packet,[],{})
 packet['context']=[copy.deepcopy(packet['events'][0])]
 facts=gen.annotated_facts(packet,tables)
 for f in facts.values():
  for ident,(seen,rows) in zip(f['evidence_ids'],f['occurrences']):
   if ident==packet['events'][0]['id']:assert seen is None

def test_revision_display_roundtrip_keeps_exact_statement_and_join_metadata():
 p=linked_packet();schema,logical=gen.prepare(p,[],{})
 w=gen.example(p);can=gen.decode(w,p,[],{});logical['provisional_answer']={'draft_binding':'a'*64,'rendered':rev.view(can,p,sy),'choices':{}}
 before=copy.deepcopy(logical);q=rev.request(schema,logical,'synthetic',gen,'synthetic')
 decoded=rep.expand(json.loads(q['messages'][1]['content']))
 decoded['offered']['facts']=rev.restore_facts(decoded['offered']['facts'],decoded['provisional_answer']['rendered'])
 assert decoded==logical==before
