"""Provisional presentation fidelity; synthetic selections do not predict model quality."""
import copy,json
import pytest
import behavior_revision as rev
from behavior_representation import expand

class EmptyPresentation:
 @staticmethod
 def presentation(canonical,events):return None

def canonical():return {'analysis_summary':'inconclusive','findings':[{'summary':'Connection observed.','evidence_ids':['event-a']}],'contradictory_evidence':[{'summary':'Verified context.','evidence_ids':['context-a']}],'observable_synthesis':[]}

def test_display_keeps_exact_observations_without_selected_accounts():
 value=canonical();shown=rev.view(value,{'events':[]},EmptyPresentation)
 assert shown['findings']==value['findings'] and shown['counterevidence']==value['contradictory_evidence']
 assert shown['accounts']==[] and shown['rendered_presentation_is_null']
 shown['findings'][0]['evidence_ids'].append('changed')
 assert value['findings'][0]['evidence_ids']==['event-a']

def test_duplicate_body_codec_retains_metadata_and_every_offer():
 shown=rev.view(canonical(),{'events':[]},EmptyPresentation)
 facts={'selected':{**shown['findings'][0],'allowed_roles':['omit','detail','support'],'summary_fields':['action']},'counter':{**shown['counterevidence'][0],'allowed_roles':['omit','counterevidence']},'unselected':{'summary':'Unselected source label.','evidence_ids':['event-b'],'allowed_roles':['omit','detail']}}
 before=copy.deepcopy(facts);projected=rev.reference_facts(facts,shown)
 assert projected['selected']['draft_statement_ref']==['findings',0]
 assert projected['counter']['draft_statement_ref']==['counterevidence',0]
 assert projected['unselected']==facts['unselected']
 assert rev.restore_facts(projected,shown)==facts==before
 assert projected['selected']['allowed_roles']==facts['selected']['allowed_roles']

def test_ambiguous_body_stays_literal_without_guessing():
 shown=rev.view(canonical(),{'events':[]},EmptyPresentation)
 shown['findings'].append(copy.deepcopy(shown['findings'][0]))
 fact={'x':copy.deepcopy(shown['findings'][0])}
 assert rev.reference_facts(fact,shown)==fact

@pytest.mark.parametrize('reference',[['findings',True],['findings',-1],['findings',1],['unknown',0]])
def test_invalid_reference_rejected(reference):
 shown=rev.view(canonical(),{'events':[]},EmptyPresentation)
 with pytest.raises(ValueError):rev.restore_facts({'x':{'draft_statement_ref':reference}},shown)

def test_reference_cannot_overwrite_body_or_accept_extra_fields():
 shown=rev.view(canonical(),{'events':[]},EmptyPresentation)
 with pytest.raises(ValueError):rev.restore_facts({'x':{'draft_statement_ref':['findings',0],'summary':'replacement'}},shown)
 shown['findings'][0]['extra']='injected'
 with pytest.raises(ValueError):rev.restore_facts({'x':{'draft_statement_ref':['findings',0]}},shown)

def test_source_literal_marker_is_not_interpreted_outside_offered_facts():
 import behavior_generation as gen
 logical={'offered':{'facts':{}},'source':{'draft_statement_ref':['findings',0]},'provisional_answer':{'draft_binding':'a'*64,'rendered':{'findings':[],'counterevidence':[]},'choices':{}}}
 q=rev.request({},logical,'synthetic',gen,'synthetic')
 assert expand(json.loads(q['messages'][1]['content']))==logical


def test_duplicate_account_body_reference_needs_exact_text_and_group_identity():
 shown={'accounts':[{'account':'Complete actual account text.','source_group_ref':'group-a'}]}
 options={'group-a':{'reported_account':'Complete actual account text.','evidence_ids':['a']},'group-b':{'reported_account':'Complete actual account text.','evidence_ids':['b']}}
 packed=rev.reference_accounts(options,shown)
 assert packed['group-a']['draft_account_ref']==0 and packed['group-b']==options['group-b']
 assert rev.restore_accounts(packed,shown)==options
 for bad in [True,-1,1]:
  with pytest.raises(ValueError):rev.restore_accounts({'group-a':{'draft_account_ref':bad}},shown)
 with pytest.raises(ValueError):rev.restore_accounts({'group-b':{'draft_account_ref':0}},shown)
 with pytest.raises(ValueError):rev.restore_accounts({'group-a':{'draft_account_ref':0,'reported_account':'replacement'}},shown)
