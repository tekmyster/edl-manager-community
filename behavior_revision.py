"""Lossless provisional-answer representation. No transport, repair or inference."""
import copy,json,hashlib
from behavior_generation import VERSION as DRAFT
from behavior_generation import SELECTION_OBJECTIVE,SELECTION_RULES
POLICY='Reassess behavior independently of intent; freely replace draft. Sparsity/agreement are not goals. Keep distinct occurrences, syntax, intervals, uncertainty. Compare literal statements to selected account/row content; raw fields/names/citations alone are not coverage. Labels may add no behavior. Every generic/all-omit choice stays legal. Findings/counterevidence are exact. draft_statement_ref=[display-list,index] copies only summary/evidence_ids; source_group_ref binds account tuples only. Copy draft_binding. '+SELECTION_RULES

def compact(v):return json.dumps(v,ensure_ascii=True,separators=(',',':'),allow_nan=False)
def digest(v):return hashlib.sha256(compact(v).encode()).hexdigest()
INDEX_RULE=' Draft [index,value] pairs use zero-based offer order: observations=facts, attack_techniques=attack, d3fend_context=d3fend, observable_synthesis=synthesis_options; hypotheses=own table/confidence. Packet/version are constants.'
POLICY+=INDEX_RULE
FIELDS={'observations':'facts','attack_techniques':'attack','d3fend_context':'d3fend','observable_synthesis':'synthesis_options','automation':'automation','intent':'intent','actor_correlation':'relations'}
def draft_orders(tables,logical):return {field:list(logical['synthesis_options'] if kind=='synthesis_options' else tables[kind]) for field,kind in FIELDS.items()}
def pack_choices(v,tables,logical):
 orders=draft_orders(tables,logical);out={k:copy.deepcopy(x) for k,x in v.items() if k not in FIELDS and k not in ('generation_schema_version','packet_id')}
 for field,keys in orders.items():
  if field in ('automation','intent','actor_correlation'):out[field]=[[keys.index(x['choice_id']),x['confidence']] for x in v[field]]
  else:out[field]=[[keys.index(k),copy.deepcopy(x)] for k,x in v[field].items()]
 return out
def unpack_choices(v,tables,logical,packet):
 orders=draft_orders(tables,logical);out={k:copy.deepcopy(x) for k,x in v.items() if k not in FIELDS};out.update(generation_schema_version=DRAFT,packet_id=packet['packet_id'])
 for field,keys in orders.items():
  used=set();items=[]
  for pair in v[field]:
   if not isinstance(pair,list) or len(pair)!=2:raise ValueError('Malformed draft pair')
   i,x=pair
   if type(i) is not int or not 0<=i<len(keys) or i in used:raise ValueError('Invalid or duplicate draft index')
   used.add(i);items.append((keys[i],copy.deepcopy(x)))
  out[field]=[{'choice_id':k,'confidence':x} for k,x in items] if field in ('automation','intent','actor_correlation') else dict(items)
 return out
def request(schema,logical,system,gen,model):
 from behavior_representation import factor_selection
 logical=copy.deepcopy(logical);binding=logical.get('provisional_answer',{}).pop('draft_binding',None)
 # Keep the complete selected statement readable in the draft display.
 # Reference its duplicate offered body only after an exact unique match.
 shown=logical.get('provisional_answer',{}).get('rendered')
 if shown is not None:
  facts=logical['offered']['facts'];projected=reference_facts(facts,shown)
  if restore_facts(projected,shown)!=facts:raise ValueError('Draft statement reference mismatch')
  logical['offered']['facts']=projected
 encoded=factor_selection(logical)
 # Literal digest insertion prevents a hypothetical equality with a source
 # string from changing the source factor table. It loses no source/draft data.
 if binding is not None:encoded['input']['provisional_answer']['draft_binding']=binding
 q={'model':model,'messages':[{'role':'system','content':system},{'role':'user','content':gen.prompt_json(encoded)}],'stream':True,'format':schema,'options':{'temperature':0,'num_predict':1800,'num_ctx':8192}}
 if len(q['messages'][1]['content'].encode())>18000 or len(compact(q).encode())>65536:raise ValueError('Complete request exceeds original byte limits')
 return q
def view(canonical,packet,sy):
 """Exact provisional answer, including both observation roles; no utility labels."""
 presentation=sy.presentation(canonical,packet['events'])
 result={'summary':canonical['analysis_summary'],'findings':copy.deepcopy(canonical['findings']),'counterevidence':copy.deepcopy(canonical['contradictory_evidence']),'accounts':[],'rendered_presentation_is_null':presentation is None}
 if presentation is None:return result
 groups=canonical['observable_synthesis'];details=presentation['details'];assert len(groups)==len(details)
 result['summary']=presentation['summary']
 result['accounts']=[{**{k:v for k,v in detail.items() if k!='rows'},'source_group_ref':group['claim_id']} for group,detail in zip(groups,details)]
 return result

def reference_facts(facts,shown):
 """Lossless duplicate-body codec, not selection or semantic coverage."""
 value=copy.deepcopy(facts)
 for key,fact in value.items():
  original={k:fact[k] for k in ('summary','evidence_ids')}
  matches=[(field,i) for field in ('findings','counterevidence') for i,item in enumerate(shown[field]) if item==original]
  if len(matches)==1:
   for k in ('summary','evidence_ids'):del fact[k]
   fact['draft_statement_ref']=list(matches[0])
 return value

def restore_facts(facts,shown):
 value=copy.deepcopy(facts)
 for fact in value.values():
  if 'draft_statement_ref' not in fact:continue
  field,index=fact.pop('draft_statement_ref')
  if field not in ('findings','counterevidence') or type(index) is not int or not 0<=index<len(shown[field]):raise ValueError('Invalid draft statement reference')
  item=shown[field][index]
  if set(item)!={'summary','evidence_ids'} or any(k in fact for k in item):raise ValueError('Invalid referenced statement body')
  fact.update(copy.deepcopy(item))
 return value
