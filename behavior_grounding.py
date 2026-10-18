"""Bounded source observations and fixed interpretations; no provider-authored facts.

This is an acceptance contract, not an accuracy or authorization oracle. Saved
source fields remain untrusted reports. Older stored assessments are not rewritten.
"""
import re

VERSION='grounded-observations-5'
MAX_FACTS=12
MAX_SIGNAL_EVENTS=24
MAX_SUPPORT_BUNDLES=6
LIMITS=['Saved source reports are partial and may be wrong; authorization, ownership and successful exploitation are unverified.',
        'Model interpretations and maliciousness estimates are uncalibrated. Shared tools or addresses do not identify an operator.']
SUMMARIES={
 'inconclusive':'The saved observations do not establish malicious or legitimate intent. More independent context is needed.',
 'benign':'Benign interpretation supported by cited positive cached context; historical ownership and authorization remain unverified.',
 'malicious':'Malicious interpretation of cited reported behavior; authorization, successful exploitation and operator identity remain unverified.'}
ALTERNATIVE='Shared tooling, NAT, proxies or address reassignment; operator identity is unknown.'
RELATION='Cited current and historical samples share observable request or client-label features. This is an uncertain behavioral similarity, not collaboration or identity.'

class GroundingError(ValueError):
 def __init__(self,message,reason,field,index=None):
  super().__init__(message);self.reason=reason;self.field=field;self.index=index
 def diagnostic(self):
  value={'category':'grounding_contract','reason':self.reason,'field':self.field}
  if self.index is not None:value['index']=self.index
  return value

def mapping_text(kind,ident,name):
 name=str(name)[:50]
 if kind=='d3fend':return f'Defensive context {ident} ({name}) for cited source reports; deployment, prevention, attacks and tests are unverified.'
 return f'Candidate {ident} ({name}) describes cited source reports; intent, subtype and successful execution remain unverified.'

SYNTAX_LABELS={'permission_change':'permission change','output_redirection':'output redirection','interpreter_input':'interpreter input','relative_execution':'relative execution syntax','network_client_input':'network-client input'}

def recorded_syntax(observation):
 values=observation.get('syntax_categories')
 if observation.get('version')!='source-observations-1' or not isinstance(values,list) or len(values)>5 or any(not isinstance(v,str) or v not in SYNTAX_LABELS for v in values):return None
 return [k for k in SYNTAX_LABELS if k in values]

def shared(left,right):
 from behavior_correlation import GENERIC_PATHS
 path=left.get('path')
 request=bool(path and path not in GENERIC_PATHS and '[identifier]' not in path and path==right.get('path') and left.get('method') and left['method']==right.get('method'))
 a=left.get('client_claim',{});b=right.get('client_claim',{})
 client=bool(isinstance(a,dict) and isinstance(b,dict) and a.get('label') and a.get('label')==b.get('label'))
 return request or client

def sufficiency(events):
 """Offer interpretations, never verdicts, from coherent distinct source reports.

Source/sensor names confer no privilege. Detailed original-record provenance,
time/target or collection scope, and two different supported behavior features
are required. Copies, repeated labels, paths alone and generic failures abstain.
"""
 from behavior_ai import timestamp
 from behavior_mapping import DETECTORS
 from behavior_references import endpoint_hint
 from source_observations import connections
 linked=connections(events)
 signals=[]
 for event in events:
  provenance=event.get('provenance') or {};origin=provenance.get('upstream_id') or provenance.get('record_id')
  seen=timestamp(event.get('seen'))
  if provenance.get('detail')!='sample' or not origin or not seen or not event.get('id') or not event.get('source') or not event.get('sensor'):continue
  action=event.get('action','').casefold();features=set()
  for ident,pattern,_ in DETECTORS:
   if re.fullmatch(pattern+r'(?: detected)?',action):features.add('reported:'+ident)
  # Machine event semantics are recognized independently of collector branding.
  semantic=(event.get('source_observation') or {}).get('semantic')
  syntax=recorded_syntax(event.get('source_observation') or {}) or []
  if action=='cowrie.command.input' and semantic=='shell_input' and any(v in syntax for v in ('permission_change','interpreter_input','relative_execution')):features.add('reported:shell_staging_input')
  if action=='cowrie.session.file_download' and semantic in ('file_capture','network_fetch'):features.add('reported:'+semantic)
  method=event.get('method');path=event.get('path','');status=str(event.get('status',''))
  if method=='POST' and path and status.isdigit() and 100<=int(status)<=599:
   category=endpoint_hint(path)
   if '[identifier]' in path and event.get('endpoint_hint') in ('phpunit_eval_stdin','apache_cgi_traversal'):category=event['endpoint_hint']
   if category:features.add('targeting:'+category)
  if not features:continue
  destination=(linked.get(event['id']) or event).get('destination') or {};target=destination.get('asset_id') or destination.get('address')
  signals.append({'event':event,'origin':origin,'seen':seen,'features':features,'target':target})
 # Bound pair comparisons and explicitly expose partial support coverage.
 signals=sorted(signals,key=lambda x:x['event']['id']);available=len(signals);signals=signals[:MAX_SIGNAL_EVENTS];bundles=[]
 for index,left in enumerate(signals):
  for right in signals[index+1:]:
   a=left['event'];b=right['event']
   if left['origin']==right['origin'] or a['id']==b['id'] or abs((left['seen']-right['seen']).total_seconds())>900:continue
   signature=lambda e:(timestamp(e.get('seen')),e.get('method'),e.get('path'),str(e.get('port','')))
   if signature(a)==signature(b):continue
   if a.get('method') and a.get('path') and (a.get('method'),a.get('path'),str(a.get('port','')))==(b.get('method'),b.get('path'),str(b.get('port',''))) and abs((left['seen']-right['seen']).total_seconds())<=1:continue
   # Two copies/repetitions of one feature are not corroborating behavior.
   if left['features']==right['features']:continue
   target_match=bool(left['target'] and left['target']==right['target'])
   if left['target'] and right['target'] and not target_match:continue
   pa=a.get('provenance') or {};pb=b.get('provenance') or {};port=str(a.get('port',''))
   stream_match=bool(pa.get('collector_agent') and pa.get('collector_agent')==pb.get('collector_agent') and (a['source'],a['sensor'])==(b['source'],b['sensor']) and port==str(b.get('port','')) and port.isdigit() and 1<=int(port)<=65535)
   if not target_match and not stream_match:continue
   link_a=linked.get(a['id']);link_b=linked.get(b['id'])
   # Session-bearing reports must resolve through the same original connection.
   if a.get('source_observation') or b.get('source_observation'):
    if not link_a or not link_b or link_a['id']!=link_b['id']:continue
   refs=list(dict.fromkeys([a['id'],b['id']]+([link_a['id']] if link_a else [])))
   bundles.append({'evidence_ids':refs,'basis':'Distinct sampled reports within 15 minutes; '+('matching observed target' if target_match else 'matching recorded collector stream and port')+'; different supported behavior features. Authorization and successful compromise remain unknown.'})
   if len(bundles)==MAX_SUPPORT_BUNDLES:break
  if len(bundles)==MAX_SUPPORT_BUNDLES:break
 return bundles,{'available_signal_events':available,'examined_signal_events':len(signals),'signal_bound':MAX_SIGNAL_EVENTS,'support_bundle_bound':MAX_SUPPORT_BUNDLES,'pair_bound':276}

def contract(packet,registry):
 from behavior_ai import safe_text,timestamp,now
 from behavior_mapping import select,FAILURE
 eligible=select(registry,packet);facts=[];positive=[]
 from source_observations import connections
 linked=connections(packet.get('events',[]))
 events=list(packet.get('events',[]))
 bundles,support_coverage=sufficiency(events)
 support_ids=list(dict.fromkeys(i for b in bundles for i in b['evidence_ids']))
 # Prefer complete sufficient pairs, then actual failures, over generic reports.
 def priority(e):
  action=e.get('action','').casefold()
  return (0 if e.get('id') in support_ids else 1 if re.fullmatch(FAILURE,action) else 2,e.get('id',''))
 events=sorted(events,key=priority)
 for e in events:
  if not e.get('id'):continue
  action=safe_text(e.get('action'),60);source=safe_text(e.get('source'),20);sensor=safe_text(e.get('sensor'),30)
  statement=f'Saved {source} / {sensor} sample reports {action or "unspecified activity"}.'
  semantic=(e.get('source_observation') or {}).get('semantic')
  if action=='cowrie.session.file_download' and semantic=='file_capture':statement=f'Saved {source} / {sensor} sample reports file capture; network transfer is unverified.'
  if action=='cowrie.session.file_download' and semantic=='network_fetch':statement=f'Saved {source} / {sensor} sample reports a network file fetch; intent and execution are unverified.'
  if action=='cowrie.command.input' and semantic in ('shell_input','interactive_input'):statement=f'Saved {source} / {sensor} sample reports '+('shell input; execution is unverified.' if semantic=='shell_input' else 'interactive input; command execution is unverified.')
  if e.get('method') and e.get('path') and not re.fullmatch(FAILURE,action.casefold()):
   statement=f'Saved request: {safe_text(e["method"],8)} {safe_text(e["path"],70)}; status {safe_text(e.get("status"),3) or "unavailable"}; source {source}.'
  connection=linked.get(e['id'])
  # Describe existing privacy-safe machine metadata, never reconstruct input
  # text or promote syntax/session linkage into execution or authorization.
  if action=='cowrie.command.input' and semantic=='shell_input':
   syntax=recorded_syntax(e.get('source_observation') or {})
   if syntax is not None:
    names=[SYNTAX_LABELS[k] for k in syntax]
    statement+=(' Recorded syntax categories: '+', '.join(names)+'.') if names else ' No allowlisted syntax category was recorded.'
   else:statement+=' Syntax detail unavailable.'
  if connection and action in ('cowrie.command.input','cowrie.session.file_download'):
   seconds=(timestamp(e['seen'])-timestamp(connection['seen'])).total_seconds()
   elapsed=f'{seconds:.3f}'.rstrip('0').rstrip('.')
   statement+=f' Same-source session link: about {elapsed} seconds after its cited connection.'
  refs=list(dict.fromkeys([e['id']]+([connection['id']] if connection else [])))
  facts.append({'summary':statement,'evidence_ids':refs})
 for c in packet.get('context',[]):
  expiry=timestamp(c.get('expires'));fresh=c.get('status')=='ok' and c.get('cache_fresh') is True and expiry is not None and expiry>timestamp(now())
  if c.get('kind')!='intelligence' or not fresh or not c.get('id'):continue
  if c.get('provider')=='crawler' and c.get('verified') is True:
   positive.append({'summary':'Fresh cached crawler verification is positive context; historical ownership and request authorization are unverified.','evidence_ids':[c['id']]})
  if c.get('provider')=='greynoise' and c.get('classification')=='benign' and c.get('observation_fresh') is True:
   positive.append({'summary':'Fresh cached GreyNoise benign classification is positive context, not independent proof of request authorization.','evidence_ids':[c['id']]})
 # Leave space for up to two positive references, with explicit bounded coverage.
 offered=(positive[:2]+facts)[:MAX_FACTS]
 offered_ids={i for f in offered for i in f['evidence_ids']}
 bundles=[b for b in bundles if set(b['evidence_ids'])<=offered_ids]
 detailed=any((e.get('provenance') or {}).get('detail')=='sample' for e in events)
 classes=['inconclusive']+(['benign'] if positive and detailed else [])+(['malicious'] if bundles else [])
 automation=['unknown'];intent=['unknown']
 if 'T1110' in eligible.get('attack',{}):automation.append('credential_attack_automation');intent.append('credential_attack')
 if any(i.startswith('T1595') for i in eligible.get('attack',{})):automation+=['vulnerability_scanner','suspicious_bot'];intent.append('reconnaissance')
 if 'T1190' in eligible.get('attack',{}):intent.append('exploitation')
 if positive:automation.append('legitimate_automation')
 if positive and any(e.get('method') in ('GET','HEAD') and e.get('path') for e in events):intent.append('ordinary_browsing')
 return {'version':VERSION,'facts':offered,'counterevidence':positive[:2],'positive_ids':[r['evidence_ids'][0] for r in positive[:2]],'malicious_support':bundles,'support_coverage':support_coverage,
         'classifications':classes,'automation':automation,'intent':intent,'available_facts':len(positive)+len(facts),'offered_facts':len(offered),
         'summaries':SUMMARIES,'limitations':LIMITS}

def validate(value,packet,candidates,registry):
 c=contract(packet,registry)
 def reject(message,reason,field,index=None):raise GroundingError(message,reason,field,index)
 for field in ('findings','contradictory_evidence'):
  seen=set()
  for index,claim in enumerate(value[field]):
   if claim not in c['facts']:
    known=any(f['summary']==claim['summary'] for f in c['facts'])
    reject('Unsupported observation statement','citation_binding' if known else 'summary_not_offered',field+('.evidence_ids' if known else '.summary'),index)
   if field=='contradictory_evidence' and claim not in c['counterevidence']:
    reject('Counterevidence requires positive opposing context','counterevidence_not_supported',field,index)
   refs=tuple(claim['evidence_ids'])
   if refs in seen:reject('Duplicate observation statement','duplicate_observation',field,index)
   seen.add(refs)
 if any(v in value['findings'] for v in value['contradictory_evidence']):reject('Observation cannot occupy opposing roles','duplicate_observation_sides','contradictory_evidence')
 if value['classification'] not in c['classifications']:reject('Unsupported decisive interpretation','classification_not_supported','classification')
 cited={i for v in value['findings']+value['contradictory_evidence'] for i in v['evidence_ids']}
 if value['classification']=='benign' and not cited.intersection(c['positive_ids']):reject('Benign interpretation requires positive context','positive_context_not_cited','findings')
 finding_ids={i for v in value['findings'] for i in v['evidence_ids']}
 if value['classification']=='malicious' and not any(set(b['evidence_ids'])<=finding_ids for b in c['malicious_support']):reject('Malicious interpretation requires reported behavior','support_bundle_not_cited','findings')
 for key in ('automation','intent'):
  if value[key]['classification'] not in c[key]:reject('Unsupported interpretation label','label_not_supported',key+'.classification')
  if value[key]['classification']=='unknown' and value[key]['confidence']!=0:reject('Unknown interpretation requires zero confidence','unknown_confidence_nonzero',key+'.confidence')
 summary=SUMMARIES[value['classification']]
 if 'observable_synthesis' in value:
  from behavior_synthesis import validate as validate_synthesis,render
  validate_synthesis(value['observable_synthesis'],packet)
  if value['observable_synthesis'] and not set(c['positive_ids'])<=cited:reject('Positive context must remain visible','synthesis_positive_context_omitted','contradictory_evidence')
  summary=(render(value['observable_synthesis'],packet)+' '+summary).strip()
 if value['analysis_summary']!=summary:reject('Unsupported assessment narrative','assessment_summary_mismatch','analysis_summary')
 if value['limitations']!=LIMITS:
  index=next((i for i,(a,b) in enumerate(zip(value['limitations'],LIMITS)) if a!=b),min(len(value['limitations']),len(LIMITS)))
  reject('Unsupported assessment narrative','limitations_mismatch','limitations',index)
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  for index,claim in enumerate(value[field]):
   if claim['explanation']!=mapping_text(kind,claim['technique_id'],registry[kind][claim['technique_id']]):reject('Unsupported mapping narrative','mapping_explanation_mismatch',field+'.explanation',index)
 own={e['id']:e for e in packet['events']}
 for index,claim in enumerate(value['actor_correlation']):
  candidate=next(v for v in candidates if v['candidate_id']==claim['candidate_id']);refs=set(claim['evidence_ids'])
  peers=[e for e in candidate.get('historical_events',[]) if e.get('id') in refs]
  if not any(shared(e,p) for ident,e in own.items() if ident in refs for p in peers):reject('Unsupported historical similarity','historical_similarity_not_supported','actor_correlation.evidence_ids',index)
  if claim['explanation']!=RELATION:reject('Unsupported correlation narrative','correlation_explanation_mismatch','actor_correlation.explanation',index)
  if claim['alternative_explanations']!=[ALTERNATIVE]:reject('Unsupported correlation narrative','correlation_alternatives_mismatch','actor_correlation.alternative_explanations',index)

def constrain(schema,packet,candidates,registry,choices):
 """Enum constraints aid decoding; validate() enforces citation/text binding."""
 c=contract(packet,registry);p=schema['properties']
 p['classification']['enum']=c['classifications']
 for key in ('automation','intent'):p[key]['properties']['classification']['enum']=c[key]
 for field in ('findings','contradictory_evidence'):
  offered=c['counterevidence'] if field=='contradictory_evidence' else c['facts']
  p[field]['items']['properties']['summary']['enum']=[f['summary'] for f in offered] or ['No observations available']
  if not offered:p[field]['maxItems']=0
 p['analysis_summary']['enum']=list(SUMMARIES.values())
 p['limitations']['minItems']=p['limitations']['maxItems']=2;p['limitations']['items']['maxLength']=200;p['limitations']['items']['enum']=LIMITS
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  p[field]['items']['properties']['explanation']['enum']=[mapping_text(kind,v['technique_id'],v['name']) for v in choices[kind].values()] or ['Unavailable']
 fields=p['actor_correlation']['items']['properties'];fields['explanation']['enum']=[RELATION];fields['alternative_explanations']['items']['enum']=[ALTERNATIVE]
 return {k:v for k,v in c.items() if k!='positive_ids'}

def example(packet,registry=None):
 """Conservative complete example for isolated contract fixtures; no model call."""
 from behavior_ai import VERSION as STORAGE_VERSION
 c=contract(packet,registry or {})
 return {'schema_version':STORAGE_VERSION,'packet_id':packet['packet_id'],'classification':'inconclusive','maliciousness_confidence':.5,
         'automation':{'classification':'unknown','confidence':0},'intent':{'classification':'unknown','confidence':0},'findings':c['facts'][:1],
         'attack_techniques':[],'d3fend_context':[],'actor_correlation':[],'contradictory_evidence':[],'limitations':list(LIMITS),'analysis_summary':SUMMARIES['inconclusive']}
