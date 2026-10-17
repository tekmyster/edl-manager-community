"""Bounded source observations and fixed interpretations; no provider-authored facts.

This is an acceptance contract, not an accuracy or authorization oracle. Saved
source fields remain untrusted reports. Older stored assessments are not rewritten.
"""
import re

VERSION='grounded-observations-1'
MAX_FACTS=12
LIMITS=['Saved source reports are partial and may be wrong; authorization, ownership and successful exploitation are unverified.',
        'Model interpretations and maliciousness estimates are uncalibrated. Shared tools or addresses do not identify an operator.']
SUMMARIES={
 'inconclusive':'The saved observations do not establish malicious or legitimate intent. More independent context is needed.',
 'benign':'Benign interpretation supported by cited positive cached context; historical ownership and authorization remain unverified.',
 'malicious':'Malicious interpretation of cited reported behavior; authorization, successful exploitation and operator identity remain unverified.'}
ALTERNATIVE='Shared tooling, NAT, proxies or address reassignment; operator identity is unknown.'
RELATION='Cited current and historical samples share observable request or client-label features. This is an uncertain behavioral similarity, not collaboration or identity.'

def mapping_text(kind,ident,name):
 name=str(name)[:50]
 if kind=='d3fend':return f'Defensive context {ident} ({name}) for cited source reports; deployment, prevention, attacks and tests are unverified.'
 return f'Candidate {ident} ({name}) describes cited source reports; intent, subtype and successful execution remain unverified.'

def shared(left,right):
 from behavior_correlation import GENERIC_PATHS
 path=left.get('path')
 request=bool(path and path not in GENERIC_PATHS and '[identifier]' not in path and path==right.get('path') and left.get('method') and left['method']==right.get('method'))
 a=left.get('client_claim',{});b=right.get('client_claim',{})
 client=bool(isinstance(a,dict) and isinstance(b,dict) and a.get('label') and a.get('label')==b.get('label'))
 return request or client

def contract(packet,registry):
 from behavior_ai import safe_text,timestamp,now
 from behavior_mapping import select,FAILURE
 eligible=select(registry,packet);facts=[];positive=[];strong=[]
 events=list(packet.get('events',[]))
 # Prefer actual explicit failures/commands to generic connection summaries.
 def priority(e):
  action=e.get('action','').casefold()
  return (0 if re.fullmatch(FAILURE,action) else 1 if action in ('cowrie.command.input','cowrie.session.file_download') else 2,e.get('id',''))
 events=sorted(events,key=priority)
 for e in events:
  if not e.get('id'):continue
  action=safe_text(e.get('action'),60);source=safe_text(e.get('source'),20);sensor=safe_text(e.get('sensor'),30)
  statement=f'Saved {source} / {sensor} sample reports {action or "unspecified activity"}.'
  if e.get('method') and e.get('path') and not re.fullmatch(FAILURE,action.casefold()):
   statement=f'Saved request: {safe_text(e["method"],8)} {safe_text(e["path"],70)}; status {safe_text(e.get("status"),3) or "unavailable"}; source {source}.'
  facts.append({'summary':statement,'evidence_ids':[e['id']]})
  if (e.get('provenance') or {}).get('detail')=='sample' and e.get('source')=='tpot' and e.get('sensor','').casefold()=='cowrie' and action in ('cowrie.command.input','cowrie.session.file_download'):strong.append(e['id'])
 for c in packet.get('context',[]):
  expiry=timestamp(c.get('expires'));fresh=c.get('status')=='ok' and c.get('cache_fresh') is True and expiry is not None and expiry>timestamp(now())
  if c.get('kind')!='intelligence' or not fresh or not c.get('id'):continue
  if c.get('provider')=='crawler' and c.get('verified') is True:
   positive.append({'summary':'Fresh cached crawler verification is positive context; historical ownership and request authorization are unverified.','evidence_ids':[c['id']]})
  if c.get('provider')=='greynoise' and c.get('classification')=='benign' and c.get('observation_fresh') is True:
   positive.append({'summary':'Fresh cached GreyNoise benign classification is positive context, not independent proof of request authorization.','evidence_ids':[c['id']]})
 # Leave space for up to two positive references, with explicit bounded coverage.
 offered=(positive[:2]+facts)[:MAX_FACTS]
 strong=[ident for ident in strong if any(f['evidence_ids']==[ident] for f in offered)]
 detailed=any((e.get('provenance') or {}).get('detail')=='sample' for e in events)
 classes=['inconclusive']+(['benign'] if positive and detailed else [])+(['malicious'] if strong else [])
 automation=['unknown'];intent=['unknown']
 if 'T1110' in eligible.get('attack',{}):automation.append('credential_attack_automation');intent.append('credential_attack')
 if any(i.startswith('T1595') for i in eligible.get('attack',{})):automation+=['vulnerability_scanner','suspicious_bot'];intent.append('reconnaissance')
 if 'T1190' in eligible.get('attack',{}):intent.append('exploitation')
 if positive:automation.append('legitimate_automation')
 if positive and any(e.get('method') in ('GET','HEAD') and e.get('path') for e in events):intent.append('ordinary_browsing')
 return {'version':VERSION,'facts':offered,'positive_ids':[r['evidence_ids'][0] for r in positive[:2]],'strong_ids':strong,
         'classifications':classes,'automation':automation,'intent':intent,'available_facts':len(positive)+len(facts),'offered_facts':len(offered),
         'summaries':SUMMARIES,'limitations':LIMITS}

def validate(value,packet,candidates,registry):
 c=contract(packet,registry)
 for field in ('findings','contradictory_evidence'):
  for claim in value[field]:
   if claim not in c['facts']:raise ValueError('Unsupported observation statement')
  if len({tuple(v['evidence_ids']) for v in value[field]})!=len(value[field]):raise ValueError('Duplicate observation statement')
 if value['classification'] not in c['classifications']:raise ValueError('Unsupported decisive interpretation')
 cited={i for v in value['findings']+value['contradictory_evidence'] for i in v['evidence_ids']}
 if value['classification']=='benign' and not cited.intersection(c['positive_ids']):raise ValueError('Benign interpretation requires positive context')
 if value['classification']=='malicious' and not {i for v in value['findings'] for i in v['evidence_ids']}.intersection(c['strong_ids']):raise ValueError('Malicious interpretation requires reported behavior')
 for key in ('automation','intent'):
  if value[key]['classification'] not in c[key]:raise ValueError('Unsupported interpretation label')
  if value[key]['classification']=='unknown' and value[key]['confidence']!=0:raise ValueError('Unknown interpretation requires zero confidence')
 if value['analysis_summary']!=SUMMARIES[value['classification']] or value['limitations']!=LIMITS:raise ValueError('Unsupported assessment narrative')
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  for claim in value[field]:
   if claim['explanation']!=mapping_text(kind,claim['technique_id'],registry[kind][claim['technique_id']]):raise ValueError('Unsupported mapping narrative')
 own={e['id']:e for e in packet['events']}
 for claim in value['actor_correlation']:
  candidate=next(v for v in candidates if v['candidate_id']==claim['candidate_id']);refs=set(claim['evidence_ids'])
  peers=[e for e in candidate.get('historical_events',[]) if e.get('id') in refs]
  if not any(shared(e,p) for ident,e in own.items() if ident in refs for p in peers):raise ValueError('Unsupported historical similarity')
  if claim['explanation']!=RELATION or claim['alternative_explanations']!=[ALTERNATIVE]:raise ValueError('Unsupported correlation narrative')

def constrain(schema,packet,candidates,registry,choices):
 """Enum constraints aid decoding; validate() enforces citation/text binding."""
 c=contract(packet,registry);p=schema['properties']
 p['classification']['enum']=c['classifications']
 for key in ('automation','intent'):p[key]['properties']['classification']['enum']=c[key]
 for field in ('findings','contradictory_evidence'):
  p[field]['items']['properties']['summary']['enum']=[f['summary'] for f in c['facts']] or ['No observations available']
  if not c['facts']:p[field]['maxItems']=0
 p['analysis_summary']['enum']=list(SUMMARIES.values())
 p['limitations']['minItems']=p['limitations']['maxItems']=2;p['limitations']['items']['maxLength']=200;p['limitations']['items']['enum']=LIMITS
 for field,kind in [('attack_techniques','attack'),('d3fend_context','d3fend')]:
  p[field]['items']['properties']['explanation']['enum']=[mapping_text(kind,v['technique_id'],v['name']) for v in choices[kind].values()] or ['Unavailable']
 fields=p['actor_correlation']['items']['properties'];fields['explanation']['enum']=[RELATION];fields['alternative_explanations']['items']['enum']=[ALTERNATIVE]
 return {k:v for k,v in c.items() if k not in ('positive_ids','strong_ids')}

def example(packet,registry=None):
 """Conservative complete example for isolated contract fixtures; no model call."""
 from behavior_ai import VERSION as STORAGE_VERSION
 c=contract(packet,registry or {})
 return {'schema_version':STORAGE_VERSION,'packet_id':packet['packet_id'],'classification':'inconclusive','maliciousness_confidence':.5,
         'automation':{'classification':'unknown','confidence':0},'intent':{'classification':'unknown','confidence':0},'findings':c['facts'][:1],
         'attack_techniques':[],'d3fend_context':[],'actor_correlation':[],'contradictory_evidence':[],'limitations':list(LIMITS),'analysis_summary':SUMMARIES['inconclusive']}
