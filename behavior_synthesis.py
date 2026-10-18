"""Bounded model-authored observable synthesis, separate from verdict/scoring.

Typed source checks and a closed, privacy-safe reporting vocabulary reject
unsupported entities/actions and instruction copying. They are not a proof of
natural-language entailment; semantic utility still requires independent review.
"""
import re

VERSION='observable-synthesis-1'
MAX_ITEMS=3
LIMITS={
 'session_sequence':'Reported input and capture do not establish execution, network transfer, payload identity or authorization.',
 'authentication_failure':'A sampled failed login does not establish brute force, authorization, successful access or operator identity.',
 'http_navigation':'Paths and response codes do not establish authorization, authenticated access or successful exploitation.',
 'resource_discovery':'Resource targeting is not successful disclosure; ordinary crawling and authorized testing remain alternatives.',
 'client_recurrence':'Client labels are spoofable; repeated same-IP observations do not establish verified tooling or operator continuity.',
 'denied_recurrence':'Firewall decisions are policy outcomes, not independent attack or successful-access evidence; address reuse remains possible.',
 'insufficient_detail':'Opaque summaries do not establish a specific behavior, intent, tool, vulnerability or operator.'}
COMMON=set('a an the and or of to in on at by for from with as is are was were be been has have had source sources report reports reported record records recorded saved sampled sample samples observed observation observations supplied following followed then after before between over across within about this these that those it its also same distinct different single one two three four several multiple repeated repeating request requests response responses status statuses code codes point points time times date dates day days sequence pattern activity behavior contact connection connections access attempt attempts compatible consistent suggests suggest may indicate indicates reflects could involve remains available only detail details account limited partial data context shows show carry carries potential possible potentially'.split())
WORDS={
 'session_sequence':set('ssh shell input file capture captures captured syntax permission change output redirection session linked link staging workflow'.split()),
 'authentication_failure':set('ssh login logins failed failure failures authentication credential negotiation closed close session'.split()),
 'http_navigation':set('http get head root redirects redirect navigation page pages route routes path paths authentication sitemap response returned returns'.split()),
 'resource_discovery':set('http get head path paths resource resources discovery enumeration probing probe probes configuration config sensitive environment file files sitemap targeting targeted returned returns'.split()),
 'client_recurrence':set('http get head client label labels claimed unverified recurring recurrence repeated repeated-IP ip user agent claim claims spoofable dates'.split()),
 'denied_recurrence':set('ssh port firewall drop drops dropped denied denies deny policy policies recurrence recurring ip closed close session'.split()),
 'insufficient_detail':set('opaque summary summaries unspecified unknown insufficient missing unavailable cannot support specific concrete meaningful establish'.split())}
TOKENS=re.compile(r"/[A-Za-z0-9._/-]+|\b[A-Za-z]+(?:-[A-Za-z]+)*\b|\b[0-9]+\b")
SENSITIVE={'/.env','/config.json','/sitemap.xml','/.git/config','/wp-config.php'}


def facts(packet,refs):
 from behavior_ai import timestamp
 own={e['id']:e for e in packet.get('events',[]) if e.get('id')}
 if len(set(refs))!=len(refs) or not refs or len(refs)>8 or any(r not in own for r in refs):return None
 events=[own[r] for r in refs]
 if any(not timestamp(e.get('seen')) for e in events):return None
 return sorted(events,key=lambda e:(timestamp(e['seen']),e['id']))


def supports(kind,events):
 from behavior_ai import timestamp
 from source_observations import connections
 if not events:return False
 detailed=[e for e in events if (e.get('provenance') or {}).get('detail')=='sample']
 action=lambda e:e.get('action','').casefold()
 http=[e for e in detailed if e.get('method') in ('GET','HEAD') and re.fullmatch(r'/[A-Za-z0-9._/-]{0,69}',e.get('path',''))]
 dates={timestamp(e['seen']).date() for e in detailed}
 if kind=='session_sequence':
  linked=connections(events);shell=[e for e in detailed if action(e)=='cowrie.command.input' and (e.get('source_observation') or {}).get('semantic')=='shell_input'];files=[e for e in detailed if action(e)=='cowrie.session.file_download' and (e.get('source_observation') or {}).get('semantic')=='file_capture']
  return any(a['id'] in linked and b['id'] in linked and linked[a['id']]['id']==linked[b['id']]['id'] and 0<=(timestamp(a['seen'])-timestamp(linked[a['id']]['seen'])).total_seconds()<=(timestamp(b['seen'])-timestamp(linked[a['id']]['seen'])).total_seconds()<=900 for a in shell for b in files)
 if kind=='authentication_failure':return any(action(e)=='cowrie.login.failed' for e in detailed)
 if kind=='http_navigation':return len(http)>=2
 if kind=='resource_discovery':return any(e.get('path') in SENSITIVE for e in http)
 if kind=='client_recurrence':
  claims={}
  for e in detailed:
   label=(e.get('client_claim') or {}).get('label')
   if isinstance(label,str) and label:claims.setdefault(label,set()).add(timestamp(e['seen']).date())
  return any(len(v)>1 for v in claims.values())
 if kind=='denied_recurrence':return len({timestamp(e['seen']).date() for e in detailed if action(e) in ('drop','deny','denied') and str(e.get('port',''))=='22'})>1
 if kind=='insufficient_detail':return not detailed and all(not any(e.get(k) for k in ('method','path','port')) for e in events)
 return False


def options(packet):
 """Source-only applicability hints, not generated findings or verdicts."""
 events=packet.get('events',[])
 groups={
  'session_sequence':[e for e in events if e.get('action') in ('cowrie.session.connect','cowrie.command.input','cowrie.session.file_download')],
  'authentication_failure':[e for e in events if e.get('action')=='cowrie.login.failed'],
  'http_navigation':[e for e in events if e.get('method') in ('GET','HEAD')],
  'resource_discovery':[e for e in events if e.get('method') in ('GET','HEAD') and e.get('path') in SENSITIVE],
  'client_recurrence':[e for e in events if e.get('client_claim')],
  'denied_recurrence':[e for e in events if e.get('action') in ('drop','deny','denied')],
  'insufficient_detail':events}
 result={}
 for kind,items in groups.items():
  # Endpoints preserve temporal coverage without enumerating an unbounded pool.
  items=items if len(items)<=8 else items[:4]+items[-4:]
  refs=[e['id'] for e in items if e.get('id')];selected=facts(packet,refs)
  if selected and supports(kind,selected):result[kind]=refs
 return result


def schema(packet):
 from behavior_ai import obj,text,array
 choices=options(packet);ids=list(dict.fromkeys(i for refs in choices.values() for i in refs))
 item=obj({'kind':text(32,enum=choices or ['unavailable']),'evidence_ids':array(text(80,enum=ids or ['unavailable']),8,1),'observation':text(180),'meaning':text(140)})
 return array(item,MAX_ITEMS if choices else 0)


def validate(items,packet):
 from behavior_generation import ChoiceError
 from behavior_ai import shape
 shape(schema(packet),items)
 seen=set()
 for index,item in enumerate(items):
  def reject(reason):raise ChoiceError('synthesis_'+reason,'observable_synthesis',index)
  kind=item['kind'];events=facts(packet,item['evidence_ids'])
  if not events or not supports(kind,events):reject('source_support')
  if kind in seen:reject('duplicate_kind')
  seen.add(kind)
  paths={e['path'].lower() for e in events if re.fullmatch(r'/[A-Za-z0-9._/-]{0,69}',e.get('path',''))}
  numbers={str(len(events)),str(sum(e.get('action')=='cowrie.login.failed' for e in events))}|{str(e.get(k,'')) for e in events for k in ('status','port') if str(e.get(k,'')).isdigit()}
  for field in ('observation','meaning'):
   text=item[field]
   if not text.strip() or text!=text.strip() or not re.fullmatch(r'[A-Za-z0-9 /.,;:()\-]+',text) or re.search(r'\b\d+\.\d+\.\d+\.\d+\b',text):reject('text_characters')
   tokens=[t.rstrip('.') if t.startswith('/') else t for t in TOKENS.findall(text.lower())]
   if not tokens or any(t not in COMMON|WORDS[kind] and t not in paths and t not in numbers for t in tokens):reject('text_vocabulary')
  text=(item['observation']+' '+item['meaning']).lower();tokens=set(TOKENS.findall(text))
  if kind=='session_sequence':
   if not {'connection','shell','input','file','capture'}<=tokens:reject('sequence_anchors')
   observation=item['observation'].lower()
   if not all(word in observation for word in ('connection','shell','file')) or not observation.index('connection')<observation.index('shell')<observation.index('file'):reject('sequence_word_order')
   syntax=set(v for e in events for v in (e.get('source_observation') or {}).get('syntax_categories',[]))
   if 'permission' in tokens and 'permission_change' not in syntax or 'redirection' in tokens and 'output_redirection' not in syntax:reject('syntax_not_recorded')
  if kind=='authentication_failure':
   failures=sum(e.get('action')=='cowrie.login.failed' for e in events)
   if 'failed' not in tokens or not {'login','authentication'}&tokens:reject('authentication_anchor')
   if failures==1 and (not {'one','single','1'}&tokens or {'repeated','multiple','several','two','three','four','logins','failures'}&tokens):reject('authentication_count')
  if kind=='resource_discovery' and not any(p in text for p in paths&SENSITIVE):reject('resource_anchor')
  if kind=='resource_discovery' and not {'discovery','probing','probe','probes','targeting','enumeration'}&tokens:reject('resource_meaning')
  if kind in ('http_navigation','resource_discovery'):
   for status in ('200','301','302','404'):
    if status in tokens and not any(str(e.get('status'))==status for e in events):reject('status_not_observed')
  if kind=='client_recurrence' and not {'client','label'}<=tokens:reject('client_anchor')
  if kind=='denied_recurrence' and not {'drop','drops','denied','deny','denies'}&tokens:reject('denial_anchor')
  if kind=='insufficient_detail' and not {'opaque','summary','insufficient','missing','unavailable'}&tokens:reject('insufficiency_anchor')
 return items


def render(items):
 # Text reaches the existing escaped summary surface only after validate().
 return ' '.join(item['observation']+' '+item['meaning']+' '+LIMITS[item['kind']]+' ['+', '.join(item['evidence_ids'])+']' for item in items)


INSTRUCTION='''Observable synthesis is separate from the intent verdict. Return zero to three observable_synthesis items, each with kind, exact current-event evidence_ids, a concise authored observation (180 chars), and meaning (140 chars). Use synthesis_options as applicability hints, not answers. Group the important what-happened sequence and its limited meaning; do not repeat every parent summary. Write only source-supported reporting language, not instructions or source quotations. No negations in authored prose: trusted uncertainty is appended by validation. No tools, CVEs, technique IDs, identities, payloads, execution, success, compromise, authorization, benign/malicious claims or raw commands. Use simple words about recorded source reports. session_sequence must mention connection, shell input and file capture; staging-compatible is a hypothesis. authentication_failure must state one/single failed login when only one is cited; never imply brute force. resource_discovery must name a cited exact path and discovery/probing; 404 is not disclosure. client_recurrence refers to the same IP and unverified client label across dates, not a verified actor/tool. denied_recurrence describes firewall policy outcomes across dates. insufficient_detail describes opaque summaries and missing detail. Meaning may use 'compatible with', 'may indicate', 'suggests' and 'consistent with'. Keep it short and literal. Required caveats and source citations are added after validation; never substitute synthesis for positive opposing context or verdict support.'''
