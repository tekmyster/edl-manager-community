"""Conservative telemetry eligibility, never scoring or ground-truth attack labels."""
import datetime as dt
import re

RULE_VERSION='telemetry-1'
MAX_ATTACK=12
MAX_DEFEND=6
# Explicit observed detector descriptions only. Paths, ports, feed labels,
# drops and ownership cannot establish host or credential subtype behaviors.
# ATT&CK ID, detector phrase, defensive analysis context (not control status).
DETECTORS=(
 ('T1110.001',r'password guessing','D3-ANET'),
 ('T1110.003',r'password spraying','D3-ANET'),
 ('T1110.004',r'credential stuffing','D3-ANET'),
 ('T1595.001',r'(?:scanning ip blocks|ip block scanning)','D3-CAA'),
 ('T1595.002',r'vulnerability scan(?:ning)?','D3-NTSA'),
 ('T1595.003',r'wordlist scan(?:ning)?','D3-WSAA'),
 ('T1046',r'network service discovery','D3-NTA'),
 ('T1190',r'(?:public.facing application exploit attempt|exploit public.facing application)','D3-WSAA'),
 ('T1003',r'(?:os credential dumping|credential dump attempt)','D3-PA'),
 ('T1059.001',r'powershell (?:execution|command)','D3-SEA'),
 ('T1059.003',r'windows command shell (?:execution|command)','D3-SEA'),
 ('T1059.004',r'unix shell (?:execution|command)','D3-SEA'),
 ('T1082',r'system information discovery','D3-PA'),
 ('T1083',r'file and directory discovery','D3-FAPA'),
 ('T1016',r'system network configuration discovery','D3-PA'),
 ('T1057',r'process discovery','D3-PA'),
 ('T1033',r'system owner/user discovery','D3-PA'),
 ('T1105',r'ingress tool transfer','D3-UDTA'),
 ('T1505.003',r'web shell (?:execution|upload attempt)','D3-WSAA'),
 ('T1498',r'network denial of service','D3-ISVA'),
)
UNCERTAINTY='Candidate mappings describe saved observations, not confirmed compromise. Detector descriptions can be incomplete or wrong. D3FEND is analysis context only; control deployment and prevention are unverified.'
FAILURE=r'(?:authentication failure|login failed|failed login|cowrie\.login\.failed)'

def _nearby(left,right):
 try:
  a=dt.datetime.fromisoformat(left['seen'].replace('Z','+00:00'));b=dt.datetime.fromisoformat(right['seen'].replace('Z','+00:00'))
  return bool(a.tzinfo and b.tzinfo and (left.get('source'),left.get('sensor'))==(right.get('source'),right.get('sensor')) and abs((a-b).total_seconds())<=900)
 except (ValueError,KeyError,TypeError):return False

def select(registry,packet):
 """Bound IDs and evidence; eligibility does not confirm execution or identity."""
 events={e['id']:e for e in packet.get('events',[]) if e.get('id')};support={'attack':{},'d3fend':{}}
 def offer(kind,ident,refs):
  if ident in registry.get(kind,{}) and refs:support[kind][ident]=sorted(set(support[kind].get(ident,[]))|set(refs))[:2]
 for event in events.values():
  action=event.get('action','').casefold()
  if re.search(r'\b(?:no|not|benign|test|simulation|blocked by policy)\b',action):continue
  for ident,pattern,defense in DETECTORS:
   if re.fullmatch(pattern+r'(?: detected)?',action):
    offer('attack',ident,[event['id']]);offer('d3fend',defense,[event['id']])
  if event.get('source')=='tpot' and event.get('sensor','').casefold()=='cowrie':
   if action=='cowrie.command.input':
    offer('attack','T1059',[event['id']]);offer('d3fend','D3-SEA',[event['id']])
   if action=='cowrie.session.file_download':
    offer('attack','T1105',[event['id']]);offer('d3fend','D3-UDTA',[event['id']])
  if event.get('source') in ('tpot','owapot'):offer('d3fend','D3-DE',[event['id']])
  if event.get('path') and event.get('method'):
   offer('d3fend','D3-UA',[event['id']]);offer('d3fend','D3-WSAA',[event['id']])
  if re.fullmatch(FAILURE,action):offer('d3fend','D3-ANET',[event['id']])
 failures=[e for e in events.values() if re.fullmatch(FAILURE,e.get('action','').casefold())]
 # No account/password detail: never infer spraying/guessing/stuffing from failures.
 for index,left in enumerate(failures):
  peer=next((right for right in failures[index+1:] if _nearby(left,right)),None)
  if peer:
   offer('attack','T1110',[left['id'],peer['id']]);break
 # Three distinct sensitive-path probes from one collector in 15 minutes permit
 # the broad scan family only. This does not prove vulnerability exploitation,
 # wordlist use, successful access or maliciousness. Summaries cannot substitute.
 groups={}
 for event in events.values():
  if event.get('action','').casefold()!='sensitive path request' or not event.get('path') or not event.get('method'):continue
  try:
   seen=dt.datetime.fromisoformat(event['seen'].replace('Z','+00:00'))
   if not seen.tzinfo:continue
  except (ValueError,KeyError,TypeError):continue
  groups.setdefault((event.get('source'),event.get('sensor')),[]).append((seen,event))
 for group in groups.values():
  ordered=sorted(group,key=lambda pair:(pair[0],pair[1]['id']))
  for start,(seen,event) in enumerate(ordered):
   window=[e for t,e in ordered[start:] if (t-seen).total_seconds()<=900]
   if len({e['path'] for e in window})>=3:
    offer('attack','T1595',[e['id'] for e in window])
 selected={'version':registry.get('version','unavailable'),'rule_version':RULE_VERSION,'registry_sha256':registry.get('registry_sha256'),'support':{},'coverage':{},'uncertainty':UNCERTAINTY}
 for kind,limit in [('attack',MAX_ATTACK),('d3fend',MAX_DEFEND)]:
  ids=sorted(support[kind])[:limit]
  selected[kind]={ident:registry[kind][ident] for ident in ids}
  selected['support'][kind]={ident:support[kind][ident] for ident in ids}
  selected['coverage'][kind]=registry.get('coverage',{}).get(kind,{'eligible':len(support[kind]),'supplied':len(ids)})
 return selected

def validate_mapping(kind,item,registry,packet):
 # Recompute eligibility even if a caller passes the entire catalog.
 eligible=select(registry,packet);refs=set(item['evidence_ids'])
 supported=set(eligible['support'][kind].get(item['technique_id'],[]))
 if not refs or not refs<=supported:raise ValueError('Taxonomy mapping requires supporting observations')
 if kind=='attack' and item['technique_id']=='T1110' and len(refs)<2:raise ValueError('Brute force mapping requires multiple sampled failures')
