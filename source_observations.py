"""Portable, additive source-report metadata. No commands, URLs or session values.

Collectors must count original connections over their entire declared lookback,
not merely the returned sample. A partial query must never assert uniqueness.
These are untrusted source reports, not execution or authorization attestations.
"""
import datetime as dt
import hashlib
import ipaddress
import re
import json

VERSION='source-observations-1'
SEMANTICS={'shell_input','interactive_input','file_capture','file_event','network_fetch','connection'}
SYNTAX={'permission_change','output_redirection','interpreter_input','relative_execution','network_client_input'}
LOOKUP_STATES={'complete','not_selected','partial','error'}
PROOF_VERSION='source-connection-proof-1'

def fingerprint(value):return reference(json.dumps(value,sort_keys=True,separators=(',',':')))

def proof_scope(observation,start,end):
 return fingerprint([observation.get(k) for k in ('collector_ref','source_ref','session_ref')]+[start,end,'Cowrie','original-connection-count'])

def binding_proof(observation):
 """Validate a complete declared query receipt; never infer one from samples."""
 p=observation.get('binding_proof')
 if not isinstance(p,dict) or p.get('version')!=PROOF_VERSION:return None
 required={'version','record_id','record_sha256','scope_ref','window_start','window_end','checked_at','connection_count','connection_id','connection_sha256'}
 if set(p)!=required:return None
 start,end,checked=(_time(p.get(k)) for k in ('window_start','window_end','checked_at'))
 if not start or not end or not checked or not dt.timedelta(days=29)<=end-start<=dt.timedelta(days=31) or not end<=checked<=end+dt.timedelta(hours=1):return None
 if not isinstance(p['record_id'],str) or not re.fullmatch(r'[A-Za-z0-9_.:/+=-]{1,120}',p['record_id']):return None
 if any(not isinstance(p[k],str) or not re.fullmatch('[0-9a-f]{64}',p[k]) for k in ('record_sha256','scope_ref')):return None
 if p['scope_ref']!=proof_scope(observation,p['window_start'],p['window_end']):return None
 count=p['connection_count']
 if type(count) is not int or not 0<=count<=10000000:return None
 if count==1:
  if not isinstance(p['connection_id'],str) or not re.fullmatch(r'[A-Za-z0-9_.:/+=-]{1,120}',p['connection_id']) or not isinstance(p['connection_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',p['connection_sha256']):return None
 elif p['connection_id'] is not None or p['connection_sha256'] is not None:return None
 return p

def reference(value):
 return hashlib.sha256(str(value).encode()).hexdigest()

def source_reference(address):
 try:return reference(str(ipaddress.ip_address(address)))
 except ValueError:return ''

def metadata(collector,address,session,semantic):
 if not collector or not session or semantic not in SEMANTICS:return {}
 scope=reference(collector);source=source_reference(address)
 if not source:return {}
 return {'version':VERSION,'collector_ref':scope,'source_ref':source,'session_ref':reference(scope+'|'+source+'|'+str(session)), 'semantic':semantic}

def sanitize(value,address):
 if isinstance(value,dict) and value.get('conflict') is True:return {'conflict':True}
 if not isinstance(value,dict) or value.get('version')!=VERSION:return {}
 if value.get('semantic') not in SEMANTICS or value.get('source_ref')!=source_reference(address):return {}
 keys=('collector_ref','source_ref','session_ref')
 if any(not isinstance(value.get(k),str) or not re.fullmatch('[0-9a-f]{64}',value[k]) for k in keys):return {}
 clean={k:value[k] for k in ('version','semantic')+keys}
 categories=value.get('syntax_categories')
 if isinstance(categories,list):clean['syntax_categories']=sorted({v for v in categories[:5] if isinstance(v,str) and v in SYNTAX})
 if value.get('lookup_status') in LOOKUP_STATES:clean['lookup_status']=value['lookup_status']
 ident=value.get('connection_id')
 if value.get('connection_count')==1 and type(value.get('connection_count')) is int and isinstance(ident,str) and re.fullmatch(r'[A-Za-z0-9_.:/+=-]{1,120}',ident):
  clean.update(connection_id=ident,connection_count=1)
 elif type(value.get('connection_count')) is int and 2<=value['connection_count']<=10000000:clean['connection_count']=value['connection_count']
 proof=binding_proof(value)
 if 'binding_proof' in value and not proof:return {'conflict':True}
 if proof:
  clean['binding_proof']=dict(proof);clean['connection_count']=proof['connection_count']
  if proof['connection_count']==1:clean['connection_id']=proof['connection_id']
  else:clean.pop('connection_id',None)
 if value.get('binding_state') in ('ambiguous','missing_connection') and type(value.get('connection_count')) is int and (value['connection_count']>1 or value['binding_state']=='missing_connection' and value['connection_count']==0):
  clean['binding_state']=value['binding_state'];clean['connection_count']=value['connection_count']
  if isinstance(value.get('ambiguity_ref'),str) and re.fullmatch('[0-9a-f]{64}',value['ambiguity_ref']):clean['ambiguity_ref']=value['ambiguity_ref']
 return clean

def _time(value):
 try:
  parsed=dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
  return parsed if parsed.tzinfo else None
 except ValueError:return None

def merge_reports(left,right):
 """Unknown optional lookup detail is not contradictory source evidence.

 Actual contradictory identities/semantics remain sticky. A complete later
 multi-connection query defeats an older unique claim; unknown detail cannot.
 Legacy conflict recovery is an explicit separately audited operation.
 """
 if not left or not right:return left or right or {}
 if not isinstance(left,dict) or not isinstance(right,dict):return {'conflict':True}
 if left.get('conflict') or right.get('conflict'):return {'conflict':True}
 core=lambda o:{k:v for k,v in o.items() if k not in ('connection_id','connection_count','binding_proof','lookup_status','binding_state','ambiguity_ref')}
 if core(left)!=core(right):return {'conflict':True}
 lp,rp=binding_proof(left),binding_proof(right)
 if lp and rp and (lp['record_id'],lp['record_sha256'])!=(rp['record_id'],rp['record_sha256']):return {'conflict':True}
 # Known session reuse never becomes unique merely by rotating a window.
 ambiguous=[o for o in (left,right) if o.get('binding_state') in ('ambiguous','missing_connection') or (binding_proof(o) and o['binding_proof']['connection_count']!=1)]
 if ambiguous:
  chosen=max(ambiguous,key=lambda o:(o.get('connection_count',0),(binding_proof(o) or {}).get('checked_at','')))
  result=dict(chosen);result['binding_state']='ambiguous' if result.get('connection_count',0)>1 else 'missing_connection';result.pop('connection_id',None);return result
 if any(o.get('connection_count',0)>1 for o in (left,right)):return {'conflict':True}
 a,b=left.get('connection_id'),right.get('connection_id')
 if a and b and a!=b:return {'conflict':True}
 proofs=[o for o in (left,right) if binding_proof(o)]
 if proofs:
  chosen=max(proofs,key=lambda o:o['binding_proof']['checked_at'])
  # A complete zero-connection query covering the same original defeats an old
  # binding. Do not restore it through a subsequent partial/legacy copy.
  if any(o['binding_proof']['connection_count']==0 for o in proofs):chosen=next(o for o in proofs if o['binding_proof']['connection_count']==0)
 else:chosen=right if b else left if a else right
 result=dict(chosen)
 if right.get('lookup_status') in LOOKUP_STATES:result['lookup_status']=right['lookup_status']
 return result

def connections(events):
 """Resolve only a co-included, unique original connection; never fill a target.

 Conflicts, missing references, time reversal, session reuse and cross-stream
 references abstain. Original event identity and destination stay untouched.
 """
 result={}
 for event in events:
  observation=event.get('source_observation') or {};ident=observation.get('connection_id')
  if observation.get('version')!=VERSION or type(observation.get('connection_count')) is not int or observation.get('connection_count')!=1 or not ident:continue
  if any(not isinstance(observation.get(k),str) or not re.fullmatch('[0-9a-f]{64}',observation[k]) for k in ('collector_ref','source_ref','session_ref')):continue
  scope=lambda e:tuple((e.get('source_observation') or {}).get(k) for k in ('collector_ref','source_ref','session_ref'))+(e.get('source'),e.get('sensor'),(e.get('provenance') or {}).get('collector_agent',''))
  same=[e for e in events if scope(e)==scope(event)]
  candidates=[e for e in same if e.get('action')=='cowrie.session.connect']
  origins={(e.get('provenance') or {}).get('upstream_id') for e in candidates}
  matches=[e for e in candidates if (e.get('provenance') or {}).get('upstream_id')==ident]
  if origins!={ident} or len(matches)!=1:continue
  connection=matches[0];start=_time(connection.get('seen'));end=_time(event.get('seen'))
  if (connection.get('source_observation') or {}).get('semantic')!='connection' or (connection.get('provenance') or {}).get('detail')!='sample':continue
  destination=connection.get('destination') or {};target=destination.get('asset_id') or destination.get('address');port=str(connection.get('port',''))
  if not target or not port.isdigit() or not 1<=int(port)<=65535 or not start or not end or not 0<=(end-start).total_seconds()<=900:continue
  if any((e.get('source_observation') or {}).get('connection_id') not in (None,ident) for e in same):continue
  own=event.get('destination') or {};own_target=own.get('asset_id') or own.get('address')
  if own_target and own_target!=target or event.get('port') and str(event['port'])!=port:continue
  result[event['id']]=connection
 return result

def prioritize(events,limit=24):
 """Retain complete linked groups before generic newest samples, within a bound."""
 unique={e['id']:e for e in events if e and e.get('id')};events=list(unique.values());chosen=[]
 # Works on sanitized collector samples as well as normalized history.
 def scope(e):
  o=e.get('source_observation') or {};p=e.get('provenance')
  return tuple(o.get(k) for k in ('collector_ref','source_ref','session_ref'))+(e.get('source'),e.get('sensor'),p.get('collector_agent','') if isinstance(p,dict) else '')
 by_origin={((e.get('provenance') or {}).get('upstream_id',e['id']) if isinstance(e.get('provenance'),dict) else e['id'],scope(e)):e for e in events}
 for event in sorted(events,key=lambda e:(e.get('action')!='cowrie.session.file_download',e.get('seen',''),e['id'])):
  observation=event.get('source_observation') or {};connection=by_origin.get((observation.get('connection_id'),scope(event)))
  if not connection:continue
  group=[connection,event]
  commands=[e for e in events if scope(e)==scope(event) and e.get('action')=='cowrie.command.input']
  def staging(e):
   values=(e.get('source_observation') or {}).get('syntax_categories')
   return isinstance(values,list) and len(values)<=5 and all(isinstance(v,str) and v in SYNTAX for v in values) and bool(set(values)&{'permission_change','interpreter_input','relative_execution'})
  commands.sort(key=lambda e:(not staging(e),e.get('seen',''),e['id']))
  group += commands[:4]
  group=list({e['id']:e for e in group}.values())
  fresh=[e for e in group if e['id'] not in {v['id'] for v in chosen}]
  if len(chosen)+len(fresh)<=limit:chosen+=fresh
 ordered=sorted(events,key=lambda e:(e.get('seen',''),e['id']),reverse=True)
 for event in sorted(ordered,key=lambda e:(e.get('action')!='cowrie.session.file_download',e.get('action')!='cowrie.command.input')):
  if len(chosen)>=limit:break
  if event['id'] not in {v['id'] for v in chosen}:chosen.append(event)
 return chosen
