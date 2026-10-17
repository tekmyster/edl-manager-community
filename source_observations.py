"""Portable, additive source-report metadata. No commands, URLs or session values.

Collectors must count original connections over their entire declared lookback,
not merely the returned sample. A partial query must never assert uniqueness.
These are untrusted source reports, not execution or authorization attestations.
"""
import datetime as dt
import hashlib
import ipaddress
import re

VERSION='source-observations-1'
SEMANTICS={'shell_input','interactive_input','file_capture','file_event','network_fetch','connection'}
SYNTAX={'permission_change','output_redirection','interpreter_input','relative_execution','network_client_input'}

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
 if not isinstance(value,dict) or value.get('version')!=VERSION:return {}
 if value.get('semantic') not in SEMANTICS or value.get('source_ref')!=source_reference(address):return {}
 keys=('collector_ref','source_ref','session_ref')
 if any(not isinstance(value.get(k),str) or not re.fullmatch('[0-9a-f]{64}',value[k]) for k in keys):return {}
 clean={k:value[k] for k in ('version','semantic')+keys}
 categories=value.get('syntax_categories')
 if isinstance(categories,list):clean['syntax_categories']=sorted({v for v in categories[:5] if isinstance(v,str) and v in SYNTAX})
 ident=value.get('connection_id')
 if value.get('connection_count')==1 and type(value.get('connection_count')) is int and isinstance(ident,str) and re.fullmatch(r'[A-Za-z0-9_.:/+=-]{1,120}',ident):
  clean.update(connection_id=ident,connection_count=1)
 return clean

def _time(value):
 try:
  parsed=dt.datetime.fromisoformat(str(value).replace('Z','+00:00'))
  return parsed if parsed.tzinfo else None
 except ValueError:return None

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
 by_origin={(e.get('provenance') or {}).get('upstream_id',e['id']) if isinstance(e.get('provenance'),dict) else e['id']:e for e in events}
 for event in sorted(events,key=lambda e:(e.get('action')!='cowrie.session.file_download',e.get('seen',''),e['id'])):
  observation=event.get('source_observation') or {};connection=by_origin.get(observation.get('connection_id'))
  if not connection:continue
  group=[connection,event]
  group += [e for e in events if (e.get('source_observation') or {}).get('session_ref')==observation.get('session_ref') and e.get('action')=='cowrie.command.input'][:4]
  group=list({e['id']:e for e in group}.values())
  fresh=[e for e in group if e['id'] not in {v['id'] for v in chosen}]
  if len(chosen)+len(fresh)<=limit:chosen+=fresh
 ordered=sorted(events,key=lambda e:(e.get('seen',''),e['id']),reverse=True)
 for event in sorted(ordered,key=lambda e:(e.get('action')!='cowrie.session.file_download',e.get('action')!='cowrie.command.input')):
  if len(chosen)>=limit:break
  if event['id'] not in {v['id'] for v in chosen}:chosen.append(event)
 return chosen
