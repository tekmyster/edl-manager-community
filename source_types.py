"""Locally cached descriptive labels, independent of scoring and allow rules."""
import bisect,datetime as dt,hashlib,ipaddress,json
from core import now

ROLES={'google-common':('Google','Search crawler'),'google-special':('Google','Special crawler'),'bing':('Bing','Search crawler'),'duckduckgo':('DuckDuckGo','Search crawler'),'apple':('Apple','Search crawler'),'openai-search':('OpenAI','AI search'),'openai-user':('OpenAI','AI user fetch'),'openai-training':('OpenAI','AI training')}

def classify(events,observations,verified=None):
 labels=[];seen=set()
 def add(kind,operator,confidence,evidence):
  key=(kind,operator,confidence)
  if key not in seen:labels.append({'type':kind,'operator':operator,'confidence':confidence,'evidence':evidence});seen.add(key)
 for operator,role in verified or []:add(role,operator,'Verified','Published operator range')
 for e in events:
  role=e.get('client_type','Unknown');operator=e.get('operator','')
  if role!='Unknown' and not any(x['type']==role and x['operator']==operator and x['confidence']=='Verified' for x in labels):add(role,operator,e.get('confidence','Inferred'),'Request headers')
  action=e.get('action','').casefold()
  if 'login.failed' in action:add('Credential attempts','','Observed','Failed authentication')
  if 'command.input' in action or 'file_download' in action or 'file_upload' in action:add('Honeypot interaction','','Observed','Command or file activity')
 honeypots={(e['source'],e['sensor']) for e in observations if e['source'] in ['tpot','owapot']}
 ports={str(p) for e in observations if e['source'] in ['tpot','owapot'] for p in e.get('ports',[])}
 if len(honeypots)>=2 or len(ports)>=3:add('Likely scanner','','Inferred','Multiple honeypots or ports')
 if any(e['source']=='waf' and e['sensor']!='web-request' for e in observations):add('WAF-triggering traffic','','Observed','WAF interruption')
 if any(e['source']=='nginx' and e['sensor']!='web-request' for e in observations):add('Web probes','','Observed','Sensitive path requests')
 if not labels:add('Unknown','','Unknown','No identifying metadata')
 return {'labels':labels,'types':sorted({x['type'] for x in labels}),'clients':sorted({e['client'] for e in events if e.get('client')}),'platforms':sorted({e['platform'] for e in events if e.get('platform')})}

def refresh(store):
 from activity import local_activity
 feeds=store.state('crawler_feeds') or {};fresh=feeds.get('expires','')>now();nets=[]
 if fresh:
  for name,values in feeds.get('data',{}).items():
   if name not in ROLES:continue
   ranges={4:[],6:[]}
   for v in values:
    try:
     n=ipaddress.ip_network(v.get('ipv4Prefix') or v.get('ipv6Prefix'));ranges[n.version].append(n)
    except (ValueError,TypeError):continue
   for version,items in ranges.items():
    values=sorted(ipaddress.collapse_addresses(items),key=lambda n:int(n.network_address))
    nets.append((version,[int(n.network_address) for n in values],[int(n.broadcast_address) for n in values],ROLES[name]))
 cut=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)).isoformat(timespec='seconds')
 configuration=store.state('source_configuration')
 enabled={k for k,v in configuration.get('sources',{}).items() if v} if configuration is not None and configuration.get('index_url') else set() if configuration is not None else None
 grouped={};previous={}
 with store.connect() as d:
  for r in d.execute('SELECT * FROM source_activity WHERE seen>=?',(cut,)):
   if enabled is None or r['source'] in enabled:grouped.setdefault(r['ip'],[]).append(dict(r))
  for r in d.execute("SELECT ip,payload,expires FROM cache WHERE provider='source_type'"):previous[r['ip']]=(json.loads(r['payload']).get('fingerprint'),r['expires'])
 updates=[]
 for address,rows in grouped.items():
  fingerprint=hashlib.sha256(json.dumps([sorted((r['source'],r['sensor'],r['seen'],r['details']) for r in rows),feeds.get('fetched') if fresh else 'expired',2]).encode()).hexdigest()
  if previous.get(address,(None,''))[0]==fingerprint and previous[address][1]>now():continue
  a=ipaddress.ip_address(address);value=int(a);verified=[]
  for version,starts,ends,role in nets:
   if version!=a.version:continue
   i=bisect.bisect_right(starts,value)-1
   if i>=0 and value<=ends[i]:verified.append(role)
  events,observations=local_activity({'activity':sorted(rows,key=lambda r:r['seen'],reverse=True),'evidence':[]})
  payload=classify(events,observations,verified);payload['fingerprint']=fingerprint;payload['window_end']=now()
  hours=min(24,max(1/3600,(dt.datetime.fromisoformat(feeds['expires'])-dt.datetime.now(dt.timezone.utc)).total_seconds()/3600)) if verified else 24
  updates.append((address,'source_type',payload,'ok',hours))
 for address in previous.keys()-grouped.keys():
  if previous[address][0]!='no-activity':updates.append((address,'source_type',{**classify([],[]),'fingerprint':'no-activity'},'ok',24))
 if updates:store.cache_many(updates)
 return len(updates)
