"""Durable operator and generated-list events; no inferred firewall actions."""
import datetime as dt,hashlib,ipaddress,json,pathlib

SCHEMA='''
CREATE TABLE IF NOT EXISTS policy_events(event_key TEXT PRIMARY KEY,at TEXT NOT NULL,recorded TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,details TEXT NOT NULL,family INTEGER NOT NULL,lo TEXT NOT NULL,hi TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS policy_events_target ON policy_events(kind,target,at);
CREATE INDEX IF NOT EXISTS policy_events_time ON policy_events(at);
CREATE INDEX IF NOT EXISTS policy_events_bounds ON policy_events(family,lo,hi);
'''
LABELS={'intelligence.reviewed':'Intelligence reviewed','whitelist.added':'Whitelist added','blacklist.added':'Blacklist added','whitelist.disabled':'Whitelist disabled','blacklist.disabled':'Blacklist disabled','whitelist.expired':'Whitelist expired','blacklist.expired':'Blacklist expired','block.expired':'Block retention expired','list.added':'Added to list','list.removed':'Removed from list','enrichment.queued':'Enrichment requested'}

def insert(d,key,at,actor,action,kind,target,details):
 from core import now
 from core import selector
 _,_,nets=selector(target);family=nets[0].version if nets else 0
 lo=format(int(nets[0].network_address),'032x') if nets else ''
 hi=format(int(nets[-1].broadcast_address),'032x') if nets else ''
 d.execute('INSERT OR IGNORE INTO policy_events VALUES(?,?,?,?,?,?,?,?,?,?,?)',(key,at,now(),actor,action,kind,target,json.dumps(details,separators=(',',':')),family,lo,hi))

def audit_event(d,ident,at,actor,action,details):
 from core import selector
 if action in ('rule.add','rule.disable'):
  kind,target,_=selector(details['value']);verb='added' if action=='rule.add' else 'disabled'
  event=('whitelist' if details['action']=='allow' else 'blacklist')+'.'+verb
  safe={k:details.get(k) for k in ['id','reason','expires','emergency']}
  if action=='rule.disable' and details.get('expires') and details['expires']<=at:
   insert(d,'rule-expiry:'+details['id'],details['expires'],'System',('whitelist' if details['action']=='allow' else 'blacklist')+'.expired',kind,target,safe)
 elif action=='intelligence.review':
  kind,target,_=selector(details['ip']);event='intelligence.reviewed'
  outcome={'false_positive':'False positive','confirmed_malicious':'Confirmed malicious','inconclusive':'Inconclusive'}.get(details.get('outcome'),'Review')
  safe={'reason':outcome+': '+details['note']}
 elif action=='enrichment.queue':
  kind,target,_=selector(details['ip']);event='enrichment.queued';safe={}
 else:return
 insert(d,'audit:'+str(ident),at,actor,event,kind,target,safe)

def recover_audit(store):
 """Replay saved, actual operator actions, keeping original event times."""
 with store.connect() as d:
  r=d.execute("SELECT value FROM state WHERE key='policy_event_audit_cursor'").fetchone();cursor=json.loads(r[0]) if r else 0
  for r in d.execute('SELECT * FROM audit WHERE id>? ORDER BY id',(cursor,)).fetchall():
   try:audit_event(d,r['id'],r['at'],r['actor'],r['action'],json.loads(r['details']))
   except (ValueError,KeyError,TypeError):pass
   cursor=r['id']
  d.execute('INSERT OR REPLACE INTO state VALUES(?,?)',('policy_event_audit_cursor',json.dumps(cursor)))

def expirations(store,at):
 with store.connect() as d:
  for r in d.execute("SELECT * FROM rules WHERE enabled=1 AND expires IS NOT NULL AND expires<=? AND NOT EXISTS (SELECT 1 FROM policy_events e WHERE e.event_key='rule-expiry:'||rules.id)",(at,)).fetchall():
   event=('whitelist' if r['action']=='allow' else 'blacklist')+'.expired'
   insert(d,'rule-expiry:'+r['id'],r['expires'],'System',event,r['kind'],r['value'],{'reason':r['reason'],'id':r['id'],'expires':r['expires']})
  for r in d.execute("SELECT * FROM block_retention WHERE expires<=? AND NOT EXISTS (SELECT 1 FROM policy_events e WHERE e.event_key='block-expiry:'||block_retention.ip||':'||block_retention.expires)",(at,)).fetchall():
   insert(d,'block-expiry:'+r['ip']+':'+r['expires'],r['expires'],'System','block.expired','ip',r['ip'],{'expires':r['expires'],'source':r['last_source'],'score':r['score']})

def intervals(values,version):
 result=[]
 for n in sorted((n for n in values if n.version==version),key=lambda n:int(n.network_address)):
  lo,hi=int(n.network_address),int(n.broadcast_address)
  if result and lo<=result[-1][1]+1:result[-1][1]=max(hi,result[-1][1])
  else:result.append([lo,hi])
 return result

def difference(values,others):
 """Address coverage difference, rather than textual prefix changes."""
 result=[]
 for version,cls in [(4,ipaddress.IPv4Address),(6,ipaddress.IPv6Address)]:
  left,right=intervals(values,version),intervals(others,version);j=0
  for lo,hi in left:
   while j<len(right) and right[j][1]<lo:j+=1
   p=j;start=lo
   while p<len(right) and right[p][0]<=hi:
    a,b=right[p]
    if a>start:result.extend(ipaddress.summarize_address_range(cls(start),cls(min(hi,a-1))))
    start=max(start,b+1)
    if start>hi:break
    p+=1
   if start<=hi:result.extend(ipaddress.summarize_address_range(cls(start),cls(hi)))
 return result

def list_changes(store,lists,created,generation,actor='System',initial_baseline=False):
 from core import now
 with store.connect() as d:
  tracked=d.execute("SELECT 1 FROM state WHERE key='policy_event_list_tracking'").fetchone()
  for name,nets in lists.items():
   values=sorted(set(str(n) for n in nets));digest=hashlib.sha256(json.dumps(values).encode()).hexdigest();key='policy_event_list:'+name
   saved=d.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone();old=json.loads(saved[0]) if saved else None
   if old and old['hash']==digest:continue
   if not initial_baseline:
    previous=[ipaddress.ip_network(v) for v in old['values']] if old else []
    for action,changed in [('list.added',difference(nets,previous)),('list.removed',difference(previous,nets))]:
     for n in changed:
      target=str(n.network_address) if n.num_addresses==1 else str(n)
      insert(d,'list:'+generation+':'+name+':'+action+':'+target,created,actor,action,'ip' if n.num_addresses==1 else 'network',target,{'list':name,'generation':generation})
   d.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(key,json.dumps({'hash':digest,'values':values})))
  if not tracked:d.execute('INSERT INTO state VALUES(?,?)',('policy_event_list_tracking',json.dumps({'started':now(),'baseline_created':created})))

def baseline(store,output):
 if store.state('policy_event_list_tracking'):return
 generation=(pathlib.Path(output)/'current').resolve()
 try:
  m=json.loads((generation/'manifest.json').read_text());lists={}
  for name in m['counts']:
   data=(generation/(name+'.txt')).read_bytes()
   if hashlib.sha256(data).hexdigest()!=m['sha256'][name]:raise ValueError('Event baseline checksum mismatch')
   lines=data.decode().splitlines()
   if len(lines)!=m['counts'][name]:raise ValueError('Event baseline count mismatch')
   lists[name]=[ipaddress.ip_network(v) for v in lines]
 except FileNotFoundError:return
 list_changes(store,lists,m['created'],generation.name,initial_baseline=True)

def matching(store,address,asn='',limit=None,offset=0):
 """Exact-IP index plus related network/range/current-ASN rules."""
 from core import ip
 target=ip(address);address=str(target);point=format(int(target),'032x')
 with store.connect(commit=False) as d:
  where="((kind='ip' AND target=?) OR (kind IN ('network','range') AND family=? AND lo<=? AND hi>=?))";args=[address,target.version,point,point]
  owners=['AS'+v for v in str(asn).split() if v.isdigit()]
  if owners:where='('+where+" OR (kind='asn' AND target IN ("+','.join('?' for v in owners)+')))';args+=owners
  total=d.execute('SELECT count(*) FROM policy_events WHERE '+where,args).fetchone()[0]
  query='SELECT * FROM policy_events WHERE '+where+' ORDER BY at DESC,recorded DESC,event_key DESC'
  if limit is not None:query+=' LIMIT ? OFFSET ?';args.extend([limit,offset])
  rows=[]
  for r in d.execute(query,args):
   item=dict(r);details=json.loads(item.pop('details'));item.update(label=LABELS.get(item['action'],item['action']),list=details.get('list',''),notes=details.get('reason',''),expires=details.get('expires'),emergency=bool(details.get('emergency')),score=details.get('score'));rows.append(item)
  return {'rows':rows,'total':total,'tracking':store.state('policy_event_list_tracking')}
