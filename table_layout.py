"""Account-scoped IP table layout and effective Manager policy labels."""

import datetime as dt,ipaddress,json

DEFAULT=('ip','policy','priority','score','last_seen','sources','ports','client_type','asn','enrichment_sources','enrichment','repeat','first_seen','block_recorded','block_expires')

def layout(saved,available):

 order=['ip']+[k for k in saved.get('order',DEFAULT) if k in available and k!='ip']

 order=list(dict.fromkeys(order+[k for k in DEFAULT if k in available]))
 if 'priority' in available and 'priority' not in saved.get('order',DEFAULT):
  order.remove('priority');order.insert(order.index('policy')+1 if 'policy' in order else 1,'priority')

 visible=set(saved.get('visible',order)) & set(available);visible.add('ip')
 if 'priority' in available and 'priority' not in saved.get('order',DEFAULT):visible.add('priority')

 if 'priority' in available and 'priority' not in saved.get('order',DEFAULT):visible.add('priority')

 return order,visible



def policy_rows(store,rows,rules):

 from core import selector
 from permanent_policy import active
 permanent=active(store)

 compiled=[]

 for rule in rules:

  if rule['kind']=='asn':nets=[]

  else:nets=selector(rule['value'])[2]

  compiled.append((rule,nets))

 owners={}

 if any(r['kind']=='asn' for r in rules):

  from core import now

  with store.connect(commit=False) as d:

   owners={r['ip']:json.loads(r['payload']) for r in d.execute("SELECT ip,payload FROM cache WHERE provider='asn' AND status='ok' AND expires>?",(now(),))}

 result=[];epoch=dt.datetime.now(dt.timezone.utc).timestamp()

 for row in rows:

  address=ipaddress.ip_address(row['ip']);matched=[]

  for rule,nets in compiled:

   if rule['kind']=='asn':

    owner=owners.get(row['ip'],{});hit=rule['value'][2:] in str(owner.get('asn','')).split() and owner.get('database_build_epoch',epoch)>epoch-30*86400

   else:hit=any(address in n for n in nets)

   if hit:matched.append(rule)

  emergency=next((r for r in matched if r['emergency']),None)

  allowed=next((r for r in matched if r['action']=='allow'),None)

  blocked=next((r for r in matched if r['action']=='block'),None)

  if emergency:policy,reason='Denied','Emergency override: '+emergency['reason']

  elif allowed:policy,reason='Allowed','Whitelist: '+allowed['reason']

  elif row.get('verified_crawler'):policy,reason='Allowed','Verified crawler protection'

  elif blocked:policy,reason='Denied','Blacklist: '+blocked['reason']

  elif row['ip'] in permanent:policy,reason='Denied','Permanent repeat-offender block earned '+permanent[row['ip']]

  elif row.get('auto_candidate'):policy,reason='Denied','Automatic block threshold reached'

  else:policy,reason='Evaluating','No active allow or block decision'

  result.append({**row,'policy':policy,'policy_reason':reason})

 from greynoise_enrichment import decorate

 return decorate(result)

