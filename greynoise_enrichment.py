"""Bounded shared IP intelligence, freshness, and analyst review signals."""
import datetime as dt,ipaddress,json,requests
from core import now
UTC=dt.timezone.utc
DEFAULT={'enabled':True,'weekly_budget':30,'score_enabled':True}

def settings(store):return {**DEFAULT,**(store.state('greynoise_settings') or {})}

def observed_fresh(payload,at=None):
 try:
  stamp=dt.datetime.fromisoformat(str(payload['last_seen']).replace('Z','+00:00'))
  if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=UTC)
  current=at or dt.datetime.now(UTC)
  return current-dt.timedelta(days=7)<=stamp<=current+dt.timedelta(minutes=5)
 except (ValueError,TypeError,KeyError):return False

def assessment(payload,base_score=0,local_sources=False,valid=True):
 classification=payload.get('classification','unchecked')
 fresh=valid and (payload.get('found') is False or observed_fresh(payload))
 malicious=fresh and classification=='malicious' and payload.get('found') is not False
 benign=fresh and classification=='benign'
 return {'classification':classification,'fresh':fresh,'last_seen':payload.get('last_seen'),
         'actor':payload.get('name') or '', 'corroborated':bool(malicious and local_sources),
         'possible_conflict':bool(benign and base_score>=75),
         'priority':('Review benign conflict' if benign and base_score>=75 else 'Corroborated attack' if malicious and local_sources else 'Review suspicious activity' if fresh and classification=='suspicious' else 'Local evidence only'),
         'score_signal':bool(malicious and local_sources)}

def enrich(store,rows,key,requester=None):
 config=settings(store)
 if not key or not config['enabled']:return 0
 current=dt.datetime.now(UTC);week=current.strftime('%G-W%V');quota_key='greynoise_quota:'+week
 used=int(store.state(quota_key) or 0);budget=int(config['weekly_budget']);count=0
 status=store.state('greynoise_status') or {}
 if status.get('retry_after','')>now():return 0
 request=requester or requests.get
 def collateral_risk(row):
  return row.get('auto_candidate') and (row['score']<=75 or any('Shared search/cloud' in note or 'Provider/research' in note for note in row.get('review_notes',[])))
 pending=sorted(rows,key=lambda r:(any(c['provider']=='greynoise' for c in r.get('cache_status',[])),0 if collateral_risk(r) else 1,0 if r.get('auto_candidate') else 1,-r['score'],r['ip']))
 for row in pending:
  if count>=2 or used>=budget:break
  address=row['ip']
  parsed=ipaddress.ip_address(address)
  if parsed.version!=4 or not parsed.is_global or store.cached(address,'greynoise'):continue
  # Persist the claim and quota before I/O, under the shared enrichment worker lock.
  store.cache(address,'greynoise',{},status='in-flight',hours=.25)
  used+=1;count+=1;store.state(quota_key,used)
  try:
   from analytics_store import event
   event(store,'greynoise','outbound',address)
   response=request('https://api.greynoise.io/v3/community/'+address,headers={'key':key,'User-Agent':'Community-EDL-Manager/1.0'},timeout=15)
   if response.status_code==429:
    event(store,'greynoise','rate_limited',address)
    store.cache(address,'greynoise',{},status='rate-limited',hours=24)
    store.state('greynoise_status',{'status':'rate-limited','retry_after':(current+dt.timedelta(hours=24)).isoformat(timespec='seconds')});break
   if response.status_code==404:
    event(store,'greynoise','no_data',address)
    store.cache(address,'greynoise',{'classification':'unknown','found':False},hours=168);continue
   response.raise_for_status();data=response.json()
   if data.get('ip')!=address or data.get('classification') not in ('benign','malicious','suspicious','unknown'):raise ValueError('Unexpected IP classification')
   payload={k:data.get(k) for k in ('classification','name','last_seen','noise','riot')}
   payload.update(found=True,origin='GreyNoise',score_enabled=config['score_enabled'])
   store.cache(address,'greynoise',payload,hours=168)
   event(store,'greynoise','usable',address)
  except (requests.RequestException,ValueError,TypeError):
   from analytics_store import event
   event(store,'greynoise','error',address)
   store.cache(address,'greynoise',{},status='failed',hours=1)
 store.state('greynoise_usage',{'week':week,'used':used,'budget':budget,'updated':now()})
 return count

def decorate(rows):
 result=[]
 for row in rows:
  intelligence=row.get('intelligence') or assessment({},valid=False)
  benign=intelligence.get('fresh') and intelligence.get('classification')=='benign'
  conflict=bool(benign and row.get('policy')=='Denied')
  priority='Review benign conflict' if conflict else 'Protected benign actor' if benign and row.get('policy')=='Allowed' else intelligence['priority']
  result.append({**row,'intelligence':{**intelligence,'conflict':conflict},'priority':priority})
 return result

def metrics(store,rows):
 data=decorate(rows);fresh=sum(r['intelligence']['fresh'] for r in data)
 with store.connect(commit=False) as d:
  reviews=[json.loads(r['details']) for r in d.execute("SELECT details FROM audit WHERE action='intelligence.review' AND at>=? ORDER BY id DESC",((dt.datetime.now(UTC)-dt.timedelta(days=30)).isoformat(timespec='seconds'),))]
 latest={}
 for review in reviews:latest.setdefault(review['ip'],review)
 reviews=list(latest.values())
 return {'total':len(data),'fresh':fresh,'coverage_percent':round(100*fresh/len(data),1) if data else 0,
         'malicious':sum(r['intelligence']['fresh'] and r['intelligence']['classification']=='malicious' for r in data),
         'conflicts':sum(r['intelligence']['conflict'] for r in data),
         'stale':sum(r['intelligence']['classification']!='unchecked' and not r['intelligence']['fresh'] for r in data),
         'unchecked':sum(r['intelligence']['classification']=='unchecked' for r in data),
         'reviewed':len({r['ip'] for r in reviews}),
         'false_positives':len({r['ip'] for r in reviews if r.get('outcome')=='false_positive'})}
