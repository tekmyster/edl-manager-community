"""Bounded local behavior retrieval. Similarity is a review aid, never identity."""
import datetime as dt,json

VERSION='correlation-2'
TOKEN_LIMIT=64
POSTING_LIMIT=128
POOL_LIMIT=512
SCHEMA='''
CREATE TABLE IF NOT EXISTS correlation_features(feature TEXT NOT NULL,created TEXT NOT NULL,packet_id TEXT NOT NULL,PRIMARY KEY(feature,created,packet_id));
CREATE TABLE IF NOT EXISTS correlation_ready(packet_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS correlation_link_evidence(link_id TEXT PRIMARY KEY,version TEXT NOT NULL,details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS correlation_state(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS correlation_runs(packet_id TEXT PRIMARY KEY,created TEXT NOT NULL,details TEXT NOT NULL);
'''
UNCERTAINTY=[
 'Shared scanners, tools, NAT or proxies can produce similar activity from unrelated users.',
 'Address ownership can change; these observations do not establish a persistent operator.',
 'History is partial. Missing samples, collection delays and clock differences can distort timing.',
 'Feature similarity is uncalibrated and transfers no scores, blocks or permanent status.'
]

def tokens(features):
 # Paths first; sensor, method, ownership and policy are never retrieval evidence.
 return sorted((v for v in features if v.startswith(('path:','params:','action:','sequence:'))),key=lambda v:(not v.startswith('path:'),v))[:TOKEN_LIMIT]

def index(db,ident,features):
 if db.execute('SELECT 1 FROM correlation_ready WHERE packet_id=?',(ident,)).fetchone():return
 row=db.execute('SELECT created FROM packets WHERE id=?',(ident,)).fetchone()
 db.executemany('INSERT OR IGNORE INTO correlation_features VALUES(?,?,?)',[(v,row[0],ident) for v in tokens(features)])
 db.execute('INSERT OR IGNORE INTO correlation_ready VALUES(?)',(ident,))

def citations(packet,common):
 # Select the same deterministic paths on each side, then cite actual events.
 events={}
 for event in sorted(packet.get('events',[]),key=lambda e:(e.get('seen',''),e['id'])):
  events.setdefault(event.get('path',''),event)
 paths=sorted(v[5:] for v in common if v.startswith('path:') and v not in ('path:/','path:'))[:3]
 return [events[path] for path in paths if path in events]

def weight(v):
 return 1 if v.startswith('path:') else .5 if v.startswith('params:') else .2 if v.startswith('action:') else 0

def retrieve(db,ident,limit=3,at=None):
 at=at or dt.datetime.now(dt.timezone.utc)
 own=db.execute('SELECT * FROM packets WHERE id=?',(ident,)).fetchone()
 if not own:return [],{}
 features=set(json.loads(own['features']));packet=json.loads(own['content'])
 selected=[v for v in tokens(features) if v.startswith('path:') and v not in ('path:/','path:')]
 if len(selected)<2:selected=[]
 cut=(at-dt.timedelta(days=365)).isoformat(timespec='seconds');end=(at+dt.timedelta(minutes=5)).isoformat(timespec='seconds')
 pool={};read=0;saturated=[]
 for token in selected:
  # Each index range reads at most 129 entries, even for a ubiquitous scanner.
  rows=db.execute('SELECT packet_id FROM correlation_features WHERE feature=? AND created>=? AND created<=? ORDER BY created DESC,packet_id DESC LIMIT ?',(token,cut,end,POSTING_LIMIT+1)).fetchall()
  read+=len(rows)
  if len(rows)>POSTING_LIMIT:saturated.append(token.split(':',1)[0])
  for r in rows[:POSTING_LIMIT]:pool[r[0]]=pool.get(r[0],0)+1
 ids=sorted(pool,key=lambda p:(-pool[p],p))[:POOL_LIMIT];result=[]
 for peer in ids:
  row=db.execute('SELECT id,ip,created,features,content FROM packets WHERE id=?',(peer,)).fetchone()
  if not row or row['ip']==own['ip']:continue
  other=set(json.loads(row['features']));common=features&other
  # Two distinct paths are required; generic actions/parameters alone abstain.
  if len([v for v in common if v.startswith('path:') and v not in ('path:/','path:')])<2:continue
  denominator=sum(weight(v) for v in features|other)
  score=sum(weight(v) for v in common)/denominator if denominator else 0
  if score<.45:continue
  historical=json.loads(row['content'])
  supported=common&{'path:'+e.get('path','') for e in packet.get('events',[])}&{'path:'+e.get('path','') for e in historical.get('events',[])}
  current_events=citations(packet,supported);historical_events=citations(historical,supported)
  if len(current_events)<2 or len(historical_events)<2:continue
  result.append({'candidate_id':peer,'candidate_ip':row['ip'],'similarity':round(score,3),'shared_features':sorted(common,key=lambda v:(not v.startswith('path:'),v))[:8],'current_events':current_events,'historical_events':historical_events,'coverage':historical.get('coverage','unknown'),'indexed':row['created'],'retrieval_version':VERSION,'uncertainty':UNCERTAINTY,'interpretation':'Similar observed behavior; shared tooling remains an alternative, not actor attribution or inherited enforcement'})
 unique=[];seen=set()
 for candidate in sorted(result,key=lambda c:(-c['similarity'],c['candidate_id'])):
  if candidate['candidate_ip'] in seen:continue
  seen.add(candidate['candidate_ip']);unique.append(candidate)
  if len(unique)>=max(0,min(10,limit)):break
 if limit<=0:unique=[]
 state=db.execute("SELECT value FROM correlation_state WHERE name='index_partial'").fetchone();pending=state[0] if state else 1
 details={'version':VERSION,'tokens':len(selected),'postings_read':read,'postings_bound':TOKEN_LIMIT*(POSTING_LIMIT+1),'pool_examined':len(ids),'pool_bound':POOL_LIMIT,'saturated_token_kinds':sorted(set(saturated)),'pool_truncated':len(pool)>POOL_LIMIT,'index_partial':bool(pending),'returned':len(unique),'window_days':365,'uncertainty':UNCERTAINTY}
 db.execute('INSERT INTO correlation_runs VALUES(?,?,?) ON CONFLICT(packet_id) DO UPDATE SET created=excluded.created,details=excluded.details',(ident,at.isoformat(timespec='seconds'),json.dumps(details)))
 return unique,details
