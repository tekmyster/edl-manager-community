"""Reviewed public advisory context. No model, scores, private outbound data or auto-activation."""
import argparse,copy,datetime as dt,hashlib,json,os,pathlib,re,urllib.request,uuid
from filelock import FileLock
from behavior_ai import digest,timestamp,now

MAX_BYTES=3000000
STARTER=pathlib.Path(__file__).with_name('behavior-reference-starter.json')
PUBLIC_SOURCES={
 'apache':('https://httpd.apache.org/security/vulnerabilities_24.html',b'CVE-2021-41773'),
 'phpunit-maintainer':('https://phpunit.expert/articles/phpunit-a-security-risk.html',b'CVE-2017-9841'),
 'phpunit-fix':('https://raw.githubusercontent.com/sebastianbergmann/phpunit/284a69fb88a2d0845d23f42974a583d8f59bf5a5/src/Util/PHP/eval-stdin.php',b'php://stdin'),
 'papercut':('https://www.papercut.com/kb/Main/PO-1216-and-PO-1219',b'SetupCompleted')}
SCHEMA='''
CREATE TABLE IF NOT EXISTS reference_reviews(id TEXT PRIMARY KEY,created TEXT NOT NULL,actor TEXT NOT NULL,outcome TEXT NOT NULL,candidate_hash TEXT NOT NULL,active_hash TEXT NOT NULL,notes TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS history_reference_index(id TEXT NOT NULL,scope TEXT NOT NULL,ip TEXT NOT NULL,pattern TEXT NOT NULL,seen TEXT NOT NULL,PRIMARY KEY(id,scope));
CREATE INDEX IF NOT EXISTS history_reference_lookup ON history_reference_index(ip,scope,pattern,seen DESC,id);
CREATE TRIGGER IF NOT EXISTS history_reference_delete AFTER DELETE ON event_history BEGIN DELETE FROM history_reference_index WHERE id=OLD.id AND scope=OLD.scope; END;
'''

def read(path,maximum=131072):
 with pathlib.Path(path).open('rb') as stream:body=stream.read(maximum+1)
 if len(body)>maximum:raise ValueError('Reference file exceeds its size bound.')
 return json.loads(body)

def validate(data):
 if data.get('schema') not in (1,2) or not isinstance(data.get('rules'),list) or len(data['rules'])>32:raise ValueError('Invalid reference catalog.')
 for rule in data['rules']:
  if not all(isinstance(rule.get(k),str) and 0<len(rule[k])<=500 for k in ('id','version','label','reviewed_by','rationale')):raise ValueError('Missing reviewed rule provenance.')
  if rule['kind'] not in ('tool','cve') or rule['kind']=='cve' and not re.fullmatch(r'CVE-\d{4}-\d{4,}',rule['label']):raise ValueError('Invalid association label.')
  match=rule['match']
  if data['schema']==1:
   if not isinstance(match,dict) or not 3<=len(match)<=4 or not set(match)<=set(('path','method','action','client_type')):raise ValueError('Invalid legacy match.')
   if not match.get('path','').startswith('/') or match.get('method') not in ('GET','POST','PUT','PATCH','DELETE','HEAD'):raise ValueError('Invalid legacy request match.')
   if not all(isinstance(v,str) and 0<len(v)<=200 for v in match.values()):raise ValueError('Invalid legacy match fields.')
  else:
   if match not in ({'pattern':'apache_cgi_traversal','method':'POST'},{'pattern':'phpunit_eval_stdin','method':'POST'}):raise ValueError('Unreviewed matcher implementation.')
   if rule.get('evidence_level') not in ('targeting_only','traversal_probe'):raise ValueError('Unsupported evidence strength.')
   if not isinstance(rule.get('limitations'),list) or not rule['limitations']:raise ValueError('Explain association uncertainty.')
  if not isinstance(rule.get('references'),list) or not 1<=len(rule['references'])<=4:raise ValueError('Primary references required.')
  for ref in rule['references']:
   from urllib.parse import urlsplit
   u=urlsplit(ref['url'])
   if u.scheme!='https' or not u.hostname or u.username or u.password or ref['primary'] is not True or not timestamp(ref['retrieved_at']):raise ValueError('Invalid primary reference.')
   if not re.fullmatch('[a-f0-9]{64}',ref['sha256']) or not ref['publisher'] or not ref['version']:raise ValueError('Source byte hash and version required.')
 return data

def load(path):
 path=pathlib.Path(path)
 try:
  data=validate(read(path));return {**data,'status':'reviewed_local','sha256':digest(data)}
 except (OSError,ValueError,KeyError,TypeError,AttributeError):return {'status':'missing_or_invalid','rules':[]}

def active(directory):
 directory=pathlib.Path(directory);path=directory/'behavior-references.json'
 if not path.exists():
  result=load(STARTER);return {**result,'status':'packaged_starter' if result['status']=='reviewed_local' else 'unavailable'}
 result=load(path)
 if result['status']=='reviewed_local':return result
 previous=load(directory/'behavior-references.last-good.json')
 return {**previous,'status':'last_good' if previous['status']=='reviewed_local' else 'unavailable','warning':'Local catalog invalid; last-good context only, or unavailable. No automatic source or rule changes.'}

def matches(rule,event):
 match=rule['match']
 if 'pattern' not in match:return all(event.get(k)==v for k,v in match.items())
 if event.get('method')!=match['method']:return False
 # Fixed, privacy-safe hints are derived from the original saved path before
 # identifier redaction. They are not an additional independent observation.
 pattern=match['pattern'];hint=event.get('endpoint_hint')
 if hint==pattern:return True
 return endpoint_hint(event.get('path',''))==pattern

def endpoint_hint(value):
 from urllib.parse import unquote,urlsplit
 try:path=unquote(urlsplit(str(value)[:4096]).path)
 except ValueError:return ''
 if path.endswith('/phpunit/phpunit/src/Util/PHP/eval-stdin.php') or path=='/phpunit/src/Util/PHP/eval-stdin.php':return 'phpunit_eval_stdin'
 if path.startswith('/cgi-bin/') and '..' in path.split('/') and path.endswith(('/bin/sh','/bin/bash','/etc/passwd')):return 'apache_cgi_traversal'
 return ''

def index_event(db,address,event,scope):
 hint=event.get('endpoint_hint') or endpoint_hint(event.get('path',''))
 if hint and event.get('method')=='POST' and event.get('provenance',{}).get('detail')!='summary':
  db.execute('INSERT OR IGNORE INTO history_reference_index VALUES(?,?,?,?,?)',(event['id'],scope,address,hint,event['seen']))

def backfill(brain,limit=200):
 with brain.connect() as db:
  row=db.execute("SELECT value FROM retention_state WHERE name='reference_history_cursor'").fetchone();cursor=int(row[0]) if row else 0
  rows=db.execute('SELECT rowid,ip,scope,content FROM event_history WHERE rowid>? ORDER BY rowid LIMIT ?',(cursor,max(1,min(200,limit)))).fetchall()
  for row in rows:index_event(db,row['ip'],json.loads(row['content']),row['scope'])
  if rows:cursor=rows[-1]['rowid']
  db.execute("INSERT OR REPLACE INTO retention_state VALUES('reference_history_cursor',?)",(str(cursor),))
  partial=bool(db.execute('SELECT 1 FROM event_history WHERE rowid>? LIMIT 1',(cursor,)).fetchone())
 return {'scanned':len(rows),'bound':200,'partial':partial}

def representative_events(brain,address,source_cfg,at,days=30):
 from evidence_history import collection_scope,active_sources
 scope=collection_scope(brain,source_cfg);allowed=active_sources(brain,source_cfg);result=[]
 cut=(at-dt.timedelta(days=max(1,min(30,days)))).isoformat();end=(at+dt.timedelta(minutes=5)).isoformat()
 with brain.connect() as db:
  for pattern in ('apache_cgi_traversal','phpunit_eval_stdin'):
   rows=db.execute('SELECT id,scope FROM history_reference_index WHERE ip=? AND scope=? AND pattern=? AND seen>=? AND seen<=? ORDER BY seen DESC,id LIMIT 2',(address,scope,pattern,cut,end)).fetchall()
   for row in rows:
    event=db.execute('SELECT content FROM event_history WHERE id=? AND scope=?',(row['id'],row['scope'])).fetchone()
    if event:
     event=json.loads(event[0])
     if allowed is None or event['source'] in allowed:result.append(event)
 return result

def atomic(path,value):
 path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True);temp=path.with_name(path.name+'.'+uuid.uuid4().hex+'.tmp')
 try:
  with temp.open('w',encoding='utf-8') as stream:json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
  os.replace(temp,path)
 finally:temp.unlink(missing_ok=True)

def fetch(url):
 # Only fixed public URLs below reach this function. No request includes local
 # evidence, IPs, inventory, authentication or user-supplied URLs.
 with urllib.request.urlopen(url,timeout=8) as response:
  if response.url!=url:raise ValueError('Source redirected; review the new URL offline.')
  body=response.read(MAX_BYTES+1)
  if not body or len(body)>MAX_BYTES:raise ValueError('Public source exceeds read bound.')
  return body,{'etag':response.headers.get('ETag'),'last_modified':response.headers.get('Last-Modified')}

def refresh(directory,fetcher=None,at=None):
 directory=pathlib.Path(directory);directory.mkdir(parents=True,exist_ok=True);at=at or dt.datetime.now(dt.timezone.utc)
 with FileLock(str(directory/'reference-refresh.lock'),timeout=0):
  state_path=directory/'reference-refresh.json'
  try:state=read(state_path)
  except (OSError,ValueError):state={}
  prior=timestamp(state.get('at'))
  if prior and (at-prior).total_seconds()<86400:raise ValueError('Public reference refresh is limited to once per 24 hours, including failed attempts.')
  state={'at':at.isoformat(),'status':'fetching','maximum_sources':4,'maximum_bytes_per_source':MAX_BYTES};atomic(state_path,state)
  current=active(directory);candidate={k:copy.deepcopy(v) for k,v in current.items() if k not in ('status','sha256','warning')};sources={};blobs=directory/'reference-sources';blobs.mkdir(exist_ok=True)
  try:
   for ident,(url,marker) in PUBLIC_SOURCES.items():
    body,headers=(fetcher or fetch)(url)
    if len(body)>MAX_BYTES or marker not in body:raise ValueError('Expected primary-source content unavailable.')
    sha=hashlib.sha256(body).hexdigest();dest=blobs/(sha+'.source')
    if not dest.exists():
     with dest.open('wb') as stream:stream.write(body)
    sources[ident]={'url':url,'sha256':sha,'retrieved_at':at.isoformat(),'version':'source-bytes-'+sha[:16],**headers}
   changes=[]
   collections=[rule['references'] for rule in candidate['rules']]+[item['references'] for item in candidate.get('unavailable_associations',[])]
   for refs in collections:
    for ref in refs:
     ident=ref.get('source_id')
     if ident not in sources:continue
     fresh=sources[ident]
     if ref['sha256']!=fresh['sha256']:changes.append({'source':ident,'before':ref['sha256'],'after':fresh['sha256']})
     ref.update(fresh)
   # Retrieval timestamps alone are not new source or attack patterns.
   if changes:candidate['version']='sources-'+digest({k:v['sha256'] for k,v in sources.items()})[:16]
   changed_ids={v['source'] for v in changes}
   for rule in candidate['rules']:
    if any(ref.get('source_id') in changed_ids for ref in rule['references']):rule['version']='pattern-1-sources-'+digest([ref['sha256'] for ref in rule['references']])[:16]
   validate(candidate);pending={'candidate':candidate,'hash':digest(candidate),'created':at.isoformat(),'changes':changes,'sources':sources,'note':'Rule logic is unchanged. Review changed source bytes and applicability before activation.'}
   atomic(directory/'behavior-references.pending.json',pending);state.update(status='pending_review',candidate_hash=pending['hash'],changes=changes);atomic(state_path,state)
   # Active, last-good and pending source bytes remain protected. Older public
   # snapshots beyond sixteen blobs expire; review hashes remain in the ledger.
   keep={v['sha256'] for v in sources.values()}
   for catalog in (current,load(directory/'behavior-references.last-good.json')):
    for rule in catalog.get('rules',[])+catalog.get('unavailable_associations',[]):keep.update(r['sha256'] for r in rule['references'])
   files=sorted(blobs.glob('*.source'),key=lambda p:p.stat().st_mtime,reverse=True)
   for blob in files[16:]:
    if blob.stem not in keep:blob.unlink()
   return state
  except Exception as exc:
   state.update(status='failed_last_good_retained',error_type=type(exc).__name__);atomic(state_path,state);return state

def review(brain,expected,outcome,notes,actor):
 if outcome not in ('accepted','rejected') or not 5<=len(notes.strip())<=1000:raise ValueError('Explain the reference review in 5–1,000 characters.')
 directory=pathlib.Path(brain.store.path).parent
 with FileLock(str(directory/'reference-refresh.lock'),timeout=0):
  try:pending=read(directory/'behavior-references.pending.json',262144);candidate=validate(pending['candidate'])
  except (OSError,ValueError,KeyError,TypeError):raise ValueError('No valid pending reference review.') from None
  if expected!=pending['hash'] or digest(candidate)!=expected:raise ValueError('Reference candidate changed; review it again.')
  for ident,source in pending.get('sources',{}).items():
   if ident not in PUBLIC_SOURCES or source['url']!=PUBLIC_SOURCES[ident][0]:raise ValueError('Unexpected source location.')
   source_file=directory/'reference-sources'/(source['sha256']+'.source')
   if not re.fullmatch('[a-f0-9]{64}',source['sha256']) or not source_file.exists() or source_file.stat().st_size>MAX_BYTES or hashlib.sha256(source_file.read_bytes()).hexdigest()!=source['sha256']:raise ValueError('Reviewed source bytes are missing or changed.')
  previous=active(directory)
  if outcome=='accepted':
   for rule in candidate['rules']:rule.update(reviewed_by=actor,reviewed_at=now())
   atomic(directory/'behavior-references.last-good.json',{k:v for k,v in previous.items() if k not in ('status','sha256','warning')})
   atomic(directory/'behavior-references.json',candidate)
  with brain.connect() as db:db.execute('INSERT INTO reference_reviews VALUES(?,?,?,?,?,?,?)',(uuid.uuid4().hex,now(),actor,outcome,expected,digest(candidate) if outcome=='accepted' else previous.get('sha256',''),notes.strip()))
  (directory/'behavior-references.pending.json').unlink()
 brain.store.audit(actor,'behavior.references.review',{'candidate':expected,'outcome':outcome})

def state(brain):
 directory=pathlib.Path(brain.store.path).parent;result={'active':active(directory),'pending':None,'refresh':None}
 for key,name in [('pending','behavior-references.pending.json'),('refresh','reference-refresh.json')]:
  try:result[key]=read(directory/name,262144)
  except (OSError,ValueError):pass
 with brain.connect() as db:result['history']=[dict(r) for r in db.execute('SELECT * FROM reference_reviews ORDER BY rowid DESC LIMIT 20')]
 return result

if __name__=='__main__':
 parser=argparse.ArgumentParser(description='Stage public primary-source refresh; never activate rules automatically.');parser.add_argument('action',choices=['refresh']);parser.add_argument('--directory',required=True);args=parser.parse_args();print(json.dumps(refresh(args.directory)))
