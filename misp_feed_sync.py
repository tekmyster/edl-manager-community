"""Validate public IP feeds and stage local-only, context-only MISP snapshots.

No firewall export or MISP import occurs unless --import is explicitly selected.
The configured native Cake shell performs imports using an existing local account.
"""
import argparse,datetime as dt,hashlib,ipaddress,json,pathlib,re,shutil,subprocess,tempfile,urllib.request,urllib.parse,uuid
UTC=dt.timezone.utc
MAX_BYTES=8_000_000
MAX_ENTRIES=50_000

def stamp(at):return at.astimezone(UTC).isoformat(timespec='seconds')
def digest(value):return hashlib.sha256(value).hexdigest()

def validate_config(config):
 sources=config.get('sources',[])
 if not sources or len(sources)>30:raise ValueError('Configure between 1 and 30 sources')
 ids=set();urls=set()
 for source in sources:
  identity=source['id'];url=source['url'];parsed=urllib.parse.urlsplit(url)
  if not re.fullmatch(r'[a-z0-9_-]{1,64}',identity) or identity in ids:raise ValueError('Source IDs must be unique safe identifiers')
  if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:raise ValueError('Use an HTTP(S) source without credentials or fragment')
  if any(re.search(r'key|token|pass|secret',name,re.I) for name,value in urllib.parse.parse_qsl(parsed.query)):raise ValueError('Credential-bearing source URLs are not supported')
  canonical=urllib.parse.urlunsplit((parsed.scheme.lower(),parsed.netloc.lower(),parsed.path.rstrip('/'),parsed.query,''))
  if canonical in urls:raise ValueError('Duplicate source URL')
  if not 1<=source.get('ttl_hours',48)<=168:raise ValueError('Source TTL must be between 1 and 168 hours')
  if source.get('to_ids',False):raise ValueError('Managed feeds are context only; to_ids must remain false')
  ids.add(identity);urls.add(canonical)
 return sources

def public_network(value):
 network=ipaddress.ip_network(value,strict=False)
 if not network.network_address.is_global or not network.broadcast_address.is_global or network.is_multicast:raise ValueError('Nonpublic IP indicator')
 # Endpoints alone do not detect a supernet crossing reserved/private space.
 forbidden=list(network.network_address._constants._private_networks)
 if network.version==4:forbidden += [ipaddress.ip_network('100.64.0.0/10'),ipaddress.ip_network('224.0.0.0/3')]
 if any(network.overlaps(other) for other in forbidden if other.version==network.version):raise ValueError('IP indicator crosses nonpublic space')
 return str(network.network_address) if network.num_addresses==1 else str(network)

def parse_feed(raw,content_type='',allow_empty=False):
 if len(raw)>MAX_BYTES:raise ValueError('Feed byte guard exceeded')
 text=raw.decode('utf-8-sig')
 if 'html' in content_type.lower() or re.search(r'<(?:!doctype|html|head|body)\b',text[:2048],re.I):raise ValueError('HTML is not an IP feed')
 values=set();comment_count=0
 for line in text.splitlines():
  line=line.strip()
  if not line:continue
  if line.startswith(('#',';','//')):comment_count+=1;continue
  line=line.split('#',1)[0].strip()
  if '-' in line:
   first,last=[ipaddress.ip_address(part.strip()) for part in line.split('-',1)]
   if first.version!=last.version or int(first)>int(last):raise ValueError('Invalid IP range')
   for network in ipaddress.summarize_address_range(first,last):values.add(public_network(network))
  else:values.add(public_network(line))
  if len(values)>MAX_ENTRIES:raise ValueError('Feed indicator guard exceeded')
 if not values and not (allow_empty and comment_count):raise ValueError('Empty feed without an explicit valid-empty policy')
 return sorted(values),comment_count

def fetch(source):
 request=urllib.request.Request(source['url'],headers={'User-Agent':'Local MISP context ingestion/1.0'})
 with urllib.request.urlopen(request,timeout=45) as response:
  raw=response.read(MAX_BYTES+1);metadata={'http_status':response.status,'content_type':response.headers.get('Content-Type',''),'last_modified':response.headers.get('Last-Modified'),'final_url':response.url}
 if urllib.parse.urlsplit(metadata['final_url']).scheme not in ('http','https'):raise ValueError('Unexpected redirect scheme')
 if source['url'].startswith('https:') and not metadata['final_url'].startswith('https:'):raise ValueError('HTTPS downgrade rejected')
 return raw,metadata

def make_event(source,values,fetched):
 url=source['url'];event_uuid=str(uuid.uuid5(uuid.NAMESPACE_URL,'local-context-feed:'+url))
 attributes=[]
 for value in values:
  attributes.append({'uuid':str(uuid.uuid5(uuid.NAMESPACE_URL,'local-context-indicator:'+url+'|'+value)),'type':'ip-dst','category':'Network activity','value':value,'timestamp':str(int(fetched.timestamp())),'to_ids':False,'deleted':False,'distribution':0,'comment':'Local managed IP context; expires='+stamp(fetched+dt.timedelta(hours=source.get('ttl_hours',48)))+'; source '+source['name']+'; '+url+'; collected '+stamp(fetched)+'; native observation time unavailable.'})
 return {'Event':{'uuid':event_uuid,'info':source['name']+' [local managed IP context]','date':fetched.strftime('%Y-%m-%d'),'timestamp':str(int(fetched.timestamp())),'published':False,'distribution':0,'analysis':2,'threat_level_id':4,'Attribute':attributes}}

def stage(config,destination,previous=None,fetcher=fetch,at=None):
 at=at or dt.datetime.now(UTC);sources=validate_config(config);destination=pathlib.Path(destination);destination.mkdir(parents=True,exist_ok=True)
 previous=pathlib.Path(previous) if previous else None
 summary={'format':'local-managed-ip-context-v1','fetched':stamp(at),'distribution':0,'to_ids':False,'sources':[],'required_failures':0}
 if previous and (previous/'status.json').exists():
  old_ids={s['id'] for s in json.loads((previous/'status.json').read_text())['sources']}
  if old_ids-{s['id'] for s in sources}:raise ValueError('Retire old source events explicitly before removing their configuration')
 for source in sources:
  old=previous/source['id'] if previous else None
  if old and (old/'source.json').exists() and json.loads((old/'source.json').read_text()).get('source_url')!=source['url']:
   raise ValueError('A managed source ID cannot be reassigned to another URL')
  folder=destination/source['id'];folder.mkdir();record={'id':source['id'],'name':source['name'],'provider':source.get('provider',source['name']),'source_url':source['url'],'ttl_hours':source.get('ttl_hours',48),'optional':source.get('optional',False)}
  try:
   raw,metadata=fetcher(source);values,comments=parse_feed(raw,metadata.get('content_type',''),source.get('allow_empty',False));event=make_event(source,values,at)
   record.update(status='healthy_empty' if not values else 'ok',count=len(values),last_success=stamp(at),expires=stamp(at+dt.timedelta(hours=record['ttl_hours'])),raw_sha256=digest(raw),canonical_sha256=digest(('\n'.join(values)+'\n').encode()),comment_rows=comments,transport=metadata)
   (folder/'source.json').write_text(json.dumps(record,indent=2));(folder/'values.json').write_text(json.dumps(values))
   (folder/'event.json').write_text(json.dumps(event));(folder/'manifest.json').write_text(json.dumps({event['Event']['uuid']:{'timestamp':int(at.timestamp())}}))
  except Exception as error:
   record.update(status='unavailable',error_type=type(error).__name__,count=0)
   if hasattr(error,'code'):record['http_status']=error.code
   old=previous/source['id'] if previous else None
   if old and (old/'source.json').exists():
    prior=json.loads((old/'source.json').read_text());record['last_success']=prior.get('last_success');record['expires']=prior.get('expires')
    same_source=prior.get('source_url')==source['url']
    if same_source and prior.get('expires','')>stamp(at) and (old/'event.json').exists():
     for name in ['event.json','manifest.json','values.json']:shutil.copy2(old/name,folder/name)
     record.update(status='held_last_good',count=prior['count'])
     for key in ('raw_sha256','canonical_sha256','comment_rows','transport'):record[key]=prior.get(key)
    else:record['status']='expired_revoke'
   if record['status'] in ('unavailable','expired_revoke'):
    event=make_event(source,[],at);(folder/'event.json').write_text(json.dumps(event));(folder/'manifest.json').write_text(json.dumps({event['Event']['uuid']:{'timestamp':int(at.timestamp())}}));(folder/'values.json').write_text('[]')
   if not source.get('optional',False):summary['required_failures']+=1
   (folder/'source.json').write_text(json.dumps(record,indent=2))
  summary['sources'].append(record)
 (destination/'status.json').write_text(json.dumps(summary,indent=2))
 return summary

def import_snapshot(destination,container,app='/var/www/MISP/app',redis_no_password=False):
 # This explicit administrative mode is used only after source/code review.
 subprocess.run(['docker','exec',container,'mkdir','-p',app+'/tmp/managed-ip-context'],check=True)
 subprocess.run(['docker','cp',str(pathlib.Path(destination).resolve())+'/.',container+':'+app+'/tmp/managed-ip-context/'],check=True)
 subprocess.run(['docker','exec',container,'chown','-R','www-data:www-data',app+'/tmp/managed-ip-context'],check=True)
 shell=pathlib.Path(__file__).with_name('MispManagedFeedShell.php')
 subprocess.run(['docker','cp',str(shell),container+':'+app+'/Console/Command/MispManagedFeedShell.php'],check=True)
 command=['docker','exec','-u','www-data',container,app+'/Console/cake','MispManagedFeed',app+'/tmp/managed-ip-context/status.json','import']
 if redis_no_password:command.append('redis-no-password')
 subprocess.run(command,check=True)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--config',required=True);parser.add_argument('--output',required=True);parser.add_argument('--import',dest='do_import',action='store_true');parser.add_argument('--container');args=parser.parse_args()
 config=json.loads(pathlib.Path(args.config).read_text());target=pathlib.Path(args.output).resolve();target.parent.mkdir(parents=True,exist_ok=True)
 backup=target.with_name(target.name+'.previous')
 for path in (target,backup):
  if path.exists() and (not (path/'status.json').is_file() or json.loads((path/'status.json').read_text()).get('format')!='local-managed-ip-context-v1'):
   raise ValueError('Refuse to replace a directory outside managed snapshot state')
 with tempfile.TemporaryDirectory(prefix='misp-context-stage-',dir=target.parent) as name:
  summary=stage(config,name,target if target.exists() else None)
  if args.do_import:
   if not args.container:parser.error('--container is required for --import')
   import_snapshot(name,args.container,redis_no_password=config.get('redis_no_password',False))
  # Keep the previous successful/held source data for bounded TTL fallback.
  if backup.exists():shutil.rmtree(backup)
  if target.exists():target.rename(backup)
  shutil.copytree(name,target)
 print(json.dumps(summary,indent=2))
 return 1 if summary['required_failures'] else 0

if __name__=='__main__':raise SystemExit(main())
