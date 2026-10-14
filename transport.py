"""Validate a complete public EDL generation before transporting or serving it."""
import datetime as dt,hashlib,json,pathlib,ipaddress
NAMES=('manual-block','manual-allow','scored-block','review-hold','protected-crawlers','palo-drops-review','tpot-review','owapot-review','nginx-review','waf-review','crowdsec-review','wazuh-review','combined-block')
def validate(package):
 manifest=package['manifest'];files=package['files']
 created=dt.datetime.fromisoformat(manifest['created']);now=dt.datetime.now(dt.timezone.utc)
 if created.tzinfo is None or not now-dt.timedelta(minutes=10)<=created<=now+dt.timedelta(minutes=1):raise ValueError('Generation is stale or future-dated')
 if set(files)!=set(NAMES):raise ValueError('Incomplete generation')
 for name in NAMES:
  text=files[name]
  if not isinstance(text,str) or len(text)>4_000_000:raise ValueError('Invalid EDL payload')
  if hashlib.sha256(text.encode('utf-8')).hexdigest()!=manifest['sha256'][name]:raise ValueError('EDL checksum mismatch')
  lines=text.splitlines()
  if len(lines)>50000 or len(lines)!=len(set(lines)) or len(lines)!=manifest['counts'][name]:raise ValueError('EDL count mismatch')
  for line in lines:
   n=ipaddress.ip_network(line,strict=True)
   if '%' in line or not n.network_address.is_global or not n.broadcast_address.is_global or n.network_address.is_multicast:raise ValueError('EDL contains nonpublic space')
   bad=list(n.network_address._constants._private_networks)
   bad += [ipaddress.ip_network(v) for v in (['100.64.0.0/10','224.0.0.0/3'] if n.version==4 else ['ff00::/8'])]
   if any(n.overlaps(b) for b in bad):raise ValueError('EDL crosses nonpublic space')
 return package
def prepare(output,target):
 # Pin the resolved generation before reading any files, even if current swaps.
 generation=(pathlib.Path(output)/'current').resolve(strict=True)
 package={'manifest':json.loads((generation/'manifest.json').read_text()),'files':{name:(generation/(name+'.txt')).read_text(encoding='utf-8') for name in NAMES}}
 validate(package)
 p=pathlib.Path(target);tmp=p.with_suffix('.new');tmp.write_text(json.dumps(package,separators=(',',':')),encoding='utf-8');tmp.chmod(0o600);tmp.replace(p)
 return package['manifest']
