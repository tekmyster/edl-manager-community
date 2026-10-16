"""Import administrator-supplied official MITRE datasets without runtime downloads."""
import argparse,hashlib,json,pathlib,re

def fingerprint(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def build(attack_file,defend_file,attack_version,defend_version,manifest=None):
 attack_body=pathlib.Path(attack_file).read_bytes();defend_body=pathlib.Path(defend_file).read_bytes()
 manifest=manifest or json.loads(pathlib.Path(__file__).with_name('mitre-sources.json').read_text(encoding='utf-8'))
 for kind,version,body in [('attack',attack_version,attack_body),('d3fend',defend_version,defend_body)]:
  if manifest[kind]['version']!=version or manifest[kind]['sha256']!=hashlib.sha256(body).hexdigest():raise ValueError('Dataset version or SHA256 does not match reviewed manifest')
 objects=json.loads(attack_body)['objects'];graph=json.loads(defend_body)['@graph']
 if not any(o.get('type')=='x-mitre-collection' and o.get('name')=='Enterprise ATT&CK' and o.get('x_mitre_version')==attack_version for o in objects):raise ValueError('Enterprise ATT&CK collection version mismatch')
 if not any(o.get('@id')=='http://d3fend.mitre.org/ontologies/d3fend.owl' and o.get('owl:versionInfo')==defend_version for o in graph):raise ValueError('D3FEND ontology version mismatch')
 attack={};defend={};defensive=_defensive_classes(graph)
 for item in objects:
  if item.get('type')!='attack-pattern' or item.get('revoked') or item.get('x_mitre_deprecated'):continue
  for ref in item.get('external_references',[]):
   if ref.get('source_name')=='mitre-attack' and re.fullmatch(r'T\d{4}(?:\.\d{3})?',ref.get('external_id','')):_add(attack,ref['external_id'],item.get('name'))
 for item in graph:
  ident=item.get('d3f:d3fend-id');label=item.get('rdfs:label')
  if isinstance(ident,str) and re.fullmatch(r'D3-[A-Z0-9]+',ident) and item.get('@id') in defensive and not item.get('owl:deprecated'):_add(defend,ident,label)
 if not attack or not defend:raise ValueError('No valid technique identifiers found')
 registry={'schema':2,'version':f'ATT&CK {attack_version}; D3FEND {defend_version}','attack':dict(sorted(attack.items())),'d3fend':dict(sorted(defend.items())),'provenance':manifest,'notices':pathlib.Path(__file__).with_name('MITRE-NOTICES.txt').read_text(encoding='utf-8')}
 registry['registry_sha256']=fingerprint(registry)
 return registry

def _add(target,ident,label):
 if not isinstance(label,str) or not label.strip() or len(label)>200:raise ValueError('Invalid taxonomy label')
 if ident in target and target[ident]!=label:raise ValueError('Conflicting taxonomy identifier')
 target[ident]=label

def _defensive_classes(graph):
 # IDs alone do not establish ontology type (1.6.0 includes D3-ARMA,
 # an algorithm). Follow declared subclass edges, not inferred control status.
 children={}
 for item in graph:
  parents=item.get('rdfs:subClassOf',[])
  if not isinstance(parents,list):parents=[parents]
  for parent in parents:
   if isinstance(parent,dict):children.setdefault(parent.get('@id'),set()).add(item.get('@id'))
 seen=set();pending=['d3f:DefensiveTechnique']
 while pending:
  ident=pending.pop()
  if ident in seen:continue
  seen.add(ident);pending.extend(children.get(ident,()))
 return seen

def load(path):
 """Unavailable, legacy or damaged catalogs disable taxonomy only."""
 try:
  registry=json.loads(pathlib.Path(path).read_text(encoding='utf-8'))
  if registry.get('schema')!=2 or registry.get('registry_sha256')!=fingerprint({k:v for k,v in registry.items() if k!='registry_sha256'}):raise ValueError('Registry integrity mismatch')
  for kind,pattern in [('attack',r'T\d{4}(?:\.\d{3})?'),('d3fend',r'D3-[A-Z0-9]+')]:
   for ident,label in registry[kind].items():
    if not re.fullmatch(pattern,ident) or not isinstance(label,str) or len(label)>200:raise ValueError('Invalid registry entry')
  return registry
 except (OSError,ValueError,KeyError,TypeError,AttributeError):return {'version':'unavailable','attack':{},'d3fend':{}}

def main():
 p=argparse.ArgumentParser();p.add_argument('--attack',required=True);p.add_argument('--d3fend',required=True);p.add_argument('--attack-version',required=True);p.add_argument('--d3fend-version',required=True);p.add_argument('--output',required=True);p.add_argument('--manifest',default=str(pathlib.Path(__file__).with_name('mitre-sources.json')));a=p.parse_args()
 registry=build(a.attack,a.d3fend,a.attack_version,a.d3fend_version,json.loads(pathlib.Path(a.manifest).read_text(encoding='utf-8')));path=pathlib.Path(a.output);temp=path.with_suffix('.new');temp.write_text(json.dumps(registry),encoding='utf-8');temp.chmod(0o600);temp.replace(path)
 print(f"Imported {len(registry['attack'])} ATT&CK and {len(registry['d3fend'])} D3FEND techniques.")
if __name__=='__main__':main()
