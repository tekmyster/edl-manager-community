"""Import administrator-supplied official MITRE datasets without runtime downloads."""
import argparse,hashlib,json,pathlib,re

def build(attack_file,defend_file,attack_version,defend_version):
 attack_body=pathlib.Path(attack_file).read_bytes();defend_body=pathlib.Path(defend_file).read_bytes()
 attack={};defend={}
 for item in json.loads(attack_body)['objects']:
  if item.get('type')!='attack-pattern' or item.get('revoked') or item.get('x_mitre_deprecated'):continue
  for ref in item.get('external_references',[]):
   if ref.get('source_name')=='mitre-attack' and re.fullmatch(r'T\d{4}(?:\.\d{3})?',ref.get('external_id','')):attack[ref['external_id']]=item['name']
 for item in json.loads(defend_body)['@graph']:
  ident=item.get('d3f:d3fend-id');label=item.get('rdfs:label')
  if isinstance(ident,str) and ident.startswith('D3-') and isinstance(label,str):defend[ident]=label
 if not attack or not defend:raise ValueError('No valid technique identifiers found')
 return {'version':f'ATT&CK {attack_version}; D3FEND {defend_version}','attack':dict(sorted(attack.items())),'d3fend':dict(sorted(defend.items())),'provenance':{'attack_sha256':hashlib.sha256(attack_body).hexdigest(),'d3fend_sha256':hashlib.sha256(defend_body).hexdigest(),'attack_source':'https://github.com/mitre-attack/attack-stix-data','d3fend_source':'https://d3fend.mitre.org/resources/ontology/'}}

def main():
 p=argparse.ArgumentParser();p.add_argument('--attack',required=True);p.add_argument('--d3fend',required=True);p.add_argument('--attack-version',required=True);p.add_argument('--d3fend-version',required=True);p.add_argument('--output',required=True);a=p.parse_args()
 registry=build(a.attack,a.d3fend,a.attack_version,a.d3fend_version);path=pathlib.Path(a.output);temp=path.with_suffix('.new');temp.write_text(json.dumps(registry),encoding='utf-8');temp.chmod(0o600);temp.replace(path)
 print(f"Imported {len(registry['attack'])} ATT&CK and {len(registry['d3fend'])} D3FEND techniques.")
if __name__=='__main__':main()
