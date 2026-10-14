"""Optional collector settings, stored locally without exposing secrets."""
from urllib.parse import urlsplit
import re
SOURCES={'tpot':'T-Pot','owapot':'OWAPot','nginx':'NGINX','waf':'NGINX WAF','crowdsec':'CrowdSec','wazuh':'Wazuh alerts'}
FIELDS={'asn':'ASN / organization','client_type':'Source type','ports':'Destination ports','enrichment':'Enrichment details','enrichment_sources':'Enrichment source','method':'HTTP method','host':'Requested host','path':'Request path','status':'HTTP status','client':'Web client','platform':'Client OS','confidence':'Identity confidence','destination':'Network destination','nat':'NAT destination','nat_port':'NAT port','application':'Application','action':'Network action','zone':'Network zone','rule':'Firewall rule','reason':'Outcome detail'}
def preferences(store,cfg):
 saved=store.state('source_configuration')
 defaults={'index_url':cfg.get('index_url',''),'misp_url':cfg.get('misp_url',''),'misp_sha256':cfg.get('misp_sha256',''),'palo_location':cfg.get('palo_location',''),'sources':cfg.get('source_agents',{k:'' for k in SOURCES}),'fields':list(FIELDS)}
 return {**defaults,**(saved or {})}
def effective(store,cfg):
 p=preferences(store,cfg)
 return {**cfg,'index_url':p['index_url'],'misp_url':p['misp_url'],'misp_sha256':p['misp_sha256'],'palo_location':p['palo_location'],'source_agents':p['sources'],'collected_fields':p['fields']}
def validate(form):
 result={k:form.get(k,'').strip().rstrip('/') for k in ['index_url','misp_url','palo_location']}
 for k in ['index_url','misp_url']:
  if not result[k]:continue
  u=urlsplit(result[k])
  if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment:raise ValueError('Use an HTTPS server URL without embedded credentials, a query or a fragment.')
  try:u.port
  except ValueError:raise ValueError('Enter a valid server port.')
 if len(result['palo_location'])>255:raise ValueError('Firewall log source is too long.')
 result['misp_sha256']=form.get('misp_sha256','').strip().replace(':','').lower()
 if result['misp_sha256'] and not re.fullmatch('[0-9a-f]{64}',result['misp_sha256']):raise ValueError('The MISP certificate fingerprint must contain 64 hexadecimal characters.')
 result['sources']={k:form.get('source_'+k,'').strip() for k in SOURCES}
 if any(len(v)>255 for v in result['sources'].values()):raise ValueError('Agent names must be no longer than 255 characters.')
 result['fields']=[k for k in form.getlist('fields') if k in FIELDS]
 return result
