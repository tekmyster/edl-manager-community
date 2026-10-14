"""First-install setup; never resets an existing account or database."""
import argparse,getpass,ipaddress,json,os,pathlib,secrets
from core import Store
from source_settings import SOURCES
from werkzeug.security import generate_password_hash

def initialize(data,username,password,hosts,management,feeds):
 data=pathlib.Path(data).resolve();data.mkdir(parents=True,exist_ok=True,mode=0o700)
 target=data/'config.json'
 if target.exists() or (data/'manager.sqlite3').exists():raise ValueError('An installation already exists. Setup will not replace it.')
 username=username.strip().casefold()
 if not username or len(password)<12:raise ValueError('Enter a username and a password of at least 12 characters.')
 for network in management+feeds:ipaddress.ip_network(network,strict=False)
 cfg={'edition':'community','database':str(data/'manager.sqlite3'),'output':str(data/'lists'),'providers_file':str(data/'providers.json'),'session_secret':secrets.token_urlsafe(48),'hosts':hosts,'management_networks':management,'feed_networks':feeds,'index_url':'','index_user':os.environ.get('EDL_INDEX_USER',''),'index_password':os.environ.get('EDL_INDEX_PASSWORD',''),'index_ca':os.environ.get('EDL_INDEX_CA') or True,'misp_url':'','misp_ca':os.environ.get('EDL_MISP_CA') or True,'palo_location':'','asn_database':os.environ.get('EDL_ASN_DATABASE',''),'crawler_feed_file':str(data/'crawler-feeds.json'),'source_agents':{k:'' for k in SOURCES},'incremental_ingest':True,'greynoise_transport':'direct'}
 store=Store(cfg['database'])
 with store.connect() as db:db.execute('INSERT INTO users(name,password_hash) VALUES(?,?)',(username,generate_password_hash(password)))
 store.build(cfg['output'])
 for name,value in [('config.json',cfg),('providers.json',{})]:
  path=data/name
  with path.open('x',encoding='utf-8') as f:json.dump(value,f,indent=2)
  path.chmod(0o600)
 (data/'manager.sqlite3').chmod(0o600)
 return cfg

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--data',default='/data');parser.add_argument('--hosts',default='localhost,127.0.0.1');parser.add_argument('--management',default='127.0.0.0/8,::1/128');parser.add_argument('--feed-sources',default='')
 args=parser.parse_args();username=input('Administrator username: ');password=getpass.getpass('Administrator password: ')
 if password!=getpass.getpass('Confirm password: '):raise SystemExit('Passwords do not match.')
 try:initialize(args.data,username,password,args.hosts.split(','),args.management.split(','),[v for v in args.feed_sources.split(',') if v])
 except ValueError as e:raise SystemExit(str(e))
 print('Community Edition initialized. Configure sources in System settings.')
if __name__=='__main__':main()
