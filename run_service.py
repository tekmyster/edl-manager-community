"""Run web, ingestion or enrichment using the installation's private config."""
import argparse,json,os,pathlib,subprocess,sys,time

def main():
 p=argparse.ArgumentParser();p.add_argument('service',choices=['web','ingest','enrich']);args=p.parse_args()
 config=pathlib.Path(os.environ.get('EDL_CONFIG','/data/config.json'))
 if not config.is_file():raise SystemExit('Run setup.py before starting the service.')
 os.environ['EDL_CONFIG']=str(config)
 if args.service=='web':
  cert=os.environ.get('EDL_TLS_CERT','/data/tls/server.crt');key=os.environ.get('EDL_TLS_KEY','/data/tls/server.key')
  if not pathlib.Path(cert).is_file() or not pathlib.Path(key).is_file():raise SystemExit('Configure an HTTPS certificate and key before starting the web service.')
  os.execv(sys.executable,[sys.executable,'-m','gunicorn','--bind',os.environ.get('EDL_BIND','127.0.0.1:9445'),'--workers','1','--threads','4','--certfile',cert,'--keyfile',key,'app:app'])
 while True:
  result=subprocess.run([sys.executable,'worker.py','--ingest-only' if args.service=='ingest' else '--enrich-only'])
  if result.returncode:print('Background task failed; retrying on the next interval.',flush=True)
  time.sleep(30 if args.service=='ingest' else 300)
if __name__=='__main__':main()
