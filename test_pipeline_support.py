"""Synthetic-only SQLite/process fixture. No real transport/grants/credentials."""
import json,os,pathlib,sys,time
import behavior_ai as ai
import behavior_tokens
from core import Store
from behavior_pipeline_job import run
from test_source_observations import linked_packet

class SyntheticCounter:
 value={'model':'synthetic','model_digest':'synthetic-only','runtime_sha256':'0'*64,'template_sha256':'0'*64}
 def check(self,request):return {'input_tokens':10,'reserved_output_tokens':1800,'context_tokens':8192,'EOS_spare':1,'tokenizer_version':'synthetic-state-test-not-token-proof'}

class Reply:
 status_code=200
 def __init__(self,request,wire,metadata=None):self.body=json.dumps({'done':True,'model':request['model'],'message':{'content':json.dumps(wire)},**({'prompt_eval_count':10,'eval_count':2} if metadata is None else metadata)}).encode()+b'\n'
 def iter_content(self,n):yield self.body
 def close(self):pass

def choices(request,groups='omit',purpose=None,classification='inconclusive'):
 p=request['format']['properties']
 wire={'generation_schema_version':p['generation_schema_version']['enum'][0],'packet_id':p['packet_id']['enum'][0],'classification':classification,'maliciousness_confidence':0,'automation':[],'intent':[],'observations':{},'attack_techniques':{k:'omit' for k in p['attack_techniques']['properties']},'d3fend_context':{k:'omit' for k in p['d3fend_context']['properties']},'actor_correlation':[],'observable_synthesis':{k:('omit' if groups=='omit' else v['enum'][-1]) for k,v in p['observable_synthesis']['properties'].items()}}
 if purpose:wire['observations']={k:({'comparison':'unresolved','purpose':purpose} if spec.get('type')=='object' else purpose) for k,spec in p['observations']['properties'].items()}
 if 'draft_binding' in p:wire['draft_binding']=p['draft_binding']['enum'][0]
 return wire

def setup(path,budget=2,count=1):
 path=pathlib.Path(path);store=Store(path);b=ai.Brain(store);cfg={**ai.DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':False,'model':'synthetic','endpoint':'https://127.0.0.1','daily_budget':budget,'tokenizer_sha256':'0'*64};store.state('behavior_settings',cfg)
 packets=[]
 with b.connect() as db:
  for i in range(count):
   p=linked_packet();p['packet_id']='synthetic-packet-'+str(i);packets.append(p);address='8.8.8.'+str(i+1)
   db.execute('INSERT OR IGNORE INTO packets VALUES(?,?,?,?,?,?)',(p['packet_id'],address,ai.now(),json.dumps(p),'[]',0));db.execute('INSERT OR REPLACE INTO current_packets VALUES(?,?)',(address,p['packet_id']))
 return store,b,cfg,packets

def close(store):
 for db in getattr(store,'_analytics_handles',{}).values():db.close()
 store._analytics_handles={}

def configure():
 ai.now=lambda:'2026-10-17T10:01:00+00:00';ai.local_endpoint=lambda _:None;behavior_tokens.load=lambda cfg:SyntheticCounter()

def child(directory,phase):
 directory=pathlib.Path(directory)
 if (directory/'native-test.sqlite3').exists():raise ValueError('Synthetic child requires a new fixture database')
 configure();s,b,cfg,packets=setup(directory/'native-test.sqlite3')
 def hook(value):
  if value==phase:os._exit(71)
 def send(url,**kw):
  with (directory/'mock-transport.log').open('a') as f:f.write('synthetic request\n');f.flush();os.fsync(f.fileno())
  request=kw['json'];return Reply(request,choices(request,groups='selected'))
 result=run(b,packets[0]['packet_id'],packets[0],set(),cfg,requester=send,hook=hook);close(s)
 print(json.dumps({'status':result,'units':result.request_units}))

def race_child(directory,index):
 from behavior_pipeline_store import Ledger,Refused
 directory=pathlib.Path(directory);configure();s=Store(directory/'native-test.sqlite3');b=ai.Brain(s);cfg=ai.settings(s)
 limit=time.monotonic()+10
 while not (directory/'race-start').exists():
  if time.monotonic()>limit:raise TimeoutError('Synthetic race start')
  time.sleep(.01)
 try:
  Ledger(b).begin('synthetic-packet-'+index,'race-config','race-input',cfg,time.time()+120,['synthetic-packet-'+index]);result='reserved'
 except Refused as exc:result=str(exc)
 (directory/('race-'+index+'.json')).write_text(json.dumps({'status':result}))
 if result=='reserved':
  while not (directory/'race-release').exists():
   if time.monotonic()>limit:raise TimeoutError('Synthetic race release')
   time.sleep(.01)
 close(s)

if __name__=='__main__':
 if sys.argv[2].startswith('race:'):race_child(sys.argv[1],sys.argv[2].split(':')[1])
 else:child(sys.argv[1],sys.argv[2])
