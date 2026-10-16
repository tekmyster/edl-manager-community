"""Offline temporary-database benchmark; never contacts a model, sensor or firewall.

Run with the production Python dependencies on Linux. JSON distinguishes real
measured local operations from a deliberately simulated model queue. No generated
assessment, verdict, ground-truth label, or production event is stored.
"""
import datetime as dt,ipaddress,json,pathlib,statistics,sys,tempfile,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from core import Store,now
from behavior_ai import Brain,DEFAULTS
from behavior_retention import cleanup,hold
from behavior_correlation import retrieve
from unittest.mock import patch

def stats(values):
 v=sorted(values)
 return {'samples':len(v),'median_seconds':statistics.median(v),'p95_seconds':v[min(len(v)-1,int(len(v)*.95))],'max_seconds':max(v)}

def main(count=10000):
 with tempfile.TemporaryDirectory(prefix='edl-retention-benchmark-') as tmp:
  root=pathlib.Path(tmp);s=Store(root/'manager');b=Brain(s);at=dt.datetime.now(dt.timezone.utc);old=(at-dt.timedelta(days=120)).isoformat(timespec='seconds');fresh=now()
  content=json.dumps({'events':[{'id':str(i),'seen':fresh,'path':p,'source':'offline-fixture','sensor':'fixture','action':'sample'} for i,p in enumerate(['/login','/admin']*12)],'coverage':'offline-fixture'})
  before=b.path.stat().st_size;start=time.perf_counter()
  with b.connect() as db:
   for i in range(count):
    ident='fixture-'+str(i);created=fresh if i>=count-1000 else old
    db.execute('INSERT INTO packets VALUES(?,?,?,?,?,?)',(ident,'8.8.'+str(i//254%254)+'.'+str(i%254+1),created,content,'["path:/login","path:/admin"]',0));b.index_features(db,ident,{'path:/login','path:/admin'})
   for i in range(count-1):db.execute('INSERT INTO links VALUES(?,?,?,?,?,?,?)',('link-'+str(i),'fixture-'+str(i),'fixture-'+str(i+1),.8,'[]','proposed',old))
  ingest=time.perf_counter()-start
  with b.connect() as db:db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
  after=b.path.stat().st_size;retrieval=[];bounds=[]
  with b.connect() as db:
   plan=[tuple(r) for r in db.execute('EXPLAIN QUERY PLAN SELECT packet_id FROM correlation_features WHERE feature=? AND created>=? ORDER BY created DESC,packet_id DESC LIMIT 129',('path:/login',old))]
   for i in range(100):
    start=time.perf_counter();_,details=retrieve(db,'fixture-'+str(count-1-i));retrieval.append(time.perf_counter()-start);bounds.append(details['postings_read'])
  # A held old window and its incident proposed edges stay available.
  hold(b,'packet','fixture-0','Offline benchmark investigation')
  batches=[];deleted=0
  for i in range(count//100+15):
   start=time.perf_counter();r=cleanup(b,DEFAULTS);batches.append(time.perf_counter()-start);deleted+=sum(r['deleted'].values())
  with b.connect() as db:
   retained=db.execute('SELECT count(*) FROM packets').fetchone()[0];free=db.execute('PRAGMA freelist_count').fetchone()[0];page=db.execute('PRAGMA page_size').fetchone()[0];assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
   assert db.execute('SELECT 1 FROM packets WHERE id=?',('fixture-0',)).fetchone()
  # Exercise the actual durable queue and scheduler with a failing 10ms stub.
  # No assessment is created; the stub is deliberately not a model benchmark.
  from behavior_ai import run
  s.state('behavior_settings',{**DEFAULTS,'enabled':True,'model_enabled':True})
  queued=dt.datetime.now(dt.timezone.utc).isoformat()
  with b.connect() as db:
   for i in range(50):db.execute('INSERT INTO analysis_queue VALUES(?,?,?)',('offline-'+str(i),'fixture-'+str(count-1-i),queued))
  def stub(*args,**kwargs):time.sleep(.01);return 'failed'
  passes=0;start=time.perf_counter()
  with patch('behavior_ai.model_job',stub):
   while True:
    with b.connect() as db:
     if not db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]:break
    run(s);passes+=1
  queue_seconds=time.perf_counter()-start
  with b.connect() as db:waits=[r[0] for r in db.execute('SELECT wait_seconds FROM queue_samples')]
  publication=[]
  s.state('behavior_settings',{**DEFAULTS,'enabled':True,'model_enabled':True,'scoring_enabled':True,'max_bump':10})
  for i in range(1,31):
   address='9.9.9.'+str(i);start=time.perf_counter();s.evidence(address,'waf','offline-fixture',now(),'http',75)
   manifest=s.build(root/'out');assert any(ipaddress.ip_address(address) in ipaddress.ip_network(line) for line in (root/'out'/'current'/'combined-block.txt').read_text().splitlines());publication.append(time.perf_counter()-start)
  return {'mode':'isolated Linux temporary SQLite fixtures; no network or GPU calls','storage':{'packets':count,'proposed_links':count-1,'packet_payload_bytes':len(content),'db_bytes_before':before,'db_bytes_after':after,'incremental_bytes_per_packet_including_indexes_links':(after-before)/count,'insert_seconds':ingest},'retrieval':{**stats(retrieval),'query_plan':plan,'max_postings_read':max(bounds)},'cleanup':{**stats(batches),'calls':len(batches),'deleted_rows':deleted,'retained_packets':retained,'reusable_bytes':free*page,'file_shrink_claimed':False},'queue_simulation':{**stats(waits),'service_delay_seconds':.01,'calls_per_cycle':2,'actual_scheduler_passes':passes,'elapsed_seconds':queue_seconds,'service':'isolated 10ms terminal-failure stub, no assessment or verdict','timer_wait_included':False,'production_queue_delay_claimed':False,'gpu_throughput_claimed':False},'native_detection_to_local_atomic_publication':{**stats(publication),'definition':'offline event handoff through real Store.evidence/build and membership read; excludes upstream detection, timer wait, origin sync and firewall fetch','ai_configured_without_inference':True},'gpu':{'sustained_current_prompt_inference':'not measured; production quota exhausted; no override','memory_tokenization_reliability':'not established by this benchmark'}}

if __name__=='__main__':print(json.dumps(main(),indent=2))
