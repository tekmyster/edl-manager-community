"""Separate, single-flight behavioral worker; never joins native scoring/publication."""
import os,json,pathlib,fcntl,signal,threading
from core import Store
from behavior_ai import run

def main():
 cfg=json.loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text());store=Store(cfg['database'])
 with open(pathlib.Path(store.path).parent/'behavior.lock','w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  stopped=threading.Event();finished=threading.Event();index_finished=threading.Event();quiesce=threading.Event();prior={}
  for sig in (signal.SIGTERM,signal.SIGINT):prior[sig]=signal.signal(sig,lambda *_:stopped.set())
  from source_handoff import consume
  store._source_handoff_background=True
  delivery=threading.Thread(target=consume,args=(store,stopped,finished,quiesce),name='source-sample-delivery')
  from packet_indexing import consume as consume_ready
  store._behavior_index_lock=threading.RLock();store._packet_index_background=True
  indexing=threading.Thread(target=consume_ready,args=(store,cfg,stopped,index_finished,quiesce),name='packet-readiness')
  try:
   delivery.start()
   indexing.start()
   while not stopped.is_set():
    print(json.dumps(run(store,index_only='--index-only' in __import__('sys').argv,source_cfg=cfg,should_stop=stopped.is_set)),flush=True)
    if '--continuous' not in __import__('sys').argv:break
    # The drain has stopped for idle/backoff/finite mode; this is an idle
    # indexing/availability poll, never a request-count ceiling during a drain.
    stopped.wait(60)
  except BaseException:
   stopped.set();raise
  finally:
   # Request both consumers to yield before joining either. Quiescence is
   # separate from hard cancellation: an active atomic commit may finish.
   finished.set();index_finished.set();quiesce.set()
   while delivery.is_alive():delivery.join(.2)
   while indexing.is_alive():indexing.join(.2)
   store._source_handoff_background=False
   store._packet_index_background=False
   for sig,handler in prior.items():signal.signal(sig,handler)
   if getattr(store,'_source_handoff_status',{}).get('status')=='failed':raise RuntimeError('Source sample delivery failed: '+store._source_handoff_status['error'])
   if getattr(store,'_packet_index_status',{}).get('status')=='failed':raise RuntimeError('Packet readiness indexing failed: '+store._packet_index_status['error'])
if __name__=='__main__':main()
