"""Separate, single-flight behavioral worker; never joins native scoring/publication."""
import os,json,pathlib,fcntl,signal,threading
from core import Store
from behavior_ai import run

def main():
 cfg=json.loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text());store=Store(cfg['database'])
 with open(pathlib.Path(store.path).parent/'behavior.lock','w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  stopped=threading.Event();finished=threading.Event();prior={}
  for sig in (signal.SIGTERM,signal.SIGINT):prior[sig]=signal.signal(sig,lambda *_:stopped.set())
  from source_handoff import consume
  store._source_handoff_background=True
  delivery=threading.Thread(target=consume,args=(store,stopped,finished),name='source-sample-delivery')
  delivery.start()
  try:
   while not stopped.is_set():
    print(json.dumps(run(store,index_only='--index-only' in __import__('sys').argv,source_cfg=cfg,should_stop=stopped.is_set)),flush=True)
    if '--continuous' not in __import__('sys').argv:break
    # The drain has stopped for idle/backoff/finite mode; this is an idle
    # indexing/availability poll, never a request-count ceiling during a drain.
    stopped.wait(60)
  except BaseException:
   stopped.set();raise
  finally:
   finished.set()
   while delivery.is_alive():delivery.join(.2)
   store._source_handoff_background=False
   for sig,handler in prior.items():signal.signal(sig,handler)
   if getattr(store,'_source_handoff_status',{}).get('status')=='failed':raise RuntimeError('Source sample delivery failed: '+store._source_handoff_status['error'])
if __name__=='__main__':main()
