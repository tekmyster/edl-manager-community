"""Separate, single-flight behavioral worker; never joins native scoring/publication."""
import os,json,pathlib,fcntl,signal,threading
from core import Store
from behavior_ai import run

def main():
 cfg=json.loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text());store=Store(cfg['database'])
 with open(pathlib.Path(store.path).parent/'behavior.lock','w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  stopped=threading.Event();prior={}
  for sig in (signal.SIGTERM,signal.SIGINT):prior[sig]=signal.signal(sig,lambda *_:stopped.set())
  try:
   while not stopped.is_set():
    print(json.dumps(run(store,index_only='--index-only' in __import__('sys').argv,source_cfg=cfg,should_stop=stopped.is_set)),flush=True)
    if '--continuous' not in __import__('sys').argv:break
    # The drain has stopped for idle/backoff/finite mode; this is an idle
    # indexing/availability poll, never a request-count ceiling during a drain.
    stopped.wait(60)
  finally:
   for sig,handler in prior.items():signal.signal(sig,handler)
if __name__=='__main__':main()
