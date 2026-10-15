"""Separate, single-flight behavioral worker; never joins native scoring/publication."""
import os,json,pathlib,fcntl
from core import Store
from behavior_ai import run

def main():
 cfg=json.loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text());store=Store(cfg['database'])
 with open(pathlib.Path(store.path).parent/'behavior.lock','w') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:return
  print(json.dumps(run(store,index_only='--index-only' in __import__('sys').argv,source_cfg=cfg)))
if __name__=='__main__':main()
