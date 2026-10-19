"""Drain durable packet readiness inside the existing single-flight worker."""
import datetime as dt
import pathlib
import sqlite3
import time
import contextlib
import copy

class Cancelled(Exception):pass

def native_identity(db):
 # Indexed small configuration rows, never the large MISP snapshot. The
 # preparation reader stays on its coherent snapshot; verification is fresh.
 return list(db.execute("SELECT key,value FROM state WHERE key IN ('source_configuration','behavior_settings') ORDER BY key"))

def index_packet(brain,store,address,cfg,source_cfg=None,revision=None,should_stop=None,at=None):
 """One bounded derived commit; native access remains strictly read-only."""
 from core import now
 stopped=should_stop or (lambda:False)
 # Copies bind existing methods to these transaction-local handles. Never
 # replace a connection on the Store/Brain shared by another worker thread.
 local=copy.copy(brain);reader=copy.copy(store);local.store=reader
 prepared_cfg=copy.deepcopy(cfg);prepared_source=copy.deepcopy(source_cfg)
 uri=pathlib.Path(store.path).resolve().as_uri()+'?mode=ro'
 prepared_valid=False
 try:
  with contextlib.closing(sqlite3.connect(uri,uri=True,timeout=30)) as native:
   native.row_factory=sqlite3.Row;native.execute('PRAGMA query_only=ON');native.execute('BEGIN')
   reader.connect=lambda *a,**kw:contextlib.nullcontext(native)
   if stopped():raise Cancelled
   identity=[tuple(r) for r in native_identity(native)]
   detailed=reader.describe(address)
   prepared_at=at or dt.datetime.now(dt.timezone.utc)
   from behavior_context import context
   native_context=context(reader,detailed,prepared_source,prepared_at)
   from evidence_history import collection_scope
   scope=collection_scope(local,prepared_source)
   if stopped():raise Cancelled
   with brain.connect() as db:
    local.connect=lambda:contextlib.nullcontext(db)
    db.execute('BEGIN IMMEDIATE')
    if stopped():raise Cancelled
    with contextlib.closing(sqlite3.connect(uri,uri=True,timeout=30)) as check:
     check.execute('PRAGMA query_only=ON')
     if [tuple(r) for r in native_identity(check)]!=identity or cfg!=prepared_cfg or source_cfg!=prepared_source:return None,[]
    if revision is not None:
     current=db.execute('SELECT revision FROM source_sample_ready WHERE ip=? AND scope=?',(address,scope)).fetchone()
     if current is None or current['revision']!=revision:return None,[]
    prepared_valid=True
    options={'native_context':native_context} if getattr(local,'prepared_native_context',False) else {}
    ident,packet,features=local.packet(detailed,prepared_cfg,at=prepared_at,source_cfg=prepared_source,**options)
    candidates=local.candidates(ident,features) if prepared_cfg['correlation_enabled'] else []
    if prepared_cfg['correlation_enabled']:
     from behavior_intelligence import inspect,load_catalog
     inspect(local,ident,candidates,load_catalog(pathlib.Path(store.path).parent/'behavior-references.json'))
    if prepared_cfg['model_enabled'] and packet['events']:
     db.execute('INSERT INTO analysis_queue SELECT ?,?,? WHERE EXISTS(SELECT 1 FROM analysis_queue WHERE ip=?) OR (SELECT count(*) FROM analysis_queue)<10000 ON CONFLICT(ip) DO UPDATE SET packet_id=excluded.packet_id',(address,ident,now(),address))
    if revision is not None:
     from source_handoff import indexed
     indexed(local,address,revision,prepared_source,collection=scope)
    if stopped():raise Cancelled
    assert native.total_changes==0
 finally:
  # The existing 60-second snapshot cache survives per-packet handle reuse.
  for name in ('_behavior_misp_snapshot','_behavior_misp_snapshot_at','_behavior_misp_lookup'):
   if prepared_valid and hasattr(reader,name):setattr(store,name,getattr(reader,name))
 return ident,candidates


def lock(store):
 # The worker installs this before either indexing path starts. Direct run()
 # callers have no companion thread and retain their existing behavior.
 import contextlib
 return getattr(store,'_behavior_index_lock',None) or contextlib.nullcontext()


def page(brain,store,source_cfg,should_stop=None,should_yield=None):
 """Page size bounds reads/memory; successful pages have no drain quota."""
 from behavior_ai import settings
 from source_handoff import ready
 stop=should_stop or (lambda:False)
 yielding=should_yield or (lambda:False)
 if yielding():return {'status':'yielded','indexed':0}
 addresses=getattr(store,'_behavior_index_addresses',())
 if not addresses:return {'status':'waiting_for_native_snapshot','indexed':0}
 pending=ready(brain,source_cfg,addresses=addresses)
 count=0;started=time.monotonic();maximum=0
 def outcome(status):
  return {'status':status,'indexed':count,'page_rows':len(pending),'page_bound':100,'seconds':round(time.monotonic()-started,6),'max_packet_seconds':round(maximum,6)}
 for address,revision in pending.items():
  if stop():return {'status':'cancelled','indexed':count}
  if yielding():return outcome('yielded')
  cfg=settings(store)
  if not cfg['enabled']:return {'status':'disabled','indexed':count}
  with lock(store):
   if stop():return {'status':'cancelled','indexed':count}
   # Quiescence never enters index_packet's rollback-oriented cancellation.
   if yielding():return outcome('yielded')
   item_started=time.monotonic()
   try:ident,_=index_packet(brain,store,address,cfg,source_cfg,revision=revision,should_stop=stop)
   except Cancelled:return {'status':'cancelled','indexed':count}
   if ident is None:continue
   maximum=max(maximum,time.monotonic()-item_started);count+=1
 return outcome('indexed' if pending else 'idle')


def consume(store,source_cfg,stopped,finished,quiesce=None):
 from behavior_ai import Brain,settings
 brain=None;totals={'pages':0,'indexed':0,'max_packet_seconds':0}
 while not stopped.is_set() and not (quiesce and quiesce.is_set()):
  try:
   if not settings(store)['enabled']:result={'status':'disabled','indexed':0}
   else:
    if brain is None:brain=Brain(store)
    result=page(brain,store,source_cfg,stopped.is_set,quiesce.is_set if quiesce else None)
  except sqlite3.OperationalError as exc:
   if (getattr(exc,'sqlite_errorcode',0) or 0)&255 not in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):
    store._packet_index_status={'status':'failed','error':type(exc).__name__};stopped.set();return
   result={'status':'busy_retry','indexed':0}
  except Exception as exc:
   store._packet_index_status={'status':'failed','error':type(exc).__name__};stopped.set();return
  if result['status']=='indexed' or result['status']=='yielded' and result['indexed']:
   totals['pages']+=1;totals['indexed']+=result['indexed']
   totals['max_packet_seconds']=max(totals['max_packet_seconds'],result['max_packet_seconds'])
  store._packet_index_status={**result,'totals':dict(totals),'at':dt.datetime.now(dt.timezone.utc).isoformat()}
  if result['status'] in ('cancelled','yielded'):return
  if result['status']!='indexed':
   if finished.is_set():return
   stopped.wait(1)
