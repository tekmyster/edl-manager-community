"""Explicit, source-provenance recovery of derived metadata; never model truth.

No automatic legacy reset. A caller first obtains a dry-run plan, independently
reviews its exact hashes, then requests one event/scope recovery with an actor
and review reference. Original packets, assessments and native data are read-only.
"""
import json,datetime as dt,hashlib
from source_observations import binding_proof,fingerprint,merge_reports,_time

SCHEMA='''
CREATE TABLE IF NOT EXISTS source_binding_receipts(event_id TEXT NOT NULL,scope TEXT NOT NULL,checked_at TEXT NOT NULL,content TEXT NOT NULL,PRIMARY KEY(event_id,scope));
CREATE TABLE IF NOT EXISTS source_binding_audit(id TEXT PRIMARY KEY,event_id TEXT NOT NULL,scope TEXT NOT NULL,created TEXT NOT NULL,action TEXT NOT NULL,before_sha256 TEXT NOT NULL,after_sha256 TEXT NOT NULL,evidence TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS source_binding_audit_event ON source_binding_audit(event_id,scope,action);
CREATE INDEX IF NOT EXISTS source_binding_audit_session ON source_binding_audit(scope,json_extract(evidence,'$.complete_query_receipt.source_observation.session_ref'));
CREATE INDEX IF NOT EXISTS event_history_session ON event_history(ip,source,sensor,scope,json_extract(content,'$.source_observation.session_ref'));
CREATE TRIGGER IF NOT EXISTS source_binding_audit_no_update BEFORE UPDATE ON source_binding_audit BEGIN SELECT RAISE(ABORT,'Source binding audit is append-only'); END;
CREATE TRIGGER IF NOT EXISTS source_binding_audit_no_delete BEFORE DELETE ON source_binding_audit WHEN EXISTS(SELECT 1 FROM event_history WHERE id=OLD.event_id AND scope=OLD.scope) OR EXISTS(SELECT 1 FROM source_binding_receipts WHERE event_id=OLD.event_id AND scope=OLD.scope) BEGIN SELECT RAISE(ABORT,'Source binding audit is append-only while original history is retained'); END;
'''

def immutable(event):
 return {k:event.get(k) for k in ('id','seen','source','sensor','action','path','parameter_names','parameter_count','method','status','port','destination','client_claim','endpoint_hint','http_metadata')}

def core(observation):
 return {k:v for k,v in observation.items() if k not in ('connection_id','connection_count','binding_proof','lookup_status','binding_state','ambiguity_ref')}

def audit(db,event,scope,created,action,before,after,evidence):
 value={'event_id':event['id'],'scope':scope,'action':action,'before_sha256':fingerprint(before),'after_sha256':fingerprint(after),'evidence':evidence}
 ident=fingerprint(value)
 db.execute('INSERT OR IGNORE INTO source_binding_audit VALUES(?,?,?,?,?,?,?,?)',(ident,event['id'],scope,created,action,value['before_sha256'],value['after_sha256'],json.dumps(evidence)))
 return ident

def receive(db,address,event,scope,received):
 """Retain the latest complete receipt; propagate actual session nonuniqueness."""
 observation=event.get('source_observation') or {};proof=binding_proof(observation)
 if not proof:return
 previous=db.execute('SELECT content,checked_at FROM source_binding_receipts WHERE event_id=? AND scope=?',(event['id'],scope)).fetchone()
 if previous:
  old=json.loads(previous['content'])
  if immutable(old)!=immutable(event) or core(old['source_observation'])!=core(observation) or old['source_observation']['binding_proof']['record_sha256']!=proof['record_sha256']:
   audit(db,event,scope,received,'hard_record_disagreement',old,event,{'prior_receipt':old,'incoming_receipt':event})
  if _time(previous['checked_at'])>_time(proof['checked_at']):return
 db.execute('INSERT INTO source_binding_receipts VALUES(?,?,?,?) ON CONFLICT(event_id,scope) DO UPDATE SET checked_at=excluded.checked_at,content=excluded.content',(event['id'],scope,proof['checked_at'],json.dumps(event)))
 if proof['connection_count']==1:return
 state='ambiguous' if proof['connection_count']>1 else 'missing_connection'
 if not db.execute('SELECT 1 FROM source_binding_audit WHERE event_id=? AND scope=? AND action=? LIMIT 1',(event['id'],scope,'session_'+state)).fetchone():
  audit(db,event,scope,received,'session_'+state,event,event,{'complete_query_receipt':event,'source_record_sha256':proof['record_sha256']})
 where="ip=? AND source=? AND sensor=? AND scope=? AND json_extract(content,'$.source_observation.session_ref')=?"
 args=(address,event['source'],event['sensor'],scope,observation['session_ref'])
 for row in db.execute('SELECT id,content FROM event_history WHERE '+where,args).fetchall():
  old=json.loads(row['content']);meta=old.get('source_observation') or {}
  if any(meta.get(k)!=observation.get(k) for k in ('collector_ref','source_ref','session_ref')):continue
  if meta.get('binding_state') in ('ambiguous','missing_connection') or meta.get('conflict'):continue
  new=json.loads(row['content']);state='ambiguous' if proof['connection_count']>1 else 'missing_connection'
  new['source_observation'].update(binding_state=state,connection_count=proof['connection_count']);new['source_observation'].pop('connection_id',None);new['source_observation'].pop('binding_proof',None)
  ref=audit(db,old,scope,received,'session_'+state,old,new,{'complete_query_receipt':event,'source_record_sha256':proof['record_sha256']})
  new['source_observation']['ambiguity_ref']=ref
  db.execute('UPDATE event_history SET content=? WHERE id=? AND scope=?',(json.dumps(new),row['id'],scope))

def recovery(brain,event_id,scope,anchor_packet_id,review_reference,actor='',expected=None,apply=False,at=None):
 """Dry-run default. Apply requires the reviewed exact plan hash and identity.

 A legacy conflict alone is insufficient. Both the original event and original
 connection must have fresh complete receipts and match an immutable packet
 anchor. Known reuse, changed origins/targets/times/collectors or contrary
 recorded metadata block recovery. No model result is read or used.
 """
 at=at or dt.datetime.now(dt.timezone.utc)
 if not isinstance(review_reference,str) or not 5<=len(review_reference)<=500:raise ValueError('Supply the independently reviewed source-proof reference.')
 with brain.connect() as db:
  db.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
  row=db.execute('SELECT * FROM event_history WHERE id=? AND scope=?',(event_id,scope)).fetchone()
  receipt=db.execute('SELECT content FROM source_binding_receipts WHERE event_id=? AND scope=?',(event_id,scope)).fetchone()
  anchor=db.execute('SELECT content FROM packets WHERE id=?',(anchor_packet_id,)).fetchone()
  if not row or not receipt or not anchor:raise ValueError('Original history, complete receipt and immutable packet anchor are required.')
  old=json.loads(row['content']);fresh=json.loads(receipt['content']);observation=fresh.get('source_observation') or {};proof=binding_proof(observation)
  if not (old.get('source_observation') or {}).get('conflict'):raise ValueError('This explicit operation only recovers a reviewed legacy conflict.')
  if not proof or proof['connection_count']!=1 or not _time(proof['checked_at'])<=at<=_time(proof['checked_at'])+dt.timedelta(hours=1):raise ValueError('A fresh complete unique-connection receipt is required.')
  if immutable(old)!=immutable(fresh):raise ValueError('Original source record fields changed.')
  anchors=[e for e in json.loads(anchor['content']).get('events',[]) if e.get('id')==event_id]
  if len(anchors)!=1 or immutable(anchors[0])!=immutable(old) or core(anchors[0].get('source_observation') or {})!=core(observation):raise ValueError('The original record and scope do not match the immutable anchor.')
  a=anchors[0]['source_observation']
  if a.get('connection_id')!=proof['connection_id'] or a.get('connection_count')!=1:raise ValueError('The anchored original binding disagrees.')
  origin=old['provenance']['upstream_id']
  copies=db.execute("SELECT count(*) FROM event_history WHERE ip=? AND source=? AND sensor=? AND scope=? AND json_extract(content,'$.provenance.upstream_id')=?",(row['ip'],old['source'],old['sensor'],scope,origin)).fetchone()[0]
  if copies!=1:raise ValueError('The original record has disputed time or target copies.')
  if db.execute("SELECT 1 FROM source_binding_audit WHERE event_id=? AND scope=? AND (action LIKE 'hard_%' OR action LIKE 'session_%') LIMIT 1",(event_id,scope)).fetchone():raise ValueError('Recorded contradictory source evidence blocks recovery.')
  prior_session=db.execute("SELECT evidence FROM source_binding_audit WHERE scope=? AND json_extract(evidence,'$.complete_query_receipt.source_observation.session_ref')=? AND action LIKE 'session_%'",(scope,observation['session_ref'])).fetchall()
  if any(all(json.loads(r['evidence'])['complete_query_receipt']['source_observation'].get(k)==observation.get(k) for k in ('collector_ref','source_ref','session_ref')) for r in prior_session):raise ValueError('A recorded nonunique source session blocks recovery.')
  linked=db.execute("SELECT h.content,r.content receipt FROM event_history h JOIN source_binding_receipts r ON r.event_id=h.id AND r.scope=h.scope WHERE h.ip=? AND h.source=? AND h.sensor=? AND h.scope=? AND json_extract(h.content,'$.provenance.upstream_id')=?",(row['ip'],old['source'],old['sensor'],scope,proof['connection_id'])).fetchall()
  if len(linked)!=1:raise ValueError('An undisputed original connection receipt is required.')
  connection=json.loads(linked[0]['content']);connection_fresh=json.loads(linked[0]['receipt']);cp=binding_proof(connection_fresh.get('source_observation') or {})
  ca=[e for e in json.loads(anchor['content']).get('events',[]) if e.get('id')==connection['id']]
  if len(ca)!=1 or immutable(ca[0])!=immutable(connection) or immutable(connection)!=immutable(connection_fresh) or connection.get('action')!='cowrie.session.connect' or (connection_fresh.get('source_observation') or {}).get('semantic')!='connection' or core(ca[0].get('source_observation') or {})!=core(connection_fresh.get('source_observation') or {}) or (connection.get('source_observation') or {}).get('conflict') or not cp or cp['scope_ref']!=proof['scope_ref'] or cp['connection_count']!=1 or cp['record_sha256']!=proof['connection_sha256']:raise ValueError('Original connection time, target, scope or proof differs.')
  if db.execute("SELECT 1 FROM source_binding_audit WHERE event_id=? AND scope=? AND (action LIKE 'hard_%' OR action LIKE 'session_%') LIMIT 1",(connection['id'],scope)).fetchone():raise ValueError('The original connection has recorded contradictory evidence.')
  # Preserve first receipt, original fields and enriched index provenance.
  new={**old,'source_observation':observation};evidence={'anchor_packet_id':anchor_packet_id,'anchor_packet_sha256':hashlib.sha256(anchor['content'].encode()).hexdigest(),'source_receipt_sha256':fingerprint(fresh),'connection_receipt_sha256':fingerprint(connection_fresh),'complete_query_scope':proof['scope_ref'],'source_record_sha256':proof['record_sha256'],'review_reference':review_reference}
  plan={'event_id':event_id,'scope':scope,'before_sha256':fingerprint(old),'after_sha256':fingerprint(new),'evidence':evidence};plan['plan_sha256']=fingerprint(plan)
  if apply:
   if not isinstance(actor,str) or not 1<=len(actor)<=120 or expected!=plan['plan_sha256']:raise ValueError('Apply requires the reviewer identity and exact reviewed plan hash.')
   audit(db,old,scope,at.isoformat(),'reviewed_recovery',old,new,{**evidence,'actor':actor,'plan_sha256':plan['plan_sha256']})
   db.execute('UPDATE event_history SET content=? WHERE id=? AND scope=?',(json.dumps(new),event_id,scope))
  return {**plan,'applied':apply}
