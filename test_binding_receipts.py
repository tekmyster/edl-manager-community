"""Offline source-proof/unknown/recovery invariants, never activity truth labels."""
import copy,datetime as dt,json
import pytest
from source_observations import merge_reports,proof_scope,PROOF_VERSION,sanitize,binding_proof,connections
from source_binding_recovery import recovery
from evidence_history import save,normalize
from test_source_observation_cache import samples,AT,ADDRESS,history,reload,packet
from behavior_ai import Brain
from core import Store
from behavior_grounding import contract

def proven(values=None,count=1,at=AT):
 values=copy.deepcopy(values or samples());start=(at-dt.timedelta(days=30)).isoformat();end=at.isoformat();sha={v['id']:('%064x'%(i+1)) for i,v in enumerate(values)}
 for value in values:
  o=value['source_observation'];o['lookup_status']='complete';o['binding_proof']={'version':PROOF_VERSION,'record_id':value['id'],'record_sha256':sha[value['id']],'scope_ref':proof_scope(o,start,end),'window_start':start,'window_end':end,'checked_at':at.isoformat(),'connection_count':count,'connection_id':'zconn' if count==1 else None,'connection_sha256':sha['zconn'] if count==1 else None}
  o['connection_count']=count
  if count!=1:o.pop('connection_id',None)
 return values

def partial(value,status='not_selected'):
 value=copy.deepcopy(value)
 for key in ('connection_id','connection_count','binding_proof','binding_state'):value.pop(key,None)
 value['lookup_status']=status;return value

@pytest.mark.parametrize('status',['not_selected','partial','error'])
def test_bound_partial_rebound_is_not_a_conflict_in_either_order(status):
 a=proven()[1]['source_observation'];b=partial(a,status)
 assert merge_reports(a,b)['connection_id']=='zconn' and not merge_reports(b,a).get('conflict')
 assert merge_reports(merge_reports(a,b),a)['binding_proof']==a['binding_proof']
 assert merge_reports({k:v for k,v in a.items() if k!='binding_proof'},b)['connection_id']=='zconn'

@pytest.mark.parametrize('count',[0,2,30])
def test_fresh_complete_nonunique_result_defeats_older_unique_and_stays_closed(count):
 a=proven()[1]['source_observation'];b=proven(count=count,at=AT+dt.timedelta(minutes=1))[1]['source_observation']
 result=merge_reports(a,b)
 assert result['connection_count']==count and 'connection_id' not in result and result['binding_state'] in ('ambiguous','missing_connection')
 assert 'connection_id' not in merge_reports(result,a) and 'connection_id' not in merge_reports(result,partial(a))

@pytest.mark.parametrize('mutate',[
 lambda o:o['binding_proof'].update(scope_ref='0'*64),
 lambda o:o['binding_proof'].update(checked_at='2020-01-01T00:00:00+00:00'),
 lambda o:o['binding_proof'].update(connection_count=True),
 lambda o:o['binding_proof'].update(record_id='other'),
 lambda o:o['binding_proof'].update(window_start='2026-10-17T10:00:00+00:00'),
])
def test_invalid_proof_cannot_fall_back_to_legacy_binding(mutate):
 value=proven()[1];mutate(value['source_observation']);normal=normalize(ADDRESS,'tpot','Cowrie',value,AT.isoformat())
 assert normal['source_observation']=={'conflict':True}

@pytest.mark.parametrize('field,value',[('session_ref','0'*64),('collector_ref','1'*64),('source_ref','2'*64),('semantic','interactive_input'),('syntax_categories',['interpreter_input'])])
def test_missing_optional_binding_does_not_hide_real_core_contradictions(field,value):
 a=proven()[1]['source_observation'];b=partial(a);b[field]=value
 assert merge_reports(a,b)=={'conflict':True}

def test_cache_and_packet_both_preserve_partial_lookup_without_native_or_immutable_changes(tmp_path):
 store=Store(tmp_path/'native');brain=Brain(store);values=proven();save(brain,ADDRESS,'tpot','Cowrie',values,AT.isoformat());before=history(brain);native=store.describe(ADDRESS)
 for value in values:value['source_observation']=partial(value['source_observation'],'partial')
 save(reload(store),ADDRESS,'tpot','Cowrie',values,(AT+dt.timedelta(minutes=1)).isoformat())
 b=reload(store);p=packet(b,values)
 assert 'malicious' in contract(p,{})['classifications'] and len(connections(p['events']))==3
 assert [(r['id'],r['received']) for r in before]==[(r['id'],r['received']) for r in history(b)]
 assert store.describe(ADDRESS)==native and len(json.dumps(p).encode())<=11200

def test_session_reuse_receipt_invalidates_old_sibling_even_if_not_in_new_sample_batch(tmp_path):
 b=Brain(Store(tmp_path/'native'));values=proven();save(b,ADDRESS,'tpot','Cowrie',values,AT.isoformat())
 save(b,ADDRESS,'tpot','Cowrie',[proven(count=2,at=AT+dt.timedelta(minutes=1))[1]],(AT+dt.timedelta(minutes=1)).isoformat())
 rows=[json.loads(r['content']) for r in history(reload(b.store))]
 assert len(rows)==3 and all(e['source_observation'].get('binding_state')=='ambiguous' for e in rows)
 assert not connections(rows) and 'malicious' not in contract(packet(reload(b.store)),{})['classifications']

def setup_recovery(tmp_path):
 store=Store(tmp_path/'native');b=Brain(store);values=samples();save(b,ADDRESS,'tpot','Cowrie',values,AT.isoformat());p=packet(b,values)
 target=next(e for e in p['events'] if e['action']=='cowrie.session.file_download');anchor=p['packet_id']
 # Simulate the persisted legacy absence-only marker without touching packets.
 with b.connect() as db:
  row=db.execute('SELECT content FROM event_history WHERE id=?',(target['id'],)).fetchone();e=json.loads(row[0]);e['source_observation']={'conflict':True};db.execute('UPDATE event_history SET content=? WHERE id=?',(json.dumps(e),target['id']))
 save(b,ADDRESS,'tpot','Cowrie',proven(),(AT+dt.timedelta(minutes=1)).isoformat())
 return b,target['id'],anchor

def test_legacy_recovery_is_explicit_hash_bound_source_proven_and_append_only_audited(tmp_path):
 b,ident,anchor=setup_recovery(tmp_path)
 with b.connect() as db:
  immutable_tables={t:[tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in ('packets','assessments','evaluation_cases','evaluation_labels','assessment_feedback')};before=history(b)
 plan=recovery(b,ident,'',anchor,'Synthetic independent original-source review',at=AT+dt.timedelta(minutes=2))
 assert not plan['applied'] and history(b)==before
 with pytest.raises(ValueError):recovery(b,ident,'',anchor,'Synthetic independent original-source review',actor='fixture',expected='wrong',apply=True,at=AT+dt.timedelta(minutes=2))
 assert recovery(b,ident,'',anchor,'Synthetic independent original-source review',actor='fixture',expected=plan['plan_sha256'],apply=True,at=AT+dt.timedelta(minutes=2))['applied']
 assert [(r['id'],r['received']) for r in history(b)]==[(r['id'],r['received']) for r in before]
 with b.connect() as db:
  for t,rows in immutable_tables.items():assert [tuple(r) for r in db.execute('SELECT * FROM '+t)]==rows
  assert db.execute("SELECT count(*) FROM source_binding_audit WHERE action='reviewed_recovery'").fetchone()[0]==1
  with pytest.raises(Exception,match='append-only'):db.execute('DELETE FROM source_binding_audit')
 assert 'malicious' in contract(packet(b),{})['classifications']

@pytest.mark.parametrize('bad',['stale','scope','connection_target','anchor','multi','source_record'])
def test_recovery_rejects_missing_or_contradictory_source_proof(tmp_path,bad):
 b,ident,anchor=setup_recovery(tmp_path);clock=AT+dt.timedelta(minutes=2)
 with b.connect() as db:
  if bad=='connection_target':db.execute("UPDATE event_history SET content=json_set(content,'$.destination.asset_id','other') WHERE json_extract(content,'$.action')='cowrie.session.connect'")
  if bad=='scope':db.execute("UPDATE source_binding_receipts SET scope='other'")
  if bad=='source_record':db.execute("UPDATE source_binding_receipts SET content=json_set(content,'$.path','changed') WHERE event_id=?",(ident,))
 if bad=='stale':clock=AT+dt.timedelta(hours=2)
 if bad=='anchor':anchor='not-present'
 if bad=='multi':save(b,ADDRESS,'tpot','Cowrie',[proven(count=2,at=AT+dt.timedelta(minutes=1))[1]],(AT+dt.timedelta(minutes=1)).isoformat())
 with pytest.raises(ValueError):recovery(b,ident,'',anchor,'Synthetic independent review',at=clock)

def test_old_conflict_cannot_recover_after_sibling_proves_reuse_then_later_unique(tmp_path):
 b,ident,anchor=setup_recovery(tmp_path)
 save(b,ADDRESS,'tpot','Cowrie',[proven(count=2,at=AT+dt.timedelta(minutes=1))[1]],(AT+dt.timedelta(minutes=1)).isoformat())
 save(b,ADDRESS,'tpot','Cowrie',proven(at=AT+dt.timedelta(minutes=2)),(AT+dt.timedelta(minutes=2)).isoformat())
 with pytest.raises(ValueError):recovery(b,ident,'',anchor,'Synthetic independent review',at=AT+dt.timedelta(minutes=3))

def test_proven_packet_bounds_and_original_receipt_retention(tmp_path):
 from evidence_history import cleanup
 from behavior_generation import prepare
 b=Brain(Store(tmp_path/'native'));values=proven();save(b,ADDRESS,'tpot','Cowrie',values,AT.isoformat());p=packet(b,values)
 assert 'malicious' in contract(p,{})['classifications'] and len(json.dumps(p).encode())<=11200 and len(json.dumps(prepare(p,[],{})[1]).encode())<=18000
 save(b,ADDRESS,'tpot','Cowrie',[proven(count=2,at=AT+dt.timedelta(minutes=1))[1]],(AT+dt.timedelta(minutes=1)).isoformat())
 cleanup(b,AT+dt.timedelta(days=31))
 with b.connect() as db:
  assert db.execute('SELECT count(*) FROM event_history').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM source_binding_receipts').fetchone()[0]==0
  assert db.execute('SELECT count(*) FROM source_binding_audit').fetchone()[0]==0

def test_forwarded_wrong_source_scope_is_not_silently_treated_as_missing(tmp_path):
 b=Brain(Store(tmp_path/'native'));values=samples();save(b,ADDRESS,'tpot','Cowrie',values,AT.isoformat());changed=copy.deepcopy(values[1]);changed['source_observation']['source_ref']='0'*64
 save(b,ADDRESS,'tpot','Cowrie',[changed],AT.isoformat())
 assert 'malicious' not in contract(packet(reload(b.store),values),{})['classifications']

def test_late_arriving_complete_reuse_proof_still_invalidates_all_siblings(tmp_path):
 b=Brain(Store(tmp_path/'native'));save(b,ADDRESS,'tpot','Cowrie',proven(at=AT+dt.timedelta(minutes=2)),(AT+dt.timedelta(minutes=2)).isoformat())
 save(b,ADDRESS,'tpot','Cowrie',[proven(count=2)[1]],(AT+dt.timedelta(minutes=3)).isoformat())
 assert not connections([json.loads(r['content']) for r in history(b)])

def test_new_incoming_conflict_is_audited_and_not_eligible_for_legacy_recovery(tmp_path):
 b,ident,anchor=setup_recovery(tmp_path);bad=proven()[2];bad['source_observation']['source_ref']='0'*64
 save(b,ADDRESS,'tpot','Cowrie',[bad],(AT+dt.timedelta(minutes=1)).isoformat())
 save(b,ADDRESS,'tpot','Cowrie',proven(at=AT+dt.timedelta(minutes=2)),(AT+dt.timedelta(minutes=2)).isoformat())
 with pytest.raises(ValueError,match='contradictory'):recovery(b,ident,'',anchor,'Synthetic independent source review',at=AT+dt.timedelta(minutes=3))
