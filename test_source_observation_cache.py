"""Isolated persistence regressions; source reports are not malicious labels."""
import copy,datetime as dt,json
import pytest
from core import Store
from behavior_ai import Brain,DEFAULTS
from evidence_history import save,query,normalize
from behavior_grounding import contract
from test_source_observations import linked_packet

ADDRESS='8.8.8.8'
AT=dt.datetime(2026,10,17,10,1,tzinfo=dt.timezone.utc)

def samples():
 result=[]
 for event in linked_packet()['events']:
  value={'id':event['provenance']['upstream_id'],'seen':event['seen'],'action':event['action'],'source_observation':event['source_observation']}
  if value['id']=='zconn':value.update(destination='192.168.9.1',port='22')
  result.append(value)
 return result

def reload(store):return Brain(Store(store.path))

def packet(brain,raw=None):
 row=brain.store.describe(ADDRESS)
 if raw:row['activity']=[{'source':'tpot','sensor':'Cowrie','seen':AT.isoformat(),'details':{'activity':{'events':raw}}}]
 return brain.packet(row,DEFAULTS,at=AT+dt.timedelta(minutes=10))[1]

def history(brain,scope=''):
 with brain.connect() as db:return [dict(row) for row in db.execute('SELECT id,received,content FROM event_history WHERE scope=? ORDER BY id',(scope,))]

def test_missing_legacy_metadata_enriches_across_reload_without_new_identity_or_receipt(tmp_path):
 store=Store(tmp_path/'native');brain=Brain(store);rich=samples();bare=[{k:v for k,v in sample.items() if k!='source_observation'} for sample in rich]
 save(brain,ADDRESS,'tpot','Cowrie',bare,AT.isoformat());before=history(brain)
 brain=reload(store);save(brain,ADDRESS,'tpot','Cowrie',rich,(AT+dt.timedelta(minutes=1)).isoformat())
 brain=reload(store);after=history(brain)
 assert [(r['id'],r['received']) for r in before]==[(r['id'],r['received']) for r in after]
 assert all(json.loads(r['content']).get('source_observation') for r in after)
 assert 'malicious' in contract(packet(brain),{})['classifications']
 # Later legacy copies must not erase the enrichment.
 save(brain,ADDRESS,'tpot','Cowrie',bare,(AT+dt.timedelta(minutes=2)).isoformat())
 assert history(reload(store))==after

@pytest.mark.parametrize('field,value',[
 ('connection_id','conflicting-original'),('session_ref','0'*64),('collector_ref','1'*64),('connection_count',2),
])
def test_A_B_A_conflict_survives_save_reload_packet_and_repeated_original(tmp_path,field,value):
 store=Store(tmp_path/'native');brain=Brain(store);original=samples();changed=copy.deepcopy(original[1])
 changed['source_observation'][field]=value
 save(brain,ADDRESS,'tpot','Cowrie',original,AT.isoformat());before=history(brain)
 save(brain,ADDRESS,'tpot','Cowrie',[changed],(AT+dt.timedelta(minutes=1)).isoformat())
 command=normalize(ADDRESS,'tpot','Cowrie',original[1],AT.isoformat())
 for cycle in range(3):
  brain=reload(store)
  persisted=next(json.loads(r['content']) for r in history(brain) if r['id']==command['id'])
  assert persisted['source_observation']=={'conflict':True}
  assert persisted['id']==command['id'] and persisted['seen']==command['seen']
  for raw in (None,original):
   p=packet(brain,raw)
   assert 'malicious' not in contract(p,{})['classifications']
   assert next(e for e in p['events'] if e['id']==command['id'])['source_observation']=={'conflict':True}
  save(brain,ADDRESS,'tpot','Cowrie',original,(AT+dt.timedelta(minutes=cycle+2)).isoformat())
 assert [(r['id'],r['received']) for r in history(brain)]==[(r['id'],r['received']) for r in before]

@pytest.mark.parametrize('changes',[
 {'seen':'2026-10-17T10:00:03+00:00'}, # Same original connection now follows activity.
 {'seen':'2026-10-17T09:00:00+00:00'}, # Same original now outside linkage interval.
 {'destination':'192.168.9.2'},
 {'port':'2222'},
])
def test_disputed_original_connection_time_or_target_keeps_both_ids_and_permanent_abstention(tmp_path,changes):
 store=Store(tmp_path/'native');brain=Brain(store);original=samples();changed={**copy.deepcopy(original[0]),**changes}
 save(brain,ADDRESS,'tpot','Cowrie',original,AT.isoformat());before=history(brain)
 save(brain,ADDRESS,'tpot','Cowrie',[changed],(AT+dt.timedelta(minutes=1)).isoformat())
 changed_id=normalize(ADDRESS,'tpot','Cowrie',changed,AT.isoformat())['id'];assert changed_id not in {r['id'] for r in before}
 for cycle in range(3):
  brain=reload(store);after=history(brain);assert len(after)==4
  assert {r['id']:r['received'] for r in before}.items()<={r['id']:r['received'] for r in after}.items()
  connections=[json.loads(r['content']) for r in after if json.loads(r['content'])['action']=='cowrie.session.connect']
  assert len(connections)==2 and all(e['source_observation']=={'conflict':True} for e in connections)
  # Even a packet with only one disputed copy cannot resurrect a coherent link.
  p=packet(brain,original);assert 'malicious' not in contract(p,{})['classifications']
  p['events']=[e for e in p['events'] if e['id']!=changed_id]
  assert 'malicious' not in contract(p,{})['classifications']
  save(brain,ADDRESS,'tpot','Cowrie',original,(AT+dt.timedelta(minutes=cycle+2)).isoformat())

def test_conflict_marker_survives_forwarding_missing_copies_and_provenance_enrichment(tmp_path):
 store=Store(tmp_path/'native');brain=Brain(store);value=samples()[1]
 save(brain,ADDRESS,'tpot','Cowrie',[{**value,'source_observation':{'conflict':True,'input':'PRIVATE'}}],AT.isoformat())
 enriched={**value,'_index_id':'index-record','_agent':'fixture-agent'}
 save(reload(store),ADDRESS,'tpot','Cowrie',[enriched],(AT+dt.timedelta(minutes=1)).isoformat())
 brain=reload(store);rows=history(brain);event=json.loads(rows[0]['content'])
 assert event['source_observation']=={'conflict':True} and event['provenance']['record_id']=='index-record'
 assert rows[0]['received']==AT.isoformat() and 'PRIVATE' not in rows[0]['content']
 bare={k:v for k,v in value.items() if k!='source_observation'}
 save(brain,ADDRESS,'tpot','Cowrie',[bare],(AT+dt.timedelta(minutes=2)).isoformat())
 assert history(reload(store))==rows

def test_conflicts_are_scoped_and_original_lookup_is_indexed(tmp_path):
 store=Store(tmp_path/'native');brain=Brain(store);value=samples()[1]
 save(brain,ADDRESS,'tpot','Cowrie',[value],AT.isoformat(),'old-index')
 changed=copy.deepcopy(value);changed['source_observation']['session_ref']='0'*64
 save(brain,ADDRESS,'tpot','Cowrie',[changed],AT.isoformat(),'new-index')
 assert not any(json.loads(r['content'])['source_observation'].get('conflict') for scope in ('old-index','new-index') for r in history(brain,scope))
 with brain.connect() as db:
  plan=db.execute("EXPLAIN QUERY PLAN SELECT id FROM event_history WHERE ip=? AND source=? AND sensor=? AND scope=? AND json_extract(content,'$.provenance.upstream_id')=? AND id<>? LIMIT 1",(ADDRESS,'tpot','Cowrie','old-index','cmd','other')).fetchall()
 assert any('event_history_origin' in row['detail'] for row in plan)
