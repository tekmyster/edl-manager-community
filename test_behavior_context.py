import copy,datetime as dt,hashlib,json
import pytest
from core import now
from behavior_ai import Brain,validate_result,DEFAULTS
from behavior_context import context,destination
from test_behavior_ai import evidence,result

def test_structured_intelligence_preserves_freshness_origin_and_contradictions(evidence):
 evidence.cache('8.8.8.8','misp',{'matches':1,'context_matches':2,'sources':['GreyNoise imported feed'],'attribute_ids':['101'],'fresh_to_ids_and_warninglists_enforced':True})
 evidence.cache('8.8.8.8','greynoise',{'classification':'benign','noise':True,'riot':True,'found':True,'last_seen':now(),'name':'Verified service'})
 evidence.cache('8.8.8.8','crawler',{'verified':True,'operator':'Example crawler'})
 values=context(evidence,evidence.describe('8.8.8.8'));p={v['provider']:v for v in values if v['kind']=='intelligence'}
 assert p['misp']['actionable_matches']==1 and p['misp']['context_matches']==2 and p['misp']['origins']==['GreyNoise imported feed']
 assert p['misp']['origin_independence'].startswith('unknown') and p['greynoise']['classification']=='benign' and p['crawler']['verified']
 with evidence.connect() as d:d.execute("UPDATE cache SET expires='2020-01-01T00:00:00+00:00' WHERE provider='greynoise'")
 p={v['provider']:v for v in context(evidence,evidence.describe('8.8.8.8')) if v['kind']=='intelligence'};assert not p['greynoise']['cache_fresh']

def test_palo_history_uses_current_scope_and_pseudonymizes_internal_destinations(evidence):
 cfg={'index_url':'https://collector','palo_location':'firewall'};scope=hashlib.sha256(b'https://collector|firewall').hexdigest()[:16]
 evidence.state('source_configuration',{'index_url':'https://collector','palo_location':'firewall'})
 evidence.state('ip_activity:'+scope+':8.8.8.8',{'fetched':now(),'status':'ok','total':20,'events':[{'seen':now(),'action':'deny','destination':'10.1.2.3','nat':'10.2.3.4','port':'443','rule':'Block bad sources'}]})
 items=context(evidence,evidence.describe('8.8.8.8'),cfg);p=next(v for v in items if v['kind']=='palo_history')
 assert p['total_records']==20 and p['cache_fresh'] and p['sampled_events'][0]['destination']['scope']=='internal'
 assert '10.1.2.3' not in json.dumps(items) and '10.2.3.4' not in json.dumps(items)
 assert destination('10.1.2.3')==destination('10.1.2.3') and destination('8.8.8.8')['address']=='8.8.8.8'
 assert not p['drop_is_independent_attack_evidence']
 evidence.state('source_configuration',{'index_url':'https://collector','palo_location':'other'})
 assert next(v for v in context(evidence,evidence.describe('8.8.8.8'),cfg) if v['kind']=='palo_history')['total_records']==0

def test_history_is_context_and_never_mutates_score_or_retention(evidence):
 old=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=40)).isoformat(timespec='seconds')
 with evidence.connect() as d:d.execute('INSERT INTO offender_blocks VALUES(?,?,?,?,?)',('8.8.8.8',old,old,old,75))
 before=evidence.describe('8.8.8.8');b=Brain(evidence);unused,packet,features=b.packet(before)
 history=next(v for v in packet['context'] if v['kind']=='block_history');assert history['previous_score']==75 and history['returns_by_window']['365']==0
 after=evidence.describe('8.8.8.8');assert before['score']==after['score'] and before['retention']==after['retention']

def test_cross_ip_assessment_must_cite_both_observation_windows(evidence):
 b=Brain(evidence);row=evidence.describe('8.8.8.8');ident,packet,features=b.packet(row);peer=copy.deepcopy(row);peer['ip']='1.1.1.1';other,unused,unused2=b.packet(peer);candidates=b.candidates(ident,features)
 # Identical upstream IDs on different IPs remain distinct observations.
 assert candidates
 own=packet['events'][0]['id'];remote=candidates[0]['historical_events'][0]['id'];assert own!=remote
 r=result(packet);r['actor_correlation']=[{'candidate_id':other,'confidence':.7,'evidence_ids':[remote],'explanation':'Similar sequence','alternative_explanations':['Shared tool']}]
 with pytest.raises(ValueError,match='current and historical'):validate_result(r,packet,candidates,{})
 r['actor_correlation'][0]['evidence_ids']=[own,remote];assert validate_result(r,packet,candidates,{})

def test_palo_refresh_reuses_cache_and_honors_budget_and_pending_lease(evidence):
 from behavior_context import refresh_palo
 cfg={'index_url':'https://collector','index_user':'reader','index_password':'private-fixture'};evidence.state('source_configuration',{'index_url':'https://collector','palo_location':'firewall'})
 calls=[]
 def fetcher(config,address):calls.append(address);return {'status':'ok','fetched':now(),'total':3,'events':[]}
 assert refresh_palo(evidence,cfg,'8.8.8.8',1,fetcher)=='refreshed'
 assert refresh_palo(evidence,cfg,'8.8.8.8',1,fetcher)=='cached' and len(calls)==1
 assert refresh_palo(evidence,cfg,'1.1.1.1',1,fetcher)=='budget' and len(calls)==1
 scope=hashlib.sha256(b'https://collector|firewall').hexdigest()[:16]
 evidence.state('ip_activity_pending:ip_activity:'+scope+':9.9.9.9',{'started':now()})
 assert refresh_palo(evidence,cfg,'9.9.9.9',10,fetcher)=='pending' and len(calls)==1
 assert refresh_palo(evidence,{},'8.8.4.4',10,fetcher)=='not_configured'

def test_ui_and_background_context_share_one_atomic_ip_lease(evidence):
 from activity import claim_activity
 from concurrent.futures import ThreadPoolExecutor
 with ThreadPoolExecutor(max_workers=8) as pool:outcomes=list(pool.map(lambda unused:claim_activity(evidence,'ip_activity:scope:8.8.8.8'),range(8)))
 assert outcomes.count('claimed')==1 and outcomes.count('pending')==7

def test_forwarded_sample_with_updated_bucket_count_is_one_observation(evidence):
 row=evidence.describe('8.8.8.8');duplicate=copy.deepcopy(row['evidence'][0]);duplicate['details']=json.loads(duplicate['details']) if isinstance(duplicate['details'],str) else duplicate['details'];duplicate['details']['native_attempt_count']=10
 row['evidence'].append(duplicate);unused,packet,features=Brain(evidence).packet(row)
 assert len(packet['events'])==2 and all(e['native_attempts']==10 for e in packet['events'])
 assert 'intelligence' not in packet and 'intelligence_freshness' not in packet

def test_historical_fingerprints_remain_searchable_after_current_window_changes(evidence):
 b=Brain(evidence);now_row=evidence.describe('8.8.8.8');peer=copy.deepcopy(now_row);peer['ip']='1.1.1.1';then=dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=100)
 for record in peer['evidence']:
  record['seen']=then.isoformat();details=json.loads(record['details']) if isinstance(record['details'],str) else record['details'];details['activity']=json.loads(details['activity']) if isinstance(details['activity'],str) else details['activity']
  for event in details['activity']['events']:event['seen']=then.isoformat()
  record['details']=details
 old,old_packet,old_features=b.packet(peer,at=then)
 replacement=copy.deepcopy(now_row);replacement['ip']='1.1.1.1'
 for record in replacement['evidence']:record['details']={'activity':{'events':[{'id':'different','seen':now(),'path':'/unrelated','method':'GET','action':'ordinary navigation'}]}}
 latest,unused,unused2=b.packet(replacement);assert latest!=old
 own,packet,features=b.packet(now_row);matches=b.candidates(own,features)
 assert any(match['candidate_id']==old for match in matches)
 historical=b.packet_view(old);assert historical['historical'] and historical['ip']=='1.1.1.1' and historical['evidence']
 with b.connect() as db:db.execute('DELETE FROM packet_feature_index WHERE packet_id=?',(old,));db.execute('DELETE FROM packet_feature_ready WHERE packet_id=?',(old,))
 assert b.backfill_features()>0 and any(match['candidate_id']==old for match in b.candidates(own,features))
