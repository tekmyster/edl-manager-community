"""Synthetic provenance boundaries; never production accuracy labels."""
import copy,json
import pytest
from source_observations import metadata,sanitize,connections,prioritize
from evidence_history import normalize
from behavior_grounding import contract,example,validate,GroundingError

def linked_packet():
 address='8.8.8.8';events=[]
 for ident,action,semantic,second in [('zconn','cowrie.session.connect','connection',0),('cmd','cowrie.command.input','shell_input',1),('file','cowrie.session.file_download','file_capture',2)]:
  observation=metadata('synthetic-collector',address,'synthetic-session',semantic)
  observation.update(connection_id='zconn',connection_count=1)
  if semantic=='shell_input':observation['syntax_categories']=['permission_change']
  sample={'id':ident,'action':action,'seen':f'2026-10-17T10:00:{second:02d}+00:00','source_observation':observation}
  if ident=='zconn':sample.update(destination='192.168.9.1',port='22')
  events.append(normalize(address,'tpot','Cowrie',sample,'2026-10-17T10:01:00+00:00'))
 return {'packet_id':'synthetic-linked','coverage':'saved_samples','events':events,'context':[]}

def test_additive_metadata_keeps_original_event_identity_and_unknown_target():
 p=linked_packet();e=p['events'][1];sample={'id':'cmd','action':e['action'],'seen':e['seen']}
 bare=normalize('8.8.8.8','tpot','Cowrie',sample,'2026-10-17T10:01:00+00:00')
 assert e['id']==bare['id'] and e['destination']==bare['destination'] and e['port']==''
 c=contract(p,{})
 assert 'malicious' in c['classifications'] and len(c['malicious_support'][0]['evidence_ids'])==3
 findings=[f for f in c['facts'] if len(f['evidence_ids'])==2]
 assert len(findings)==2 and all(p['events'][0]['id'] in f['evidence_ids'] for f in findings)
 value=example(p);value.update(classification='malicious',analysis_summary=c['summaries']['malicious'],findings=findings)
 validate(value,p,[],{})

@pytest.mark.parametrize('mutation',[
 lambda p:p['events'].pop(0),
 lambda p:p['events'][1]['source_observation'].update(session_ref='0'*64),
 lambda p:p['events'][1]['source_observation'].update(source_ref='0'*64),
 lambda p:p['events'][1]['source_observation'].update(collector_ref='0'*64),
 lambda p:p['events'][1]['source_observation'].update(connection_count=2),
 lambda p:p['events'][1]['source_observation'].update(connection_id='missing'),
 lambda p:p['events'][1].update(seen='2026-10-17T09:59:59+00:00'),
 lambda p:p['events'][1].update(seen='2026-10-17T10:15:01+00:00'),
 lambda p:p['events'][1].update(destination={'asset_id':'conflict'}),
 lambda p:p['events'][1].update(port='2222'),
 lambda p:p['events'][1].update(source='other'),
 lambda p:p['events'][1]['provenance'].update(collector_agent='other'),
 lambda p:p['events'].append({**copy.deepcopy(p['events'][0]),'id':'duplicate','provenance':{'upstream_id':'reused','detail':'sample'}}),
])
def test_missing_cross_session_source_stream_time_reuse_and_conflicts_abstain(mutation):
 p=linked_packet();mutation(p)
 assert 'malicious' not in contract(p,{})['classifications']

def test_privacy_contract_exports_only_fixed_categories_and_opaque_references():
 raw=metadata('PRIVATE-HOST','8.8.8.8','PRIVATE-SESSION','file_capture')
 raw.update(input='PRIVATE-COMMAND',password='PRIVATE-PASSWORD',url='https://PRIVATE-URL',body='PRIVATE-BODY')
 clean=sanitize(raw,'8.8.8.8')
 assert 'PRIVATE' not in json.dumps(clean) and set(clean)=={'version','semantic','collector_ref','source_ref','session_ref'}
 assert not sanitize(raw,'1.1.1.1')
 assert not sanitize({**raw,'semantic':'PRIVATE'},'8.8.8.8')

@pytest.mark.parametrize('field,reason', [('analysis_summary','assessment_summary_mismatch'),('limitations','limitations_mismatch')])
def test_typed_diagnostics_do_not_include_rejected_values(field,reason):
 p=linked_packet();value=example(p);value[field]=['PRIVATE'] if field=='limitations' else 'PRIVATE'
 with pytest.raises(GroundingError) as caught:validate(value,p,[],{})
 diagnostic=caught.value.diagnostic()
 assert diagnostic['reason']==reason and diagnostic['field']==field and 'PRIVATE' not in json.dumps(diagnostic)

def test_plain_file_event_and_interactive_input_do_not_claim_network_or_execution():
 from behavior_mapping import select
 registry={'attack':{'T1059':'Command','T1105':'Transfer'},'d3fend':{}}
 p=linked_packet();assert select(registry,p)['attack']=={'T1059':'Command'}
 p['events'][1]['source_observation']['semantic']='interactive_input'
 assert not select(registry,p)['attack'] and 'malicious' not in contract(p,{})['classifications']
 p['events'][2]['source_observation']['semantic']='network_fetch'
 assert set(select(registry,p)['attack'])=={'T1105'}

def test_bounded_selection_retains_rare_complete_linkage_over_noise():
 p=linked_packet();events=p['events']+[{'id':f'noise-{i}','seen':'2026-10-17T11:00:00+00:00','action':'connection observed'} for i in range(100)]
 selected=prioritize(events,24)
 assert len(selected)==len({e['id'] for e in selected})==24 and {e['id'] for e in p['events']}<={e['id'] for e in selected}

def test_cache_enrichment_and_packet_preserve_identity_receipt_native_score_and_ttl(tmp_path):
 import datetime as dt
 from core import Store
 from behavior_ai import Brain,DEFAULTS
 from evidence_history import save,query
 s=Store(tmp_path/'native.sqlite3');brain=Brain(s);at=dt.datetime(2026,10,17,10,1,tzinfo=dt.timezone.utc)
 original=linked_packet()['events'];samples=[]
 for e in original:
  sample={'id':e['provenance']['upstream_id'],'seen':e['seen'],'action':e['action'],'source_observation':e['source_observation']}
  if sample['id']=='zconn':sample.update(destination='192.168.9.1',port='22')
  samples.append(sample)
 bare=[{k:v for k,v in sample.items() if k!='source_observation'} for sample in samples]
 save(brain,'8.8.8.8','tpot','Cowrie',bare,at.isoformat())
 first=query(brain,'8.8.8.8',at)['events']
 s.source_activity('8.8.8.8','tpot','Cowrie',at.isoformat(),{'activity':{'events':samples},'native_attempt_count':1,'native_event_count':3})
 before=s.describe('8.8.8.8');ident,packet,features=brain.packet(before,DEFAULTS,at=at+dt.timedelta(minutes=1))
 after=query(brain,'8.8.8.8',at+dt.timedelta(minutes=1))['events']
 assert {e['id'] for e in first}=={e['id'] for e in after}=={e['id'] for e in packet['events']}
 assert {e['received'] for e in first}=={e['received'] for e in after}
 assert all(e.get('source_observation') for e in after)
 assert 'malicious' in contract(packet,{})['classifications'] and len(json.dumps(packet).encode())<=11200
 assert s.describe('8.8.8.8')['score']==before['score'] and s.describe('8.8.8.8')['retention']==before['retention']

def test_packet_byte_bound_keeps_rare_file_original_connection_and_support(tmp_path):
 import datetime as dt
 from core import Store
 from behavior_ai import Brain,DEFAULTS,infer
 from behavior_grounding import example
 original=linked_packet()['events'];samples=[]
 for e in original:
  sample={'id':e['provenance']['upstream_id'],'seen':e['seen'],'action':e['action'],'source_observation':e['source_observation']}
  if sample['id']=='zconn':sample.update(destination='192.168.9.1',port='22')
  samples.append(sample)
 for index in range(21):samples.append({**copy.deepcopy(samples[1]),'id':f'noise-command-{index}','seen':'2026-10-17T10:00:03+00:00'})
 s=Store(tmp_path/'native');brain=Brain(s);at=dt.datetime(2026,10,17,10,1,tzinfo=dt.timezone.utc)
 s.source_activity('8.8.8.8','tpot','Cowrie',at.isoformat(),{'activity':{'events':samples}})
 _,p,_=brain.packet(s.describe('8.8.8.8'),DEFAULTS,at=at)
 assert len(p['events'])<24 and 'malicious' in contract(p,{})['classifications']
 assert {'file','zconn'}<={(e.get('provenance') or {}).get('upstream_id') for e in p['events']}
 requests=[]
 class Response:
  status_code=200
  def close(self):pass
  def iter_content(self,n):yield json.dumps({'done':True,'model':'offline','message':{'content':json.dumps(example(p))}}).encode()
 def send(*args,**kwargs):requests.append(kwargs['json']);return Response()
 assert infer({**DEFAULTS,'endpoint':'https://127.0.0.1','model':'offline'},p,[],{},'',requester=send)[0]['classification']=='inconclusive'
 assert len(requests[0]['messages'][1]['content'].encode())<=18000
