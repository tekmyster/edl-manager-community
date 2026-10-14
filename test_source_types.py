import datetime as dt,json,os,pytest
from core import Store,now
from web_client import client_info,http_details
from source_types import classify,refresh

def test_browser_headers_are_not_verified_humans():
 c=client_info('Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.0.0 Safari/537.36')
 assert c['client']=='Chrome 130.0.0.0' and c['platform']=='Windows'
 assert c['client_type']=='Browser-like client' and c['confidence']=='Inferred'
 assert client_info('HeadlessChrome/130.0')['client_type']=='Browser automation'

def test_bot_claim_requires_operator_evidence():
 c=client_info('Mozilla/5.0 GPTBot/1.1')
 assert c['operator']=='OpenAI' and c['confidence']=='Claimed'
 labels=classify([c],[],[('OpenAI','AI training')])['labels']
 assert len(labels)==1 and labels[0]['confidence']=='Verified'
 assert classify([c],[],[('Google','Search crawler')])['labels'][1]['confidence']=='Claimed'

def test_http_metadata_excludes_sensitive_payload_and_normalizes_host():
 v={'request':{'method':'POST','headers':{'Host':'example.org:8443','User-Agent':'curl/8.0','Authorization':'Bearer secret','Cookie':'secret'},'body':'password=secret'},'response':{'status':403},'username':'secret','password':'secret'}
 r=http_details(v);assert r['host']=='example.org:8443' and r['method']=='POST' and r['status']=='403' and r['client']=='curl'
 assert 'secret' not in json.dumps(r)
 assert http_details({'http_host':'https://user:secret@example.org/path?token=secret'})['host']=='example.org'

def test_source_type_cache_dedup_expires_verification_and_has_no_policy_effect(tmp_path):
 s=Store(tmp_path/'db.sqlite');seen=now()
 s.evidence('8.8.8.8','tpot','Cowrie',seen,'ssh',50,details={'native_attempt_count':2})
 s.source_activity('8.8.8.8','nginx','web-request',seen,{'activity':{'events':[{'id':'web','seen':seen,'action':'HTTP request',**client_info('GPTBot/1.1')}]}})
 future=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(hours=1)).isoformat(timespec='seconds')
 s.state('crawler_feeds',{'fetched':seen,'expires':future,'data':{'openai-training':[{'ipv4Prefix':'8.8.8.8/32'}]}})
 before=s.describe('8.8.8.8')['score'];assert refresh(s)==1;assert refresh(s)==0
 r=s.describe('8.8.8.8');assert r['score']==before and r['source_identity']['labels'][0]['confidence']=='Verified'
 assert not any(x['provider']=='source_type' for x in r['enrichment_details'])
 with s.connect() as d:assert d.execute('SELECT COUNT(*) FROM block_retention').fetchone()[0]==0
 s.state('crawler_feeds',{'fetched':seen,'expires':seen,'data':{}});assert refresh(s)==1
 assert s.describe('8.8.8.8')['source_identity']['labels'][0]['confidence']=='Claimed'

@pytest.mark.skipif(os.name=='nt',reason='Worker uses Linux flock')
def test_nonqualifying_web_requests_never_create_evidence_or_renew_blocks(tmp_path):
 from worker import ingest_source
 s=Store(tmp_path/'db.sqlite');seen=now()
 k={'ip':'8.8.8.8','source':'nginx','detector':'web-request'}
 data={'edl_qualifying':'no','edl_seen_utc':seen,'edl_activity_json':json.dumps({'events':[{'id':'web','seen':seen,'action':'HTTP request','path':'/'}]})}
 assert ingest_source(s,k,data,seen,1) is False
 with s.connect() as d:
  assert d.execute('SELECT COUNT(*) FROM evidence').fetchone()[0]==0
  assert d.execute('SELECT COUNT(*) FROM ips').fetchone()[0]==0
  d.execute('INSERT INTO block_retention VALUES(?,?,?,?,?,?,?)',('8.8.8.8',seen,seen,(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=30)).isoformat(),'tpot',75,'{}'))
 assert ingest_source(s,k,{**data,'edl_seen_utc':(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=1)).isoformat()},seen,1) is False
 with s.connect() as d:assert d.execute('SELECT last_seen FROM block_retention').fetchone()[0]==seen
