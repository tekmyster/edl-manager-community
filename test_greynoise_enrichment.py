import datetime as dt,json
from core import Store,now
from greynoise_enrichment import assessment,enrich,metrics,decorate
from table_layout import policy_rows
from test_ui_settings import ui

def payload(kind='malicious',days=0):
 return {'classification':kind,'last_seen':(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=days)).isoformat(),'found':True}

def test_only_fresh_malicious_intelligence_scores_and_bonus_is_capped(tmp_path):
 s=Store(tmp_path/'db');s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 for kind,days,score in [('malicious',0,75),('malicious',8,50),('benign',0,50),('suspicious',0,50),('unknown',0,50)]:
  s.cache('8.8.8.8','greynoise',payload(kind,days));assert s.describe('8.8.8.8')['score']==score
 s.cache('8.8.8.8','greynoise',payload());s.cache('8.8.8.8','misp',{'matches':1,'fresh_to_ids_and_warninglists_enforced':True,'snapshot_fetched':now()})
 assert s.describe('8.8.8.8')['score_breakdown']['enrichment_bonus']==25
 s.state('greynoise_settings',{'score_enabled':False});s.cache('8.8.8.8','misp',{})
 assert s.describe('8.8.8.8')['score']==50

def test_benign_conflict_does_not_allow_and_whitelist_still_wins(tmp_path):
 s=Store(tmp_path/'db');s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50,details={'native_attempt_count':2})
 s.cache('8.8.8.8','greynoise',payload('benign'))
 r=policy_rows(s,[s.describe('8.8.8.8')],[])[0]
 assert r['policy']=='Denied' and r['intelligence']['conflict']
 s.add_rule('allow','8.8.8.8','Verified dependency',None,'admin')
 r=policy_rows(s,[s.describe('8.8.8.8')],s.active_rules())[0]
 assert r['policy']=='Allowed' and not r['intelligence']['conflict']
 assert r['priority']=='Protected benign actor'
 s.add_rule('block','9.9.9.9','Manual incident',None,'admin')
 s.cache('9.9.9.9','greynoise',payload('benign'))
 manual=policy_rows(s,[s.describe('9.9.9.9')],s.active_rules())[0]
 assert manual['intelligence']['conflict'] and manual['policy']=='Denied'

class Response:
 def __init__(self,code,value=None):self.status_code=code;self.value=value
 def raise_for_status(self):
  if self.status_code>=400:raise __import__('requests').HTTPError('Rejected')
 def json(self):return self.value

def test_shared_cache_negative_results_budget_and_rate_limit(tmp_path):
 s=Store(tmp_path/'db');rows=[{'ip':'8.8.8.8','score':50,'cache_status':[],'auto_candidate':False}]
 calls=[]
 def request(*a,**kw):calls.append(a);return Response(404)
 assert enrich(s,rows,'private-key',request)==1
 assert enrich(s,rows,'private-key',request)==0 and len(calls)==1
 assert json.loads(s.cached('8.8.8.8','greynoise')['payload'])['found'] is False
 s.state('greynoise_settings',{'weekly_budget':1})
 assert enrich(s,[{**rows[0],'ip':'9.9.9.9'}],'private-key',request)==0
 s.state('greynoise_settings',{'weekly_budget':10})
 assert enrich(s,[{**rows[0],'ip':'9.9.9.9'}],'private-key',lambda *a,**k:Response(429))==1
 assert enrich(s,[{**rows[0],'ip':'1.1.1.1'}],'private-key',request)==0

def test_review_audit_and_metrics_do_not_infer_a_whitelist_resolution(ui):
 app,c,cfg=ui;s=app.store;s.evidence('8.8.8.8','tpot','Cowrie',now(),'ssh',50)
 s.cache('8.8.8.8','greynoise',payload('malicious'))
 assert c.post('/ip/8.8.8.8/intelligence-review',data={'csrf':'csrf','outcome':'false_positive','note':'Verified owner'},base_url='https://localhost').status_code==302
 m=metrics(s,policy_rows(s,s.all_scores(),[]))
 assert m['reviewed']==1 and m['false_positives']==1 and not s.active_rules()
 assert c.get('/results/intel-fresh',base_url='https://localhost').status_code==200
 assert 'GreyNoise' in c.get('/settings',base_url='https://localhost').text
 detail=c.get('/ip/8.8.8.8',base_url='https://localhost').text
 assert 'Intelligence review' in detail and 'False positive: Verified owner' in detail
 from reporting_api import issue
 token=issue(s,'Intelligence test',30,'admin')
 response=c.get('/api/v1/intelligence',headers={'Authorization':'Bearer '+token},base_url='https://localhost')
 assert response.status_code==200 and response.json['metrics']['malicious']==1
 assert c.get('/api/v1/intelligence',base_url='https://localhost').status_code==401

def test_expired_and_unknown_never_become_benign():
 assert not assessment(payload('benign'),100,True,valid=False)['possible_conflict']
 assert not assessment({'classification':'unknown','found':False},50,True)['score_signal']
