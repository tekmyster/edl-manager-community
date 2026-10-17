"""Bounded evidence alerts. Observed recurrence never grants enforcement or identity."""
import datetime as dt,json,pathlib,re,uuid
from behavior_ai import digest,timestamp,now
from behavior_correlation import UNCERTAINTY,GENERIC_PATHS

VERSION='intelligence-1'
SCHEMA='''
CREATE TABLE IF NOT EXISTS intelligence_alerts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,fingerprint TEXT NOT NULL,ip TEXT NOT NULL,peer_ip TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,state TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS intelligence_alerts_time ON intelligence_alerts(last_seen,id);
CREATE TABLE IF NOT EXISTS intelligence_observations(id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,packet_id TEXT NOT NULL,peer_packet TEXT NOT NULL,created TEXT NOT NULL,details TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS intelligence_observations_alert ON intelligence_observations(alert_id,created);
CREATE INDEX IF NOT EXISTS intelligence_observations_age ON intelligence_observations(created,id);
CREATE TABLE IF NOT EXISTS intelligence_reviews(id TEXT PRIMARY KEY,alert_id TEXT NOT NULL,at TEXT NOT NULL,actor TEXT NOT NULL,outcome TEXT NOT NULL,notes TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS intelligence_observation_refs AFTER INSERT ON intelligence_observations BEGIN
 INSERT OR IGNORE INTO retention_refs VALUES('intelligence',NEW.id,NEW.packet_id);
 INSERT OR IGNORE INTO retention_refs SELECT 'intelligence',NEW.id,NEW.peer_packet WHERE NEW.peer_packet!='';
END;
CREATE TRIGGER IF NOT EXISTS intelligence_observation_delete AFTER DELETE ON intelligence_observations BEGIN
 DELETE FROM retention_refs WHERE kind='intelligence' AND owner=OLD.id;
END;
'''

def profile(packet):
 events=[e for e in packet.get('events',[])[:160] if e.get('id') and timestamp(e.get('seen')) and e.get('provenance',{}).get('detail')!='summary']
 paths=sorted({e['path'] for e in events if e.get('path') is not None and e.get('path','') not in GENERIC_PATHS and '[identifier]' not in e['path']})[:24]
 actions=sorted({e['action'] for e in events if e.get('action') in ('cowrie.command.input','cowrie.session.file_download','cowrie.login.failed','sensitive path request')})
 clients=sorted({e['client_type'] for e in events if e.get('client_type') not in ('',None,'Unknown')})[:8]
 tokens=['path:'+p for p in paths]+['action:'+a for a in actions]
 # Generic client classes, timing, sensor names and target ownership never add identity weight.
 claims=sorted({e['client_claim']['label'] for e in events if isinstance(e.get('client_claim'),dict) and e['client_claim'].get('label')})[:8]
 return {'fingerprint':'fp_'+digest(tokens)[:24],'paths':paths,'actions':actions,'clients':clients,'claims':claims,'events':events,'tokens':tokens,'partial':True}

def comparison(current,historical):
 a,b=profile(current),profile(historical);old={e['id'] for e in b['events']}
 fresh=[e for e in a['events'] if e['id'] not in old]
 dates=lambda events:[timestamp(e['seen']) for e in events]
 return {'shared':sorted(set(a['tokens'])&set(b['tokens']))[:24],'added':sorted(set(a['tokens'])-set(b['tokens']))[:24],
         'removed_from_sample':sorted(set(b['tokens'])-set(a['tokens']))[:24],
         'client_classes_current':a['clients'],'client_classes_historical':b['clients'],
         'client_claims_current':a['claims'],'client_claims_historical':b['claims'],
         'current_events':fresh[-8:],'historical_events':b['events'][-8:],
         'current_sequence':sequence(a['events']),'historical_sequence':sequence(b['events']),
         'new_event_count_in_sample':len(fresh),
         'gap_seconds':(min(dates(fresh))-max(dates(b['events']))).total_seconds() if fresh and b['events'] else None,
         'timing_basis':'saved native event times; absence from sample is not cessation',
         'uncertainty':UNCERTAINTY+['Client classes and headers are spoofable. TLS/header-order fingerprints are unavailable.'],
         'operator_hypothesis':'unknown; neither a person nor a named bot is identified','confidence':'uncalibrated review candidate',
         'enforcement_effect':'none','suggested_review':'Compare cited requests, targets and timing; reject shared-tool matches or review the relationship before grouping.'}

def sequence(events):
 ordered=sorted(events,key=lambda e:(timestamp(e['seen']),e['id']));result=[]
 for left,right in zip(ordered,ordered[1:]):
  gap=(timestamp(right['seen'])-timestamp(left['seen'])).total_seconds()
  if (left.get('source'),left.get('sensor'))!=(right.get('source'),right.get('sensor')) or not 0<=gap<=900:continue
  result.append({'from':left.get('path') or left.get('action'),'to':right.get('path') or right.get('action'),'gap_seconds':gap,'evidence_ids':[left['id'],right['id']]})
 return result[-8:]

def save_alert(db,kind,own,peer,details,key=None):
 p=profile(json.loads(own['content']));ident='intel_'+digest([VERSION,kind,key or [p['fingerprint'],own['ip'],peer['ip'] if peer else '']])[:24]
 events=details.get('current_events',[])+details.get('historical_events',[])
 current_times=[timestamp(e['seen']) for e in details.get('current_events',[])];historical_times=[timestamp(e['seen']) for e in details.get('historical_events',[])]
 details['gap_seconds']=(min(current_times)-max(historical_times)).total_seconds() if current_times and historical_times else None
 details['temporal_relation']='current citations follow historical citations' if details['gap_seconds'] is not None and details['gap_seconds']>0 else 'saved windows overlap or current citations precede comparison; return ordering unproven'
 details['taxonomy_context']=[]
 for row in ([own,peer] if peer else [own]):
  assessment=db.execute("SELECT id,result,created FROM assessments WHERE packet_id=? AND status='completed' ORDER BY created DESC,rowid DESC LIMIT 1",(row['id'],)).fetchone()
  if assessment:
   value=json.loads(assessment['result'])
   details['taxonomy_context'].append({'packet_id':row['id'],'assessment_id':assessment['id'],'created':assessment['created'],'attack':value.get('attack_techniques',[]),'d3fend':value.get('d3fend_context',[]),'provenance':value.get('metadata',{}).get('taxonomy_version','unknown')})
 dates=sorted(e['seen'] for e in events if timestamp(e.get('seen')))
 if not dates:return
 first,last=dates[0],dates[-1]
 db.execute('INSERT INTO intelligence_alerts VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen)',(ident,kind,p['fingerprint'],own['ip'],peer['ip'] if peer else '',first,last,'proposed'))
 observation='obs_'+digest([ident,sorted(e['id'] for e in details.get('current_events',[])),sorted(e['id'] for e in details.get('historical_events',[])),details.get('shared',[])])[:24]
 db.execute('INSERT OR IGNORE INTO intelligence_observations VALUES(?,?,?,?,?,?)',(observation,ident,own['id'],peer['id'] if peer else '',now(),json.dumps(details)))
 return ident

def cleanup(db,at=None):
 """Bound old unreviewed comparisons. Reviewed alerts and their lineage survive."""
 cut=((at or dt.datetime.now(dt.timezone.utc))-dt.timedelta(days=90)).isoformat()
 rows=db.execute("SELECT o.id FROM intelligence_observations o JOIN intelligence_alerts a ON a.id=o.alert_id WHERE o.created<? AND a.state='proposed' AND NOT EXISTS(SELECT 1 FROM intelligence_reviews r WHERE r.alert_id=a.id) ORDER BY o.created,o.id LIMIT 100",(cut,)).fetchall()
 db.executemany('DELETE FROM intelligence_observations WHERE id=?',[(r[0],) for r in rows])
 db.execute("DELETE FROM intelligence_alerts WHERE id IN (SELECT a.id FROM intelligence_alerts a WHERE a.state='proposed' AND NOT EXISTS(SELECT 1 FROM intelligence_observations o WHERE o.alert_id=a.id) AND NOT EXISTS(SELECT 1 FROM intelligence_reviews r WHERE r.alert_id=a.id) LIMIT 100)")
 return len(rows)

def inspect(brain,ident,candidates=(),catalog=None):
 """At most 32 same-IP windows, three retrieved cross-IP peers, 32 local signatures."""
 with brain.connect() as db:
  own=db.execute('SELECT * FROM packets WHERE id=?',(ident,)).fetchone()
  if not own:return {'status':'missing'}
  current=json.loads(own['content']);p=profile(current);alerts=[]
  peers=db.execute('SELECT * FROM packets WHERE ip=? AND created<=? AND id!=? ORDER BY created DESC,id LIMIT 32',(own['ip'],own['created'],ident)).fetchall()
  prior=peers[0] if peers else None
  if prior:
   detail=comparison(current,json.loads(prior['content']))
   history=profile(json.loads(prior['content']))['events'];last=max((timestamp(e['seen']) for e in history),default=None)
   later=[e for e in detail['current_events'] if last and timestamp(e['seen'])>=last+dt.timedelta(hours=1)]
   if later:
    return_detail={**detail,'current_events':later,'interpretation':'Confirmed same-IP observations in separated saved windows; address reassignment or shared egress remains possible.'}
    alerts.append(save_alert(db,'same_ip_return',own,prior,return_detail))
   if (detail['added'] or set(p['claims'])-set(profile(json.loads(prior['content']))['claims'])) and detail['new_event_count_in_sample']:
    detail['interpretation']='New behavior in this IP sample; sampling changes may explain apparent novelty. No exploit or compromise is established.'
    alerts.append(save_alert(db,'behavior_change',own,prior,detail))
  for candidate in list(candidates)[:3]:
   peer=db.execute('SELECT * FROM packets WHERE id=?',(candidate['candidate_id'],)).fetchone()
   if not peer:continue
   if len(set(p['paths'])&set(profile(json.loads(peer['content']))['paths']))<2:continue
   detail=comparison(current,json.loads(peer['content']))
   detail.update(current_events=candidate['current_events'],historical_events=candidate['historical_events'],shared=candidate['shared_features'],similarity=candidate['similarity'],retrieval_version=candidate['retrieval_version'],interpretation='Similar behavior across IPs. Possible returning activity is a hypothesis; unrelated operators using common tools remain an alternative.')
   # Persist the existing reviewed relationship and its split/merge path.
   left,right=sorted((own['id'],peer['id']));detail['relationship_id']='rel_'+digest([left,right])[:24]
   alerts.append(save_alert(db,'similar_activity',own,peer,detail,key=[p['fingerprint'],*sorted([own['ip'],peer['ip']])]))
  for rule in (catalog or {}).get('rules',[])[:32]:
   matched=[e for e in p['events'] if all(e.get(k)==v for k,v in rule['match'].items())]
   if matched:
    detail=comparison(current,{'events':[]});detail.update(current_events=matched[:8],association=rule,interpretation='Observed signature associated with a reviewed reference. Target vulnerability, successful exploitation and operator identity are unverified.')
    alerts.append(save_alert(db,'reference_pattern',own,None,detail,key=[p['fingerprint'],own['ip'],rule['id'],rule['version']]))
 return {'status':'inspected','same_ip_windows_read':len(peers),'same_ip_bound':32,'history_may_be_truncated':len(peers)==32,'alerts':len(set(a for a in alerts if a)),'catalog_status':(catalog or {}).get('status','not_configured')}

def load_catalog(path):
 """No network. Administrator-reviewed, versioned exact indicators; generic scans abstain."""
 try:
  if pathlib.Path(path).stat().st_size>131072:raise ValueError()
  data=json.loads(pathlib.Path(path).read_text());assert data['schema']==1 and len(data['rules'])<=32
  for rule in data['rules']:
   assert all(isinstance(rule.get(k),str) and 0<len(rule[k])<=500 for k in ('id','version','label','reviewed_by','rationale'))
   assert rule['kind'] in ('tool','cve')
   if rule['kind']=='cve':assert re.fullmatch(r'CVE-\d{4}-\d{4,}',rule['label'])
   match=rule['match'];assert isinstance(match,dict) and 3<=len(match)<=4 and set(match)<=set(('path','method','action','client_type'))
   assert match.get('path','').startswith('/') and match.get('method') in ('GET','POST','PUT','PATCH','DELETE','HEAD')
   assert all(isinstance(v,str) and 0<len(v)<=200 for v in match.values())
   assert rule['rationale'] and 1<=len(rule['references'])<=4
   for ref in rule['references']:
    assert ref['url'].startswith('https://') and ref['primary'] is True and timestamp(ref['retrieved_at'])
    assert re.fullmatch('[a-f0-9]{64}',ref['sha256']) and ref['publisher'] and ref['version']
  return {**data,'status':'reviewed_local','sha256':digest(data)}
 except (OSError,ValueError,KeyError,TypeError,AssertionError,AttributeError):return {'status':'missing_or_invalid','rules':[]}

def alerts(brain,ident=None,limit=50):
 with brain.connect() as db:
  rows=db.execute('SELECT * FROM intelligence_alerts '+('WHERE id=? ' if ident else '')+'ORDER BY last_seen DESC,id LIMIT ? OFFSET 0',([ident] if ident else [])+[max(1,min(100,limit))]).fetchall();result=[]
  for row in rows:
   item=dict(row);latest=db.execute('SELECT * FROM intelligence_observations WHERE alert_id=? ORDER BY created DESC,rowid DESC LIMIT 1',(row['id'],)).fetchone()
   item.update(json.loads(latest['details']));item['packet_id']=latest['packet_id'];item['peer_packet']=latest['peer_packet']
   item['history']=[dict(r) for r in db.execute('SELECT * FROM intelligence_reviews WHERE alert_id=? ORDER BY rowid DESC LIMIT 50',(row['id'],))]
   item['window_count']=db.execute('SELECT count(*) FROM intelligence_observations WHERE alert_id=?',(row['id'],)).fetchone()[0]
   result.append(item)
 return result

def review(brain,ident,outcome,notes,actor):
 if outcome not in ('accepted','rejected') or not notes.strip() or len(notes)>1000:raise ValueError('Choose a review outcome and explain the evidence (up to 1,000 characters).')
 with brain.connect() as db:
  if not db.execute('SELECT 1 FROM intelligence_alerts WHERE id=?',(ident,)).fetchone():raise ValueError('Activity alert not found.')
  db.execute('INSERT INTO intelligence_reviews VALUES(?,?,?,?,?,?)',(uuid.uuid4().hex,ident,now(),actor,outcome,notes.strip()))
  db.execute('UPDATE intelligence_alerts SET state=? WHERE id=?',(outcome,ident))
 brain.store.audit(actor,'behavior.alert.review',{'id':ident,'outcome':outcome})

def schedule(db,limit=100):
 """One oldest item then diverse recent evidence within a bounded oldest-100 pool.

 No skipping, dequeue, quotas, leases or retries here. Every oldest item remains
 first, preventing starvation even when all rich examples share one pattern.
 """
 rows=db.execute('SELECT q.ip,q.queued,q.packet_id original_packet_id,p.id packet_id,p.content,p.features FROM analysis_queue q LEFT JOIN current_packets c ON c.ip=q.ip JOIN packets p ON p.id=coalesce(c.packet_id,q.packet_id) ORDER BY q.queued,q.ip LIMIT 100').fetchall()
 if not rows:return []
 first,*rest=rows;seen={profile(json.loads(first['content']))['fingerprint']};ranked=[]
 for row in rest:
  p=profile(json.loads(row['content']));rich=min(4,len(p['paths']))+min(2,len(p['actions']))
  latest=max((timestamp(e['seen']) for e in p['events']),default=None)
  recent=bool(latest and latest>=dt.datetime.now(dt.timezone.utc)-dt.timedelta(hours=24))
  ranked.append((row,p['fingerprint'],rich,recent))
 result=[first]
 while ranked and len(result)<min(100,limit):
  best=max(range(len(ranked)),key=lambda i:(ranked[i][1] not in seen,ranked[i][3],ranked[i][2],-i))
  row,fingerprint,_,_=ranked.pop(best);seen.add(fingerprint);result.append(row)
 return result
