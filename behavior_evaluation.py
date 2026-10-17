"""Immutable review cohorts and append-only independent labels; no training or scoring."""
import json,math,uuid
from behavior_ai import digest,now

SCHEMA='''
CREATE TABLE IF NOT EXISTS evaluation_cases(id TEXT PRIMARY KEY,packet_id TEXT NOT NULL,assessment_id TEXT NOT NULL,created TEXT NOT NULL,snapshot TEXT NOT NULL,UNIQUE(packet_id,assessment_id));
CREATE TABLE IF NOT EXISTS evaluation_labels(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,created TEXT NOT NULL,reviewer TEXT NOT NULL,label TEXT NOT NULL,basis TEXT NOT NULL,provenance TEXT NOT NULL,notes TEXT NOT NULL,quality TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS evaluation_labels_case ON evaluation_labels(case_id,created);
CREATE TRIGGER IF NOT EXISTS evaluation_case_refs AFTER INSERT ON evaluation_cases BEGIN
 INSERT OR IGNORE INTO retention_refs VALUES('evaluation',NEW.id,NEW.packet_id);
 INSERT OR IGNORE INTO retention_refs SELECT 'evaluation',NEW.id,p.id FROM json_tree(NEW.snapshot) j JOIN packets p ON p.id=j.value WHERE j.type='text';
 INSERT OR IGNORE INTO retention_holds SELECT 'assessment',NEW.assessment_id,'Independent evaluation case' WHERE NEW.assessment_id!='';
END;
'''
BASES={'owner_verified':'Owner-confirmed activity','raw_event_review':'Independent raw-event investigation','authorized_test_record':'Previously documented authorized test'}

def capture(brain,ident):
 """Freeze evidence and real decision context. Historical policy stays unknown."""
 captured_at=now()
 with brain.connect() as db:
  db.execute('BEGIN')
  p=db.execute('SELECT * FROM packets WHERE id=?',(ident,)).fetchone()
  if not p:raise ValueError('Saved observations not found.')
  a=db.execute('SELECT * FROM assessments WHERE packet_id=? ORDER BY created DESC,rowid DESC LIMIT 1',(ident,)).fetchone()
  current=db.execute('SELECT packet_id FROM current_packets WHERE ip=?',(p['ip'],)).fetchone()
  comparisons=[dict(r) for r in db.execute('SELECT l.id,l.left_packet,l.right_packet,l.state,l.created,e.details FROM links l LEFT JOIN correlation_link_evidence e ON e.link_id=l.id WHERE l.left_packet=? OR l.right_packet=? ORDER BY l.created DESC LIMIT 10',(ident,ident))]
  for comparison in comparisons:
   comparison['reviews']=[dict(r) for r in db.execute('SELECT created,actor,outcome,notes FROM reviews WHERE target=? ORDER BY rowid DESC LIMIT 10',(comparison['id'],))]
  activity=[dict(r) for r in db.execute('SELECT a.id alert_id,a.kind,a.state,a.fingerprint,a.first_seen,a.last_seen,o.id observation_id,o.created,o.packet_id,o.peer_packet,o.details FROM intelligence_observations o JOIN intelligence_alerts a ON a.id=o.alert_id WHERE o.packet_id=? ORDER BY o.created DESC LIMIT 10',(ident,))]
  for observation in activity:
   observation['reviews']=[dict(r) for r in db.execute('SELECT at created,actor,outcome,notes FROM intelligence_reviews WHERE alert_id=? ORDER BY rowid DESC LIMIT 10',(observation['alert_id'],))]
 assessment=json.loads(a['result']) if a and a['status']=='completed' else None
 snapshot={'snapshot_schema':2,'context_captured_at':captured_at,'context_limits':{'comparisons':10,'activity_observations':10,'reviews_per_item':10},'packet':json.loads(p['content']),'ip':p['ip'],'indexed':p['created'],'assessment':assessment,'assessment_status':a['status'] if a else 'unassessed','assessment_created':a['created'] if a else None,'assessment_expires':a['expires'] if a else None,
           'comparisons':comparisons,'activity':activity,'native_score_at_index':p['baseline'],'decision_at_capture':None,'limitations':['Convenience sample; prevalence and population recall are unknown.','Reviewer declares independent provenance; the application cannot verify the external investigation.','Labels evaluate saved observations, not a person. Historical scores alone are not actual enforcement outcomes.']}
 if current and current[0]==ident:
  from behavior_scoring import apply
  from table_layout import policy_rows
  native=brain.store.describe(p['ip']);effective=apply(brain.store,[native])[0];rules=brain.store.active_rules()
  native_policy=policy_rows(brain.store,[native],rules)[0];effective_policy=policy_rows(brain.store,[effective],rules)[0]
  snapshot['decision_at_capture']={'captured_at':now(),'native_score':native['score'],'effective_score':effective['score'],'native_policy':native_policy['policy'],'native_policy_reason':native_policy.get('policy_reason'),
                                  'effective_policy':effective_policy['policy'],'effective_policy_reason':effective_policy.get('policy_reason'),'applied_assessment_id':effective.get('ai_assessment_id'),
                                  'ai_points':effective.get('ai_bump',0),'basis':'current local policy evaluation; no firewall-drop verification'}
 ident='eval_'+digest([p['id'],a['id'] if a else ''])[:24]
 with brain.connect() as db:db.execute('INSERT OR IGNORE INTO evaluation_cases VALUES(?,?,?,?,?)',(ident,p['id'],a['id'] if a else '',now(),json.dumps(snapshot)))
 return ident

def label(brain,ident,form,reviewer):
 value=form.get('label');basis=form.get('basis');provenance=form.get('provenance','').strip();notes=form.get('notes','').strip()
 if value not in ('legitimate','malicious','borderline') or basis not in BASES:raise ValueError('Choose an independent review label and evidence basis.')
 if form.get('independent')!='on' or not 5<=len(provenance)<=1000 or not 5<=len(notes)<=2000:raise ValueError('Confirm independent review and provide an investigation reference and evidence explanation.')
 quality={k:form.get(k,'unknown') for k in ('attack','d3fend','correlation','return_activity','tool_exploit')}
 if any(v not in ('supported','unsupported','unknown','not_applicable') for v in quality.values()):raise ValueError('Choose a supported review quality value.')
 with brain.connect() as db:
  if not db.execute('SELECT 1 FROM evaluation_cases WHERE id=?',(ident,)).fetchone():raise ValueError('Review case not found.')
  # Initial labels remain blind. Quality judgments are recorded only on a
  # subsequent review after the immutable hypotheses have become visible.
  if not db.execute('SELECT 1 FROM evaluation_labels WHERE case_id=? LIMIT 1',(ident,)).fetchone():quality={key:'unknown' for key in quality}
  db.execute('INSERT INTO evaluation_labels VALUES(?,?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,ident,now(),reviewer,value,basis,provenance,notes,json.dumps(quality)))
 brain.store.audit(reviewer,'behavior.evaluation.label',{'case':ident,'label':value,'basis':basis})

def saved_object(value):
 """Decode older snapshot strings without consulting or repairing live data."""
 if isinstance(value,dict):return value
 try:
  parsed=json.loads(value);return parsed if isinstance(parsed,dict) else {}
 except (ValueError,TypeError):return {}

def frozen_context(snapshot):
 """Presentation from immutable case bytes only; never a live relationship lookup."""
 from urllib.parse import urlsplit
 result={'comparisons':[],'activity':[]}
 for kind in result:
  for item in snapshot.get(kind,[])[:10]:
   details=saved_object(item.get('details'));refs=[]
   for ref in saved_object(details.get('association')).get('references',[])[:4]:
    if not isinstance(ref,dict):continue
    try:u=urlsplit(ref.get('url',''));safe=u.scheme=='https' and bool(u.hostname) and not u.username and not u.password
    except ValueError:safe=False
    refs.append({**ref,'safe_url':ref.get('url') if safe else None})
   result[kind].append({'record':item,'details':details,'reviews':item.get('reviews'),
                        'current_packet':details.get('current_packet_id') if kind=='comparisons' else item.get('packet_id'),
                        'historical_packet':details.get('candidate_id') if kind=='comparisons' else item.get('peer_packet'),
                        'current_events':details.get('current_events',[])[:8], 'historical_events':details.get('historical_events',[])[:8],
                        'references':refs})
 return result

def cases(brain,ident=None):
 with brain.connect() as db:
  rows=db.execute('SELECT * FROM evaluation_cases '+('WHERE id=? ' if ident else '')+'ORDER BY created DESC LIMIT 100',([ident] if ident else [])).fetchall();result=[]
  for row in rows:
   item=dict(row);item['snapshot']=json.loads(row['snapshot']);item['labels']=[dict(r) for r in db.execute('SELECT * FROM evaluation_labels WHERE case_id=? ORDER BY rowid DESC LIMIT 50',(row['id'],))];result.append(item)
 return result

def ratio(a,b):return round(a/b,4) if b else None

def evaluate(items):
 """One latest review per immutable case. Undefined denominators return None."""
 reviewed=[c for c in items if c['labels']];decisive=[c for c in reviewed if c['labels'][0]['label']!='borderline']
 result={'cases':len(items),'reviewed':len(reviewed),'unreviewed':len(items)-len(reviewed),'borderline':len(reviewed)-len(decisive),'decisive':len(decisive),
         'independence':'reviewer-attested; external provenance requires human verification','calibrated_probability':False,'population_recall':None,'quality':{},'confidence_bins':[]}
 for field in ('attack','d3fend','correlation','return_activity','tool_exploit'):
  result['quality'][field]={v:sum(json.loads(c['labels'][0]['quality']).get(field,'unknown')==v for c in reviewed) for v in ('supported','unsupported','unknown','not_applicable')}
 for mode in ('model','native','effective'):
  tp=fp=fn=tn=abstained=0;coverage=0
  for c in decisive:
   s=c['snapshot'];truth=c['labels'][0]['label']=='malicious';a=s['assessment'];decision=s.get('decision_at_capture')
   if mode=='model':pred=a.get('classification') if a else None;pred=True if pred=='malicious' else False if pred=='benign' else None
   else:pred=(decision[mode+'_policy']=='Denied') if decision and decision.get(mode+'_policy') in ('Denied','Allowed','Evaluating') else None
   if pred is None:abstained+=1;fn+=truth;continue
   coverage+=1;tp+=pred and truth;fp+=pred and not truth;fn+=not pred and truth;tn+=not pred and not truth
  result[mode]={'denominator':len(decisive),'covered':coverage,'abstained_or_unknown':abstained,'tp':tp,'fp':fp,'misses_including_abstained':fn,'tn':tn,'precision':ratio(tp,tp+fp),'false_positive_rate':ratio(fp,sum(c['labels'][0]['label']=='legitimate' for c in decisive)),'cohort_recall':ratio(tp,tp+fn),'abstention_rate':ratio(abstained,len(decisive))}
 crossings=[c for c in reviewed if c['snapshot'].get('decision_at_capture') and c['snapshot']['decision_at_capture'].get('applied_assessment_id')==c['assessment_id'] and c['snapshot']['decision_at_capture']['native_score']<75<=c['snapshot']['decision_at_capture']['effective_score']]
 result['ai_only_score_crossings']={'count':len(crossings),'malicious':sum(c['labels'][0]['label']=='malicious' for c in crossings),'legitimate':sum(c['labels'][0]['label']=='legitimate' for c in crossings),'basis':'captured current score threshold; publication and firewall drop unverified'}
 paired=[c for c in decisive if c['snapshot'].get('decision_at_capture')]
 correct=lambda c,mode:(c['snapshot']['decision_at_capture'][mode+'_policy']=='Denied')==(c['labels'][0]['label']=='malicious')
 result['paired_policy']={'denominator':len(paired),'changed':sum(c['snapshot']['decision_at_capture']['native_policy']!=c['snapshot']['decision_at_capture']['effective_policy'] for c in paired),'improved':sum(not correct(c,'native') and correct(c,'effective') for c in paired),'harmed':sum(correct(c,'native') and not correct(c,'effective') for c in paired),'basis':'same-case native and pilot policy at capture, independent labels required; model agreement is not correctness'}
 for lo,hi in ((0,.5),(.5,.9),(.9,1.00001)):
  cohort=[c for c in decisive if c['snapshot']['assessment'] and type(c['snapshot']['assessment'].get('maliciousness_confidence')) in (int,float) and lo<=c['snapshot']['assessment']['maliciousness_confidence']<hi]
  result['confidence_bins'].append({'lower':lo,'upper':min(1,hi),'count':len(cohort),'malicious_labels':sum(c['labels'][0]['label']=='malicious' for c in cohort),'note':'reported confidence distribution, not calibrated reliability'})
 result['limits']=['Independent labels are required before accuracy claims. Empty denominators are unknown, never zero accuracy.','Cohort recall covers reviewed cases only; missed unseen traffic is not measured.','Borderline cases are excluded from binary metrics and counted separately. Abstained malicious cases count as cohort misses.','Native/effective policy evaluates blocking decisions, while model metrics evaluate maliciousness. These are different tasks.','Case selection, repeated windows and shared infrastructure can bias results. Use separate held-out IP/time cohorts before generalizing.']
 return result

def report(brain):
 # Bound browser work; expose full-cohort size instead of silently sampling.
 items=cases(brain);result=evaluate(items)
 with brain.connect() as db:result['total_cases']=db.execute('SELECT count(*) FROM evaluation_cases').fetchone()[0]
 result['limited']=result['total_cases']>len(items)
 return result
