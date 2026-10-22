"""Append-only human usefulness ratings, separate from evidence support/policy."""
import hashlib,json,uuid
from core import now

SCHEMA='''
CREATE TABLE IF NOT EXISTS assessment_feedback(id TEXT PRIMARY KEY,case_id TEXT NOT NULL,assessment_id TEXT NOT NULL,created TEXT NOT NULL,reviewer TEXT NOT NULL,rating TEXT NOT NULL CHECK(rating IN ('helpful','not_helpful','uncertain')),evidence_ids TEXT NOT NULL,rationale TEXT NOT NULL,snapshot_sha256 TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS assessment_feedback_case ON assessment_feedback(case_id,created);
CREATE TRIGGER IF NOT EXISTS assessment_feedback_no_update BEFORE UPDATE ON assessment_feedback BEGIN SELECT RAISE(ABORT,'Assessment feedback is append-only'); END;
CREATE TRIGGER IF NOT EXISTS assessment_feedback_no_delete BEFORE DELETE ON assessment_feedback BEGIN SELECT RAISE(ABORT,'Assessment feedback is append-only'); END;
'''
RATINGS=('helpful','not_helpful','uncertain')

def snapshot_hash(raw):return hashlib.sha256(raw.encode()).hexdigest()

def observations(snapshot):
 """Only original frozen records actually cited by this frozen assessment."""
 assessment=snapshot.get('assessment');assessment=assessment if isinstance(assessment,dict) else {};cited=set()
 for field in ('findings','contradictory_evidence','attack_techniques','d3fend_context','actor_correlation','historical_observations'):
  for claim in assessment.get(field,[]):cited.update(claim.get('evidence_ids',[]))
 packet=snapshot.get('packet') or {};rows=list(packet.get('events',[]))+list(packet.get('context',[]))
 for comparison in snapshot.get('comparisons',[])[:10]:
  details=comparison.get('details',{})
  if isinstance(details,str):
   try:details=json.loads(details)
   except (ValueError,TypeError):details={}
  if isinstance(details,dict):rows+=details.get('current_events',[])[:8]+details.get('historical_events',[])[:8]
 result={}
 for row in rows:
  ident=row.get('id')
  if ident in cited and isinstance(ident,str) and len(ident)<=80:result.setdefault(ident,row)
 return list(result.values())

def eligible(case):
 s=case['snapshot']
 return bool(case.get('assessment_id') and isinstance(s.get('assessment'),dict) and s['assessment'] and s.get('assessment_status','completed')=='completed')

def save(brain,ident,form,reviewer):
 rating=form.get('rating');rationale=form.get('rationale','').strip()
 selected=form.getlist('evidence_ids') if hasattr(form,'getlist') else form.get('evidence_ids',[])
 if rating not in RATINGS or not 5<=len(rationale)<=2000:raise ValueError('Choose a usefulness rating and explain the practical difference (5–2,000 characters).')
 if not isinstance(reviewer,str) or not 1<=len(reviewer)<=120:raise ValueError('A signed-in reviewer is required.')
 if not isinstance(selected,list) or len(selected)>12 or any(not isinstance(v,str) for v in selected) or len(set(selected))!=len(selected):raise ValueError('Choose up to twelve distinct cited observations.')
 with brain.connect() as db:
  db.execute('BEGIN IMMEDIATE')
  row=db.execute('SELECT * FROM evaluation_cases WHERE id=?',(ident,)).fetchone()
  if not row:raise ValueError('Review case not found.')
  case=dict(row);snapshot=json.loads(row['snapshot']);case['snapshot']=snapshot
  if not db.execute('SELECT 1 FROM evaluation_labels WHERE case_id=? LIMIT 1',(ident,)).fetchone():raise ValueError('Save the initial independent label before rating usefulness.')
  if not eligible(case) or form.get('assessment_id')!=row['assessment_id']:raise ValueError('This rating must identify the completed assessment frozen with the case.')
  actual=db.execute('SELECT packet_id,status,result FROM assessments WHERE id=?',(row['assessment_id'],)).fetchone()
  if not actual or actual['packet_id']!=row['packet_id'] or actual['status']!='completed' or json.loads(actual['result'])!=snapshot['assessment']:raise ValueError('The original frozen assessment is unavailable or inconsistent.')
  known={v['id'] for v in observations(snapshot)}
  if not set(selected)<=known or (rating=='helpful' and not selected):raise ValueError('Helpful feedback requires a cited original observation from the frozen case.')
  db.execute('INSERT INTO assessment_feedback VALUES(?,?,?,?,?,?,?,?,?)',(uuid.uuid4().hex,ident,row['assessment_id'],now(),reviewer,rating,json.dumps(selected),rationale,snapshot_hash(row['snapshot'])))
 brain.store.audit(reviewer,'behavior.assessment.feedback',{'case':ident,'assessment':row['assessment_id'],'rating':rating})

def summarize(items):
 """One latest explicit rating per distinct completed frozen assessment."""
 chosen={};invalid=0
 for case in items:
  if not eligible(case):continue
  assessment=case['assessment_id'];chosen.setdefault(assessment,None)
  for row in case.get('feedback',[])[:50]:
   if row['assessment_id']!=assessment or row['snapshot_sha256']!=case.get('snapshot_sha256'):
    invalid+=1;continue
   if chosen[assessment] is None or row.get('sequence',0)>chosen[assessment].get('sequence',0):chosen[assessment]=row
   break
 counts={v:sum(bool(r and r['rating']==v) for r in chosen.values()) for v in RATINGS}
 rated=counts['helpful']+counts['not_helpful'];absent=sum(v is None for v in chosen.values())
 return {'available':True,'eligible_assessments':len(chosen),**counts,'rated':rated,'unrated':absent,'helpful_rate':round(counts['helpful']/rated,4) if rated else None,'invalid_provenance_rows':invalid,'scope':'Latest 100 retained review cases; latest explicit rating per completed frozen assessment, independent of the operational time window.'}

def report(brain):
 from behavior_evaluation import cases
 items=cases(brain);result=summarize(items)
 with brain.connect() as db:result['total_cases']=db.execute('SELECT count(*) FROM evaluation_cases').fetchone()[0]
 result['limited']=result['total_cases']>len(items)
 return result
