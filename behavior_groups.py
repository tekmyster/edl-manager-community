"""Reviewed activity groups with stable IDs and immutable membership revisions."""
import json,uuid
from core import now

SCHEMA='''
CREATE TABLE IF NOT EXISTS behavior_groups(id TEXT PRIMARY KEY,created TEXT NOT NULL,status TEXT NOT NULL,revision INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS behavior_group_members(group_id TEXT NOT NULL,packet_id TEXT NOT NULL,PRIMARY KEY(group_id,packet_id));
CREATE TABLE IF NOT EXISTS behavior_group_revisions(id TEXT PRIMARY KEY,group_id TEXT NOT NULL,at TEXT NOT NULL,actor TEXT NOT NULL,change TEXT NOT NULL,parents TEXT NOT NULL,members TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS behavior_group_members_packet ON behavior_group_members(packet_id);
'''

def synchronize(db,actor):
 """Only accepted relationships form groups; rejecting an edge can split a group."""
 links=db.execute("SELECT left_packet,right_packet FROM links WHERE state='accepted'").fetchall();graph={}
 for a,b in links:graph.setdefault(a,set()).add(b);graph.setdefault(b,set()).add(a)
 components=[];seen=set()
 for node in sorted(graph):
  if node in seen:continue
  members=set();stack=[node]
  while stack:
   current=stack.pop()
   if current in members:continue
   members.add(current);stack.extend(graph[current]-members)
  seen.update(members);components.append(members)
 old={r['id']:{'created':r['created'],'revision':r['revision'],'members':{v[0] for v in db.execute('SELECT packet_id FROM behavior_group_members WHERE group_id=?',(r['id'],))}} for r in db.execute("SELECT * FROM behavior_groups WHERE status='active'").fetchall()}
 used=set();at=now()
 for members in sorted(components,key=lambda c:(-len(c),sorted(c))):
  parents=sorted((ident for ident,g in old.items() if g['members']&members),key=lambda ident:(old[ident]['created'],ident));available=[v for v in parents if v not in used]
  ident=available[0] if available else 'group_'+uuid.uuid4().hex[:16];used.add(ident)
  if ident in old and old[ident]['members']==members:continue
  split=any(sum(bool(old[p]['members']&c) for c in components)>1 for p in parents)
  change='merged' if len(parents)>1 else 'split' if split else 'updated' if parents else 'created'
  revision=old[ident]['revision']+1 if ident in old else 1
  db.execute('INSERT INTO behavior_groups VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,revision=excluded.revision',(ident,old[ident]['created'] if ident in old else at,'active',revision))
  db.execute('DELETE FROM behavior_group_members WHERE group_id=?',(ident,));db.executemany('INSERT INTO behavior_group_members VALUES(?,?)',[(ident,p) for p in sorted(members)])
  db.execute('INSERT INTO behavior_group_revisions VALUES(?,?,?,?,?,?,?)',(uuid.uuid4().hex,ident,at,actor,change,json.dumps(parents),json.dumps(sorted(members))))
 for ident in set(old)-used:
  db.execute("UPDATE behavior_groups SET status='archived',revision=revision+1 WHERE id=?",(ident,))
  db.execute('INSERT INTO behavior_group_revisions VALUES(?,?,?,?,?,?,?)',(uuid.uuid4().hex,ident,at,actor,'archived',json.dumps([ident]),json.dumps(sorted(old[ident]['members']))))

def groups(brain,address=None,ident=None,limit=100,offset=0):
 with brain.connect() as db:
  where="g.status='active'";args=[]
  if ident:where='g.id=?';args=[ident]
  elif address:where+=" AND EXISTS(SELECT 1 FROM behavior_group_members m JOIN packets p ON p.id=m.packet_id WHERE m.group_id=g.id AND p.ip=?)";args=[address]
  result=[dict(r) for r in db.execute('SELECT g.* FROM behavior_groups g WHERE '+where+' ORDER BY created DESC,id DESC LIMIT ? OFFSET ?',args+[limit,offset])]
  for group in result:
   group['label']='Activity group '+group['id'][-6:].upper()
   group['members']=[dict(r) for r in db.execute('SELECT p.ip,p.id packet_id,p.created FROM behavior_group_members m JOIN packets p ON p.id=m.packet_id WHERE m.group_id=? ORDER BY p.ip,p.created LIMIT 500',(group['id'],))]
   group['member_total']=db.execute('SELECT count(*) FROM behavior_group_members WHERE group_id=?',(group['id'],)).fetchone()[0];group['members_limited']=group['member_total']>len(group['members'])
   group['relationships']=[dict(r) for r in db.execute("SELECT l.id,a.ip left_ip,b.ip right_ip,l.similarity FROM links l JOIN packets a ON a.id=l.left_packet JOIN packets b ON b.id=l.right_packet WHERE l.state='accepted' AND EXISTS(SELECT 1 FROM behavior_group_members m WHERE m.group_id=? AND m.packet_id=l.left_packet) AND EXISTS(SELECT 1 FROM behavior_group_members m WHERE m.group_id=? AND m.packet_id=l.right_packet) LIMIT 500",(group['id'],group['id']))]
   group['history']=[{**dict(r),'parents':json.loads(r['parents']),'members':json.loads(r['members']),'member_count':len(json.loads(r['members']))} for r in db.execute('SELECT at,actor,change,parents,members FROM behavior_group_revisions WHERE group_id=? ORDER BY rowid DESC LIMIT 100',(group['id'],))]
   group['reviews']=[dict(r) for r in db.execute('SELECT r.created,r.actor,r.outcome,r.notes,a.ip left_ip,b.ip right_ip FROM reviews r JOIN links l ON l.id=r.target JOIN packets a ON a.id=l.left_packet JOIN packets b ON b.id=l.right_packet WHERE EXISTS(SELECT 1 FROM behavior_group_members m WHERE m.group_id=? AND (m.packet_id=l.left_packet OR m.packet_id=l.right_packet)) ORDER BY r.rowid DESC LIMIT 100',(group['id'],))]
 return result
