import copy
from test_behavior_ai import evidence
from behavior_ai import Brain
from behavior_groups import groups

def test_reviewed_groups_have_stable_merge_split_history_without_policy_changes(evidence):
 b=Brain(evidence);base=evidence.describe('8.8.8.8');packets=[];native_before=base['score']
 for address in ('8.8.8.8','1.1.1.1','9.9.9.9','8.8.4.4'):
  row=copy.deepcopy(base);row['ip']=address;ident,packet,features=b.packet(row);packets.append(ident);b.candidates(ident,features)
 def review(a,z,outcome):
  left,right=sorted((packets[a],packets[z]))
  with b.connect() as db:link=db.execute('SELECT id FROM links WHERE left_packet=? AND right_packet=?',(left,right)).fetchone()[0]
  b.review(link,outcome,'Reviewed request sequences','admin')
 review(0,1,'accepted');one=groups(b)[0]['id'];review(0,1,'accepted');assert groups(b)[0]['id']==one and len(groups(b)[0]['history'])==1
 review(2,3,'accepted');assert len(groups(b))==2
 review(1,2,'accepted');merged=groups(b);assert len(merged)==1 and len(merged[0]['members'])==4 and any(v['change']=='merged' for v in merged[0]['history'])
 review(1,2,'rejected');split=groups(b);assert len(split)==2 and all(len(v['members'])==2 for v in split) and any(v['change']=='split' for g in split for v in g['history'])
 assert evidence.describe('8.8.8.8')['score']==native_before and not evidence.active_rules()
 assert groups(b,address='1.1.1.1') and groups(b,ident=one)
