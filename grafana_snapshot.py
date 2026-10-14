"""Read-only local Grafana aggregates; keeps the established dashboard contract."""
import collections,datetime as dt,json,pathlib,sqlite3,subprocess

def snapshot(cfg):
 UTC=dt.timezone.utc
 now=dt.datetime.now(UTC);cut=now-dt.timedelta(days=30)
 
 generation=(pathlib.Path(cfg['output'])/'current').resolve()
 manifest=json.loads((generation/'manifest.json').read_text())
 display=json.loads((generation/'dashboard.json').read_text())
 assert display['created']==manifest['created'],'EDL display/list generation mismatch'
 d=sqlite3.connect('file:'+cfg['database']+'?mode=ro',uri=True,timeout=10);d.row_factory=sqlite3.Row
 d.execute('PRAGMA query_only=ON');d.execute('BEGIN')
 def query(sql,args=()):return [dict(r) for r in d.execute(sql,args)]
 def state(key):
  r=d.execute('select value from state where key=?',(key,)).fetchone()
  return json.loads(r[0]) if r else {}
 sources=query('select source,count(distinct ip) ips,count(distinct sensor) sensors,min(seen) first_seen,max(seen) last_seen from evidence where seen>=? and seen<=? group by source',(cut.isoformat(),now.isoformat()))
 observations=query("select substr(seen,1,10) day,source,count(distinct ip) ips from evidence where seen>=? and seen<=? group by day,source",(cut.isoformat(),now.isoformat()))
 new_ips=query("select substr(first_seen,1,10) day,count(*) ips from ips where first_seen>=? and first_seen<=? group by day",(cut.isoformat(),now.isoformat()))
 audit=query("select substr(at,1,10) day,action,count(*) records from audit where at>=? and at<=? group by day,action",(cut.isoformat(),now.isoformat()))
 changes=query("select at,action,actor from audit where at>=? and action not in ('login') order by at desc limit 10",(cut.isoformat(),))
 retention=query("select ip,first_blocked,last_seen,expires,last_source,score from block_retention where expires>?",(now.isoformat(),))
 active_rules=query("select action,kind,count(*) rules from rules where enabled=1 and (expires is null or expires>?) group by action,kind",(now.isoformat(),))
 cache=query("select provider,status,count(*) ips,sum(case when expires>? then 1 else 0 end) fresh_ips,max(fetched) last_fetched from cache group by provider,status",(now.isoformat(),))
 scopes={}
 for table,col in [('evidence','seen'),('audit','at')]:
  scopes[table]=query('select min('+col+') earliest,max('+col+') latest from '+table)[0]
 states={k:state(k) for k in ['worker_status','ingest_status','palo_status','provider_status']}
 d.rollback();d.close()
 rows=display['rows'];scored=set((generation/'scored-block.txt').read_text().splitlines());combined=set((generation/'combined-block.txt').read_text().splitlines())
 scores=collections.Counter();asns={};types=collections.Counter();enrichment=collections.Counter();ports=collections.Counter();holds=collections.Counter()
 top=[]
 for r in rows:
  value=int(r['score']);band='0–24' if value<25 else '25–49' if value<50 else '50–74' if value<75 else '75–99' if value<100 else '100+'
  scores[band]+=1
  asn=r.get('asn') or 'Unknown';a=asns.setdefault(asn,{'asn':asn,'organization':r.get('organization') or 'Unknown','observed_ips':0,'listed_ips':0});a['observed_ips']+=1;a['listed_ips']+=int(r['ip'] in combined)
  for t in set(r.get('client_types') or ['Unknown']):types[t]+=1
  for v in set(r.get('enrichment_sources') or []):enrichment[v]+=1
  for v in set(r.get('ports') or []):ports[str(v)]+=1
  for v in set(r.get('sources') or []):holds[v]+=int(r['ip'] not in combined)
  top.append({'ip':r['ip'],'score':value,'asn':asn,'organization':r.get('organization') or 'Unknown','listed':r['ip'] in combined,'sources':r.get('sources',[])})
 expires=collections.Counter();renewals=collections.Counter()
 for r in retention:
  expires[r['expires'][:10]]+=1;renewals[r['last_source']]+=1
 services={}
 for name in ['edl-manager.service','edl-manager-ingest.service','edl-manager-worker.service']:
  p=subprocess.run(['systemctl','show',name,'-p','ActiveState','-p','Result','--value'],capture_output=True,text=True,check=True,timeout=3)
  services[name]=p.stdout.strip().splitlines()
 result={'collected_at':now.isoformat(),'window_start':cut.isoformat(),'window_days':30,'generation':manifest['created'],'counts':manifest['counts'],'scoring_policy':manifest['scoring_policy'],'policy_managed':manifest.get('palo_policy_managed'),
  'summary':{'observed_ips':len(rows),'listed_ips':len(combined),'scored_ips':len(scored),'protected_crawlers':sum(bool(r['verified_crawler']) for r in rows),'retained_blocks':len(retention),'expiring_24h':sum(r['expires']<(now+dt.timedelta(days=1)).isoformat() for r in retention),'expiring_7d':sum(r['expires']<(now+dt.timedelta(days=7)).isoformat() for r in retention),'new_ips_30d':sum(r['ips'] for r in new_ips),'policy_changes_30d':sum(r['records'] for r in audit if r['action'] in ['rule.add','rule.disable','policy.change','scoring.update'])},
  'sources':sources,'observations_daily':observations,'new_ips_daily':new_ips,'audit_daily':audit,'recent_changes':changes,'active_rules':active_rules,'cache':cache,'states':states,'scope':scopes,'services':services,
  'score_bands':[{'band':k,'ips':scores[k]} for k in ['0–24','25–49','50–74','75–99','100+']],
  'asns':sorted(asns.values(),key=lambda r:r['listed_ips'],reverse=True)[:12],'client_types':[{'type':k,'ips':v} for k,v in types.most_common(10)],'enrichment':[{'provider':k,'ips':v} for k,v in enrichment.most_common()],
  'ports':[{'port':k,'ips':v} for k,v in ports.most_common(12)],'held_by_source':[{'source':k,'ips':v} for k,v in holds.items()],
  'expiry_daily':[{'day':k,'ips':v} for k,v in sorted(expires.items())], 'retention_source':[{'source':k,'ips':v} for k,v in renewals.items()],
  'top_ips':sorted(top,key=lambda r:(r['listed'],r['score']),reverse=True)[:15]}
 return result
