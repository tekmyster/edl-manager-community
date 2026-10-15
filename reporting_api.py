"""Bounded read-only reporting API with separately revocable bearer credentials."""
import datetime as dt,functools,hashlib,hmac,ipaddress,json,secrets,uuid
from flask import jsonify,request,render_template,redirect,url_for,flash,abort
from core import now,ip
from activity import local_activity
from source_settings import effective
from offenders import WINDOWS,text

def issue(store,name,days,actor):
 name=name.strip()
 if not name or len(name)>80:raise ValueError('Enter a token name of 1–80 characters.')
 if days not in (30,90,365):raise ValueError('Select 30, 90 or 365 days.')
 ident=str(uuid.uuid4());secret='edl_'+secrets.token_urlsafe(40);created=now();expires=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(days=days)).isoformat(timespec='seconds')
 with store.connect() as d:
  if d.execute('SELECT count(*) FROM api_tokens WHERE enabled=1 AND expires>?',(created,)).fetchone()[0]>=20:raise ValueError('Revoke an unused token before creating another.')
  d.execute('INSERT INTO api_tokens VALUES(?,?,?,?,?,?,1)',(ident,name,hashlib.sha256(secret.encode()).hexdigest(),created,expires,actor))
  d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(created,actor,'api.token.create',json.dumps({'id':ident,'name':name,'expires':expires,'scope':'reporting:read'})))
 return secret

def tokens(store):
 with store.connect(commit=False) as d:return [dict(r) for r in d.execute('SELECT id,name,created,expires,actor,enabled FROM api_tokens ORDER BY created DESC LIMIT 100')]

def register(app,store,cfg,reports,display_rows,login_required):
 import threading,time
 from new_ips import Reports as ArrivalReports
 arrivals=ArrivalReports(store)
 aggregate_lock=threading.Lock();aggregate_cache={'until':0,'data':None}
 def required(fn):
  @functools.wraps(fn)
  def wrap(*a,**kw):
   auth=request.headers.get('Authorization','')
   if not auth.startswith('Bearer ') or len(auth)>256:return jsonify(error='A read-only bearer token is required'),401,{'WWW-Authenticate':'Bearer'}
   digest=hashlib.sha256(auth[7:].encode()).hexdigest()
   with store.connect(commit=False) as d:row=d.execute('SELECT digest FROM api_tokens WHERE digest=? AND enabled=1 AND expires>?',(digest,now())).fetchone()
   if not row or not hmac.compare_digest(row['digest'],digest):return jsonify(error='Invalid or expired reporting token'),401,{'WWW-Authenticate':'Bearer'}
   return fn(*a,**kw)
  return wrap
 def integer(name,default,lo,hi):
  try:value=int(request.args.get(name,str(default)))
  except ValueError:abort(400,description='Invalid '+name)
  if not lo<=value<=hi:abort(400,description='Invalid '+name)
  return value
 def window():
  days=integer('days',30,1,365)
  if days not in WINDOWS:abort(400,description='Use days=30,60,90,180 or 365')
  return days
 def page(rows):
  limit=integer('limit',250,1,1000);offset=integer('offset',0,0,1000000)
  return {'data':rows[offset:offset+limit],'total':len(rows),'limit':limit,'offset':offset,'next_offset':offset+limit if offset+limit<len(rows) else None}
 def rows():return reports.decorate(display_rows())
 @app.get('/api/v1/behavior')
 @required
 def api_behavior():
  from behavior_ai import brain
  return jsonify(schema_version=1,generated=now(),**brain(store).summary())
 @app.get('/api/v1/behavior/metrics')
 @required
 def api_behavior_metrics():
  from behavior_ai import brain
  from behavior_metrics import metrics
  try:data=metrics(brain(store),request.args.get('period','24h'))
  except ValueError:abort(400)
  return jsonify(schema_version=1,generated=now(),**data)
 @app.get('/api/v1/behavior/groups')
 @required
 def api_behavior_groups():
  from behavior_ai import brain
  from behavior_groups import groups
  service=brain(store);limit=integer('limit',50,1,100);offset=integer('offset',0,0,1000000)
  with service.connect() as db:total=db.execute("SELECT count(*) FROM behavior_groups WHERE status='active'").fetchone()[0]
  return jsonify(schema_version=1,generated=now(),data=groups(service,limit=limit,offset=offset),total=total,limit=limit,offset=offset,next_offset=offset+limit if offset+limit<total else None)
 @app.get('/api/v1/behavior/groups/<ident>')
 @required
 def api_behavior_group(ident):
  from behavior_ai import brain
  from behavior_groups import groups
  found=groups(brain(store),ident=ident)
  if not found:abort(404)
  return jsonify(schema_version=1,generated=now(),group=found[0])
 @app.get('/api/v1/behavior/observations/<ident>')
 @required
 def api_behavior_observation(ident):
  from behavior_ai import brain
  found=brain(store).packet_view(ident)
  if not found:abort(404)
  return jsonify(schema_version=1,generated=now(),observation=found)
 @app.get('/api/v1/ips/<address>/behavior')
 @required
 def api_ip_behavior(address):
  from behavior_ai import brain
  from behavior_groups import groups
  row=detail(address)
  return jsonify(schema_version=1,generated=now(),ip=row['ip'],groups=groups(brain(store),address=row['ip']),**brain(store).view(row['ip']))
 @app.get('/api/v1/intelligence')
 @required
 def api_intelligence():
  from greynoise_enrichment import metrics
  from table_layout import policy_rows
  return jsonify(schema_version=1,generated=now(),metrics=metrics(store,policy_rows(store,rows(),store.active_rules())),usage=store.state('greynoise_usage') or {})
 @app.get('/api/v1/grafana')
 @required
 def api_grafana():
  from grafana_snapshot import snapshot
  with aggregate_lock:
   if aggregate_cache['until']<=time.monotonic():
    try:data=snapshot(cfg)
    except (OSError,ValueError,AssertionError):return jsonify(error='No complete reporting generation available'),503
    h=reports.snapshot();data['reporting_transport']='authenticated HTTPS API';data['repeat_counts']=h['repeat_counts'];data['top_offender_month']=h['top_month'];data['repeat_coverage']=h['coverage'];data['repeat_daily']=h['daily']
    data['summary']['repeat_offenders']=h['repeat_counts']['30']
    recent=arrivals.snapshot();data['summary']['new_ips_24h']=recent['count'];data['new_ip_coverage']=recent['coverage']
    aggregate_cache.update(until=time.monotonic()+60,data=data)
   return jsonify(aggregate_cache['data'])
 @app.get('/api/v1/summary')
 @required
 def api_summary():
  r=reports.snapshot();v=rows();rules=store.active_rules();build=store.state('latest_build') or {}
  return jsonify(schema_version=1,generated=r['generated'],definition=r['definition'],coverage=r['coverage'],repeat_offenders=r['repeat_counts']['30'],repeat_counts=r['repeat_counts'],top_offender_month=r['top_month'],month_start=r['month_start'],observed_ips=len(v),scored_candidates=sum(x['auto_candidate'] for x in v),verified_crawlers=sum(x['verified_crawler'] for x in v),new_ips_24h=arrivals.snapshot()['count'],new_ip_coverage=arrivals.snapshot()['coverage'],manual_blocks=sum(x['action']=='block' for x in rules),policy_overrides=len(rules),list_created=build.get('created'),list_counts=build.get('counts',{}))
 @app.get('/api/v1/ips')
 @required
 def api_ips():
  days=window();v=rows();query=request.args.get('q','').casefold().strip();repeat=request.args.get('repeat','')
  if repeat not in ('','true','false'):abort(400,description='repeat must be true or false')
  if repeat:v=[x for x in v if bool((x.get('repeat_history') or {}).get('windows',{}).get(str(days),{}).get('repeat'))==(repeat=='true')]
  if query:v=[x for x in v if query in (' '.join([x['ip'],x['asn'],x['organization'],x['repeat_text']]+x['sources']+x.get('client_types',[])+[x.get('enrichment_text','')])).casefold()]
  v.sort(key=lambda x:(ipaddress.ip_address(x['ip']).version,int(ipaddress.ip_address(x['ip']))))
  return jsonify(schema_version=1,generated=reports.snapshot()['generated'],coverage=reports.snapshot()['coverage'],**page(v))
 def detail(address):
  try:address=str(ip(address))
  except ValueError:abort(400,description='A public unicast IP is required')
  with store.connect(commit=False) as d:exists=d.execute('SELECT 1 FROM ips WHERE ip=? UNION SELECT 1 FROM rules WHERE kind=? AND value=? LIMIT 1',(address,'ip',address)).fetchone()
  if not exists:abort(404,description='IP has no saved evidence or exact-IP policy')
  from behavior_scoring import apply as ai_scores
  return ai_scores(store,[store.describe(address)])[0]
 @app.get('/api/v1/ips/<address>')
 @required
 def api_ip(address):
  from violator_times import attach
  row=attach(store,[detail(address)])[0];h=reports.snapshot()['ips'].get(row['ip']);native,summaries=local_activity(row)
  return jsonify(schema_version=1,generated=now(),ip=row['ip'],score=row['score'],score_breakdown=row['score_breakdown'],intelligence=row.get('intelligence',{}),scored_candidate=row['auto_candidate'],verified_crawler=row['verified_crawler'],asn=row['asn'],organization=row['organization'],sources=row['source_details'],source_identity=row['source_identity'],enrichment=row['enrichment_details'],retention=row['retention'],repeat_history=h,repeat_text=text(h),source_summaries=summaries,policy_rules=matching_rules(store,row),timestamps={k:row[k] for k in ('first_seen','last_seen','block_recorded','block_expires')},activity_url=url_for('api_ip_activity',address=row['ip']))
 @app.get('/api/v1/ips/<address>/activity')
 @required
 def api_ip_activity(address):
  row=detail(address);native,summaries=local_activity(row);current=effective(store,cfg)
  scope=hashlib.sha256((current.get('index_url','')+'|'+current.get('palo_location','')).encode()).hexdigest()[:16]
  saved=store.state('ip_activity:'+scope+':'+row['ip']) or {}
  cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)).isoformat(timespec='seconds')
  palo=[v for v in saved.get('events',[]) if v.get('seen','')>=cutoff] if current.get('palo_location') and current.get('index_url') else []
  v=sorted(native+palo,key=lambda e:e.get('seen',''),reverse=True)
  return jsonify(schema_version=1,generated=now(),ip=row['ip'],cache_only=True,palo_cache_fetched=saved.get('fetched'),palo_cache_available=bool(saved.get('fetched')),destinations=saved.get('destinations',[]) if palo else [],destinations_limited=saved.get('destinations_limited',False),**page(v))
 @app.get('/api/v1/ips/<address>/events')
 @required
 def api_ip_events(address):
  from event_history import matching
  row=detail(address);result=matching(store,row['ip'],row['asn']);paged=page(result['rows'])
  return jsonify(schema_version=1,generated=now(),ip=row['ip'],list_tracking=result['tracking'],**paged)
 @app.get('/api/v1/history')
 @required
 def api_history():
  days=window();target=request.args.get('ip','');address=None
  if target:
   try:address=str(ip(target))
   except ValueError:abort(400,description='A public unicast IP is required')
  end=dt.datetime.now(dt.timezone.utc);cut=(end-dt.timedelta(days=days)).isoformat(timespec='seconds')
  with store.connect(commit=False) as d:
   query='SELECT substr(seen,1,10) day,count(distinct ip) ips,count(*) observations FROM offender_returns WHERE seen>=? AND seen<=?';args=[cut,end.isoformat(timespec='seconds')]
   if address:query+=' AND ip=?';args.append(address)
   v=[dict(r) for r in d.execute(query+' GROUP BY substr(seen,1,10) ORDER BY day',args)]
  return jsonify(schema_version=1,generated=now(),days=days,ip=address,coverage=reports.snapshot()['coverage'],data=v)
 @app.get('/api/v1/rules')
 @required
 def api_rules():return jsonify(schema_version=1,generated=now(),**page(store.active_rules()))
 @app.get('/api/v1/lists/<name>')
 @required
 def api_list(name):
  import pathlib
  generation=(pathlib.Path(cfg['output'])/'current').resolve()
  try:manifest=json.loads((generation/'manifest.json').read_text())
  except OSError:return jsonify(error='No completed generation'),503
  if name not in manifest['counts']:abort(404)
  entries=(generation/(name+'.txt')).read_text().splitlines()
  return jsonify(schema_version=1,created=manifest['created'],name=name,sha256=manifest['sha256'][name],**page([{'address':v} for v in entries]))
 @app.post('/settings/api-tokens')
 @login_required
 def create_api_token():
  from flask import session
  try:secret=issue(store,request.form.get('name',''),int(request.form.get('days','90')),session['user'])
  except (ValueError,TypeError) as error:flash(str(error),'error');return redirect(url_for('settings',_anchor='api-settings'))
  # Shown once in the no-store response, never in a cookie, URL, flash or audit.
  return render_template('api_token.html',token=secret,name=request.form.get('name',''))
 @app.post('/settings/api-tokens/<ident>/revoke')
 @login_required
 def revoke_api_token(ident):
  from flask import session
  with store.connect() as d:
   row=d.execute('SELECT id FROM api_tokens WHERE id=?',(ident,)).fetchone()
   if not row:abort(404)
   d.execute('UPDATE api_tokens SET enabled=0 WHERE id=?',(ident,))
   d.execute('INSERT INTO audit(at,actor,action,details) VALUES(?,?,?,?)',(now(),session['user'],'api.token.revoke',json.dumps({'id':ident})))
  flash('Reporting token revoked.','success');return redirect(url_for('settings',_anchor='api-settings'))
 @app.errorhandler(400)
 @app.errorhandler(404)
 @app.errorhandler(403)
 @app.errorhandler(405)
 def api_error(error):
  if request.path.startswith('/api/'):return jsonify(error=error.description),error.code
  return app.extensions['ui_error'](error) if 'ui_error' in app.extensions else error

def matching_rules(store,row):
 from core import selector
 a=ipaddress.ip_address(row['ip']);result=[]
 for rule in store.active_rules():
  try:
   kind,value,nets=selector(rule['value'])
   matches=str(row['asn'])==value[2:] if kind=='asn' else any(a.version==n.version and a in n for n in nets)
   if matches:result.append(rule)
  except (ValueError,TypeError):continue
 return result
