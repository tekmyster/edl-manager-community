"""Authenticated behavioral investigation and shadow-analysis settings."""
import json,pathlib,os
from flask import request,render_template,redirect,url_for,flash,session,abort
from behavior_ai import brain,settings,validate_settings

def register(app,store,cfg,login_required):
 service=brain(store)
 from behavior_groups import groups
 @app.get('/behavior')
 @login_required
 def behavior_overview():
  return render_template('behavior.html',behavior_settings=settings(store),behavior_summary=service.summary(),worker_state=store.state('behavior_worker') or {},activity_groups=groups(service))
 @app.get('/behavior/metrics')
 @login_required
 def behavior_metrics():
  from behavior_metrics import metrics
  try:data=metrics(service,request.args.get('period','24h'))
  except ValueError:abort(400)
  return render_template('behavior_metrics.html',metrics=data)
 @app.get('/behavior/groups/<ident>')
 @login_required
 def behavior_group(ident):
  found=groups(service,ident=ident)
  if not found:abort(404)
  return render_template('behavior_group.html',group=found[0])
 @app.get('/behavior/observations/<ident>')
 @login_required
 def behavior_observation(ident):
  found=service.packet_view(ident)
  if not found:abort(404)
  return render_template('behavior_observation.html',analysis=found)
 @app.post('/settings/behavior')
 @login_required
 def behavior_settings():
  try:value=validate_settings(request.form)
  except ValueError as exc:flash(str(exc),'error');return redirect(url_for('behavior_overview'))
  secret=pathlib.Path(store.path).parent/'behavior-provider.json'
  if request.form.get('api_key','').strip():
   temp=secret.with_suffix('.new');temp.write_text(json.dumps({'key':request.form['api_key'].strip()}));temp.chmod(0o600);os.replace(temp,secret)
  if request.form.get('clear_key')=='on':secret.unlink(missing_ok=True)
  store.state('behavior_settings',value);store.audit(session['user'],'behavior.configure',{'mode':'shadow','enabled':value['enabled'],'model_enabled':value['model_enabled'],'correlation_enabled':value['correlation_enabled']})
  flash('Behavioral analysis settings saved. Blocking decisions remain deterministic.','success');return redirect(url_for('behavior_overview'))
 @app.post('/behavior/<address>/prepare')
 @login_required
 def behavior_prepare(address):
  try:
   row=store.describe(address);ident,packet,features=service.packet(row,source_cfg=cfg)
   if settings(store)['correlation_enabled']:service.candidates(ident,features)
  except ValueError:abort(400)
  store.audit(session['user'],'behavior.prepare',{'ip':row['ip'],'packet_id':ident})
  flash('Evidence prepared. AI inspection runs in the background when configured.','success');return redirect(url_for('detail',address=row['ip'],_anchor='behavior'))
 @app.post('/behavior/relationships/<ident>/review')
 @login_required
 def behavior_relationship(ident):
  try:service.review(ident,request.form.get('outcome',''),request.form.get('notes',''),session['user'])
  except ValueError as exc:flash(str(exc),'error')
  else:flash('Relationship review saved. No policy was changed.','success')
  return redirect(url_for('behavior_overview'))
 app.jinja_env.globals['behavior_view']=service.view
 app.jinja_env.globals['behavior_groups']=lambda address:groups(service,address=address)
 from source_settings import SOURCES
 app.jinja_env.filters['behavior_source']=lambda value:{**SOURCES,'palo':'Palo Alto'}.get(value,value)
