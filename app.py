import datetime as dt,functools,hmac,ipaddress,json,os,pathlib,secrets,threading,time

from flask import Flask,abort,flash,redirect,render_template,request,send_file,session,url_for,g

from flask.sessions import SecureCookieSessionInterface

from werkzeug.security import check_password_hash,generate_password_hash

from core import Store,now,selector,display_sources
from behavior_scoring import apply as ai_scores

from presentation import feed_label,audit_label,PROVIDERS

from werkzeug.exceptions import HTTPException

from activity import ActivityCache,local_activity

from source_settings import preferences,effective,validate,SOURCES,FIELDS

from metric_trends import initialize as initialize_trends,trends as tile_trends,values as tile_values

from table_layout import ALL as COLUMN_ORDER,DEFAULT as DEFAULT_COLUMNS,OPTIONAL as AI_COLUMNS,layout as column_layout,policy_rows

from table_filters import DATE_KEYS,highlight

from violator_times import attach as attach_times,columns as recorded_columns,format_time as utc_format_time,LABELS as TIME_LABELS

def browse_table(rows,args,prefix,columns,default_sort,choices=None,matchers=None,multi=None):

 """Filter and sort the whole result before selecting a bounded page."""

 def arg(key,default=''):return args.get(prefix+key,default).strip()

 choices=dict(choices or {});matchers=matchers or {}

 dates=set(columns) & DATE_KEYS

 for key in set(columns) & {'port','ports','nat_port'}:
  if key not in choices:
   observed={str(p) for r in rows for p in (r.get('ports',[]) if key=='ports' else [r.get(key)]) if str(p).isdigit() and 0<=int(p)<=65535}
   choices[key]=[(p,p) for p in sorted(observed,key=int)]

 multi=set(multi or [])

 state={prefix+'f_'+key:(list(dict.fromkeys(v.strip() for v in args.getlist(prefix+'f_'+key) if v.strip())) if key in multi else arg('f_'+key)) for key in columns}

 for key,(label,value,sort_value) in columns.items():

  if key in dates:
   for suffix in ('_from','_to'):state[prefix+'f_'+key+suffix]=arg('f_'+key+suffix)
   day=state[prefix+'f_'+key];start=state[prefix+'f_'+key+'_from'];end=state[prefix+'f_'+key+'_to']
   if day or start or end:
    try:
     for raw in (day,start,end):
      if raw and dt.date.fromisoformat(raw).isoformat()!=raw:raise ValueError()
     if start and end and start>end:raise ValueError()
    except ValueError:rows=[];continue
    # Display values already use the user's saved timezone. Both endpoints are inclusive.
    rows=[r for r in rows if (shown:=str(value(r))[:10]) and (not day or shown==day) and (not start or shown>=start) and (not end or shown<=end)]
   continue

  if key in multi:

   selected=state[prefix+'f_'+key];valid=dict(choices[key])

   if selected:rows=[r for r in rows if any(v in valid and (matchers[key](r,v) if key in matchers else str(value(r))==v) for v in selected)]

   continue

  query=state[prefix+'f_'+key].casefold()

  selected=state[prefix+'f_'+key]

  if not prefix and key=='asn' and selected.upper().startswith('AS') and selected[2:].isdigit():

   rows=[r for r in rows if r['asn']==str(int(selected[2:]))]

  elif not prefix and key=='ports' and selected.isdigit():

   rows=[r for r in rows if int(selected) in r.get('ports',[])]

  elif selected and key in {'port','nat_port'} and key in choices:

   rows=[r for r in rows if str(r.get(key,''))==selected]

  elif selected and key in matchers and selected in dict(choices.get(key,[])):

   rows=[r for r in rows if matchers[key](r,selected)]

  elif query:rows=[r for r in rows if query in str(value(r)).casefold()]

 if prefix=='' and 'score' in columns:

  for key,compare in [('min_score',lambda a,b:a>=b),('max_score',lambda a,b:a<=b)]:

   raw=arg(key);state[key]=raw

   try:bound=int(raw)

   except ValueError:continue

   rows=[r for r in rows if compare(r['score'],bound)]

 sort=arg('sort',default_sort)

 if sort not in columns:sort=default_sort

 direction=arg('direction','desc' if sort=='score' else 'asc')

 if direction not in ('asc','desc'):direction='asc'

 rows=sorted(rows,key=lambda r:str(r.get('ip',r.get('id',''))))

 rows.sort(key=columns[sort][2],reverse=direction=='desc')

 try:size=int(arg('size','50'))

 except ValueError:size=50

 if size not in (25,50,100,250):size=50

 total=len(rows);pages=max(1,(total+size-1)//size)

 try:page=max(1,min(pages,int(arg('page','1'))))

 except ValueError:page=1

 state.update({prefix+'sort':sort,prefix+'direction':direction,prefix+'size':size})

 return {'rows':rows[(page-1)*size:page*size],'total':total,'pages':pages,'page':page,'size':size,'start':(page-1)*size+1 if total else 0,'end':min(page*size,total),'sort':sort,'direction':direction,'state':state,'prefix':prefix,'columns':columns,'choices':choices,'multi':multi,'dates':dates}



@functools.lru_cache(maxsize=1)

def timezone_options():

 from zoneinfo import available_timezones

 return ['UTC']+sorted(n for n in available_timezones() if '/' in n and not n.startswith(('Etc/','posix/','right/')))



SESSION_TIMEOUTS={1800:'30 minutes',3600:'1 hour',28800:'8 hours',86400:'24 hours',604800:'7 days',2592000:'30 days'}

class TimedSessionInterface(SecureCookieSessionInterface):

 def get_expiration_time(self,app,session):

  if session.permanent and 'expires_at' in session:

   return dt.datetime.fromtimestamp(session['expires_at'],dt.timezone.utc)

  return super().get_expiration_time(app,session)



def create_app(config=None):

 cfg=config or json.loads(pathlib.Path(os.environ.get('EDL_CONFIG','/etc/edl-manager/config.json')).read_text())

 app=Flask(__name__);app.secret_key=cfg['session_secret'];app.config.update(SESSION_COOKIE_NAME='__Host-edl_manager_session',SESSION_COOKIE_PATH='/',SESSION_COOKIE_SECURE=True,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',SESSION_REFRESH_EACH_REQUEST=False,PERMANENT_SESSION_LIFETIME=dt.timedelta(days=30),MAX_CONTENT_LENGTH=32768,TRUSTED_HOSTS=cfg.get('hosts',['localhost','127.0.0.1']))

 app.session_interface=TimedSessionInterface()

 store=Store(cfg['database']);app.store=store;initialize_trends(store)

 app.jinja_env.filters.update(feed_label=feed_label,audit_label=audit_label,filter_match=lambda value,table,key:highlight(value,table,key,request.args.get('q','')))

 @app.errorhandler(HTTPException)

 def ui_error(error):

  # Reporting endpoints and feed consumers retain their existing error contracts.

  if request.path.startswith(('/api/','/lists/')):return error

  messages={400:('Request expired or invalid','Refresh the page and try again. If your session expired, sign in again.'),403:('Access unavailable','Open the site from an authorized management network.'),404:('Page not found','Check the address or return to the lists.'),405:('Action unavailable','Return to the page and use its controls.'),413:('Request too large','Reduce the submitted content and try again.'),429:('Too many sign-in attempts','Wait 15 minutes before trying again.'),500:('Unable to load this page','Try again. If the problem continues, contact your administrator.')}

  title,message=messages.get(error.code,('Request unsuccessful','Return to the page and try again.'))

  return render_template('error.html',error_code=error.code,error_title=title,error_message=message),error.code

 from offenders import Reports,maintain,text as offender_text

 from reporting_api import register as register_api,tokens as reporting_tokens

 maintain(store);reports=Reports(store)

 from new_ips import Reports as ArrivalReports

 arrivals=ArrivalReports(store)

 investigation=ActivityCache(store,cfg)

 dashboard_cache={'until':0,'rows':None,'snapshot':None};dashboard_lock=threading.Lock()

 def cached_scores():

  # This is display only; decisions and list builds always use current policy/evidence.

  with dashboard_lock:

   try:

    p=(pathlib.Path(cfg['output'])/'current').resolve()/'dashboard.json'

    stat=p.stat();signature=(str(p),stat.st_mtime_ns,stat.st_size)

    if time.time()-stat.st_mtime>600:raise ValueError('Display snapshot is stale')

    if signature!=dashboard_cache['snapshot']:

     data=json.loads(p.read_text(encoding='utf-8'))

     if not isinstance(data.get('rows'),list):raise ValueError('Invalid display snapshot')

     dashboard_cache.update(rows=data['rows'],snapshot=signature,until=0)

    return dashboard_cache['rows']

   except (OSError,ValueError,KeyError):

    if dashboard_cache['until']<=time.monotonic() or dashboard_cache['snapshot'] is not None:

     dashboard_cache.update(rows=ai_scores(store,store.all_scores()),snapshot=None,until=time.monotonic()+15)

    return dashboard_cache['rows']

 def dashboard_scores():

  return attach_times(store,cached_scores())

 def display_timezone():

  if not hasattr(g,'display_timezone'):

   from zoneinfo import ZoneInfo,ZoneInfoNotFoundError

   value=(store.state('user_preferences:'+session.get('user','')) or {}).get('timezone','UTC')

   try:

    if value!='UTC':ZoneInfo(value)

   except (ZoneInfoNotFoundError,ValueError,TypeError):value='UTC'

   g.display_timezone=value

  return g.display_timezone

 def format_time(value):return utc_format_time(value,display_timezone())

 def time_columns():return recorded_columns(format_time,display_timezone())

 def date_columns(columns):

  keys={'at','seen','last_seen','created','expires','new_seen'}

  return {k:(label.replace('UTC',display_timezone()) if k in keys else label,lambda r,k=k,value=value:format_time(r.get(k)) if k in keys else value(r),sort_value) for k,(label,value,sort_value) in columns.items()}

 app.jinja_env.filters['recorded_time']=format_time

 def signed_in():

  with store.connect() as d:r=d.execute('SELECT * FROM users WHERE name=?',(session.get('user',''),)).fetchone()

  return r and session.get('version')==r['version']

 def login_required(fn):

  @functools.wraps(fn)

  def wrap(*a,**kw):

   if not signed_in():return redirect(url_for('login'))

   return fn(*a,**kw)

  return wrap

 @app.before_request

 def protect():

  if request.path.startswith('/feeds/'):return

  try:a=ipaddress.ip_address(request.remote_addr)

  except ValueError:abort(403)

  if not any(a in ipaddress.ip_network(n) for n in cfg.get('management_networks',['127.0.0.0/8','::1/128'])):abort(403)

  if request.path.startswith('/api/'):

   if request.method!='GET':abort(405)

   return

  if session.get('user') and session.get('expires_at',0)<=dt.datetime.now(dt.timezone.utc).timestamp():

   session.clear()

  if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(32)

  if request.method=='POST' and not hmac.compare_digest(request.form.get('csrf',''),session.get('csrf','')):

   if request.endpoint=='login':

    flash('Your sign-in page expired or its session changed. Please enter your credentials again on this refreshed page.','error')

    return render_template('login.html'),400

   abort(400,'Invalid CSRF token')

 @app.after_request

 def headers(r):

  if request.method=='POST' and request.endpoint not in ['login','logout','settings','password']:

   with dashboard_lock:dashboard_cache['until']=0

  r.headers.update({'Cache-Control':r.headers.get('Cache-Control','no-store') if request.path.startswith('/feeds/') else 'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})

  return r

 def login_timeout(username=None):

  preferences=store.state('user_preferences:'+(username or session.get('user',''))) or {}

  try:value=int(request.form.get('session_timeout',preferences.get('session_timeout',request.cookies.get('__Host-edl_manager_timeout','1800'))))

  except (ValueError,TypeError):value=1800

  return value if value in SESSION_TIMEOUTS else 1800

 @app.context_processor

 def login_preferences():

  return {'session_timeouts':SESSION_TIMEOUTS,'selected_timeout':login_timeout(),

   'remembered_username':(request.form.get('username','') if request.method=='POST' else request.cookies.get('__Host-edl_manager_username',''))[:128],

   'remember_username':('remember_username' in request.form if request.method=='POST' else bool(request.cookies.get('__Host-edl_manager_username')))}

 @app.context_processor

 def context():return {'community_usage':__import__('community_usage').snapshot(store),'greynoise_settings':__import__('greynoise_enrichment').settings(store),'greynoise_usage':store.state('greynoise_usage') or {},'display_timezone':display_timezone(),'timezones':timezone_options(),'source_settings':preferences(store,cfg),'source_names':SOURCES,'field_names':FIELDS,'provider_names':PROVIDERS,'csrf':session.get('csrf'),'user':session.get('user'),'built':store.state('latest_build'),'worker':store.state('worker_status'),'ingest':store.state('ingest_status')}

 @app.route('/login',methods=['GET','POST'])

 def login():

  if request.method=='POST':

   address=request.remote_addr

   with store.connect() as d:

    attempt=d.execute('SELECT * FROM login_attempts WHERE address=?',(address,)).fetchone()

    if attempt and attempt['attempts']>=5 and attempt['until']>now():abort(429,'Login rate limit; try again in 15 minutes')

    matches=d.execute('SELECT * FROM users WHERE name=? COLLATE NOCASE LIMIT 2',(request.form.get('username',''),)).fetchall()

    row=matches[0] if len(matches)==1 else None

    good=check_password_hash(row['password_hash'] if row else generate_password_hash('unavailable'),request.form.get('password',''))

    if good and row:

     timeout=login_timeout(row['name'])

     d.execute('DELETE FROM login_attempts WHERE address=?',(address,));session.clear();session.update(user=row['name'],version=row['version'],csrf=secrets.token_urlsafe(32),expires_at=dt.datetime.now(dt.timezone.utc).timestamp()+timeout);session.permanent=True

     d.commit();store.audit(row['name'],'login',{'address':address})

     response=redirect(url_for('dashboard'))

     options={'secure':True,'httponly':True,'samesite':'Strict','path':'/'}

     if 'remember_username' in request.form:

      response.set_cookie('__Host-edl_manager_username',row['name'],max_age=90*86400,**options)

     else:response.delete_cookie('__Host-edl_manager_username',**options)

     response.set_cookie('__Host-edl_manager_timeout',str(timeout),max_age=90*86400,**options)

     return response

    count=attempt['attempts']+1 if attempt and attempt['until']>now() else 1

    d.execute('INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)',(address,count,(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=15)).isoformat(timespec='seconds')))

   flash('Invalid username or password','error')

  return render_template('login.html')

 @app.get('/help')

 @login_required

 def help_page():return render_template('help.html')

 @app.get('/help/images/<name>')

 @login_required

 def help_image(name):

  if name not in {'dashboard.jpg','evidence.jpg','ip-policy.jpg','settings.jpg'}:abort(404)

  return send_file(pathlib.Path(app.root_path)/'help-assets'/name,mimetype='image/jpeg')

 @app.route('/settings',methods=['GET','POST'])

 @login_required

 def settings():

  if request.method=='POST':

   try:timeout=int(request.form.get('session_timeout',''))

   except ValueError:timeout=0

   if timeout not in SESSION_TIMEOUTS:

    flash('Select a valid session timeout.','error')

    return render_template('settings.html',api_tokens=reporting_tokens(store)),400

   store.state('user_preferences:'+session['user'],{**(store.state('user_preferences:'+session['user']) or {}),'session_timeout':timeout})

   session['expires_at']=dt.datetime.now(dt.timezone.utc).timestamp()+timeout

   session.permanent=True

   store.audit(session['user'],'session.timeout.change',{'seconds':timeout})

   flash('Session timeout saved. It applies now and to future sign-ins.','success')

   response=redirect(url_for('settings'))

   response.set_cookie('__Host-edl_manager_timeout',str(timeout),max_age=90*86400,secure=True,httponly=True,samesite='Strict',path='/')

   return response

  return render_template('settings.html',api_tokens=reporting_tokens(store))

 @app.post('/settings/timezone')

 @login_required

 def save_timezone():

  value=request.form.get('timezone','')

  if value not in timezone_options():

   flash('Select a valid display timezone.','error');return redirect(url_for('settings',_anchor='timezone-settings'))

  store.state('user_preferences:'+session['user'],{**(store.state('user_preferences:'+session['user']) or {}),'timezone':value})

  store.audit(session['user'],'display.timezone.change',{'timezone':value})

  flash('Display timezone saved.','success')

  return redirect(url_for('settings',_anchor='timezone-settings'))

 @app.post('/settings/columns')

 @login_required

 def save_columns():

  saved=store.state('user_preferences:'+session['user']) or {}

  if request.form.get('restore')=='1':saved.pop('ip_columns',None)

  else:

   order=request.form.getlist('column_order');visible=request.form.getlist('visible_columns')

   if any(k not in COLUMN_ORDER for k in order+visible) or len(set(order))!=len(order):abort(400,'Invalid column layout')

   saved['ip_columns']={'order':['ip']+[k for k in order if k!='ip'],'visible':['ip']+[k for k in visible if k!='ip']}

  store.state('user_preferences:'+session['user'],saved)

  store.audit(session['user'],'display.columns.change',{'restored':request.form.get('restore')=='1'})

  flash('Column layout saved for your account.','success')

  from urllib.parse import parse_qsl,urlencode

  query=urlencode(parse_qsl(request.form.get('return_query','')[:4096],keep_blank_values=True))

  return redirect(url_for('dashboard')+('?' + query if query else '')+'#ip-evidence')

 @app.post('/settings/sources')

 @login_required

 def save_sources():

  try:value=validate(request.form)

  except ValueError as error:

   flash(str(error),'error');return redirect(url_for('settings',_anchor='source-settings'))

  previous=preferences(store,cfg)

  if value['misp_url']!=previous['misp_url'] or value['misp_sha256']!=previous['misp_sha256']:

   store.state('misp_snapshot',{})

   with store.connect() as d:d.execute("DELETE FROM cache WHERE provider='misp'")

  store.state('source_configuration',value)

  store.state('native_ingest_cursor',{})

  store.state('palo_status',{})

  store.audit(session['user'],'sources.configure',{'sources':sorted(k for k,v in value['sources'].items() if v),'fields':value['fields']})

  flash('Sources saved. Changes apply on the next collection.','success')

  return redirect(url_for('settings',_anchor='source-settings'))

 @app.post('/logout')

 @login_required

 def logout():session.clear();return redirect(url_for('login'))

 @app.route('/')

 @login_required

 def dashboard():

  rules=store.active_rules();scores=reports.decorate(dashboard_scores());known={r['ip'] for r in scores};observed_count=len(scores)

  extra=[store.describe(value) for value in dict.fromkeys(r['value'] for r in rules if r['kind']=='ip' and r['value'] not in known)];scores+=reports.decorate(attach_times(store,extra),include_historical=False)

  scores=policy_rows(store,scores,rules);report=reports.snapshot();query=request.args.get('q','').strip().lower();view=request.args.get('view','all')

  saved_layout=(store.state('user_preferences:'+session['user']) or {}).get('ip_columns',{})
  ai_visible=set(saved_layout.get('visible',DEFAULT_COLUMNS)) & set(AI_COLUMNS)
  if ai_visible:
   from ai_table import decorate as ai_table_rows
   scores=ai_table_rows(store,scores,ai_visible)

  rows=[r for r in scores if not query or query in (' '.join([r['ip'],r['asn'],r['organization'],r['repeat_text']]+r.get('source_labels',r['sources'])+[str(p) for p in r.get('ports',[])]+[r.get('enrichment_text',''),r.get('ai_search','')]+r.get('client_types',[])+r.get('source_identity',{}).get('clients',[]))).lower()]

  if view=='candidate':rows=[r for r in rows if r['auto_candidate']]

  if view=='hold':rows=[r for r in rows if not r['auto_candidate'] and not r.get('history_only')]

  def enrichment_sources(row):

   if 'enrichment_sources' in row:return row['enrichment_sources']

   return display_sources(row)

  rows=[{**r,'enrichment_sources':enrichment_sources(r)} for r in rows]

  ip_columns={'ip':('IP address',lambda r:r['ip'],lambda r:(ipaddress.ip_address(r['ip']).version,int(ipaddress.ip_address(r['ip'])))),

   'asn':('ASN / organization',lambda r:'AS'+r['asn']+' '+r['organization'],lambda r:(int(r['asn']) if r['asn'].isdigit() else -1,r['organization'].casefold())),

   'client_type':('Source type',lambda r:', '.join(r.get('client_types',['Unknown'])),lambda r:', '.join(r.get('client_types',['Unknown'])).casefold()),

   'sources':('Sources / honeypots',lambda r:', '.join(r.get('source_labels',r['sources'])),lambda r:', '.join(r.get('source_labels',r['sources'])).casefold()),

   'ports':('Destination ports',lambda r:', '.join(str(p) for p in r.get('ports',[])),lambda r:tuple(r.get('ports',[]))),

   'enrichment':('Enrichment',lambda r:r.get('enrichment_text','Pending enrichment'),lambda r:r.get('enrichment_text','').casefold()),

   'enrichment_sources':('Enrichment source',lambda r:', '.join(r['enrichment_sources']),lambda r:', '.join(r['enrichment_sources']).casefold()),

   'repeat':('Repeat offender',lambda r:r['repeat_text'],lambda r:(len(r['repeat_windows']),r['repeat_history']['windows']['30']['active_days'] if r.get('repeat_history') else 0)),

   'score':('Score',lambda r:r['score'],lambda r:r['score']),

   'priority':('Review priority',lambda r:r.get('priority','Local evidence only'),lambda r:{'Review benign conflict':4,'Corroborated attack':3,'Review suspicious activity':2,'Local evidence only':1,'Protected benign actor':0}.get(r.get('priority'),1)),

   'ai_assessment':('AI assessment',lambda r:r.get('ai_assessment','Unavailable'),lambda r:r.get('ai_assessment','').casefold()),
   'ai_contribution':('AI contribution',lambda r:r.get('ai_contribution','Unavailable'),lambda r:(r.get('ai_contribution_value') is not None,r.get('ai_contribution_value') or 0)),
   'ai_coverage':('AI evidence coverage',lambda r:r.get('ai_coverage','Unavailable'),lambda r:r.get('ai_coverage','').casefold()),
   'policy':('Policy',lambda r:r['policy'],lambda r:r['policy']),**time_columns()}

  visible=set(preferences(store,cfg)['fields'])

  available={k:v for k,v in ip_columns.items() if k not in FIELDS or k in visible}

  ordered,shown=column_layout(saved_layout,available)

  column_options=[{'key':k,'label':available[k][0],'visible':k in shown} for k in ordered]

  ip_columns={k:available[k] for k in ordered if k in shown}

  asn_identity=lambda r:'AS'+r['asn']+' '+r['organization'] if r['asn'] else 'Unknown ASN / organization'

  owners=sorted({asn_identity(r) for r in scores},key=str.casefold)

  sources=sorted({source for r in scores for source in r['sources']},key=str.casefold)

  names={'tpot':'T-Pot (all honeypots)','owapot':'T-Pot (OWAPot)','nginx':'NGINX','waf':'WAF','crowdsec':'CrowdSec','wazuh':'Wazuh'}

  honeypots=sorted({(row['source'],row['sensor'],row['label']) for r in scores for row in r.get('source_details',[]) if row['source']=='tpot'})

  source_choices=[(source,names.get(source,source)) for source in sources]+[('tpot:'+sensor,label) for source,sensor,label in honeypots]

  def source_matches(r,value):

   if value=='tpot':return bool(set(r['sources']) & {'tpot','owapot'})

   if value.startswith('tpot:'):return any(d['source']=='tpot' and d['sensor']==value[5:] for d in r.get('source_details',[]))

   return value in r['sources']

  ip_choices={'client_type':[(v,v) for v in sorted({v for r in scores for v in r.get('client_types',['Unknown'])})],'asn':[(owner,owner) for owner in owners],'sources':source_choices,

   'enrichment_sources':[(name,name) for name in ['ASN','MISP','GreyNoise','Palo','Crawler','AbuseIPDB','VirusTotal']],

   'repeat':[('any','Any repeat offender'),('none','No repeat activity')]+[(str(n),'1 year' if n==365 else str(n)+' days') for n in (30,60,90,180,365)],

   'priority':[(v,v) for v in ('Review benign conflict','Corroborated attack','Review suspicious activity','Local evidence only','Protected benign actor')],

   'policy':[(v,v) for v in ('Allowed','Denied','Evaluating')]}

  ip_choices.update(ai_assessment=[(k,v) for k,v in __import__('ai_table').LABELS.items()],ai_contribution=[('applied','Points applied'),('none','No points applied'),('unknown','Unavailable')],ai_coverage=[('sampled','Saved samples'),('unknown','Coverage unavailable'),('not_indexed','Not indexed')])

  ip_matchers={'ai_assessment':lambda r,v:r.get('ai_assessment_status')==v,'ai_coverage':lambda r,v:r.get('ai_coverage_status')==v,
   'ai_contribution':lambda r,v:(r.get('ai_contribution_value') or 0)>0 if v=='applied' else r.get('ai_contribution_value')==0 if v=='none' else r.get('ai_contribution_value') is None,
   'client_type':lambda r,v:v in r.get('client_types',['Unknown']),'asn':lambda r,v:asn_identity(r)==v,'sources':source_matches,

   'enrichment_sources':lambda r,v:v in r['enrichment_sources'],

   'repeat':lambda r,v:bool(r['repeat_windows']) if v=='any' else not r['repeat_windows'] if v=='none' else int(v) in r['repeat_windows'],

   'ports':lambda r,v:v in r.get('ports',[]),

   'policy':lambda r,v:r['policy']==v}

  evidence=browse_table(rows,request.args,'',ip_columns,'score' if 'score' in ip_columns else next(iter(ip_columns)),ip_choices,ip_matchers,multi={'enrichment_sources'} & set(ip_columns))

  state={'q':query,'view':view,**evidence['state'],'page':evidence['page']}

  def table_url(table,**changes):

   params=dict(state);params.update({table['prefix']+key:value for key,value in changes.items()})

   return url_for('dashboard',**params,_anchor='ip-evidence')

  with store.connect() as d:audit=[dict(r) for r in d.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 12')]

  new_report=arrivals.snapshot()

  stats=tile_values(scores,rules,report,new_report['count'],observed_count)

  try:
   from production_analytics import summary as analytics_summary
   from behavior_ai import brain as analytics_brain
   analytics=analytics_summary(analytics_brain(store),display_timezone())
  except (OSError,__import__('sqlite3').Error):analytics=None
  return render_template('dashboard.html',analytics=analytics,intelligence_metrics=__import__('greynoise_enrichment').metrics(store,scores),report=report,stats=stats,trends=tile_trends(store,stats,report,new_report=new_report),evidence=evidence,column_options=column_options,table_url=table_url,table_state=state,query=query,view=view,rules=rules,audit=audit,providers=store.state('provider_status') or {})

 @app.get('/results/<metric>')

 @login_required

 def metric_results(metric):

  titles={'new':'New IPs in the last 24 hours','total':'Tracked IPs','candidate':'Block candidates','crawler':'Protected crawlers','policy':'Policy overrides','blacklisted':'Manual blocks','repeat':'Repeat offenders','top-month':'Top offenders this month'}

  titles.update({'intel-fresh':'Fresh intelligence','intel-malicious':'Known malicious scanners','intel-conflicts':'Benign blocking conflicts','intel-stale':'Stale intelligence','intel-reviewed':'Intelligence reviews'})

  titles.update({'intel-fresh':'Fresh intelligence','intel-malicious':'Known malicious scanners','intel-conflicts':'Benign blocking conflicts','intel-stale':'Stale intelligence','intel-reviewed':'Intelligence reviews'})
  if metric not in titles:abort(404)

  days=request.args.get('days','30')

  if days not in ('30','60','90','180','365'):days='30'

  if metric.startswith('intel-'):

   from greynoise_enrichment import decorate

   rows=decorate(policy_rows(store,reports.decorate(dashboard_scores()),store.active_rules()))

   predicates={'intel-fresh':lambda r:r['intelligence']['fresh'],'intel-malicious':lambda r:r['intelligence']['fresh'] and r['intelligence']['classification']=='malicious','intel-conflicts':lambda r:r['intelligence']['conflict'],'intel-stale':lambda r:r['intelligence']['classification']!='unchecked' and not r['intelligence']['fresh']}

   if metric=='intel-reviewed':

    with store.connect(commit=False) as d:

     rows=[{**__import__('json').loads(r['details']),'at':r['at'],'actor':r['actor']} for r in d.execute("SELECT at,actor,details FROM audit WHERE action='intelligence.review' AND at>=? ORDER BY id DESC",((dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)).isoformat(timespec='seconds'),))]
    latest={}
    for reviewed in rows:latest.setdefault(reviewed['ip'],reviewed)
    rows=list(latest.values())

    labels=[('ip','IP address'),('outcome','Outcome'),('note','Notes'),('actor','Reviewed by'),('at','Reviewed UTC')]

   else:

    rows=[r for r in rows if predicates[metric](r)];labels=[('ip','IP address'),('policy','Policy'),('priority','Review priority'),('enrichment_text','Intelligence')]

   columns={k:(label,lambda r,k=k:str(r.get(k,'')).replace('_',' '),lambda r,k=k:str(r.get(k,''))) for k,label in labels}

  elif metric=='new':

   recent=arrivals.snapshot();known={r['ip']:r for r in reports.decorate(dashboard_scores())}

   rows=[{**known.get(r['ip'],{'asn':'','organization':'','score':0,'sources':[]} ),**r} for r in recent['rows']]

   columns={k:(label,lambda r,k=k:str(r.get(k,'') or ''),lambda r,k=k:r.get(k,0) if k=='score' else str(r.get(k,'') or '')) for k,label in [('ip','IP address'),('new_seen','New arrival UTC'),('last_seen','Last seen UTC'),('asn','ASN'),('organization','Organization'),('score','Score')]}

  elif metric in ('repeat','top-month'):

   history=reports.snapshot()

   rows=[{**r,**r['month']} for r in history['ips'].values() if r['month']['active_days']] if metric=='top-month' else [{**r,**r['windows'][days]} for r in history['ips'].values() if r['windows'][days]['repeat']]

   columns={k:(label,lambda r,k=k:str(r[k]),lambda r,k=k:r[k] if k in ('active_days','observations') else str(r[k])) for k,label in [('active_days','Active UTC days'),('observations','Recorded observations'),('ip','IP address'),('last_seen','Last seen UTC')]}

  elif metric in ('policy','blacklisted'):

   rows=store.active_rules()

   if metric=='blacklisted':rows=[r for r in rows if r['action']=='block']

   columns={k:(label,lambda r,k=k:format_time(r[k]) if k in ('created','expires') else str(r[k] or ''),lambda r,k=k:str(r[k] or '').casefold()) for k,label in [('action','Action'),('value','IP / subnet / ASN'),('reason','Notes / reason'),('created','Added UTC'),('expires','Expiry UTC')]}

  else:

   rows=reports.decorate(dashboard_scores())

   if metric=='candidate':rows=[r for r in rows if r['auto_candidate']]

   if metric=='crawler':rows=[r for r in rows if r['verified_crawler']]

   columns={k:(label,lambda r,k=k: ', '.join(r[k]) if isinstance(r[k],list) else str(r[k]),lambda r,k=k:r[k] if k=='score' else str(r[k]).casefold()) for k,label in [('ip','IP address'),('score','Score'),('asn','ASN'),('organization','Organization'),('sources','Sources')]}

   columns.update(time_columns())

  visible=set(preferences(store,cfg)['fields'])

  columns={k:v for k,v in columns.items() if k not in FIELDS or k in visible}

  args=request.args.copy()

  if metric in ('repeat','top-month') and 'm_direction' not in args:args['m_direction']='desc'

  if metric=='top-month' and 'm_sort' not in args:args['m_sort']='observations'

  if metric.startswith('intel-'):
   from greynoise_enrichment import decorate
   rows=decorate(policy_rows(store,reports.decorate(dashboard_scores()),store.active_rules()))
   predicates={'intel-fresh':lambda r:r['intelligence']['fresh'],'intel-malicious':lambda r:r['intelligence']['fresh'] and r['intelligence']['classification']=='malicious','intel-conflicts':lambda r:r['intelligence']['conflict'],'intel-stale':lambda r:r['intelligence']['classification']!='unchecked' and not r['intelligence']['fresh']}
   if metric=='intel-reviewed':
    with store.connect(commit=False) as d:
     rows=[{**__import__('json').loads(r['details']),'at':r['at'],'actor':r['actor']} for r in d.execute("SELECT at,actor,details FROM audit WHERE action='intelligence.review' AND at>=? ORDER BY id DESC",((dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)).isoformat(timespec='seconds'),))]
    latest={}
    for reviewed in rows:latest.setdefault(reviewed['ip'],reviewed)
    rows=list(latest.values())
    labels=[('ip','IP address'),('outcome','Outcome'),('note','Notes'),('actor','Reviewed by'),('at','Reviewed UTC')]
   else:
    rows=[r for r in rows if predicates[metric](r)];labels=[('ip','IP address'),('policy','Policy'),('priority','Review priority'),('enrichment_text','Intelligence')]
   columns={k:(label,lambda r,k=k:str(r.get(k,'')).replace('_',' '),lambda r,k=k:str(r.get(k,''))) for k,label in labels}
  elif metric=='new':

   if 'm_sort' not in args:args['m_sort']='new_seen'

   if 'm_direction' not in args:args['m_direction']='desc'

  table=browse_table(rows,args,'m_',date_columns(columns),next(iter(columns)),{'action':[('allow','Whitelist'),('block','Blacklist')]} if metric in ('policy','blacklisted') else None,{'action':lambda r,v:r['action']==v} if metric in ('policy','blacklisted') else None)

  state={**table['state'],'m_page':table['page'],**({'days':days} if metric=='repeat' else {})}

  def table_url(table,**changes):return url_for('metric_results',metric=metric,**{**state,**{'m_'+k:v for k,v in changes.items()}})

  return render_template('metric_results.html',title=titles[metric],table=table,table_state=state,table_url=table_url,metric=metric,days=days,new_report=arrivals.snapshot() if metric=='new' else None,partial=request.headers.get('X-EDL-Modal')=='1')

 def investigation_view(r):

  current=effective(store,cfg);investigation.cfg=current

  data=investigation.get(r['ip']) if current['palo_location'] and current['index_url'] else {'enabled':False,'loading':False}

  events,summaries=local_activity(r)

  enabled={k for k,v in current['source_agents'].items() if v}

  events=[e for e in events if e['source'] in enabled];summaries=[e for e in summaries if e['source'] in enabled]

  visible=set(current['collected_fields'])

  args=request.args.copy()

  for prefix in ['a_','d_','w_']:

   if prefix+'direction' not in args:args[prefix+'direction']='desc'

  cutoff=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=30)).isoformat(timespec='seconds')

  events+= [e for e in data.get('events',[]) if e['seen']>=cutoff]

  columns={k:(label,lambda r,k=k:str(r.get(k,'') or ''),lambda r,k=k:str(r.get(k,'') or '')) for k,label in [('seen','Time UTC'),('source','Source'),('sensor','Service / honeypot'),('destination','Destination'),('port','Port'),('action','Action / event'),('path','Request path'),('nat','NAT destination'),('rule','Rule'),('reason','Outcome detail')]}

  choices={k:[(v,v) for v in sorted({str(e.get(k,'') or '') for e in events}) if v] for k in ['source','action']}

  columns={k:v for k,v in columns.items() if (k not in FIELDS or k in visible) and (k!='port' or 'ports' in visible) and (k not in ['nat','rule','reason'] or data.get('enabled'))}

  timeline=browse_table(events,args,'a_',date_columns(columns),'seen',choices)

  dest_columns={k:(label,lambda r,k=k:str(r.get(k,'') or ''),lambda r,k=k:int(r.get(k,0) or 0) if k=='count' else str(r.get(k,'') or '')) for k,label in [('destination','Destination'),('port','Port'),('nat','NAT destination'),('nat_port','NAT port'),('application','Application'),('action','Action'),('zone','Zone'),('count','Log records')]}

  dest_columns={k:v for k,v in dest_columns.items() if (k not in FIELDS or k in visible) and (k!='port' or 'ports' in visible)}

  destinations=browse_table(data.get('destinations',[]),args,'d_',dest_columns,'count',{'action':[(v,v) for v in sorted({str(e.get('action','') or '') for e in data.get('destinations',[])}) if v]})

  web_events=[e for e in events if any(e.get(k) for k in ['path','method','client','status','host'])]

  web_columns={k:(label,lambda r,k=k:str(r.get(k,'') or ''),lambda r,k=k:str(r.get(k,'') or '')) for k,label in [('seen','Time UTC'),('source','Source'),('method','Method'),('host','Requested host'),('path','Path'),('status','HTTP status'),('client','Client'),('platform','OS'),('client_type','Client type'),('confidence','Confidence')]}

  web_choices={k:[(v,v) for v in sorted({str(e.get(k,'') or '') for e in web_events}) if v] for k in ['source','method','status','client_type','confidence']}

  web_columns={k:v for k,v in web_columns.items() if k not in FIELDS or k in visible}

  web=browse_table(web_events,args,'w_',date_columns(web_columns),'seen',web_choices)

  state={**timeline['state'],**destinations['state'],**web['state'],'a_page':timeline['page'],'d_page':destinations['page'],'w_page':web['page']}

  def activity_url(table,**changes):return url_for('detail',address=r['ip'],**{**state,**{table['prefix']+k:v for k,v in changes.items()}},_anchor='activity')

  return {'web':web,'activity':data,'timeline':timeline,'destinations':destinations,'summaries':summaries,'activity_url':activity_url,'activity_state':state,'activity_api_url':url_for('ip_activity',address=r['ip'],**state)}

 @app.route('/ip/<path:address>')

 @login_required

 def detail(address):

  try:r=attach_times(store,ai_scores(store,[store.describe(address)]))[0]

  except ValueError:abort(400)

  r=policy_rows(store,[r],store.active_rules())[0]

  related=[];target=ipaddress.ip_address(r['ip']);current=now()

  with store.connect() as d:

   for record in d.execute('SELECT * FROM rules ORDER BY created DESC'):

    rule=dict(record)

    try:

     kind,value,nets=selector(rule['value'])

     matches=value=='AS'+r['asn'] if kind=='asn' else any(target in network for network in nets)

    except ValueError:continue

    if not matches:continue

    rule['status']='Disabled' if not rule['enabled'] else 'Expired' if rule['expires'] and rule['expires']<=current else 'Active'

    related.append(rule)

    if len(related)>=25:break

  h=reports.snapshot()['ips'].get(r['ip'])

  from event_history import matching

  saved=matching(store,r['ip'],r['asn'])

  columns={k:(label,lambda item,k=k:str(item.get(k,'') or ''),lambda item,k=k:str(item.get(k,'') or '')) for k,label in [('at','Time UTC'),('label','Event'),('actor','By'),('list','List'),('target','IP / selector'),('notes','Notes')]}

  args=request.args.copy()

  if 'e_direction' not in args:args['e_direction']='desc'

  events=browse_table(saved['rows'],args,'e_',date_columns(columns),'at',{'label':[(v,v) for v in sorted({item['label'] for item in saved['rows']})],'list':[(v,v) for v in sorted({item['list'] for item in saved['rows'] if item['list']})]})

  investigation=investigation_view(r);state={**investigation['activity_state'],**events['state'],'e_page':events['page']}

  def event_url(table,**changes):return url_for('detail',address=r['ip'],**{**state,**{table['prefix']+k:v for k,v in changes.items()}},_anchor='policy-history')

  from permanent_policy import view as permanent_view
  return render_template('detail.html',row=r,permanent_policy=permanent_view(store,r['ip']),time_labels=[(k,label.replace("UTC",display_timezone())) for k,label in TIME_LABELS],repeat_history=h,repeat_text=offender_text(h),repeat_report=reports.snapshot(),policy_notes=related,events=events,event_state=state,event_url=event_url,event_tracking=saved['tracking'],**investigation)

 @app.post('/ip/<path:address>/permanent-reversal')
 @login_required
 def permanent_reversal(address):
  from permanent_policy import reverse
  try:
   address=store.describe(address)['ip']
   reverse(store,address,request.form.get('reason',''),session['user'])
   flash('Permanent policy reversed. Other native and manual blocks still apply. Lists update on the next publication.','success')
  except ValueError as error:flash(str(error),'error')
  return redirect(url_for('detail',address=address,_anchor='permanent-policy'))

 @app.post('/ip/<path:address>/policy')

 @login_required

 def ip_policy(address):

  try:address=store.describe(address)['ip']

  except ValueError:abort(400)

  try:

   notes=request.form.get('reason','').strip()

   if len(notes)>1000:raise ValueError('Notes must be 1,000 characters or fewer.')

   expires=request.form.get('expires','').strip() or None

   if expires and len(expires)==16:expires+=':00+00:00'

   store.add_rule(request.form.get('action',''),address,notes,expires,session['user'],request.form.get('emergency')=='on')

   flash('Rule and notes saved. Lists update on the next publication.','success')

  except (ValueError,TypeError) as error:flash(str(error),'error')

  return redirect(url_for('detail',address=address,_anchor='ip-policy'))

 @app.route('/ip-activity/<path:address>')

 @login_required

 def ip_activity(address):

  try:r=store.describe(address)

  except ValueError:abort(400)

  return render_template('activity.html',row=r,**investigation_view(r))

 @app.post('/rules')

 @login_required

 def rules():

  try:

   expires=request.form.get('expires','').strip() or None

   if expires and len(expires)==16:expires+=':00+00:00'

   id=store.add_rule(request.form.get('action',''),request.form.get('value',''),request.form.get('reason',''),expires,session['user'],request.form.get('emergency')=='on')

   flash('Rule and notes saved. Lists update on the next publication.','success')

  except (ValueError,TypeError) as e:flash(str(e),'error')

  return redirect(url_for('dashboard'))

 @app.post('/rules/bulk-whitelist')

 @login_required

 def bulk_whitelist():

  try:

   addresses=[]

   for value in request.form.getlist('addresses'):

    kind,canonical,nets=selector(value)

    if kind!='ip':raise ValueError('Select individual IP addresses. Use the rule form for subnets or address ranges.')

    addresses.append(canonical)

   expires=request.form.get('expires','').strip() or None

   if expires and len(expires)==16:expires+=':00+00:00'

   ids=store.add_rules('allow',addresses,request.form.get('reason',''),expires,session['user'])

   flash(str(len(ids))+' addresses whitelisted with comments. Lists update on the next publication.','success')

  except (ValueError,TypeError) as error:flash(str(error),'error')

  return redirect(url_for('dashboard',_anchor='ip-evidence'))

 @app.post('/rules/<id>/disable')

 @login_required

 def disable(id):

  try:store.disable_rule(id,session['user']);flash('Rule disabled. Lists update on the next publication.','success')

  except ValueError as e:flash(str(e),'error')

  return redirect(url_for('dashboard'))

 @app.post('/build')

 @login_required

 def build():

  try:

   m=store.build(cfg['output'],actor=session['user']);store.audit(session['user'],'lists.build',m);flash('Lists rebuilt. Publication is queued.','success')

  except ValueError as e:flash(str(e),'error')

  except OSError:

   app.logger.exception('List build failed');flash('Unable to rebuild lists. Try again or contact your administrator.','error')

  return redirect(url_for('dashboard'))

 @app.route('/lists/<name>.txt')

 @login_required

 def lists(name):

  m=store.state('latest_build') or {}

  if name not in m.get('counts',{}):abort(404)

  return send_file(pathlib.Path(cfg['output'])/'current'/(name+'.txt'),mimetype='text/plain',as_attachment=True)

 @app.post('/enrich/<path:address>')

 @login_required

 def enrich(address):

  try:store.describe(address)

  except ValueError:abort(400)

  store.state('enrich_request:'+address,{'requested':now(),'actor':session['user']});store.audit(session['user'],'enrichment.queue',{'ip':address});flash('Enrichment refresh queued.','success');return redirect(url_for('detail',address=address))

 @app.post('/password')

 @login_required

 def password():

  old=request.form.get('current','');new=request.form.get('new','')

  with store.connect() as d:

   r=d.execute('SELECT * FROM users WHERE name=?',(session['user'],)).fetchone()

   if len(new)<16 or not check_password_hash(r['password_hash'],old):flash('Current password must match; new password must have at least 16 characters.','error')

   else:

    d.execute('UPDATE users SET password_hash=?,version=version+1 WHERE name=?',(generate_password_hash(new),session['user']));d.commit();store.audit(session['user'],'password.change',{});session.clear();return redirect(url_for('login'))

  return redirect(url_for('settings',_anchor='password-settings'))

 @app.post('/settings/greynoise')

 @login_required

 def configure_greynoise():

  try:budget=int(request.form.get('weekly_budget','30'))

  except ValueError:abort(400)

  if not 1<=budget<=10000:abort(400)

  store.state('greynoise_settings',{'enabled':request.form.get('enabled')=='on','score_enabled':request.form.get('score_enabled')=='on','weekly_budget':budget})

  store._greynoise_settings=store.state('greynoise_settings')
  store.audit(session['user'],'intelligence.configure',{'weekly_budget':budget})

  flash('Intelligence settings saved.','success');return redirect(url_for('settings',_anchor='intelligence-settings'))

 @app.post('/ip/<address>/intelligence-review')

 @login_required

 def intelligence_review(address):

  try:address=str(__import__('core').ip(address))

  except ValueError:abort(400)

  outcome=request.form.get('outcome');note=request.form.get('note','').strip()

  if outcome not in ('false_positive','confirmed_malicious','inconclusive') or not 1<=len(note)<=1000:abort(400)

  with store.connect(commit=False) as d:

   if not d.execute('SELECT 1 FROM ips WHERE ip=?',(address,)).fetchone():abort(404)

  store.audit(session['user'],'intelligence.review',{'ip':address,'outcome':outcome,'note':note})

  flash('Review saved.','success');return redirect(url_for('detail',address=address))

 @app.post('/providers')

 @login_required

 def providers():

  p=pathlib.Path(cfg['providers_file']);keys=json.loads(p.read_text()) if p.exists() else {}

  for name in ['misp','abuseipdb','virustotal','greynoise']:

   if request.form.get('disable_'+name)=='on':keys.pop(name,None)

   elif request.form.get(name):keys[name]=request.form[name].strip()

  temp=p.with_suffix('.new');temp.write_text(json.dumps(keys));temp.chmod(0o600);os.replace(temp,p)

  store.audit(session['user'],'providers.configure',{'enabled':sorted(keys)});flash('Enrichment keys saved. Changes apply on the next check.','success');return redirect(url_for('settings',_anchor='provider-settings'))

 app.extensions['ui_error']=ui_error

 @app.post('/settings/community-use')
 @login_required
 def community_use():
  profile=request.form.get('use_class','')
  if profile not in ('homelab','nonprofit','enterprise'):abort(400)
  store.state('community_use_class',profile);store._community_usage_until=0;store.audit(session['user'],'community.use',{'use_class':profile})
  flash('Usage profile saved.','success');return redirect(url_for('settings',_anchor='community-usage'))

 @app.get('/feeds/<name>.txt')
 def consumer_feed(name):
  if name not in __import__('transport').NAMES:abort(404)
  try:remote=ipaddress.ip_address(request.remote_addr)
  except ValueError:abort(403)
  if not any(remote in ipaddress.ip_network(n) for n in cfg.get('feed_networks',[])):abort(403)
  current=pathlib.Path(cfg['output'])/'current'/(name+'.txt')
  if not current.is_file():abort(503)
  response=send_file(current,mimetype='text/plain',conditional=True)
  response.headers['Cache-Control']='private, no-cache, must-revalidate'
  return response

 register_api(app,store,cfg,reports,dashboard_scores,login_required)
 from behavior_routes import register as register_behavior
 register_behavior(app,store,cfg,login_required)

 return app

if __name__!='__main__':

 if os.environ.get('EDL_CONFIG'):app=create_app()

