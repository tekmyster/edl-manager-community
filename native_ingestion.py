"""Bounded daily source ingestion with independently durable coverage lanes.

Native event time still controls eligibility. These cursors describe indexed
arrival coverage, not historical source completeness or incident truth.
"""
import copy,datetime as dt,hashlib,json,time,requests
UTC=dt.timezone.utc
class PartitionUnavailable(ValueError):
    def __init__(self,message,shrink=False):super().__init__(message);self.shrink=shrink

def parse(value):
    value=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if value.tzinfo is None:raise PartitionUnavailable('Ingestion checkpoint requires timezone')
    return value.astimezone(UTC)

def page(store,session,cfg,name,filters,aggregation,apply,started,seed,*,history=False):
    key='ingest_partition_'+name;state=store.state(key) or {};cutoff=started-dt.timedelta(days=30)
    scope=hashlib.sha256(json.dumps([cfg['index_url'],filters,name],sort_keys=True).encode()).hexdigest()
    if state.get('scope') not in (None,scope):
        # Configuration changes define a different query domain. Keep the old
        # checkpoint addressable, and reconcile the newly enabled domain from
        # its retention floor instead of skipping it with another scope's cursor.
        store.state(key+'_scope_'+state['scope'],state)
        state=store.state(key+'_scope_'+scope) or {'through':cutoff.isoformat(),'status':'partial'}
        state={**state,'scope':scope};store.state(key,state)
    if history and not state.get('pending') and state.get('completed') and parse(state['completed'])>=started-dt.timedelta(hours=24):return 0
    pending=state.get('pending')
    if not pending:
        if history or name.startswith('general'):lower=cutoff;ceiling=started
        else:
            through=parse(state.get('through') or seed or cutoff.isoformat())
            if through>started:raise PartitionUnavailable('Future ingestion checkpoint retained')
            lower=max(cutoff,through-(dt.timedelta(minutes=10) if through.time()!=dt.time() else dt.timedelta()))
            ceiling=started
        upper=ceiling if name.startswith('general') else min(ceiling,lower.replace(hour=0,minute=0,second=0,microsecond=0)+dt.timedelta(days=1))
        pending={'lower':lower.isoformat(),'upper':upper.isoformat(),'ceiling':ceiling.isoformat(),'cutoff':cutoff.isoformat(),'after':None,'page_size':state.get('page_size',500)}
    lower=parse(pending['lower']);upper=parse(pending['upper']);ceiling=parse(pending['ceiling'])
    if not lower<=upper<=ceiling<=started:raise PartitionUnavailable('Invalid bounded ingestion window retained')
    page_size=pending.get('page_size',500)
    if type(page_size) is not int or not 1<=page_size<=500:raise PartitionUnavailable('Invalid source page admission retained')
    # Retain a fixed query fence even if the first request fails or a process
    # restarts before its first returned page. This is not an acknowledged EOF.
    store.state(key,{**state,'scope':scope,'pending':pending,'status':'partial'})
    query={'size':0,'timeout':'8s','query':{'bool':{'filter':copy.deepcopy(filters)+[{'range':{'timestamp':{'gte':pending['lower'],'lte':pending['upper']}}}]}},'aggs':{'items':copy.deepcopy(aggregation)}}
    query['aggs']['items']['composite']['size']=page_size
    if name.startswith('native'):query['query']['bool']['filter'].append({'range':{'data.edl_seen_utc':{'gte':pending['cutoff'],'lte':pending['ceiling']}}})
    if pending['after']:query['aggs']['items']['composite']['after']=pending['after']
    # Native work touches one UTC day. General authentication qualification
    # must retain its original aggregate count across days (five alerts).
    # Enumerate only its fixed, at most 31 retention-day partitions; a timeout
    # holds this independent lane and cannot cancel native progress.
    index='wazuh-alerts-*'+lower.strftime('%Y.%m.%d')
    if name.startswith('general'):
        day=lower.replace(hour=0,minute=0,second=0,microsecond=0);indices=[]
        while day<=upper:
            indices.append('wazuh-alerts-*'+day.strftime('%Y.%m.%d'));day+=dt.timedelta(days=1)
            if len(indices)>31:raise PartitionUnavailable('General source retention admission exceeded')
        index=','.join(indices)
    anchor=getattr(store,'_worker_connection',None)
    if anchor is not None:store._worker_last_direct_commit='native_page_before_fetch' if name.startswith('native') else 'wazuh_page_before_fetch';anchor.commit()
    deadline=time.monotonic()+15
    response=session.post(cfg['index_url']+'/'+index+'/_search?ignore_unavailable=true&allow_no_indices=true&allow_partial_search_results=false',json=query,timeout=(3,8),stream=True)
    try:
        response.raise_for_status()
        if hasattr(response,'iter_content'):
            chunks=[];size=0
            for chunk in response.iter_content(65536):
                size+=len(chunk)
                if size>8*1024**2 or time.monotonic()>deadline:raise PartitionUnavailable('Daily source response admission exhausted',shrink=True)
                chunks.append(chunk)
            try:value=json.loads(b''.join(chunks))
            except json.JSONDecodeError as exc:raise PartitionUnavailable('Invalid daily source response') from exc
        else:value=response.json() # isolated in-memory response fixtures
    finally:
        if callable(getattr(response,'close',None)):response.close()
    if value.get('timed_out') or value.get('_shards',{}).get('failed'):raise PartitionUnavailable('Incomplete daily source query; partition retained',shrink=True)
    if value.get('_shards',{}).get('total')==0:
        # A successful empty search can mean an absent index/layout, not an
        # observed source with zero events. Keep bounded permanent uncertainty
        # while allowing other daily partitions and the live lane to progress.
        debt=copy.deepcopy(state.get('source_debt') or {'first_observed_at':started.isoformat(),'observations':0,'examples':[]})
        debt['last_observed_at']=started.isoformat();debt['observations']+=1
        example={'index':index,'lower':pending['lower'],'upper':pending['upper'],'reason':'No index shards matched; source availability/completeness not established'}
        if len(debt['examples'])<8 and example not in debt['examples']:debt['examples'].append(example)
        debt['latest']=example;state={**state,'source_debt':debt}
    # OpenSearch omits aggregations when no index shards match. Only that
    # explicit response may advance as an empty partition, with debt retained.
    # Malformed responses from an existing index hold the query fence.
    try:
        agg=value['aggregations']['items'];buckets=agg['buckets']
    except (KeyError,TypeError) as exc:
        if value.get('_shards',{}).get('total')==0 and 'aggregations' not in value:
            agg={'buckets':[]};buckets=[]
        else:raise PartitionUnavailable('Missing daily source aggregation; partition retained') from exc
    if not isinstance(buckets,list) or len(buckets)>page_size:raise PartitionUnavailable('Source page admission exceeded',shrink=True)
    for bucket in buckets:apply(bucket)
    after=agg.get('after_key');count=len(buckets)
    if after and buckets:
        if after==pending.get('after'):raise PartitionUnavailable('Source pagination failed to advance')
        pending={**pending,'after':after}
    elif history and upper<ceiling:
        pending={**pending,'lower':upper.isoformat(),'upper':min(upper+dt.timedelta(days=1),ceiling).isoformat(),'after':None}
    else:
        pending=None
    result={**state,'scope':scope,'pending':pending,'status':'partial' if pending else 'complete','last_page_at':started.isoformat(),'page_buckets':count,'page_size':page_size}
    if not history and pending is None and upper<started-dt.timedelta(minutes=10):result['status']='partial'
    if history:
        if pending is None:
            result['cycle_finished_at']=ceiling.isoformat()
            if not result.get('source_debt'):result['completed']=ceiling.isoformat()
    elif pending is None:result['through']=upper.isoformat()
    if result.get('source_debt'):result['status']='partial'
    # Evidence calls can already have committed a bounded unit. A crash before
    # this state write repeats that page; Store's native evidence keys dedupe it.
    store.state(key,result)
    return count

def collect_partitioned(store,cfg,session,enabled,ingest,started,seed):
    if not enabled:
        store.state('native_ingest_coverage',{'status':'complete','lanes':[],'sources_enabled':False,'historical_source_completeness':'not_established_by_index_cursor'})
        return 0
    source_scope=[{'bool':{'filter':[{'term':{'data.edl_source':source}}]+([] if agent=='*' else [{'term':{'agent.name':agent}}])}} for source,agent in enabled.items()]
    filters=[{'bool':{'should':source_scope or [{'match_none':{}}],'minimum_should_match':1}},{'terms':{'rule.id':['119900','119902']}},{'terms':{'data.edl_source':list(enabled)}}]
    comp={'size':500,'sources':[{'ip':{'terms':{'field':'data.srcip'}}},{'source':{'terms':{'field':'data.edl_source'}}},{'detector':{'terms':{'field':'data.edl_detector'}}}]}
    aggregation={'composite':comp,'aggs':{'last':{'top_hits':{'size':1,'sort':[{'data.edl_seen_utc':{'order':'desc','unmapped_type':'keyword'}},{'timestamp':'desc'}],'_source':['data','timestamp','agent']}}}}
    def native(bucket):
        key=bucket['key'];row=bucket['last']['hits']['hits'][0]['_source'];agent=row.get('agent',{}).get('name','')
        if enabled.get(key['source']) in ('*',agent):ingest(store,key,row['data'],row['timestamp'],bucket['doc_count'],cfg)
    tasks=[('native_live',filters,aggregation,native,False),('native_history',filters,aggregation,native,True)]
    if enabled.get('wazuh'):
        excluded=cfg.get('native_excluded_locations',[cfg['palo_location']] if cfg.get('palo_location') else [])
        general_filters=([] if enabled['wazuh']=='*' else [{'term':{'agent.name':enabled['wazuh']}}])+[{'range':{'rule.level':{'gte':8}}},{'exists':{'field':'data.srcip'}},{'bool':{'must_not':[{'terms':{'rule.id':['119900','119902']}},{'terms':{'location':excluded}}]}}]
        general_agg={'composite':{'size':500,'sources':[{'ip':{'terms':{'field':'data.srcip'}}},{'rule':{'terms':{'field':'rule.id'}}}]},'aggs':{'last':{'top_hits':{'size':1,'sort':[{'timestamp':'desc'}],'_source':['timestamp','rule']}}}}
        def general(bucket):
            hit=bucket['last']['hits']['hits'][0];row=hit['_source'];rule=row['rule'];desc=rule.get('description','').lower();groups=rule.get('groups',[])
            auth=any(t in desc for t in ['brute force','authentication failed','login failed','invalid user']) or any('authentication_fail' in g for g in groups)
            attack=any(t in desc for t in ['exploit','malware','sql injection','command injection','web attack','attack detected']);ids=any(g in ['ids','suricata'] for g in groups) and int(rule.get('level',0))>=12
            if any(t in desc for t in ['success','404','not found','400 error','edl','flow event']) or not (attack or ids or auth and bucket['doc_count']>=5):return
            try:store.evidence(bucket['key']['ip'],'wazuh','rule:'+str(rule['id']),row['timestamp'],'authentication' if auth else 'exploit',55 if auth else 75,details={'description':rule.get('description'),'records':bucket['doc_count'],'native_pipeline':'wazuh-qualified-alert-v1','native_qualifying':True,'native_record_id':hit.get('_id',''),'native_rule':{'id':rule['id'],'level':int(rule.get('level',0)),'groups':groups}})
            except ValueError:return
        tasks.append(('general_live',general_filters,general_agg,general,False))
    # Seed every lane from the original shared cursor BEFORE any lane advances.
    # Otherwise an unavailable general source could inherit newer native state
    # on the next pass and silently skip its own older interval.
    for name,*_ in tasks:
        if store.state('ingest_partition_'+name) is None:store.state('ingest_partition_'+name,{'through':seed.get('through'),'status':'partial'})
    processed=0;errors={}
    for name,terms,agg,apply,history in tasks:
        try:processed+=page(store,session,cfg,name,terms,agg,apply,started,seed.get('through'),history=history)
        except (requests.RequestException,PartitionUnavailable) as exc:
            # Preserve the lane checkpoint; publish other already committed
            # sources. Errors remain visible and never masquerade as coverage.
            errors[name]=type(exc).__name__
            if isinstance(exc,requests.Timeout) or getattr(exc,'shrink',False):
                checkpoint=store.state('ingest_partition_'+name) or {};pending=checkpoint.get('pending')
                if pending:
                    store.state('ingest_partition_'+name,{**checkpoint,'pending':{**pending,'page_size':max(1,pending.get('page_size',500)//2)},'status':'partial','last_error':type(exc).__name__})
    live=store.state('ingest_partition_native_live') or {};history=store.state('ingest_partition_native_history') or {}
    if live.get('through') and live.get('last_page_at'):
        store.state('native_ingest_cursor',{**seed,'through':live['through'],'reconciled':history.get('completed',seed.get('reconciled','')),'mode':'bounded_daily_partitions','scope':live['scope'],'overlap_seconds':600})
    store.state('native_ingest_coverage',{'status':'partial' if errors or any((store.state('ingest_partition_'+name) or {}).get('status')!='complete' for name,*_ in tasks) else 'complete','errors':errors,'lanes':[name for name,*_ in tasks],'index_scope':'Native: one UTC daily partition/page; general: fixed <=31 daily partitions/page preserving aggregate qualification; other index layouts not certified','historical_source_completeness':'not_established_by_index_cursor'})
    return processed
