"""Authenticated UI read models; operational counts are never truth labels."""
import datetime as dt
import json
import math
import sqlite3
from collections import Counter
from zoneinfo import ZoneInfo
from analytics_store import connect, stamp, path

UTC=dt.timezone.utc


def parse(value):
    try:
        v=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
        return v.astimezone(UTC) if v.tzinfo else None
    except (ValueError,TypeError,AttributeError): return None


def mean(values):
    valid=[v for v in values if type(v) in (int,float) and math.isfinite(v) and v>=0]
    return round(sum(valid)/len(valid),3) if valid else None


def summary(brain, timezone='UTC', at=None):
    at=(at or dt.datetime.now(UTC)).astimezone(UTC)
    zone=UTC if timezone=='UTC' else ZoneInfo(timezone)
    hour=at.astimezone(zone).replace(minute=0,second=0,microsecond=0).astimezone(UTC)
    midnight=at.astimezone(zone).replace(hour=0,minute=0,second=0,microsecond=0).astimezone(UTC)
    # Fixed UTC hourly buckets keep provider aggregates and all plots aligned,
    # including display zones with half-hour/quarter-hour offsets.
    start=at.replace(minute=0,second=0,microsecond=0)-dt.timedelta(hours=23)
    bins=[dict(start=stamp(start+dt.timedelta(hours=i)),end=stamp(min(start+dt.timedelta(hours=i+1),at)),requests=0,input=0,output=0,token_reports=0,unknown_tokens=0,first=[],accepted=0,rejected=0,failed=0,pending=0) for i in range(24)]
    coverage={};attempts=[];counters=[];unique_ips={};error=False
    try:
        with connect(brain.store) as db:
            coverage={r['name']:r['started'] for r in db.execute("SELECT * FROM coverage WHERE name!='pruned'")}
            attempts=[dict(r) for r in db.execute('SELECT * FROM requests WHERE (started>=? OR finished>=?) AND started<? ORDER BY started DESC',(stamp(min(start,midnight)),stamp(min(start,midnight)),stamp(at)))]
            bounds=(stamp(start),stamp(at))
            counters=[dict(r) for r in db.execute('SELECT hour,provider,kind,sum(n) n,max(last) last FROM counters WHERE hour>=? AND hour<? GROUP BY hour,provider,kind',bounds)]
            for r in db.execute("SELECT provider,count(distinct nullif(ip,'')) touched,count(distinct CASE WHEN kind='outbound' THEN nullif(ip,'') END) outbound,count(distinct CASE WHEN kind='usable' THEN nullif(ip,'') END) usable,count(distinct CASE WHEN kind='local_query' THEN nullif(ip,'') END) local_query FROM counters WHERE hour>=? AND hour<? GROUP BY provider",bounds):unique_ips[r['provider']]=dict(r)
    except (sqlite3.Error,OSError): error=path(brain.store).exists()
    for r in attempts:
        if r['finished'] and parse(r['finished'])>=at:
            r.update(finished=None,state='pending',first_seconds=None,input_tokens=None,output_tokens=None,total_seconds=None)
    def bucket(when):
        t=parse(when)
        i=int((t-start).total_seconds()//3600) if t else -1
        return bins[i] if 0<=i<24 and t<at else None
    for r in attempts:
        b=bucket(r['started'])
        if b is not None:
            b['requests']+=1;b[r['state'] if r['state'] in ('accepted','rejected','failed') else 'pending']+=1
            if r['first_seconds'] is not None:b['first'].append(r['first_seconds'])
    # Tokens are counted once per completed transport, including rejected output.
    # Legacy assessment metadata uses its recorded completion, with no invented start.
    token_records=[];historical=0
    with brain.connect() as db:
        rows=db.execute('SELECT packet_id,created,status,result FROM assessments WHERE created>=? AND created<?',(stamp(min(start,midnight)),stamp(at))).fetchall()
        cached=db.execute("SELECT coalesce(sum(count),0) FROM analysis_counters WHERE kind='cached' AND hour>=? AND hour<?",(stamp(start),stamp(at))).fetchone()[0]
        publications=db.execute('SELECT * FROM publication_samples WHERE created>=? AND created<? ORDER BY created',(stamp(start),stamp(at))).fetchall()
    classifications=Counter()
    # New assessments carry request timing. They are already represented by ledger.
    ledger_ids={r['id'] for r in attempts}
    for r in rows:
        result=json.loads(r['result']);v=result.get('metadata',{})
        if r['status']=='completed' and parse(r['created'])>=start:classifications[result.get('classification','unknown')]+=1
        if v.get('request_id') in ledger_ids:continue
        historical+=1
        token_records.append((r['created'],v.get('input_tokens'),v.get('output_tokens')))
    token_records += [(r['finished'],r['input_tokens'],r['output_tokens']) for r in attempts if r['finished']]
    day_input=day_output=day_known=day_unknown=0
    for when,inp,out in token_records:
        known=all(type(n) is int and n>=0 for n in (inp,out))
        b=bucket(when)
        if b is not None:
            if known:b['input']+=inp;b['output']+=out;b['token_reports']+=1
            else:b['unknown_tokens']+=1
        if parse(when) and midnight<=parse(when)<at:
            if known:day_input+=inp;day_output+=out;day_known+=1
            else:day_unknown+=1
    for b in bins:
        b['first_samples']=len(b['first']);b['first_seconds']=mean(b.pop('first'))
        b['tokens']=b['input']+b['output']
        b['covered']=bool(coverage.get('ai') and parse(b['start'])>=parse(coverage['ai']))
        b['label']=parse(b['start']).astimezone(zone).strftime('%H:%M %z')
        saved=[r for r in publications if parse(b['start'])<=parse(r['created'])<parse(b['end'])]
        b.update(points=saved[-1]['points'] if saved else None,blocks=saved[-1]['blocks'] if saved else None,publication_samples=len(saved))
    current=[r for r in attempts if parse(r['started'])>=hour]
    measured=[r['first_seconds'] for r in attempts if parse(r['started'])>=midnight and r['first_seconds'] is not None]
    providers=[]
    for provider in ('greynoise','misp','asn','crawler','abuseipdb','virustotal'):
        own=[r for r in counters if r['provider']==provider]
        kinds=Counter()
        for r in own:kinds[r['kind']]+=r['n']
        reads=sum(kinds[k] for k in ('hit','negative_hit','miss','stale','cached_error'))
        hits=kinds['hit']+kinds['negative_hit']
        timeline=[]
        for b in bins:
            hour_counts=Counter()
            for r in own:
                if parse(b['start'])<=parse(r['hour'])<parse(b['end']):hour_counts[r['kind']]+=r['n']
            hits=hour_counts['hit']+hour_counts['negative_hit'];misses=hour_counts['miss']+hour_counts['stale']+hour_counts['cached_error']
            timeline.append(dict(start=b['start'],label=b['label'],hits=hits,misses=misses,total=hits+misses,outbound=hour_counts['outbound']))
        unique=lambda kind:unique_ips.get(provider,{}).get(kind,0)
        providers.append(dict(name=provider,started=coverage.get(provider),outbound_started=coverage.get(provider+':outbound'),local_started=coverage.get(provider+':local_query'),outcome_started=any(coverage.get(provider+':'+k) for k in ('usable','no_data','error','rate_limited')),counts=dict(kinds),reads=reads,hits=hits,hit_ratio=round(100*hits/reads,1) if reads else None,unique_ips=unique('touched'),unique_outbound=unique('outbound'),unique_usable=unique('usable'),unique_local=unique('local_query'),last=max((r['last'] for r in own),default=None),timeline=timeline))
    def ceiling(v):
        if not v:return 2
        step=max(1,10**math.floor(math.log10(v)))
        return math.ceil(v/step/2)*step*2
    peaks={key:ceiling(max((b[key] or 0) for b in bins)) for key in ('requests','tokens','first_seconds','points','blocks')}
    cache_snapshot=[]
    with brain.store.connect() as db:
        for provider in ('greynoise','misp'):
            saved=db.execute('SELECT status,expires,fetched,payload FROM cache WHERE provider=?',(provider,)).fetchall()
            fresh=[r for r in saved if parse(r['expires']) and parse(r['expires'])>at and r['status']=='ok']
            payloads=[json.loads(r['payload']) for r in fresh]
            matched=sum(v.get('found') is True for v in payloads) if provider=='greynoise' else sum(v.get('matches',0)+v.get('context_matches',0)>0 for v in payloads)
            indicators={str(i) for v in payloads for i in v.get('attribute_ids',[]) if isinstance(i,(str,int))}
            cache_snapshot.append(dict(provider=provider,entries=len(saved),fresh=len(fresh),stale=sum(bool(parse(r['expires']) and parse(r['expires'])<=at) for r in saved),matched=matched,indicator_ids=len(indicators),latest=max((r['fetched'] for r in saved),default=None)))
    return dict(start=stamp(start),end=stamp(at),day_start=stamp(midnight),hour_start=stamp(hour),timezone=timezone,bins=bins,peaks=peaks,cache_snapshot=cache_snapshot,classifications=dict(classifications),
                day_input=day_input,day_output=day_output,day_tokens=day_input+day_output,day_known=day_known,day_unknown=day_unknown,
                first_seconds=mean(measured),first_samples=len(measured),day_attempts=sum(parse(r['started'])>=midnight for r in attempts),
                hour_requests=len(current),hour_outcomes=dict(Counter(r['state'] for r in current)),coverage=coverage,error=error,
                requests=sum(start<=parse(r['started'])<at for r in attempts),outcomes=dict(Counter(r['state'] for r in attempts if start<=parse(r['started'])<at)),cached=cached,historical_completions=historical,
                providers=providers,recent=attempts[:30])


def investigations(brain, start, end):
    """Saved evidence cohorts: deduplicate observation IDs across packet rebuilds."""
    start,end=parse(start),parse(end)
    kinds=Counter();states=Counter();features=Counter();seen=set();unknown=0;events=0;timeline={}
    with brain.connect() as db:
        alerts=[dict(r) for r in db.execute('SELECT * FROM intelligence_alerts WHERE last_seen>=? AND first_seen<? ORDER BY last_seen DESC LIMIT 101',(stamp(start),stamp(end)))]
        # A bounded recent cohort, prominently disclosed; never population totals.
        packets=db.execute('SELECT id,content FROM packets WHERE created>=? AND created<? ORDER BY created DESC LIMIT 501',(stamp(start),stamp(end))).fetchall()
        for row in packets[:500]:
            packet=json.loads(row['content'])
            for event in packet.get('events',[]):
                t=parse(event.get('seen'))
                if not event.get('id') or event['id'] in seen or not t or not start<=t<end:continue
                seen.add(event['id']);events+=1
                value=event.get('client_type') or 'Unknown'
                features[value]+=1;unknown+=value=='Unknown'
                h=t.replace(minute=0,second=0,microsecond=0).isoformat()
                timeline.setdefault(h,Counter())[value]+=1
        for r in alerts[:100]:kinds[r['kind']]+=1;states[r['state']]+=1
        total=db.execute('SELECT count(*) FROM intelligence_alerts WHERE last_seen>=? AND first_seen<?',(stamp(start),stamp(end))).fetchone()[0]
    from behavior_evaluation import report
    activity=[];client_timeline=[]
    for i in range(24):
        lo=start+dt.timedelta(hours=i);hi=min(lo+dt.timedelta(hours=1),end)
        counts=Counter(a['kind'] for a in alerts[:100] if lo<=parse(a['last_seen'])<hi)
        activity.append(dict(start=stamp(lo),total=sum(counts.values()),**counts))
        matches=Counter()
        for when,counts in timeline.items():
            if lo<=parse(when)<hi:matches.update(counts)
        client_timeline.append(dict(start=stamp(lo),total=sum(matches.values()),classified=sum(v for k,v in matches.items() if k!='Unknown'),unknown=matches['Unknown']))
    return dict(alerts=alerts[:100],kinds=dict(kinds),states=dict(states),total=total,limited=total>100,features=features.most_common(),events=events,unknown=unknown,packets=min(500,len(packets)),packets_limited=len(packets)>500,evaluation=report(brain),activity_timeline=activity,feature_timeline=client_timeline)
