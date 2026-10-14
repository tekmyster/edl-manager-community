"""Recorded observation and Manager-policy times; no inferred Palo enforcement time."""
import datetime as dt

LABELS=(('first_seen','First seen UTC'),('last_seen','Last seen UTC'),('block_recorded','Block recorded UTC'),('block_expires','Automatic expiry UTC'))

def attach(store,rows):
 # One bulk read, including rows loaded from an older display-only snapshot.
 with store.connect(commit=False) as d:
  saved={r['ip']:dict(r) for r in d.execute('''SELECT i.ip,i.first_seen,i.last_seen,
   b.first_blocked recorded_block,r.first_blocked retention_block,r.last_seen retention_seen,r.expires
   FROM ips i LEFT JOIN offender_blocks b ON b.ip=i.ip LEFT JOIN block_retention r ON r.ip=i.ip''')}
  # Exact manual selectors can be remembered before the IP has native evidence.
  for r in d.execute('SELECT ip,first_blocked FROM offender_blocks WHERE ip NOT IN (SELECT ip FROM ips)'):
   saved[r['ip']]={'recorded_block':r['first_blocked']}
 result=[]
 for row in rows:
  s=saved.get(row['ip'],{});last=max(s.get('last_seen') or '',s.get('retention_seen') or '')
  result.append({**row,'first_seen':s.get('first_seen') or None,'last_seen':last or None,
   'block_recorded':s.get('retention_block') or s.get('recorded_block') or None,'block_expires':s.get('expires') or None})
 return result

def format_time(value,timezone="UTC"):
 from zoneinfo import ZoneInfo
 if not value:return ''
 try:
  t=dt.datetime.fromisoformat(value)
  if t.tzinfo is None:return str(value)
  zone=dt.timezone.utc if timezone=='UTC' else ZoneInfo(timezone)
  value=t.astimezone(zone).strftime('%Y-%m-%d %H:%M:%S')
  return value if timezone=='UTC' else value+' '+t.astimezone(zone).strftime('%Z %z')
 except (ValueError,TypeError):return str(value)

def columns(formatter=format_time,timezone="UTC"):
 return {k:(label.replace("UTC",timezone),lambda r,k=k:formatter(r.get(k)),lambda r,k=k:r.get(k) or '') for k,label in LABELS}
