"""Sanitize normalized event samples; never retain credentials or URL queries."""
import datetime as dt,ipaddress,urllib.parse
from web_client import http_details
UTC=dt.timezone.utc

def stamp(value):
    try:
        if isinstance(value,(int,float)): return dt.datetime.fromtimestamp(value,UTC)
        s=str(value).replace('Z','+00:00')
        try: v=dt.datetime.fromisoformat(s)
        except ValueError:
            try:v=dt.datetime.strptime(s,'%Y/%m/%d %H:%M:%S')
            except ValueError:v=dt.datetime.strptime(s,'%d/%b/%Y:%H:%M:%S %z')
        return v.replace(tzinfo=UTC) if v.tzinfo is None else v.astimezone(UTC)
    except (ValueError,TypeError,OverflowError,OSError): return None
def public(value):
    try:
        a=ipaddress.ip_address(str(value))
        return str(a) if a.is_global and not a.is_multicast else None
    except ValueError:return None
def activity_event(v,seen=None,event_id=''):
    t=stamp(seen or v.get('@timestamp') or v.get('timestamp'))
    if not t:return None
    dest=v.get('dest_ip') or v.get('dst_ip') or v.get('host_ip') or v.get('server_addr')
    try:
        addr=ipaddress.ip_address(str(dest));dest='' if addr.is_unspecified else str(addr)
    except ValueError:dest=''
    port=v.get('dest_port') or v.get('dst_port') or v.get('host_port') or v.get('server_port')
    try:port=str(int(port)) if 1<=int(port)<=65535 else ''
    except (ValueError,TypeError):port=''
    path=v.get('uri_path') or v.get('request_uri') or v.get('url') or ''
    try:path=urllib.parse.urlsplit(str(path)).path[:200]
    except ValueError:path=''
    return {'id':str(event_id)[:120],'seen':t.isoformat(),'destination':dest,'port':port,'action':str(v.get('eventid') or v.get('event_type') or v.get('action') or v.get('status_code') or v.get('status') or 'connection observed')[:120],'path':path,**http_details(v)}

