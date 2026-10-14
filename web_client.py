"""Small, bounded HTTP summaries; request bodies and credential headers are ignored."""
import re,urllib.parse,functools

BOTS=[
 ('oai-searchbot','OpenAI','AI search'),('chatgpt-user','OpenAI','AI user fetch'),('gptbot','OpenAI','AI training'),
 ('claude-searchbot','Anthropic','AI search'),('claude-user','Anthropic','AI user fetch'),('claudebot','Anthropic','AI training'),
 ('perplexity-user','Perplexity','AI user fetch'),('perplexitybot','Perplexity','AI search'),
 ('googlebot','Google','Search crawler'),('bingbot','Bing','Search crawler'),('duckduckbot','DuckDuckGo','Search crawler'),('applebot','Apple','Search crawler'),('yandexbot','Yandex','Search crawler'),('baiduspider','Baidu','Search crawler'),
 ('ccbot','Common Crawl','Dataset crawler'),('amazonbot','Amazon','Content crawler'),('meta-externalagent','Meta','AI training'),('meta-externalfetcher','Meta','AI user fetch'),
 ('ahrefsbot','Ahrefs','SEO crawler'),('semrushbot','Semrush','SEO crawler'),('mj12bot','Majestic','SEO crawler'),
 ('uptimerobot','UptimeRobot','Monitoring'),('pingdom','Pingdom','Monitoring'),
 ('shodan','Shodan','Internet scanner'),('censys','Censys','Internet scanner'),('zgrab','ZGrab','Internet scanner'),('masscan','Masscan','Internet scanner'),('nmap','Nmap','Internet scanner'),('nikto','Nikto','Security tool'),('sqlmap','sqlmap','Security tool')]

def client_info(value):
 return dict(_client_info(str(value or '')[:1024]))

@functools.lru_cache(maxsize=4096)
def _client_info(value):
 ua=str(value or '')[:1024];lower=ua.casefold()
 for token,operator,role in BOTS:
  if re.search(r'(?<![a-z0-9])'+re.escape(token)+r'(?![a-z0-9])',lower):return {'client':operator+' / '+token,'operator':operator,'client_type':role,'confidence':'Claimed','platform':''}
 for token,label in [('headlesschrome','Headless Chrome'),('playwright','Playwright'),('puppeteer','Puppeteer'),('selenium','Selenium')]:
  if token in lower:return {'client':label,'client_type':'Browser automation','confidence':'Inferred','platform':''}
 platform=next((label for token,label in [('android','Android'),('iphone','iOS'),('ipad','iPadOS'),('windows','Windows'),('macintosh','macOS'),('linux','Linux')] if token in lower),'')
 for token,label in [('Edg','Edge'),('OPR','Opera'),('Chrome','Chrome'),('Firefox','Firefox')]:
  m=re.search(r'\b'+token+r'/([0-9.]{1,20})',ua,re.I)
  if m:return {'client':label+' '+m.group(1),'client_type':'Browser-like client','confidence':'Inferred','platform':platform}
 if 'safari/' in lower:
  m=re.search(r'Version/([0-9.]{1,20})',ua,re.I)
  return {'client':'Safari'+(' '+m.group(1) if m else ''),'client_type':'Browser-like client','confidence':'Inferred','platform':platform}
 for token,label in [('python-requests','Python requests'),('python-urllib','Python urllib'),('aiohttp','aiohttp'),('httpx','httpx'),('go-http-client','Go HTTP client'),('curl/','curl'),('wget/','Wget'),('okhttp','OkHttp'),('powershell','PowerShell'),('node-fetch','Node fetch'),('apache-httpclient','Apache HTTP client')]:
  if token in lower:return {'client':label,'client_type':'HTTP tool','confidence':'Observed','platform':platform}
 if any(token in lower for token in ['bot','spider','crawler']):return {'client':'Unidentified crawler','client_type':'Unidentified crawler','confidence':'Claimed','platform':platform}
 return {'client':'Unrecognized client' if ua else '', 'client_type':'Unknown','confidence':'Unknown','platform':platform}

def host_name(value):
 value=str(value or '')[:300]
 try:
  p=urllib.parse.urlsplit(value if '://' in value else '//'+value)
  name=p.hostname or ''
  if not re.fullmatch(r'[a-zA-Z0-9_.:\-]+',name):return ''
  port=p.port
  return name.lower()+(':'+str(port) if port else '')
 except ValueError:return ''

def http_details(v):
 req=v.get('request',{}) if isinstance(v.get('request'),dict) else {}
 headers=req.get('headers',v.get('headers',{}));headers=headers if isinstance(headers,dict) else {}
 headers={str(k).casefold():value[0] if isinstance(value,list) and value else value for k,value in headers.items()}
 ua=v.get('user_agent') or v.get('http_user_agent') or v.get('header_user-agent') or headers.get('user-agent')
 info=client_info(ua)
 method=str(v.get('method') or v.get('request_method') or req.get('method') or '').upper()
 if method not in ['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS','CONNECT','TRACE']:method=''
 response=v.get('response',{});response=response if isinstance(response,dict) else {}
 status=v.get('status_code') or v.get('status') or response.get('status') or response.get('status_code')
 try:status=str(int(status)) if 100<=int(status)<=599 else ''
 except (ValueError,TypeError):status=''
 host=host_name(v.get('http_host') or v.get('request_host') or v.get('server_name') or v.get('hostname') or headers.get('host'))
 return {**info,'method':method,'status':status,'host':host}
