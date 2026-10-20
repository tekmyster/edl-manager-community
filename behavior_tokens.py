"""Pinned, ASCII-wire Qwen2 byte-BPE accounting; no model/HTTP/native dependency.

Source JSON is escaped losslessly to ASCII by prompt_json. Other tokenizer or
template families fail closed; metadata is configured data, never bundled keys,
lab inventory, weights or an inferred chars/token estimate.
"""
import functools,hashlib,json,os,pathlib,re,stat,struct

VERSION='qwen2-ascii-bpe-1'
SUPPORTED_TEMPLATES={'eb4402837c7829a690fa845de4d7f3fd842c2adee476d5341da8a46ea9255175'}
PATTERN=re.compile(r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\nA-Za-z0-9]?[A-Za-z]+|[0-9]| ?[^\sA-Za-z0-9]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+",re.ASCII)
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def export(show,name,model_digest,runtime_digest):
 info=show['model_info'];fields={k:v for k,v in info.items() if k.startswith('tokenizer.')}
 return {'version':VERSION,'model':name,'model_digest':model_digest,'runtime_sha256':runtime_digest,'template':show['template'],'template_sha256':hashlib.sha256(show['template'].encode()).hexdigest(),'tokenizer':fields}

class Tokenizer:
 def __init__(self,value):
  self.value=value;t=value['tokenizer'];self.model=value['model']
  if value['version']!=VERSION or t.get('tokenizer.ggml.model')!='gpt2' or t.get('tokenizer.ggml.pre')!='qwen2' or t.get('tokenizer.ggml.add_bos_token') is not False or t.get('tokenizer.ggml.add_eos_token',False) is not False:raise ValueError('Unsupported input verification metadata')
  if hashlib.sha256(value['template'].encode()).hexdigest()!=value['template_sha256'] or value['template_sha256'] not in SUPPORTED_TEMPLATES:raise ValueError('Unsupported input template identity')
  # Only the inspected system/user/no-tools ChatML family is supported. Exact
  # template identity remains part of the operator-pinned metadata hash.
  if '<|im_start|>system' not in value['template'] or '<|im_start|>assistant' not in value['template'] or '{{ .Response }}' not in value['template']:raise ValueError('Unsupported input template')
  tokens=t['tokenizer.ggml.tokens'];types=t['tokenizer.ggml.token_type'];merges=t['tokenizer.ggml.merges']
  if len(tokens)!=len(types) or len(tokens)>300000 or len(merges)>300000:raise ValueError('Invalid tokenizer bounds')
  self.vocab={v:i for i,v in enumerate(tokens)}
  if len(self.vocab)!=len(tokens):raise ValueError('Duplicate tokenizer entry')
  self.ranks={tuple(v.split(' ')):i for i,v in enumerate(merges)}
  if any(len(k)!=2 for k in self.ranks):raise ValueError('Invalid tokenizer merges')
  byte_values=list(range(33,127))+list(range(161,173))+list(range(174,256));chars=byte_values[:];n=0
  for b in range(256):
   if b not in byte_values:byte_values.append(b);chars.append(256+n);n+=1
  self.bytes={b:chr(c) for b,c in zip(byte_values,chars)}
  self.special={v:i for i,(v,kind) in enumerate(zip(tokens,types)) if kind in (3,4)}
  self.special_re=re.compile('|'.join(re.escape(v) for v in sorted(self.special,key=len,reverse=True))) if self.special else None
  self._word=functools.lru_cache(maxsize=8192)(self.word)
 def word(self,text):
  word=tuple(self.bytes[b] for b in text.encode('utf-8'))
  while len(word)>1:
   pair=min(zip(word,word[1:]),key=lambda p:self.ranks.get(p,float('inf')))
   if pair not in self.ranks:break
   merged=[];i=0
   while i<len(word):
    if i+1<len(word) and (word[i],word[i+1])==pair:merged.append(word[i]+word[i+1]);i+=2
    else:merged.append(word[i]);i+=1
   word=tuple(merged)
  return tuple(self.vocab[w] for w in word)
 def ids(self,text):
  if not text.isascii():raise ValueError('Input wire must use lossless ASCII escaping')
  result=[];start=0
  matches=self.special_re.finditer(text) if self.special_re else []
  for m in matches:
   for part in PATTERN.findall(text[start:m.start()]):result.extend(self._word(part))
   result.append(self.special[m.group()]);start=m.end()
  for part in PATTERN.findall(text[start:]):result.extend(self._word(part))
  return result
 def render(self,request):
  if request['model']!=self.model or [v['role'] for v in request['messages']]!=['system','user'] or len(request['messages'])!=2:raise ValueError('Unsupported verified request family')
  a,b=[v['content'] for v in request['messages']]
  return '<|im_start|>system\n'+a+'<|im_end|>\n<|im_start|>user\n'+b+'<|im_end|>\n<|im_start|>assistant\n'
 def check(self,request):
  if request['options']!={'temperature':0,'num_predict':1800,'num_ctx':8192}:raise ValueError('Input verification options mismatch')
  count=len(self.ids(self.render(request)))
  if count+1800+1>8192:raise ValueError('Complete input and output reservation exceed context')
  return {'input_tokens':count,'reserved_output_tokens':1800,'EOS_spare':1,'context_tokens':8192,'tokenizer_version':VERSION}

@functools.lru_cache(maxsize=2)
def cached(path,expected):
 p=pathlib.Path(path)
 if p.is_symlink() or not p.is_file() or p.stat().st_size>12000000:raise ValueError('Invalid input verification file')
 if os.name=='posix' and (p.stat().st_uid!=os.geteuid() or stat.S_IMODE(p.stat().st_mode)&0o022):raise ValueError('Input verification file is writable by another account')
 data=p.read_bytes()
 if hashlib.sha256(data).hexdigest()!=expected:raise ValueError('Input verification identity mismatch')
 return Tokenizer(json.loads(data))

def load(cfg):
 path=cfg.get('tokenizer_file','');expected=cfg.get('tokenizer_sha256','')
 if not path or not re.fullmatch('[a-f0-9]{64}',expected):raise ValueError('Verified input metadata is not configured')
 # Check bytes even on a cache hit: replacement never inherits a trusted parser.
 p=pathlib.Path(path)
 if p.is_symlink() or p.stat().st_size>12000000 or hashlib.sha256(p.read_bytes()).hexdigest()!=expected:raise ValueError('Input verification identity mismatch')
 return cached(str(p.resolve()),expected)
