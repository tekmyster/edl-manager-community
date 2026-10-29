"""Synthetic generation/IO contracts; no live source, production events or network."""
import copy,dataclasses,gzip,hashlib,io,json,os,pathlib,zlib
import pytest
import source_log_reader as r
import receipt_pages as pages


def limits(**kw):return dataclasses.replace(r.InputLimits(),seconds=5,**kw)
def state_for(path,data):
 st=path.stat();return {'inode':st.st_ino,'size':len(data),'mtime':st.st_mtime-10,'offset':len(data)+9000,'anchor':None,'legacy_prefix_unverified':True,'unknown':{'null':None,'all':['retained']},'prefix_reconcile':{'offset':len(data)//3,'through':len(data)+9000,'delivery_offset':len(data)//2,'anchor':r._anchor(path,len(data)//3),'delivery_anchor':r._anchor(path,len(data)//2)},'prior_generations':[{'offset':17,'unknown_prior':None}]}

def pair_fixture(tmp_path,archive_size='grow'):
 current=tmp_path/'audit.log';archive=tmp_path/'audit.log.1'
 old_data=(b'{"id":"old"}\n'*1000);older=(b'{"id":"older"}\n'*({'grow':100,'shrink':2000,'same':0}[archive_size]))
 if archive_size=='same':older=b'Y'*(len(old_data)-1)+b'\n'
 current.write_bytes(old_data);archive.write_bytes(older);old={str(p):state_for(p,d) for p,d in ((current,old_data),(archive,older))}
 archive.write_bytes(old_data);current.write_bytes(b'{"id":"new"}\n')
 return current,archive,old,old_data

def run(current,archive,files,seen,**kw):
 paths=kw.pop('paths',[current,archive]);bound=kw.pop('limits',limits());pairs=kw.pop('rotation_pairs',(r.RotationPair(current,archive),))
 out=r.collect_log_inputs(paths,files,lambda p,line:seen.append((str(p),line)),cutoff=0,limits=bound,rotation_pairs=pairs,**kw)
 if out.get('generation_transitions'):
  transitions=out['generation_transitions']
  out=r.collect_log_inputs(paths,files,lambda p,line:seen.append((str(p),line)),cutoff=0,limits=bound,rotation_pairs=pairs,**kw)
  out['generation_transitions']=transitions
 return out

@pytest.mark.parametrize('archive_size',['grow','shrink','same'])
def test_explicit_pair_retains_whole_old_objects_and_reads_both_from_zero(tmp_path,archive_size):
 a,b,files,data=pair_fixture(tmp_path,archive_size);before=copy.deepcopy(files);seen=[]
 out=run(a,b,files,seen)
 assert out['generation_transitions'] and out['status']=='partial'
 assert seen==[(str(a),'{"id":"new"}\n')]+[(str(b),'{"id":"old"}\n')]*1000
 for p in (a,b):
  assert files[str(p)]['prior_generations']==[before[str(p)]]
  assert files[str(p)]['generation_origin']['historical_equivalence_verified'] is False
  assert files[str(p)]['offset']==p.stat().st_size
 assert len([x for x in pages.lanes(files) if x.get('unknown_prior') is None and 'unknown_prior' in x])==2
 reloaded=json.loads(json.dumps(files));second=[];run(a,b,reloaded,second)
 assert not second and reloaded==files


def test_no_explicit_policy_preserves_changed_prefix_and_all_cursors(tmp_path):
 a,b,files,data=pair_fixture(tmp_path);before=copy.deepcopy(files);seen=[]
 out=run(a,b,files,seen,rotation_pairs=())
 assert not seen and files==before and out['status']=='partial'


def test_unexpected_same_size_edit_is_not_rotation_even_with_policy(tmp_path):
 a,b,files,data=pair_fixture(tmp_path);a.write_bytes(b'Z'*(len(data)-1)+b'\n');before=copy.deepcopy(files);seen=[]
 run(a,b,files,seen)
 assert not seen and files==before


def test_matching_boundary_anchors_do_not_skip_changed_interior(tmp_path):
 a,b,files,data=pair_fixture(tmp_path)
 # A gap between head and both tails remains outside the boundary proof.
 old=b.read_bytes();changed=old[:9000]+old[9000:].replace(b'old',b'NEW',1);b.write_bytes(changed)
 for anchor in r._rotation_anchors(files[str(a)]):assert r._anchor(b,anchor['offset'])==anchor
 seen=[];out=run(a,b,files,seen)
 assert out['generation_transitions'] and b'{"id":"NEW"}' in ''.join(line for p,line in seen if p==str(b)).encode()
 assert seen[1][1]=='{"id":"old"}\n' and files[str(a)]['prior_generations'][0]['offset']>len(data)


def test_ambiguous_matching_archives_hold_pair_without_callbacks(tmp_path):
 a,b,files,data=pair_fixture(tmp_path);extra=tmp_path/'audit.log.2';extra.write_bytes(data);before=copy.deepcopy(files);seen=[]
 out=run(a,b,files,seen,paths=[a,b,extra])
 assert files[str(a)]==before[str(a)] and files[str(b)]==before[str(b)]
 assert not any(p in (str(a),str(b)) for p,line in seen)
 assert any('ambiguous' in x['reason'] for x in out['deferred'])

@pytest.mark.parametrize('field',['size','mtime','inode'])
def test_missing_or_null_generation_metadata_is_not_coerced(tmp_path,field):
 a,b,files,data=pair_fixture(tmp_path);files[str(a)][field]=None;before=copy.deepcopy(files);seen=[]
 out=run(a,b,files,seen)
 assert not seen and files==before and out['status']=='partial'


def test_lineage_bound_is_enforced_without_dropping_nested_history(tmp_path):
 a,b,files,data=pair_fixture(tmp_path);history=[{'offset':7,'unknown':i} for i in range(64)]
 files[str(a)]['prior_generations']=history;before=copy.deepcopy(files);seen=[]
 out=run(a,b,files,seen);assert not seen and files==before
 assert any('bound' in x['reason'] for x in out['deferred'])

@pytest.mark.parametrize('phase',['association','after_capture','callback'])
def test_source_mutation_cannot_commit_half_pair(tmp_path,monkeypatch,phase):
 a,b,files,data=pair_fixture(tmp_path);before=copy.deepcopy(files);seen=[]
 if phase=='association':
  original=r._rotation_anchor;changed=False
  def mutate(path,offset,admission):
   nonlocal changed
   value=original(path,offset,admission)
   if path==b and not changed:b.write_bytes(data+b'changed');changed=True
   return value
  monkeypatch.setattr(r,'_rotation_anchor',mutate)
 elif phase=='after_capture':
  original=r._collect_bounded
  def mutate(*args,**kw):
   value=original(*args,**kw);a.write_bytes(b'{"id":"rewrite"}\n');return value
  monkeypatch.setattr(r,'_collect_bounded',mutate)
 if phase=='callback':
  r.collect_log_inputs([a,b],files,lambda *_:pytest.fail('Association callback'),cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
  before=copy.deepcopy(files)
  def consume(p,line):a.write_bytes(b'{"id":"rewrite"}\n')
  with pytest.raises((pages.ReceiptPageError,r.DeferredInput)):r.collect_log_inputs([a,b],files,consume,cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
 elif phase=='after_capture':
  r.collect_log_inputs([a,b],files,lambda *_:pytest.fail('Association callback'),cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
  before=copy.deepcopy(files)
  with pytest.raises(r.DeferredInput):run(a,b,files,seen)
 else:run(a,b,files,seen)
 assert files==before
 if phase=='association':assert not seen


def test_callback_failure_and_state_reload_retries_same_generation_lineage(tmp_path):
 a,b,files,data=pair_fixture(tmp_path);before=copy.deepcopy(files)
 def fail(*args):raise RuntimeError('synthetic aggregation fault')
 r.collect_log_inputs([a,b],files,lambda *_:pytest.fail('Association callback'),cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
 before=copy.deepcopy(files)
 with pytest.raises(RuntimeError):r.collect_log_inputs([a,b],files,fail,cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
 assert files==before
 first=[];run(a,b,files,first);lineages=[files[str(p)]['generation_origin']['lineage'] for p in (a,b)]
 retry=copy.deepcopy(before);again=[];run(a,b,retry,again)
 assert first==again and lineages==[retry[str(p)]['generation_origin']['lineage'] for p in (a,b)]


def test_new_pending_and_paged_receipts_have_actual_identity_and_old_fields_survive(tmp_path):
 from test_receipt_pages import receipts_for
 a=tmp_path/'audit.log';b=tmp_path/'audit.log.1';data=b'x'*160+b'\n'
 old={}
 for p in (a,b):
  p.write_bytes(data*64);lane=receipts_for(p);lane['prefix_reconcile']=copy.deepcopy(lane);lane['unknown']={'missing':None};old[str(p)]=lane
 # The pair's source anchors need distinct old data; rewrite archive's historical lane synthetically.
 b.write_bytes(b'Y'*20000);old[str(b)]=state_for(b,b'Y'*20000)
 a.write_bytes(data*64);old[str(a)].update(state_for(a,data*64));old[str(a)]['prefix_reconcile']['record_debt']=copy.deepcopy(old[str(a)]['record_debt'])
 before=copy.deepcopy(old);b.write_bytes(data*64);a.write_bytes(b'Q'*300+b'\n'+b'{"id":"current"}\n');seen=[];store=pages.ReceiptPages(tmp_path/'pages')
 out=run(a,b,old,seen,receipt_store=store,limits=limits(record_bytes=128,file_bytes=65536,input_bytes=131072))
 assert out.get('generation_transitions')
 assert old[str(a)]['prior_generations']==[before[str(a)]]
 assert old[str(a)]['record_debt'][0]['source']['inode']==a.stat().st_ino
 assert len(old[str(b)]['record_debt'])==64
 assert old[str(a)]['offset']==0 and old[str(a)]['delivery_offset']==a.stat().st_size
 assert out['unresolved_record_references']>=193

class TrackedRaw:
 def __init__(self,raw,tracker):self.raw=raw;self.tracker=tracker
 def read(self,n=-1):
  assert n>=0
  if self.tracker['budget'] is not None:assert n<=self.tracker['budget']-self.tracker['raw']-self.tracker['expanded']
  self.tracker['requests'].append(n);data=self.raw.read(n);self.tracker['raw']+=len(data);return data
 def __getattr__(self,n):return getattr(self.raw,n)
 def __enter__(self):self.raw.__enter__();return self
 def __exit__(self,*a):return self.raw.__exit__(*a)

def trace_io(monkeypatch,budget=None,expanded_cap=None):
 tracker={'raw':0,'expanded':0,'requests':[],'outputs':[],'budget':budget};opened=pathlib.Path.open;decompressobj=zlib.decompressobj
 def tracked_open(p,*a,**kw):
  raw=opened(p,*a,**kw)
  return TrackedRaw(raw,tracker) if p.suffix=='.gz' and a and a[0]=='rb' else raw
 class Decoder:
  def __init__(self,*a,**kw):self.obj=decompressobj(*a,**kw)
  def decompress(self,data,maximum):
   assert maximum>0
   if budget is not None:assert maximum<=budget-tracker['raw']-tracker['expanded']
   if expanded_cap is not None:assert maximum<=expanded_cap-tracker['expanded']
   out=self.obj.decompress(data,maximum);assert len(out)<=maximum;tracker['expanded']+=len(out);tracker['outputs'].append((maximum,len(out)));return out
  def __getattr__(self,n):return getattr(self.obj,n)
 monkeypatch.setattr(pathlib.Path,'open',tracked_open);monkeypatch.setattr(zlib,'decompressobj',Decoder);return tracker

@pytest.mark.parametrize('budget',[16,30,35,45,78,100])
def test_multi_archive_actual_IO_never_exceeds_shared_validation_allowance(tmp_path,monkeypatch,budget):
 paths=[]
 for i in range(3):
  p=tmp_path/(str(i)+'.gz');p.write_bytes(gzip.compress(b'{"id":1}\n'));paths.append(p)
 tracker=trace_io(monkeypatch,budget);state={};seen=[]
 out=r.collect_log_inputs(paths,state,lambda p,line:seen.append(line),cutoff=0,limits=limits(validation_bytes=budget))
 assert tracker['raw']+tracker['expanded']==out['validation_bytes']<=budget
 assert tracker['raw']<=sum(p.stat().st_size for p in paths)
 if budget<paths[0].stat().st_size:assert not tracker['requests'] and not seen and state=={}

@pytest.mark.parametrize('damage',['crc','truncated','concatenated_bad','overflow'])
def test_full_validation_before_callbacks_and_exact_prior_state(tmp_path,monkeypatch,damage):
 p=tmp_path/'archive.gz';raw=gzip.compress(b'{"id":1}\n')
 if damage=='crc':raw=raw[:-8]+bytes([raw[-8]^1])+raw[-7:]
 if damage=='truncated':raw=raw[:-1]
 if damage=='concatenated_bad':raw+=gzip.compress(b'{"id":2}\n')[:-2]
 if damage=='overflow':raw=gzip.compress(b'x'*1000)
 p.write_bytes(raw);prior={'inode':p.stat().st_ino,'offset':17,'mtime':1,'unknown':None};files={str(p):prior.copy()};seen=[];tracker=trace_io(monkeypatch)
 out=r.collect_log_inputs([p],files,lambda *a:seen.append(a),cutoff=0,limits=limits(expanded_bytes=128,validation_bytes=len(raw)+128))
 assert not seen and files[str(p)]==prior and out['status']=='partial'
 assert tracker['raw']+tracker['expanded']==out['validation_bytes']<=len(raw)+128

@pytest.mark.parametrize('delta',[-1,0,1])
def test_exact_expansion_boundary_and_validation_boundary(tmp_path,monkeypatch,delta):
 p=tmp_path/'archive.gz';payload=b'{"id":1}\n';raw=gzip.compress(payload);p.write_bytes(raw);files={};seen=[]
 budget=len(raw)+len(payload)+delta;tracker=trace_io(monkeypatch,budget,len(payload))
 out=r.collect_log_inputs([p],files,lambda p,line:seen.append(line),cutoff=0,limits=limits(expanded_bytes=len(payload),validation_bytes=budget))
 assert out['validation_bytes']==tracker['raw']+tracker['expanded']<=budget
 assert bool(seen)==(delta>=0)
 if delta<0:assert files=={}


@pytest.mark.parametrize('point',['after_stage_create','after_publish_link','before_reference_return'])
def test_pair_crash_keeps_original_state_and_reuses_immutable_page_orphans(tmp_path,point):
 a=tmp_path/'audit.log';b=tmp_path/'audit.log.1';data=(b'x'*160+b'\n')*80+b'{"id":"retained"}\n'
 a.write_bytes(data);b.write_bytes(b'Y'*30000)
 files={str(p):state_for(p,p.read_bytes()) for p in (a,b)};before=copy.deepcopy(files)
 b.write_bytes(data);a.write_bytes(b'{"id":"current"}\n');seen=[];fired=False
 def fault(where):
  nonlocal fired
  if where==point and not fired:fired=True;raise RuntimeError('synthetic paired crash')
 r.collect_log_inputs([a,b],files,lambda *_:pytest.fail('Association callback'),cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
 historical=before;before=copy.deepcopy(files)
 store=pages.ReceiptPages(tmp_path/'pages',_fault=fault)
 with pytest.raises(RuntimeError):run(a,b,files,seen,receipt_store=store,limits=limits(record_bytes=128,file_bytes=65536,input_bytes=131072))
 assert files==before and fired
 seen=[]
 orphan_names={p.name for p in (tmp_path/'pages').iterdir()};seen=[]
 out=run(a,b,files,seen,receipt_store=pages.ReceiptPages(tmp_path/'pages'),limits=limits(record_bytes=128,file_bytes=65536,input_bytes=131072))
 assert {p for p,line in seen}=={str(a),str(b)}
 assert files[str(a)]['prior_generations']==[historical[str(a)]] and files[str(b)]['prior_generations']==[historical[str(b)]]
 assert orphan_names<={p.name for p in (tmp_path/'pages').iterdir()}
 with pages.ReceiptPages(tmp_path/'pages').invocation(lambda:None) as store:
  store.verify_files(files);ref=files[str(b)]['record_debt_pages'];receipts=[v for item in ref['manifest'] for v in store.read(item['hash'])[0]['receipts']]+files[str(b)]['record_debt']
  assert len(receipts)==80 and all(x['source']['inode']==b.stat().st_ino for x in receipts)
  assert store.total<=128*1024**2 and len(store.entries)<=512


def test_append_only_current_growth_after_pair_capture_is_next_pass_work(tmp_path,monkeypatch):
 a,b,files,data=pair_fixture(tmp_path);original=r._collect_bounded
 def append(*args,**kw):
  result=original(*args,**kw)
  with a.open('ab') as f:f.write(b'{"id":"appended"}\n')
  return result
 monkeypatch.setattr(r,'_collect_bounded',append);seen=[];out=run(a,b,files,seen)
 assert out['generation_transitions'] and not any('appended' in line for p,line in seen)
 monkeypatch.setattr(r,'_collect_bounded',original);later=[];run(a,b,files,later)
 assert later==[(str(a),'{"id":"appended"}\n')]


def test_page_or_source_inventory_bound_holds_before_association_io(tmp_path,monkeypatch):
 a,b,files,data=pair_fixture(tmp_path);before=copy.deepcopy(files)
 monkeypatch.setattr(r,'_rotation_anchor',lambda *a:pytest.fail('Oversized inventory performed association IO'))
 with pytest.raises(ValueError):run(a,b,files,[],paths=[a,b,tmp_path/'extra'],limits=limits(files=2))
 assert files==before


@pytest.mark.parametrize('growth',[False,True])
def test_callback_rewrite_outside_head_is_not_hidden_by_append_growth(tmp_path,growth):
 a,b,files,data=pair_fixture(tmp_path);a.write_bytes(b'{"id":"new"}\n'*600)
 r.collect_log_inputs([a,b],files,lambda *_:pytest.fail('Association callback'),cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
 before=copy.deepcopy(files);fired=False
 def mutate(path,line):
  nonlocal fired
  if fired:return
  fired=True;body=a.read_bytes();body=body[:6000]+body[6000:].replace(b'new',b'BAD',1)
  if growth:body+=b'{"id":"tail"}\n'
  a.write_bytes(body)
 with pytest.raises((pages.ReceiptPageError,r.DeferredInput)):r.collect_log_inputs([a,b],files,mutate,cutoff=0,limits=limits(),rotation_pairs=(r.RotationPair(a,b),))
 assert files==before


def test_gzip_optional_headers_members_padding_and_crc_are_fully_validated(tmp_path,monkeypatch):
 import struct
 payload=b'{"id":7}\n';base=gzip.compress(payload);header=b'\x1f\x8b\x08\x1e'+b'\0'*6+struct.pack('<H',3)+b'ext'+b'name\0comment\0';header+=struct.pack('<H',zlib.crc32(header)&0xffff)
 p=tmp_path/'archive.gz';p.write_bytes(header+base[10:]+gzip.compress(b'{"id":8}\n')+b'\0'*4);seen=[];files={};tracker=trace_io(monkeypatch)
 out=r.collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)),cutoff=0,limits=limits())
 assert seen==[{'id':7},{'id':8}] and out['status']=='complete'
 assert out['validation_bytes']==tracker['raw']+tracker['expanded']


def test_invalid_deflate_retires_pre_admitted_output_allowance_before_next_archive(tmp_path,monkeypatch):
 p=tmp_path/'0.gz';p.write_bytes(b'\x1f\x8b\x08'+b'\0'*7+b'\x07'+b'\0'*8);q=tmp_path/'1.gz';q.write_bytes(gzip.compress(b'{"id":1}\n'));seen=[];tracker=trace_io(monkeypatch,100)
 out=r.collect_log_inputs([p,q],{},lambda p,line:seen.append(line),cutoff=0,limits=limits(validation_bytes=100))
 assert not seen and out['validation_bytes']<=100 and out['validation_error_reserved_bytes']>0
 assert out['validation_bytes']==tracker['raw']+tracker['expanded']+out['validation_error_reserved_bytes']
 assert tracker['raw']==p.stat().st_size



def test_old_pending_is_preserved_while_new_generation_pending_finishes_before_No(tmp_path):
 a,b,files,data=pair_fixture(tmp_path);prefix=files[str(a)]['prefix_reconcile'];start,end=prefix['offset'],prefix['delivery_offset'];digest=hashlib.sha256(data[start:end]).hexdigest();chain=hashlib.sha256(hashlib.sha256(b'').digest()+str(start).encode()+b':'+str(end).encode()+b':'+bytes.fromhex(digest)).hexdigest()
 prefix['opaque_pending']={'start':start,'through':end,'source':{'device':a.stat().st_dev,'inode':a.stat().st_ino,'size':len(data),'mtime_ns':int(files[str(a)]['mtime']*1e9),'ctime_ns':int(files[str(a)]['mtime']*1e9),'offset_space':'source_bytes','unknown':None},'segments':[{'start':start,'end':end,'sha256':digest}],'chain_sha256':chain,'status':'unresolved_record','boundary_verified':False,'unknown_pending':['keep',None]}
 before=copy.deepcopy(files);a.write_bytes(b'Q'*700);seen=[];bound=limits(record_bytes=64,file_bytes=256,input_bytes=512)
 out=run(a,b,files,seen,limits=bound);assert out['generation_transitions'] and files[str(a)]['opaque_pending']['through']>0
 assert files[str(a)]['prior_generations']==[before[str(a)]]
 for i in range(30):run(a,b,files,seen,limits=bound)
 assert files[str(a)]['opaque_pending']['through']==700 and not any(p==str(a) for p,line in seen)
 with a.open('ab') as f:f.write(b'\n{"id":"later-No"}\n')
 for i in range(30):run(a,b,files,seen,limits=bound)
 assert [json.loads(line) for p,line in seen if p==str(a)]==[{'id':'later-No'}]
 assert 'opaque_pending' not in files[str(a)] and len(files[str(a)]['record_debt'])==1
 debt=files[str(a)]['record_debt'][0];assert debt['boundary_verified'] and debt['end']==701 and len(debt['segments'])>=4
 assert files[str(a)]['prior_generations'][0]['prefix_reconcile']['opaque_pending']==before[str(a)]['prefix_reconcile']['opaque_pending']


def test_63_existing_generations_can_transition_once_then_hold_at64(tmp_path):
 a,b,files,data=pair_fixture(tmp_path)
 for p in (a,b):files[str(p)]['prior_generations']=[{'offset':i,'unknown':None} for i in range(63)]
 before=copy.deepcopy(files);seen=[];out=run(a,b,files,seen);assert out['generation_transitions']
 for p in (a,b):assert files[str(p)]['prior_generations']==[before[str(p)]]
 prior=copy.deepcopy(files);b.write_bytes(a.read_bytes());a.write_bytes(b'');seen=[];out=run(a,b,files,seen)
 assert not seen and files==prior and any('bound' in x['reason'] for x in out['deferred'])
