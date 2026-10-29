"""Exact old JSON bytes and bounded commit boundaries; synthetic local data only."""
import hashlib,json,os,pathlib
import pytest
import edge_transaction as tx
import source_log_reader as reader


def setup(tmp_path,state):
 root=tmp_path/'state';root.mkdir();saved=root/'edge.json';saved.write_text('{"files":{},"prior":true}')
 output=tmp_path/'output.jsonl';output.write_bytes(b'{"edl_event_id":"prior"}\n')
 guard=reader.GenerationCommitGuard();guard.arm([],reader._Admission(reader.InputLimits(seconds=20)))
 transaction=tx.EdgeTransaction(saved,output,guard)
 payload=b'{"edl_event_id":"synthetic-No","edl_qualifying":"no"}\n'
 with transaction.open_output() as stage:stage.write(payload.decode());stage.flush();os.fsync(stage.fileno())
 return transaction,saved,output,payload


STATES=[{'files':{},'null':None,'unknown':{'keep':[True,False,None]}},
 {'files':{},'unicode':'ASCII é 中 U0001f642 \ud800','escape':'quote" slash\\\n\t'},
 {'files':{},'legacy':{'whole_cursor':{'offset':11567760973,'inode':5794491,'unknown':None},'opaque_receipts':[{'start':i,'unknown':{'null':None,'values':['same',i]}} for i in range(128)]}},
 {'files':{},'numbers':[0,-0.0,1e-20,1e20,float('inf'),float('-inf'),float('nan')]},
 {'files':{},'unknown_keys':{1:'integer',None:'null',2.5:'float','s':'string'}},
 {'files':{},'nested':[{'unknown':(i,None,'ö')} for i in range(1000)]}]


@pytest.mark.parametrize('state',STATES,ids=['null-unknown','unicode-surrogate','legacy-128','numbers','key-semantics','nested'])
def test_fast_encoder_matches_exact_old_default_bytes(tmp_path,state):
 expected=''.join(json.JSONEncoder().iterencode(state)).encode('utf-8')
 assert json.dumps(state).encode()==expected and json.encoder.c_make_encoder is not None
 transaction,saved,output,payload=setup(tmp_path,state);transaction.commit(state)
 assert saved.read_bytes()==expected
 assert output.read_bytes()==b'{"edl_event_id":"prior"}\n'+payload
 assert not transaction.ready.exists() and not transaction.saved.exists() and not transaction.stage.exists()


@pytest.mark.parametrize('delta',[-1,0,1])
def test_state_size_admission_is_exact_ascii_byte_length_before_writes(tmp_path,monkeypatch,delta):
 state={'files':{},'unicode':'U0001f642'*100};expected=json.dumps(state).encode();transaction,saved,output,payload=setup(tmp_path,state)
 old=saved.read_bytes();prior_output=output.read_bytes();transaction.saved.write_bytes(b'preserve unready prior stage')
 monkeypatch.setattr(tx,'MAX_STATE',len(expected)+delta)
 if delta<0:
  with pytest.raises(tx.ReceiptPageError,match='admission exceeded'):transaction.commit(state)
  assert saved.read_bytes()==old and output.read_bytes()==prior_output
  assert transaction.saved.read_bytes()==b'preserve unready prior stage' and not transaction.ready.exists()
 else:transaction.commit(state);assert saved.read_bytes()==expected


def test_encoding_memory_error_keeps_checkpoint_output_and_unready_stage(tmp_path,monkeypatch):
 state={'files':{}};transaction,saved,output,payload=setup(tmp_path,state);old=saved.read_bytes();prior_output=output.read_bytes();transaction.saved.write_bytes(b'old unready')
 def oom(value,*args,**kw):raise MemoryError('synthetic bounded-allocation failure')
 monkeypatch.setattr(tx.json,'dumps',oom)
 with pytest.raises(MemoryError):transaction.commit(state)
 assert saved.read_bytes()==old and output.read_bytes()==prior_output
 assert transaction.saved.read_bytes()==b'old unready' and not transaction.ready.exists()


@pytest.mark.parametrize('phase',['before_encoding','encoding','write','hash','ready','append','replace','after_replace'])
def test_original_deadline_accounts_encoding_and_each_commit_phase(tmp_path,monkeypatch,phase):
 state={'files':{},'unknown':'x'*(3*tx.CHUNK)};transaction,saved,output,payload=setup(tmp_path,state)
 old=saved.read_bytes();prior_output=output.read_bytes();expected=json.dumps(state).encode()
 clock=[1000.];transaction.guard.admission.deadline=1020.;transaction.guard.admission.whole_deadline=1180.;transaction.guard.whole_deadline=1180.;fired=[False];sizes=[]
 with monkeypatch.context() as patch:
  patch.setattr(reader.time,'monotonic',lambda:clock[0])
  transaction.guard.begin_checkpoint()
  encode=json.dumps
  def encoding(value,*args,**kw):
   result=encode(value,*args,**kw)
   if phase=='encoding' and value is state:clock[0]=1046.;fired[0]=True
   return result
  patch.setattr(tx.json,'dumps',encoding)
  if phase=='before_encoding':clock[0]=1046.;fired[0]=True
  opened=pathlib.Path.open
  class Writer:
   def __init__(self,raw):self.raw=raw
   def __enter__(self):self.raw.__enter__();return self
   def __exit__(self,*a):return self.raw.__exit__(*a)
   def __getattr__(self,name):return getattr(self.raw,name)
   def write(self,value):
    sizes.append(len(value.encode()));assert sizes[-1]<=tx.CHUNK
    result=self.raw.write(value)
    if phase=='write' and not fired[0]:clock[0]=1046.;fired[0]=True
    return result
  def opening(path,*args,**kw):
   raw=opened(path,*args,**kw)
   return Writer(raw) if path==transaction.saved and args and args[0]=='w' else raw
  patch.setattr(pathlib.Path,'open',opening)
  digest=tx.digest
  def hashing(path,*args,**kw):
   if phase=='hash' and path==transaction.saved:clock[0]=1046.;fired[0]=True
   return digest(path,*args,**kw)
  patch.setattr(tx,'digest',hashing)
  replace=os.replace
  def replacing(src,dst):
   if phase=='replace' and pathlib.Path(dst)==saved:clock[0]=1046.;fired[0]=True;transaction.guard.check()
   result=replace(src,dst)
   if (phase=='ready' and pathlib.Path(dst)==transaction.ready) or (phase=='after_replace' and pathlib.Path(dst)==saved):clock[0]=1046.;fired[0]=True
   return result
  patch.setattr(os,'replace',replacing)
  check=transaction.guard.check
  def checked():
   if phase=='append' and output.stat().st_size>len(prior_output) and not fired[0]:clock[0]=1046.;fired[0]=True
   return check()
  patch.setattr(transaction.guard,'check',checked)
  with pytest.raises(reader.DeferredInput,match='Checkpoint work budget exhausted'):transaction.commit(state)
 assert fired[0]
 if phase=='after_replace':assert saved.read_bytes()==expected
 else:assert saved.read_bytes()==old
 if transaction.ready.exists():
  before=output.read_bytes();assert tx.recover_edge_transaction(saved,output)
  assert saved.read_bytes()==expected and not transaction.ready.exists()
  if len(before)>len(prior_output):assert output.read_bytes()==before+payload
  else:assert output.read_bytes()==prior_output+payload
 else:assert output.read_bytes()==prior_output


def test_corrupt_prepared_checkpoint_appends_nothing(tmp_path,monkeypatch):
 state={'files':{},'unknown':None};transaction,saved,output,payload=setup(tmp_path,state);prior_output=output.read_bytes()
 finish=tx.EdgeTransaction.finish
 with monkeypatch.context() as patch:
  def crash(self,*a,**kw):raise OSError('synthetic crash after durable ready marker')
  patch.setattr(tx.EdgeTransaction,'finish',crash)
  with pytest.raises(OSError):transaction.commit(state)
 assert transaction.ready.exists();transaction.saved.write_bytes(b'{"files":{},"corrupt":true}')
 with pytest.raises(tx.ReceiptPageError,match='hash mismatch'):tx.recover_edge_transaction(saved,output)
 assert output.read_bytes()==prior_output and transaction.ready.exists()


def test_crash_after_output_replays_identical_event_ids(tmp_path,monkeypatch):
 state={'files':{},'unknown':None};transaction,saved,output,payload=setup(tmp_path,state);replace=os.replace
 with monkeypatch.context() as patch:
  def crash(src,dst):
   if pathlib.Path(dst)==saved:raise OSError('synthetic output-before-state crash')
   return replace(src,dst)
  patch.setattr(os,'replace',crash)
  with pytest.raises(OSError):transaction.commit(state)
 first=output.read_bytes();assert first.endswith(payload) and transaction.ready.exists()
 assert tx.recover_edge_transaction(saved,output)
 assert output.read_bytes()==first+payload
 rows=[json.loads(line) for line in output.read_text().splitlines()]
 assert [r['edl_event_id'] for r in rows]==['prior','synthetic-No','synthetic-No']
 assert all(r.get('edl_qualifying')=='no' for r in rows[1:])
