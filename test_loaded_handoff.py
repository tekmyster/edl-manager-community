"""Actual pinned prior indexed API on real isolated SQLite transactions."""
import copy,importlib.util,json,pathlib,inspect
import pytest
import source_handoff as handoff,packet_indexing as indexing
from behavior_ai import DEFAULTS
from evidence_history import collection_scope
from test_writer_occupancy import fixture,values
from test_writer_occupancy import test_stale_preparation_never_publishes_or_acks_successor as _stale
from test_writer_occupancy import test_frozen_packet_matches_prior_atomic_path_with_misp_and_correlation as _frozen
from test_source_observation_cache import AT,ADDRESS

@pytest.fixture(autouse=True)
def previous_handoff(monkeypatch):
 spec=importlib.util.spec_from_file_location('previous_handoff',pathlib.Path(__file__).parent/'testdata/source_handoff_prior_indexed.py')
 previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
 assert tuple(inspect.signature(previous.indexed).parameters)==('brain','address','revision','source_cfg')
 monkeypatch.setattr(handoff,'indexed',previous.indexed)
 return previous

def prepared(tmp_path,scoped=True):
 s,b=fixture(tmp_path,0)
 cfg={'index_url':'https://collector.example.test','source_agents':{'tpot':'*'},'palo_location':'fixture-firewall'} if scoped else None
 if cfg:s.state('source_configuration',{'index_url':cfg['index_url'],'sources':cfg['source_agents'],'palo_location':cfg['palo_location']})
 s.source_activity(ADDRESS,'tpot','Cowrie',AT.isoformat(),{'activity':{'events':values(3)}},source_cfg=cfg)
 handoff.deliver(b,at=AT)
 return s,b,cfg,handoff.ready(b,cfg)[ADDRESS]

CFG={**DEFAULTS,'enabled':True,'model_enabled':True,'correlation_enabled':False}

@pytest.mark.parametrize('scoped',[False,True])
def test_previously_loaded_handoff_accepts_new_indexer(tmp_path,scoped):
 s,b,cfg,revision=prepared(tmp_path,scoped)
 ident,_=indexing.index_packet(b,s,ADDRESS,copy.deepcopy(CFG),cfg,revision=revision,at=AT)
 assert ident and not handoff.ready(b,cfg)
 with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==1

def test_prior_ack_uses_captured_scope_and_same_owner(tmp_path,monkeypatch,previous_handoff):
 s,b,cfg,revision=prepared(tmp_path);captured=collection_scope(b,cfg);observed=[];new_scope=[]
 def acknowledge(local,address,exact_revision,source_cfg=None):
  # A later native commit cannot change the pinned reader's captured scope.
  s.state('source_configuration',{'index_url':'https://changed.example.test','sources':{'tpot':'other'},'palo_location':'changed'})
  successor_scope=collection_scope(b,cfg);assert successor_scope!=captured;new_scope.append(successor_scope)
  with local.connect() as owner:
   assert owner.in_transaction and collection_scope(local,source_cfg)==captured
   owner.execute('INSERT INTO source_sample_ready VALUES(?,?,?,?)',(address,successor_scope,revision+100,AT.isoformat()))
   observed.append(id(owner))
  previous_handoff.indexed(local,address,exact_revision,source_cfg)
  with local.connect() as owner:assert id(owner)==observed[-1] and owner.in_transaction
 monkeypatch.setattr(handoff,'indexed',acknowledge)
 assert indexing.index_packet(b,s,ADDRESS,copy.deepcopy(CFG),cfg,revision=revision,at=AT)[0]
 with b.connect() as db:assert [tuple(r) for r in db.execute('SELECT scope,revision FROM source_sample_ready')]==[(new_scope[0],revision+100)]

@pytest.mark.parametrize('change',['revision','native_scope','native_config','caller_config'])
def test_old_loaded_handoff_keeps_stale_preparation_guards(tmp_path,monkeypatch,change):
 _stale(tmp_path,monkeypatch,change)

def test_old_loaded_handoff_keeps_frozen_packet_and_old_brain_equivalence(tmp_path,monkeypatch):
 _frozen(tmp_path,monkeypatch)

def test_actual_prior_ack_rolls_back_with_packet_and_queue(tmp_path,monkeypatch,previous_handoff):
 s,b,cfg,revision=prepared(tmp_path)
 def interrupted(local,address,exact_revision,source_cfg=None):
  previous_handoff.indexed(local,address,exact_revision,source_cfg)
  raise RuntimeError('Isolated failure after prior ACK SQL, before owner commit')
 monkeypatch.setattr(handoff,'indexed',interrupted)
 with pytest.raises(RuntimeError,match='before owner commit'):indexing.index_packet(b,s,ADDRESS,copy.deepcopy(CFG),cfg,revision=revision,at=AT)
 with b.connect() as db:
  for table in ('packets','current_packets','analysis_queue'):assert db.execute('SELECT count(*) FROM '+table).fetchone()[0]==0
 assert handoff.ready(b,cfg)[ADDRESS]==revision
 monkeypatch.setattr(handoff,'indexed',previous_handoff.indexed)
 assert indexing.index_packet(b,s,ADDRESS,copy.deepcopy(CFG),cfg,revision=revision,at=AT)[0] and not handoff.ready(b,cfg)
 with b.connect() as db:assert db.execute('SELECT count(*) FROM analysis_queue').fetchone()[0]==1
