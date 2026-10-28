"""Synthetic POSIX tests; no production source payload or service calls."""
import copy, dataclasses, errno, gzip, hashlib, json, os, pathlib, stat, types
import pytest
import receipt_pages as pages
import source_log_reader as reader


def limits(**values):
    return dataclasses.replace(reader.InputLimits(), seconds=5, record_bytes=128,
                               file_bytes=2048, input_bytes=16384, **values)


def collect(path, state, store, seen, **kwargs):
    return reader.collect_log_inputs([path], state, lambda path,line:seen.append(json.loads(line)),
                                    cutoff=0, limits=kwargs.get('limits',limits()), receipt_store=store)


def source(tmp_path, count=150, compressed=False):
    records=[];expected=[]
    for i in range(count):
        records.append(b'x'*160+b'\n')
        event={'id':i,'qualifying':i%2==0,'seen':'2026-01-02T03:04:05Z'}
        records.append(json.dumps(event).encode()+b'\n');expected.append(event)
    path=tmp_path/('audit.log.gz' if compressed else 'audit.log')
    path.write_bytes(gzip.compress(b''.join(records)) if compressed else b''.join(records))
    return path,expected


def receipts_for(path, count=64):
    lane={'offset':0};coverage={'records':0,'input_bytes':0}
    with path.open('rb') as stream:
        lane,_=reader._slice(path,stream,path.stat(),lane,lambda *args:None,coverage,
                             reader._Admission(dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000)))
    assert len(lane['record_debt'])==count
    st=path.stat();lane.update(inode=st.st_ino,mtime=st.st_mtime,size=st.st_size,partial=True)
    return lane


def begin(store):return store.invocation(lambda:None,lambda n:None)


def all_receipts(store,ref):
    with begin(store):
        store.verify(ref)
        return [receipt for item in ref['manifest'] for receipt in store.read(item['hash'])[0]['receipts']]


def test_more_than64_interleaved_records_and_reloads_remain_partial(tmp_path):
    path,expected=source(tmp_path);state={};seen=[];root=tmp_path/'pages'
    for n in range(80):
        coverage=collect(path,state,pages.ReceiptPages(root),seen)
        state=json.loads(json.dumps(state))
        if state[str(path)].get('delivery_offset')==path.stat().st_size:break
    assert seen==expected
    row=state[str(path)];assert row['offset']==0 and row['partial'] is True
    assert coverage['status']=='partial' and coverage['unresolved_record_references']==150
    assert row['unresolved_record_count']==150 and len(row['record_debt'])<=64
    paged=all_receipts(pages.ReceiptPages(root),row['record_debt_pages'])
    combined=paged+row['record_debt'];assert len(combined)==150
    assert [r['start'] for r in combined]==sorted(r['start'] for r in combined)
    assert len({r['start'] for r in combined})==150
    before=copy.deepcopy(state);seen2=[];collect(path,state,pages.ReceiptPages(root),seen2)
    assert seen2==[] and state[str(path)]['record_debt_pages']==before[str(path)]['record_debt_pages']


def test_existing_full_receipts_and_unknown_fields_retained(tmp_path):
    path,_=source(tmp_path,65);lane=receipts_for(path)
    for i,r in enumerate(lane['record_debt']):r['unknown']={'null':None,'missing_distinct':{},'unicode':'\u03bb','i':i}
    expected=pages.canonical(lane['record_debt']);ref=None;root=tmp_path/'pages'
    with begin(pages.ReceiptPages(root)) as store:
        for i in range(0,64,16):ref=store.append(ref,lane['record_debt'][i:i+16],path.stat(),'source_bytes')
    assert pages.canonical(all_receipts(pages.ReceiptPages(root),ref))==expected


@pytest.mark.parametrize('point',['after_stage_create','after_stage_write','after_file_fsync',
    'after_mode_fsync','after_readback','after_publish_link','after_publish_dir_fsync',
    'after_stage_unlink','after_stage_cleanup_fsync','after_published_inode_fsync','before_reference_return'])
def test_every_page_crash_boundary_retains_state_and_retry_address(tmp_path,point):
    class Crash(BaseException):pass
    path,_=source(tmp_path,65);lane=receipts_for(path);state={str(path):lane};old=copy.deepcopy(state);root=tmp_path/'pages'
    def fail(value):
        if value==point:raise Crash(value)
    with pytest.raises(Crash):collect(path,state,pages.ReceiptPages(root,_fault=fail),[],limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000))
    assert state==old
    with begin(pages.ReceiptPages(root)) as store:
        entries=store.inventory();size=sum(st.st_size for st in entries.values());assert size==store.total
        if point in ('after_publish_link','after_publish_dir_fsync'):
            assert len(entries)==2 and size>0
    seen=[];collect(path,state,pages.ReceiptPages(root),seen,limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000))
    ref=state[str(path)]['record_debt_pages'];assert ref['count']==16
    archived=all_receipts(pages.ReceiptPages(root),ref);assert pages.canonical(archived)==pages.canonical(old[str(path)]['record_debt'][:16])
    assert state[str(path)]['unresolved_record_count']==65
    with begin(pages.ReceiptPages(root)) as store:
        assert store.total==sum(st.st_size for st in store.inventory().values())


def test_unreferenced_durable_page_reuse_is_exact_and_no_extra_entries(tmp_path):
    path,_=source(tmp_path,65);r=receipts_for(path)['record_debt'][:16];root=tmp_path/'pages'
    with begin(pages.ReceiptPages(root)) as store:
        first=store.append(None,r,path.stat(),'source_bytes');before=dict(store.inventory())
    with begin(pages.ReceiptPages(root)) as store:
        second=store.append(None,r,path.stat(),'source_bytes');after=dict(store.inventory())
    assert first==second and before.keys()==after.keys()


def test_staging_and_hardlinked_orphans_count_against_quota(tmp_path):
    path,_=source(tmp_path,65);r=receipts_for(path)['record_debt'][:16];root=tmp_path/'pages'
    with begin(pages.ReceiptPages(root)) as store:
        ref=store.append(None,r,path.stat(),'source_bytes');n=ref['bytes']
    stage=root/('.stage-'+'a'*32);os.link(root/(ref['tip']+'.json'),stage)
    with begin(pages.ReceiptPages(root)) as store:assert store.total==2*n
    with pytest.raises(pages.ReceiptPageError):
        with begin(pages.ReceiptPages(root,max_bytes=2*n-1)):pass
    # Another fsynced unlinked staging object is also charged, not ignored.
    stage2=root/('.stage-'+'b'*32);stage2.write_bytes(b'z'*97);stage2.chmod(0o600)
    with stage2.open('rb') as f:os.fsync(f.fileno())
    with begin(pages.ReceiptPages(root)) as store:assert store.total==2*n+97


def test_reservation_includes_new_stage_and_link_plus_old_orphan(tmp_path):
    path,_=source(tmp_path,65);r=receipts_for(path)['record_debt'][:16];probe=tmp_path/'probe'
    with begin(pages.ReceiptPages(probe)) as store:ref=store.append(None,r,path.stat(),'source_bytes')
    n=ref['bytes'];root=tmp_path/'pages';root.mkdir(mode=0o700);orphan=root/('.stage-'+'c'*32);orphan.write_bytes(b'x'*101);orphan.chmod(0o600)
    with pytest.raises(pages.ReceiptPageError,match='quota reservation'):
        with begin(pages.ReceiptPages(root,max_bytes=2*n+100)) as store:store.append(None,r,path.stat(),'source_bytes')
    assert list(root.iterdir())==[orphan]


@pytest.mark.parametrize('damage',['missing','changed_old','changed_tip','symlink','mode','foreign_link'])
def test_page_damage_rejected_before_any_source_callback(tmp_path,damage):
    path,_=source(tmp_path,100);state={};seen=[];root=tmp_path/'pages'
    for i in range(50):
        collect(path,state,pages.ReceiptPages(root),seen)
        if state[str(path)].get('record_debt_pages',{}).get('pages',0)>=2:break
    ref=state[str(path)]['record_debt_pages'];first=root/(ref['manifest'][0]['hash']+'.json');tip=root/(ref['tip']+'.json')
    if damage=='missing':first.unlink()
    elif damage in ('changed_old','changed_tip'):
        victim=first if damage=='changed_old' else tip;victim.chmod(0o600);raw=victim.read_bytes();victim.write_bytes(raw[:-1]+b' ');victim.chmod(0o400)
    elif damage=='symlink':first.unlink();first.symlink_to(tmp_path/'absent')
    elif damage=='mode':tip.chmod(0o600)
    else:os.link(tip,tmp_path/'outside-store-link')
    old=copy.deepcopy(state);new=[]
    with pytest.raises(pages.ReceiptPageError):collect(path,state,pages.ReceiptPages(root),new)
    assert state==old and new==[]


def test_wrong_source_or_offset_space_fails_before_advancing(tmp_path):
    path,_=source(tmp_path,65);r=receipts_for(path)['record_debt'][:16]
    with begin(pages.ReceiptPages(tmp_path/'pages')) as store:
        with pytest.raises(pages.ReceiptPageError,match='identity|generation'):store.append(None,r,path.stat(),'expanded_bytes')
        fake=types.SimpleNamespace(st_dev=path.stat().st_dev,st_ino=path.stat().st_ino+1)
        with pytest.raises(pages.ReceiptPageError):store.append(None,r,fake,'source_bytes')


def test_gzip_expanded_offsets_retain_pages_and_partial(tmp_path):
    path,expected=source(tmp_path,90,True);state={};seen=[];root=tmp_path/'pages'
    for n in range(60):collect(path,state,pages.ReceiptPages(root),seen)
    assert seen==expected and state[str(path)]['partial']
    assert state[str(path)]['record_debt_pages']['identity']['offset_space']=='expanded_bytes'


def test_root_symlink_wrong_owner_and_entry_bound(tmp_path,monkeypatch):
    real=tmp_path/'real';real.mkdir(mode=0o700);link=tmp_path/'link';link.symlink_to(real,target_is_directory=True)
    with pytest.raises(pages.ReceiptPageError):
        with begin(pages.ReceiptPages(link)):pass
    uid=os.geteuid();monkeypatch.setattr(os,'geteuid',lambda:uid+1)
    with pytest.raises(pages.ReceiptPageError):
        with begin(pages.ReceiptPages(real)):pass
    monkeypatch.undo()
    for i in range(5):
        f=real/('.stage-'+f'{i:032x}');f.touch(mode=0o600)
    with pytest.raises(pages.ReceiptPageError):
        with begin(pages.ReceiptPages(real,max_entries=4)):pass


@pytest.mark.parametrize('kind',['disk_full','fsync'])
def test_storage_failure_does_not_change_source_state(tmp_path,monkeypatch,kind):
    path,_=source(tmp_path,65);state={str(path):receipts_for(path)};old=copy.deepcopy(state);root=tmp_path/'pages'
    if kind=='disk_full':
        original=os.write;calls=[0]
        def write(fd,data):
            calls[0]+=1
            if calls[0]==1:return original(fd,data[:32])
            raise OSError(errno.ENOSPC,'synthetic disk full')
        monkeypatch.setattr(os,'write',write)
    else:
        original=os.fsync;calls=[0]
        def fsync(fd):
            calls[0]+=1
            if calls[0]==2:raise OSError(errno.EIO,'synthetic fsync error')
            return original(fd)
        monkeypatch.setattr(os,'fsync',fsync)
    with pytest.raises(pages.ReceiptPageError):collect(path,state,pages.ReceiptPages(root),[],limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000))
    assert state==old
    monkeypatch.undo()
    entries=list(root.iterdir());assert entries  # Kept and charged, never cleaned as GC.
    collect(path,state,pages.ReceiptPages(root),[],limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000))
    with begin(pages.ReceiptPages(root)) as store:assert store.total==sum(f.stat().st_size for f in root.iterdir())


def test_unsupported_reader_refuses_every_cursor_before_effects(tmp_path):
    path,_=source(tmp_path,65);state={};seen=[];root=tmp_path/'pages'
    for i in range(30):collect(path,state,pages.ReceiptPages(root),seen)
    assert state[str(path)].get('record_debt_pages');old=copy.deepcopy(state);received=[]
    with pytest.raises(pages.ReceiptPageError):collect(path,state,None,received)
    with pytest.raises(pages.ReceiptPageError):reader.collect_log_inputs([path],state,lambda *args:received.append(1),cutoff=0)
    assert state==old and received==[]


def test_4096_segment_pending_guard_is_not_bypassed(tmp_path):
    path=tmp_path/'audit.log';path.write_bytes(b'x'*10000)
    pending={'start':0,'through':4096,'segments':[{'start':i,'end':i+1,'sha256':hashlib.sha256(b'x').hexdigest()} for i in range(4096)]}
    state={str(path):{'inode':path.stat().st_ino,'offset':0,'delivery_offset':4096,'opaque_pending':pending,'partial':True}}
    seen=[];collect(path,state,pages.ReceiptPages(tmp_path/'pages'),seen)
    assert state[str(path)]['delivery_offset']==4096 and len(state[str(path)]['opaque_pending']['segments'])==4096 and seen==[]


def test_page_schema_and_size_admission(tmp_path):
    root=tmp_path/'pages';root.mkdir(mode=0o700)
    for raw in (b'{"format":1,"format":2}',b'[]',b'{'):
        digest=hashlib.sha256(raw).hexdigest();f=root/(digest+'.json');f.write_bytes(raw);f.chmod(0o400)
        with begin(pages.ReceiptPages(root)) as store:
            with pytest.raises(pages.ReceiptPageError):store.read(digest)
    f=root/('.stage-'+'d'*32);f.write_bytes(b'x'*1025);f.chmod(0o600)
    with pytest.raises(pages.ReceiptPageError):
        with begin(pages.ReceiptPages(root,max_page=1024)):pass


def test_path_rename_same_generation_and_replacement_preserve_page_debt(tmp_path):
    path,expected=source(tmp_path,70);state={};seen=[];root=tmp_path/'pages'
    for _ in range(40):collect(path,state,pages.ReceiptPages(root),seen)
    row=copy.deepcopy(state[str(path)]);reference=copy.deepcopy(row['record_debt_pages'])
    renamed=tmp_path/'audit.log.1';path.rename(renamed);state={str(renamed):row};extra={'id':'later-normal','qualifying':False}
    with renamed.open('ab') as f:f.write(json.dumps(extra).encode()+b'\n')
    received=[];collect(renamed,state,pages.ReceiptPages(root),received)
    assert received==[extra] and state[str(renamed)]['record_debt_pages']==reference
    # A new inode at the same pathname retains the complete former lane in prior_generations.
    held=tmp_path/'held-generation';renamed.rename(held);renamed.write_text('{"id":"new-generation"}\n')
    received=[];coverage=collect(renamed,state,pages.ReceiptPages(root),received)
    assert received==[{'id':'new-generation'}] and coverage['status']=='partial'
    active=state[str(renamed)];assert 'record_debt_pages' not in active
    assert active['prior_generations'][0]['record_debt_pages']==reference


def test_copytruncate_with_paged_debt_holds_before_callbacks(tmp_path):
    path,_=source(tmp_path,70);state={};seen=[];root=tmp_path/'pages'
    for _ in range(40):collect(path,state,pages.ReceiptPages(root),seen)
    before=copy.deepcopy(state);path.write_text('{"id":"replacement"}\n');seen=[]
    coverage=collect(path,state,pages.ReceiptPages(root),seen)
    assert seen==[] and state==before and coverage['status']=='partial'


def test_source_mutation_after_page_publish_retains_prior_cursor_and_new_continuity_debt(tmp_path):
    path,_=source(tmp_path,65);state={str(path):receipts_for(path)};old=copy.deepcopy(state);root=tmp_path/'pages'
    def mutate(p,line):
        with p.open('r+b') as f:f.write(b'!')
    result=reader.collect_log_inputs([path],state,mutate,cutoff=0,
        limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000),receipt_store=pages.ReceiptPages(root))
    current=state[str(path)];assert current['offset']==old[str(path)]['offset']
    assert current['delivery_offset']==old[str(path)]['delivery_offset']
    assert current['record_debt']==old[str(path)]['record_debt']
    assert 'record_debt_pages' not in current and current['continuity_debt'] and result['status']=='partial'
    assert list(root.glob('*.json'))  # Durable orphan is not discarded or treated as an acknowledged cursor.


def test_consumer_failure_after_page_publication_does_not_ack_source(tmp_path):
    path,_=source(tmp_path,65);state={str(path):receipts_for(path)};before=copy.deepcopy(state);root=tmp_path/'pages'
    def fail(*args):raise RuntimeError('synthetic consumer failed')
    with pytest.raises(RuntimeError,match='consumer failed'):
        reader.collect_log_inputs([path],state,fail,cutoff=0,limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000),receipt_store=pages.ReceiptPages(root))
    assert state==before and list(root.glob('*.json'))


def test_small_page_io_budget_fails_before_allocating_stage(tmp_path):
    path,_=source(tmp_path,65);state={str(path):receipts_for(path)};before=copy.deepcopy(state);root=tmp_path/'pages'
    with pytest.raises(pages.ReceiptPageError,match='bounded IO'):
        collect(path,state,pages.ReceiptPages(root,max_io=1),[],limits=dataclasses.replace(limits(),file_bytes=100000,input_bytes=100000))
    assert state==before and list(root.iterdir())==[]


def test_unbounded_metadata_is_rejected_without_publishing(tmp_path):
    path,_=source(tmp_path,65);r=receipts_for(path)['record_debt'][:16];r[0]['unknown_large']='x'*9000;root=tmp_path/'pages'
    with begin(pages.ReceiptPages(root,max_page=8192)) as store:
        with pytest.raises(pages.ReceiptPageError,match='admission'):store.append(None,r,path.stat(),'source_bytes')
    assert list(root.iterdir())==[]


def test_ambiguous_null_reference_refuses_rollback_without_normalization():
    value={'source':{'record_debt_pages':None,'unknown':{'value':None}}};before=copy.deepcopy(value)
    with pytest.raises(pages.ReceiptPageError):pages.refuse_paged_debt(value)
    assert value==before


def test_publication_never_clobbers_conflicting_existing_bytes(tmp_path,monkeypatch):
    path,_=source(tmp_path,65);r=receipts_for(path)['record_debt'][:16];root=tmp_path/'pages';real=os.link;created=[]
    def conflict(src,dst,**kw):
        name=str(dst);fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400,dir_fd=kw['dst_dir_fd'])
        try:os.write(fd,b'conflicting');os.fsync(fd)
        finally:os.close(fd)
        created.append(name)
        raise FileExistsError(name)
    monkeypatch.setattr(os,'link',conflict)
    with pytest.raises(pages.ReceiptPageError):
        with begin(pages.ReceiptPages(root)) as store:store.append(None,r,path.stat(),'source_bytes')
    assert created and (root/created[0]).read_bytes()==b'conflicting'


def test_historical_page_metadata_is_verified_without_reading_entire_history(tmp_path):
    path,_=source(tmp_path,65);receipts=receipts_for(path)['record_debt'];root=tmp_path/'pages';ref=None
    with begin(pages.ReceiptPages(root)) as store:
        for i in range(0,64,16):ref=store.append(ref,receipts[i:i+16],path.stat(),'source_bytes')
    charged=[]
    with pages.ReceiptPages(root).invocation(lambda:None,charged.append) as store:store.verify(ref)
    assert sum(charged)==ref['manifest'][-1]['size'] and sum(charged)<ref['bytes']
