"""Bounded opaque-record delivery and byte-bound mutation receipts."""
import copy,dataclasses,gzip,hashlib,json,pathlib
import pytest
from source_log_reader import collect_log_inputs,InputLimits

def run(path,files,seen,limits):
    return collect_log_inputs([path],files,lambda p,line:seen.append(json.loads(line)),cutoff=0,limits=limits)

def verify_receipt(raw,debt):
    chain=hashlib.sha256(b'').hexdigest();last=debt['start']
    for segment in debt['segments']:
        assert segment['start']==last and hashlib.sha256(raw[last:segment['end']]).hexdigest()==segment['sha256']
        chain=hashlib.sha256(bytes.fromhex(chain)+str(last).encode()+b':'+str(segment['end']).encode()+b':'+bytes.fromhex(segment['sha256'])).hexdigest();last=segment['end']
    assert last==debt['through'] and chain==debt['chain_sha256']

@pytest.mark.parametrize('compressed',[False,True])
def test_opaque_hash_progress_survives_restart_and_keeps_original_bytes(tmp_path,compressed):
    p=tmp_path/('audit.log.gz' if compressed else 'audit.log');raw=b'x'*257+b'\n'+json.dumps({'id':'later','text':'\u03b1\U0001f642'},ensure_ascii=False).encode()+b'\n';p.write_bytes(gzip.compress(raw) if compressed else raw)
    original=p.read_bytes();files={};seen=[];limits=InputLimits(record_bytes=48,file_bytes=64,input_bytes=64)
    for _ in range(20):
        coverage=run(p,files,seen,limits);files=json.loads(json.dumps(files));row=files[str(p)]
        assert row['offset']==0 and coverage['input_bytes']<=64
        for debt in row.get('record_debt',[])+([row['opaque_pending']] if row.get('opaque_pending') else []):verify_receipt(raw,debt)
        if seen:break
    assert seen==[{'id':'later','text':'\u03b1\U0001f642'}] and coverage['status']=='partial' and coverage['completed']==0 and p.read_bytes()==original
    debt=row['record_debt'][0];assert debt['start']==0 and debt['end']==258 and debt['boundary_verified']
    assert row['delivery_offset']==len(raw) and 'x'*20 not in json.dumps(row)
    previous=copy.deepcopy(row);run(p,files,seen,limits);assert seen==[{'id':'later','text':'\u03b1\U0001f642'}] and files[str(p)]['record_debt']==previous['record_debt']

def test_small_growing_utf8_tail_is_not_quarantined_or_accepted_before_newline(tmp_path):
    p=tmp_path/'audit.log';raw=json.dumps({'id':'\U0001f642'},ensure_ascii=False).encode()+b'\n';split=raw.index(b'\xf0')+2;p.write_bytes(raw[:split]);files={};seen=[]
    for _ in range(3):assert run(p,files,seen,InputLimits())['status']=='partial'
    assert not seen and files[str(p)]['offset']==0 and not files[str(p)]['record_debt']
    with p.open('ab') as f:f.write(raw[split:-1])
    run(p,files,seen,InputLimits());assert not seen and files[str(p)]['offset']==0
    with p.open('ab') as f:f.write(b'\n')
    assert run(p,files,seen,InputLimits())['status']=='complete' and seen==[{'id':'\U0001f642'}]
    assert files[str(p)]['offset']==len(raw)

def test_growing_opaque_tail_waits_for_verified_boundary_before_later_delivery(tmp_path):
    p=tmp_path/'audit.log';p.write_bytes(b'secret-payload'*40);files={};seen=[];limits=InputLimits(record_bytes=32,file_bytes=64,input_bytes=64)
    for _ in range(12):run(p,files,seen,limits);files=json.loads(json.dumps(files))
    row=files[str(p)];assert not seen and not row['opaque_pending']['boundary_verified'] and row['delivery_offset']==p.stat().st_size and row['offset']==0
    with p.open('ab') as f:f.write(b'more\n'+b'{"id":9}\n')
    run(p,files,seen,limits);assert seen==[{'id':9}] and files[str(p)]['record_debt'][0]['boundary_verified']
    verify_receipt(p.read_bytes(),files[str(p)]['record_debt'][0]);assert 'secret-payload' not in json.dumps(files)

def test_long_record_real_default_limit_delivers_later_incident_and_plain_append(tmp_path):
    p=tmp_path/'audit.log';raw=json.dumps({'payload':'opaque'*250000}).encode()+b'\n'+b'{"id":9}\n';p.write_bytes(raw);files={};seen=[];limits=InputLimits(file_bytes=256*1024,input_bytes=256*1024)
    for _ in range(16):
        coverage=run(p,files,seen,limits);files=json.loads(json.dumps(files));assert coverage['input_bytes']<=256*1024
        if seen:break
    assert seen==[{'id':9}] and coverage['status']=='partial';verify_receipt(raw,files[str(p)]['record_debt'][0])
    with p.open('ab') as f:f.write(b'{"id":10}\n')
    after=run(p,files,seen,limits);assert seen==[{'id':9},{'id':10}] and files[str(p)]['offset']==0,(seen,after,files[str(p)].get('delivery_anchor'))

@pytest.mark.parametrize('mutation',['equal_copytruncate','shrink','rename','append'])
def test_in_callback_mutation_cannot_certify_unread_generation(tmp_path,mutation):
    p=tmp_path/'audit.log';original=b'{"id":1}\n{"id":2}\n';p.write_bytes(original);files={};seen=[];changed=False
    def consume(path,line):
        nonlocal changed
        seen.append(json.loads(line)['id'])
        if changed:return
        changed=True
        if mutation=='equal_copytruncate':p.write_bytes(b'{"id":9}\n{"id":8}\n')
        elif mutation=='shrink':p.write_bytes(b'{"id":9}\n')
        elif mutation=='rename':p.rename(tmp_path/'retained.log');p.write_bytes(b'{"id":9}\n{"id":8}\n')
        else:
            with p.open('ab') as f:f.write(b'{"id":9}\n')
    first=collect_log_inputs([p],files,consume,cutoff=0,limits=InputLimits())
    row=files[str(p)]
    if mutation=='append':
        assert row['offset']==len(original) and row['size']==len(original)
    else:
        assert first['status']=='partial' and row['offset']==0 and row['continuity_debt'][0]['sha256']==hashlib.sha256(original).hexdigest()
    second=collect_log_inputs([p],files,consume,cutoff=0,limits=InputLimits())
    assert 9 in seen
    if mutation!='append':assert second['status']=='partial'

@pytest.mark.parametrize('mutation',['truncate','rewrite','rename'])
def test_pending_opaque_range_cannot_be_rebound_to_replacement(tmp_path,mutation):
    p=tmp_path/'audit.log';p.write_bytes(b'x'*200+b'\n{"id":1}\n');files={};seen=[];limits=InputLimits(record_bytes=32,file_bytes=64,input_bytes=64)
    run(p,files,seen,limits);old=copy.deepcopy(files[str(p)])
    replacement=b'{"id":9}\n'+b'z'*192
    if mutation=='truncate':p.write_bytes(b'{"id":9}\n')
    elif mutation=='rewrite':p.write_bytes(replacement)
    else:p.rename(tmp_path/'retained.log');p.write_bytes(b'{"id":9}\n')
    coverage=run(p,files,seen,limits)
    assert coverage['status']=='partial'
    if mutation=='rename':assert seen==[{'id':9}] and files[str(p)]['prior_generations'][0]['opaque_pending']==old['opaque_pending']
    else:assert not seen and files[str(p)]==old

def test_legacy_forward_cursor_stays_monotonic_while_prefix_crosses_opaque_record(tmp_path):
    p=tmp_path/'audit.log';raw=b'x'*128+b'\n{"id":9}\n';p.write_bytes(raw);legacy={'inode':p.stat().st_ino,'offset':len(raw),'size':len(raw),'mtime':1};files={str(p):legacy.copy()};seen=[]
    for _ in range(20):
        coverage=run(p,files,seen,InputLimits(record_bytes=32,file_bytes=64,input_bytes=64));files=json.loads(json.dumps(files));assert files[str(p)]['offset']==len(raw)
        if seen:break
    assert seen==[{'id':9}] and coverage['status']=='partial'
    row=files[str(p)];assert row['legacy_receipt']==legacy and row['prefix_reconcile']['offset']==0 and row['prefix_reconcile']['delivery_offset']==len(raw)
    verify_receipt(raw,row['prefix_reconcile']['record_debt'][0])

def test_consumer_failure_repeats_valid_tail_without_erasing_quarantine_receipts(tmp_path):
    p=tmp_path/'audit.log';p.write_bytes(b'x'*65+b'\n{"id":9}\n');files={};seen=[];limits=InputLimits(record_bytes=32,file_bytes=64,input_bytes=64)
    run(p,files,seen,limits);before=copy.deepcopy(files)
    def interrupted(*args):raise RuntimeError('synthetic application interruption')
    with pytest.raises(RuntimeError):collect_log_inputs([p],files,interrupted,cutoff=0,limits=limits)
    assert files==before
    run(p,files,seen,limits);assert seen==[{'id':9}] and files[str(p)]['record_debt'][0]['boundary_verified']

def test_unbounded_api_cannot_bypass_opaque_record_protocol(tmp_path):
    p=tmp_path/'audit.log';p.write_bytes(b'x'*65+b'\n{"id":9}\n');files={};seen=[];run(p,files,seen,InputLimits(record_bytes=32,file_bytes=64,input_bytes=64));before=copy.deepcopy(files)
    result=collect_log_inputs([p],files,lambda *args:pytest.fail('Unbounded bypass'),cutoff=0)
    assert result['status']=='partial' and files==before

def test_completed_unchanged_archive_retains_prior_generation_partial_coverage(tmp_path):
    p=tmp_path/'audit.log.gz';p.write_bytes(gzip.compress(b'{"id":9}\n'));files={str(p):{'inode':1,'offset':7,'size':1,'mtime':1}};seen=[]
    first=run(p,files,seen,InputLimits());second=run(p,files,seen,InputLimits())
    assert first['status']==second['status']=='partial' and second['unchanged']==1 and second['historical_debt'] and seen==[{'id':9}]
