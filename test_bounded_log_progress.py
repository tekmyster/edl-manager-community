"""Portable synthetic bounded input progress; no inventory or incident data."""
import json,gzip
import pytest
from source_log_reader import collect_log_inputs,InputLimits

def test_bounded_restart_walks_original_plain_prefix_without_loss(tmp_path):
    p=tmp_path/'audit.log';p.write_text(''.join(json.dumps({'id':i})+'\n' for i in range(19)));files={};seen=[]
    limits=InputLimits(records=3,input_bytes=256,file_bytes=128)
    for _ in range(20):
        result=collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=limits)
        assert result['records']<=3 and result['input_bytes']<=256
        files=json.loads(json.dumps(files)) # process restart boundary
        if not files[str(p)]['partial']:break
    assert seen==list(range(19));assert files[str(p)]['offset']==p.stat().st_size

def test_small_validated_gzip_can_resume_without_skipping_tail(tmp_path):
    p=tmp_path/'audit.log.1.gz';p.write_bytes(gzip.compress(''.join(json.dumps({'id':i})+'\n' for i in range(13)).encode()));files={};seen=[]
    for _ in range(15):
        result=collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits(records=2))
        files=json.loads(json.dumps(files))
        if not files[str(p)]['partial']:break
    assert seen==list(range(13))
    assert collect_log_inputs([p],files,lambda *_:pytest.fail('Completed archive replayed'),cutoff=0,limits=InputLimits())['unchanged']==1

def test_large_archive_never_starves_old_plain_backlog_or_loses_debt(tmp_path):
    bad=tmp_path/'audit.log.1.gz';bad.write_bytes(b'x'*200)
    p=tmp_path/'audit.log';p.write_text('{"id":1}\n{"id":2}\n')
    previous={'inode':7,'offset':8,'mtime':1,'size':6};files={str(bad):previous.copy()};seen=[]
    result=collect_log_inputs([bad,p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits(compressed_bytes=32))
    assert seen==[1,2] and files[str(bad)]==previous and result['status']=='partial'
    assert any(v['path']==str(bad) and 'historical debt' in v['reason'] for v in result['deferred'])

def test_unbounded_api_respects_existing_bounded_archive_checkpoint(tmp_path):
    p=tmp_path/'audit.log.1.gz';p.write_bytes(gzip.compress(''.join(json.dumps({'id':i})+'\n' for i in range(7)).encode()));files={};seen=[]
    collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits(records=2))
    collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0)
    assert seen==list(range(7)) and not files[str(p)]['partial']

def test_unanchored_legacy_prefix_is_reconciled_without_resetting_forward_cursor(tmp_path):
    p=tmp_path/'audit.log';lines=[json.dumps({'id':i})+'\n' for i in range(15)];p.write_text(''.join(lines));st=p.stat();offset=len(''.join(lines[:5]).encode());legacy={'inode':st.st_ino,'offset':offset,'mtime':1,'size':offset};files={str(p):legacy.copy()};seen=[];last=offset
    for _ in range(20):
        r=collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits(records=2))
        assert files[str(p)]['offset']>=last;last=files[str(p)]['offset'];files=json.loads(json.dumps(files))
        if last==p.stat().st_size and files[str(p)]['prefix_reconcile']['offset']>=offset:break
    assert sorted(seen)==list(range(15)) and files[str(p)]['legacy_receipt']==legacy
    assert r['status']=='partial' and r['historical_debt']

def test_incomplete_line_and_copytruncate_do_not_reset_or_skip_cursor(tmp_path):
    p=tmp_path/'audit.log';p.write_text('{"id":1}\n{"id":');files={};seen=[]
    collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits())
    assert seen==[1] and files[str(p)]['offset']==9
    with p.open('a') as f:f.write('2}\n')
    collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits())
    assert seen==[1,2];prior=json.loads(json.dumps(files[str(p)]))
    p.write_text('{"id":9}\n{"id":8}\n')
    r=collect_log_inputs([p],files,lambda *_:pytest.fail('Changed prefix consumed'),cutoff=0,limits=InputLimits())
    assert files[str(p)]==prior and r['status']=='partial'

def test_legacy_prefix_rotation_retains_prior_debt_and_restarts_only_new_inode(tmp_path):
    p=tmp_path/'audit.log';p.write_text('{"id":1}\n{"id":2}\n');legacy={'inode':p.stat().st_ino,'offset':p.stat().st_size,'mtime':1,'size':p.stat().st_size};files={str(p):legacy.copy()};seen=[]
    collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits(records=1))
    prior=json.loads(json.dumps(files[str(p)]));p.rename(tmp_path/'old-retained.log');p.write_text('{"id":3}\n{"id":4}\n')
    for _ in range(3):r=collect_log_inputs([p],files,lambda p,line:seen.append(json.loads(line)['id']),cutoff=0,limits=InputLimits(records=1))
    current=files[str(p)];assert seen==[1,3,4] and current['prior_generations']==[{k:v for k,v in prior.items() if k!='prior_generations'}]
    assert current['offset']==p.stat().st_size and 'prefix_reconcile' not in current and r['status']=='partial'
    assert prior['legacy_receipt']==legacy and prior['prefix_reconcile']['offset']<legacy['offset']
