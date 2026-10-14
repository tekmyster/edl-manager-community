import pathlib,sqlite3,datetime as dt,os,json
cfg=json.loads(pathlib.Path(os.environ['EDL_CONFIG']).read_text());p=pathlib.Path(cfg['database']).parent/'backups';p.mkdir(mode=0o700,exist_ok=True)
dest=p/('manager-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d')+'.sqlite3')
with sqlite3.connect(cfg['database']) as source,sqlite3.connect(dest) as backup:source.backup(backup)
dest.chmod(0o600)
for file in p.glob('manager-*.sqlite3'):
 if file.stat().st_mtime<(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=14)).timestamp():file.unlink()
print('SQLite backup completed')
