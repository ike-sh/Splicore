"""Build a failing-forward-migration package ONLY in a new external source copy.

No production migration or checkout file is edited. The fixture is private local
test evidence; never install it outside splicore-service-lab.py.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tarfile

sys.dont_write_bytecode=True
REPO=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('package_tool',REPO/'scripts/splicore-package.py');pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--base-package',type=pathlib.Path,required=True);a=p.parse_args()
    out=a.output.resolve()
    if out.is_relative_to(REPO):p.error('Fixture output must be external')
    out.mkdir(mode=0o700,parents=True,exist_ok=False);src=out/'source';src.mkdir(mode=0o700)
    snapshot,_=pack.source_snapshot()
    for name in snapshot:
        original=REPO/name;target=src/name;target.parent.mkdir(parents=True,exist_ok=True)
        if original.is_symlink():target.symlink_to(os.readlink(original))
        else:shutil.copyfile(original,target)
    with tarfile.open(a.base_package) as tar:
        entries={item.name:(tar.extractfile(item).read(),item.mode) for item in tar if item.isfile()}
    manifest=json.loads(entries.pop('manifest.json')[0]);entries.pop('SHA256SUMS')
    if manifest['db_schema']!=4 or manifest['goos']!='linux' or manifest['goarch']!='amd64':p.error('Fixture currently targets the frozen schema4 Linux amd64 baseline')
    v=src/'internal/splicore/version/version.go';text,n=re.subn(r'(DatabaseSchema\s*=\s*)4\b',r'\g<1>5',v.read_text());assert n==1;v.write_text(text)
    m=src/'internal/splicore/storage/sqlite/migrations.go';text=m.read_text();old='{4, "0004_private_key", string(e)}}';new='{4, "0004_private_key", string(e)}, {5, "phase9_fault", "CREATE TABLE phase9_should_rollback(id INTEGER); INSERT INTO phase9_missing VALUES(1);"}}';assert text.count(old)==1;m.write_text(text.replace(old,new))
    hashes={name:hashlib.sha256((src/name).read_bytes()).hexdigest() for name in snapshot if (src/name).is_file() and not (src/name).is_symlink()}
    digest=hashlib.sha256(json.dumps(hashes,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    manifest.update(version='0.0.0-dev.2',db_schema=5,source_sha256=digest,source_dirty=True)
    ld=' '.join(f'-X {pack.VP}.{k}={value}' for k,value in {'ProductVersion':manifest['version'],'Commit':manifest['git_commit'],'Dirty':'true','BuildTime':manifest['build_time'],'SourceDigest':digest,'BuildTags':pack.TAGS}.items())
    binary=out/'fault.bin';env=dict(os.environ,CGO_ENABLED='0',GOOS='linux',GOARCH='amd64',GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local')
    subprocess.run(['go','build','-mod=readonly','-trimpath','-buildvcs=false','-tags',pack.TAGS,'-ldflags',ld,'-o',str(binary),'./cmd/splicore'],cwd=src,env=env,check=True)
    entries['splicore']=(binary.read_bytes(),0o755);manifest['files']={name:{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'mode':mode} for name,(data,mode) in sorted(entries.items())}
    entries['manifest.json']=((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode(),0o644)
    entries['SHA256SUMS']=(''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,(data,_) in sorted(entries.items())).encode(),0o644)
    artifact=out/'fault-migration.tar.gz';pack.archive(artifact,entries,1790899200)
    metadata={'fixture':'schema5 DDL then transactional failure','source_copy':str(src),'production_migrations_changed':False,'sha256':hashlib.sha256(artifact.read_bytes()).hexdigest()}
    (out/'fixture.json').write_text(json.dumps(metadata,indent=2)+'\n');print(json.dumps(metadata))

if __name__=='__main__':main()
