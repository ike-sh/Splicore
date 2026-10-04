"""Owned disposable Linux install/upgrade gate with no downloads.

Requires explicitly pinned local A/B packages, a separately built failing-forward
migration fixture, and Phase 6/8 reference clients. See DISTRIBUTION.md. All
service mutations occur inside splicore-service-lab.py. Fixture/source/output
paths must be external and private. Never run this inner driver on a host.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import select
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import time

sys.dont_write_bytecode=True
REPO=pathlib.Path(__file__).resolve().parent.parent

def digest(path):return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def command(*args,check=True):
    p=subprocess.run(args,capture_output=True,timeout=180)
    if check and p.returncode:raise RuntimeError('gate command failed: '+args[0])
    return p

def database_rows():
    with sqlite3.connect('/var/lib/splicore/state.db') as db:
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert not db.execute('PRAGMA foreign_key_check').fetchall()
        return {name:sorted(db.execute('SELECT * FROM "'+name+'"').fetchall(),key=repr)
                for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")}

def verify_forward_upgrade(before,after):
    old_schema=dict(before['metadata'])['db_schema']
    new_schema=dict(after['metadata'])['db_schema']
    if old_schema==new_schema:
        assert after==before
        return
    assert old_schema in ('6','7') and new_schema=='8'
    additions={'client_management_profiles','provider_sources'}
    if old_schema=='6':additions.add('client_host_profiles')
    assert set(after)==set(before)|additions
    for table,rows in before.items():
        if table not in ('metadata','schema_migrations'):
            assert after[table]==rows,table
    metadata=dict(before['metadata']);metadata['db_schema']='8'
    assert dict(after['metadata'])==metadata
    old=before['schema_migrations'];new=after['schema_migrations']
    assert new[:len(old)]==old and len(new)==8
    for row in new[len(old):]:
        number,name,checksum=row[:3]
        migration=(REPO/'internal/splicore/storage/sqlite/migrations'/f'{name}.sql').read_bytes()
        assert checksum==hashlib.sha256(migration).hexdigest()
    singleton,document=after['client_management_profiles'][0]
    assert singleton==1 and json.loads(document)=={'providers':[]} and after['provider_sources']==[]
    if old_schema=='6':
        singleton,document=after['client_host_profiles'][0]
        assert singleton==1 and json.loads(document)=={'system_proxy':{'enabled':False}}

def host_snapshot():
    return {**{key:command('ip','-'+family,'-j',kind,'show',*(['table','all'] if kind=='route' else [])).stdout
               for family in ('4','6') for kind in ('route','rule') for key in [family+'-'+kind]},
            'dns':pathlib.Path('/etc/resolv.conf').read_bytes()}

def inner():
    if pathlib.Path('/etc/splicore-lab').read_text()!='Splicore disposable lab 1\n':raise RuntimeError('This is not an owned disposable lab')
    spec=importlib.util.spec_from_file_location('smoke',REPO/'scripts/splicore-installed-smoke.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
    out=pathlib.Path('/lab');results={}
    def run(label,*args,check=True):
        p=command(*args,check=False);(out/(label+'.log')).write_bytes(p.stdout+p.stderr)
        if check and p.returncode:raise RuntimeError('gate failed: '+label)
        return p
    def install(label,file,check=True):return run(label,'sh','/source/scripts/install.sh','--artifact','/lab/'+file,'--sha256',digest(out/file),'--start',check=check)
    def smoke(stage):
        run(stage+'-smoke','python3','/source/scripts/splicore-installed-smoke.py',stage)
        run(stage+'-client','python3','/source/scripts/splicore-client-smoke.py',stage)
        run(stage+'-expansion','python3','/source/scripts/splicore-client-expansion-smoke.py',stage)
    def system():return s.request('GET','/api/v1/system')
    def page():return s.request('GET','/api/v1/inbounds')
    def unit(*args):
        p=command('systemctl',*args,check=False)
        if p.returncode:
            status=command('systemctl','status','splicore.service','--no-pager',check=False)
            (out/'unit-failure.log').write_bytes(p.stdout+p.stderr+status.stdout+status.stderr)
            raise RuntimeError('gate systemd operation failed')
        return p
    def db_snapshot():
        db=sqlite3.connect('/var/lib/splicore/state.db');data={}
        for name, in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
            data[name]=hashlib.sha256(repr(sorted(db.execute('SELECT * FROM "'+name+'"').fetchall(),key=repr)).encode()).hexdigest()
        assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok';assert not db.execute('PRAGMA foreign_key_check').fetchall();db.close();return data
    install('clean-install','package-a.tar.gz');assert system()['health']=='healthy';assert not page()['items'];results['clean_install']='PASS'
    smoke('initial');assert len(page()['items'])==6
    pid=int(unit('show','splicore.service','-p','MainPID','--value').stdout)
    status=pathlib.Path('/proc/'+str(pid)+'/status').read_text()
    uid=int(status.split('Uid:')[1].splitlines()[0].split()[0]);cap=int(status.split('CapEff:')[1].splitlines()[0].strip(),16)
    assert uid!=0 and cap==1<<10
    assert int(pathlib.Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text())==1024
    modes={path:oct(pathlib.Path(path).stat().st_mode&0o777) for path in ['/etc/splicore/splicore.yaml','/var/lib/splicore/state.db','/var/lib/splicore/master.key','/var/lib/splicore','/run/splicore']}
    assert modes['/etc/splicore/splicore.yaml']=='0o640';assert modes['/var/lib/splicore/state.db']=='0o600';assert modes['/var/lib/splicore/master.key']=='0o600';assert modes['/var/lib/splicore']=='0o700';assert modes['/run/splicore']=='0o700'
    (out/'permissions.json').write_text(json.dumps({'uid':uid,'effective_capabilities':'CAP_NET_BIND_SERVICE only','low_port_threshold':1024,'modes':modes},indent=2)+'\n')
    results['non_root_low_ports']='PASS'
    run('doctor','/usr/local/bin/splicore','doctor','--config','/etc/splicore/splicore.yaml')
    old=page();parent=int(unit('show','splicore.service','-p','MainPID','--value').stdout);pfd=os.pidfd_open(parent)
    try:
        unit('restart','splicore.service');assert page()['snapshot_revision']==old['snapshot_revision'];assert select.select([pfd],[],[],10)[0]
    finally:os.close(pfd)
    smoke('restart');results['restart']='PASS'
    parent=int(unit('show','splicore.service','-p','MainPID','--value').stdout);pfd=os.pidfd_open(parent)
    signal.pidfd_send_signal(pfd,signal.SIGKILL);assert select.select([pfd],[],[],10)[0];os.close(pfd)
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        values=unit('show','splicore.service','-p','ActiveState','-p','SubState','-p','MainPID').stdout.decode()
        if 'ActiveState=active\n' in values and 'SubState=running\n' in values and int(unit('show','splicore.service','-p','MainPID','--value').stdout)!=parent:break
    else:raise RuntimeError('systemd crash recovery deadline')
    assert len(page()['items'])==6
    db_snapshot();smoke('crash-recovery');results['daemon_crash']='PASS'
    before=db_snapshot();upgrade_rows=database_rows();host_before=host_snapshot();key=digest('/var/lib/splicore/master.key');bootstrap=digest('/etc/splicore/splicore.yaml')
    # Each campaign deliberately restarts the same disposable unit repeatedly.
    # Reset only its start counter between independent install scenarios; leave
    # production unit policy intact and never retry a failed operation.
    unit('reset-failed','splicore.service')
    results['campaign_start_counter']='reset between independent lab scenarios; production policy unchanged'
    install('normal-upgrade','package-b.tar.gz');verify_forward_upgrade(upgrade_rows,database_rows());assert host_snapshot()==host_before;assert digest('/var/lib/splicore/master.key')==key;assert 'xray' not in pathlib.Path('/etc/splicore/splicore.yaml').read_text()
    results['upgrade_without_host_mutation']='PASS'
    smoke('upgrade');results['upgrade']='PASS'
    files={p:digest(p) for p in ['/usr/local/bin/splicore','/etc/systemd/system/splicore.service','/etc/splicore/install.json','/etc/splicore/splicore.yaml','/var/lib/splicore/master.key']};before=db_snapshot()
    assert install('failed-upgrade','fault-migration.tar.gz',False).returncode!=0
    assert db_snapshot()==before;assert all(digest(p)==value for p,value in files.items());assert system()['health']=='healthy'
    smoke('rollback');results['failed_migration_rollback']='PASS'
    # Send raw synthetic secrets from a temporary ExecStartPre belonging to this
    # actual unit, then remove the test drop-in before any installer operation.
    secrets=json.loads((out/'installed/synthetic-secrets.json').read_text())+['SyntheticSnellPSKPhase9','SyntheticREALITYPrivateKeyPhase9','SyntheticAPITokenPhase9']
    # Some WSL hosts restrict traversal of /usr/bin to root. Copy this sole local
    # test helper into the private lab's public bin directory; host modes stay intact.
    helper=pathlib.Path('/usr/local/bin/secret-log-fixture');shutil.copyfile('/usr/bin/printf',helper);helper.chmod(0o755)
    dropin=pathlib.Path('/etc/systemd/system/splicore.service.d');dropin.mkdir();(dropin/'secret-fixture.conf').write_text('[Service]\nExecStartPre=/usr/local/bin/secret-log-fixture "'+','.join(secrets)+'\\n"\n')
    unit('daemon-reload');unit('restart','splicore.service');(dropin/'secret-fixture.conf').unlink();dropin.rmdir();helper.unlink();unit('daemon-reload')
    support=pathlib.Path('/var/tmp/support');support.mkdir(mode=0o700);archive=support/'bundle.tar.gz'
    run('support-bundle','/usr/local/bin/splicore','support-bundle','--config','/etc/splicore/splicore.yaml','--output',str(archive))
    raw=command('journalctl','-u','splicore.service','--no-pager','-n','128').stdout;assert any(value.encode() in raw for value in secrets)
    with tarfile.open(archive) as tar:
        for member in tar:
            data=tar.extractfile(member).read();assert not any(value.encode() in data for value in secrets),'BLOCKING support secret gate'
    assert archive.stat().st_mode&0o777==0o600;shutil.copyfile(archive,out/'support.tar.gz');(out/'support.tar.gz').chmod(0o600);results['support_secret_gate']='PASS'
    unit('reset-failed','splicore.service')
    before=db_snapshot();run('uninstall','/usr/local/bin/splicore','package','uninstall');assert not pathlib.Path('/usr/local/bin/splicore').exists();assert db_snapshot()==before;assert digest('/var/lib/splicore/master.key')==key
    install('reinstall','package-b.tar.gz');assert db_snapshot()==before;smoke('reinstall');results['uninstall_retains_state']='PASS';results['reinstall']='PASS'
    # Symlink and same-filesystem bind mounts cannot become purge targets.
    link=pathlib.Path('/var/lib/splicore/foreign');link.symlink_to('/var/tmp');assert run('unsafe-purge-symlink','/usr/local/bin/splicore','package','uninstall','--purge',check=False).returncode!=0;link.unlink()
    mount=pathlib.Path('/var/lib/splicore/foreign-mount');mount.mkdir();command('mount','--bind','/var/tmp',str(mount))
    try:assert run('unsafe-purge-mount','/usr/local/bin/splicore','package','uninstall','--purge',check=False).returncode!=0
    finally:command('umount',str(mount));mount.rmdir()
    assert system()['health']=='healthy';results['purge_path_safety']='PASS'
    run('purge','/usr/local/bin/splicore','package','uninstall','--purge')
    assert all(not pathlib.Path(p).exists() for p in ['/usr/local/bin/splicore','/etc/splicore','/var/lib/splicore','/var/lib/splicore-upgrades']);results['purge']='PASS'
    (out/'distribution-gate.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(results))

def main():
    if len(sys.argv)==2 and sys.argv[1]=='--inner':inner();return
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--package-a',type=pathlib.Path,required=True);p.add_argument('--sha256-a',required=True);p.add_argument('--package-b',type=pathlib.Path,required=True);p.add_argument('--sha256-b',required=True);p.add_argument('--fault-package',type=pathlib.Path,required=True);p.add_argument('--sha256-fault',required=True);p.add_argument('--clients',type=pathlib.Path,required=True);a=p.parse_args()
    for path,sha in [(a.package_a,a.sha256_a),(a.package_b,a.sha256_b),(a.fault_package,a.sha256_fault)]:
        if path.is_symlink() or digest(path)!=sha:p.error('Pinned local package mismatch')
    lab=REPO/'scripts/splicore-service-lab.py'
    subprocess.run(['python3',str(lab),'start',str(a.output)],check=True)
    try:
        for source,name in [(a.package_a,'package-a.tar.gz'),(a.package_b,'package-b.tar.gz'),(a.fault_package,'fault-migration.tar.gz')]:shutil.copyfile(source,a.output/name);(a.output/name).chmod(0o600)
        shutil.copytree(a.clients,a.output/'clients')
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            r=command('python3',str(lab),'exec',str(a.output),'--','systemctl','is-active','splicore-p9-lab.target',check=False)
            if r.returncode==0:break
        else:raise RuntimeError('nested systemd readiness deadline')
        r=command('python3',str(lab),'exec',str(a.output),'--','python3','/source/scripts/splicore-distribution-gate.py','--inner',check=False)
        (a.output/'gate-console.log').write_bytes(r.stdout+r.stderr)
        if r.returncode:raise RuntimeError('Distribution gate failed; inspect private external gate logs')
        print((a.output/'distribution-gate.json').read_text())
    finally:subprocess.run(['python3',str(lab),'stop',str(a.output)],check=True)

if __name__=='__main__':main()
