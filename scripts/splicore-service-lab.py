"""Disposable nested systemd lab; Linux amd64, root, systemd and cgroup v2.

start OUT prepares a NEW external native-filesystem root, bind-mounts this source
read-only and isolates mount/net/PID/UTS/IPC/cgroup namespaces. exec OUT -- CMD
enters only that owned lab. stop OUT stops only its transient host unit. No host
user, program, bootstrap or Splicore service is installed. No Docker is used.
Keep a WSL command session alive while running the lab: services alone do not
keep WSL active. This script never deletes its external evidence/rootfs.
"""
import argparse
import ctypes
import hashlib
import json
import os
import pathlib
import platform
import subprocess
import sys

REPO=pathlib.Path(__file__).resolve().parent.parent
MARKER="Splicore disposable lab 1\n"

def run(*args):
    return subprocess.run(args,check=True)

def checked(path,existing=True):
    p=pathlib.Path(path)
    if not p.is_absolute() or str(p)!=os.path.normpath(str(p)) or p.resolve()!=p or p.is_relative_to(REPO) or p in (pathlib.Path('/'),pathlib.Path('/root'),pathlib.Path('/var'),pathlib.Path('/var/lib'),pathlib.Path('/tmp')):
        raise RuntimeError('Lab output must be a dedicated clean external path')
    if existing:
        if (p/'.splicore-lab').read_text()!=MARKER or p.stat().st_uid!=0 or p.stat().st_mode & 0o077:
            raise RuntimeError('Lab ownership mismatch')
    return p

def unit(out):
    return 'splicore-lab-'+hashlib.sha256(str(out).encode()).hexdigest()[:12]

def prepare(out):
    checked(str(out),False)
    out.mkdir(mode=0o700,parents=True,exist_ok=False)
    if out.stat().st_mode&0o077:
        raise RuntimeError('Use a native Linux filesystem with private modes')
    (out/'.splicore-lab').write_text(MARKER)
    root=out/'rootfs';root.mkdir(mode=0o755);root.chmod(0o755)
    for name in ('usr','usr-local','etc/systemd/system','var/lib','var/tmp','var/log/journal','root','run','tmp','proc','sys','dev','lab','source','oldroot'):
        (root/name).mkdir(parents=True,exist_ok=True)
        (root/name).chmod(0o755)
    for name,target in (('bin','usr/bin'),('sbin','usr/sbin'),('lib','usr/lib'),('lib64','usr/lib64')):
        (root/name).symlink_to(target)
    for name in ('ld.so.cache','login.defs','os-release'):
        p=pathlib.Path('/etc')/name
        if p.is_file(): (root/'etc'/name).write_bytes(p.read_bytes())
    for name,text in {
        'passwd':'root:x:0:0:root:/root:/bin/bash\n',
        'group':'root:x:0:\n', 'shadow':'root:!:19000:0:99999:7:::\n', 'gshadow':'root:!::\n',
        'nsswitch.conf':'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n',
        'hosts':'127.0.0.1 localhost\n::1 localhost\n','resolv.conf':'nameserver 127.0.0.1\n',
        'machine-id':os.urandom(16).hex()+'\n','hostname':'splicore-p9-lab\n','splicore-lab':MARKER,
    }.items():
        p=root/'etc'/name;p.write_text(text);p.chmod(0o600 if name in ('shadow','gshadow') else 0o644)
    (root/'etc/systemd/system/splicore-p9-lab.target').write_text('[Unit]\nDescription=Disposable Splicore service lab\nDefaultDependencies=no\nWants=systemd-journald.socket systemd-journald.service\n')
    for service in ('systemd-modules-load','systemd-udevd','systemd-udev-trigger','systemd-sysctl','systemd-logind','systemd-networkd','systemd-resolved','systemd-timesyncd'):
        (root/'etc/systemd/system'/f'{service}.service').symlink_to('/dev/null')
    return root

def enter(out):
    out=checked(str(out));root=out/'rootfs'
    run('mount','--make-rprivate','/')
    run('mount','--bind',str(root),str(root))
    cg=pathlib.Path('/sys/fs/cgroup')/pathlib.Path('/proc/self/cgroup').read_text().strip().split('::')[1].lstrip('/')
    inner=cg/'inner';inner.mkdir();(inner/'cgroup.procs').write_text(str(os.getpid()))
    hostpid=pathlib.Path('/proc/self/status').read_text().split('NSpid:')[1].splitlines()[0].split()[0]
    libc=ctypes.CDLL(None,use_errno=True)
    if libc.unshare(0x02000000)!=0:raise OSError(ctypes.get_errno(),'cgroup namespace')
    for source,target,readonly in ((pathlib.Path('/usr'),root/'usr',True),(root/'usr-local',root/'usr/local',False),(out,root/'lab',False),(REPO,root/'source',True)):
        run('mount','--bind',str(source),str(target))
        if readonly:run('mount','-o','remount,bind,ro',str(target))
    run('mount','-t','proc','proc',str(root/'proc'))
    run('mount','-t','sysfs','-o','ro,nosuid,nodev,noexec','sysfs',str(root/'sys'))
    run('mount','-t','cgroup2','none',str(root/'sys/fs/cgroup'))
    for name,mode in (('run','0755'),('tmp','1777'),('dev','0755')):
        run('mount','-t','tmpfs','-o','mode='+mode+',nosuid','tmpfs',str(root/name))
    for name,major,minor in (('null',1,3),('zero',1,5),('random',1,8),('urandom',1,9)):
        run('mknod',str(root/'dev'/name),'c',str(major),str(minor));(root/'dev'/name).chmod(0o666)
    for name in ('shm','pts'):(root/'dev'/name).mkdir()
    run('mount','-t','devpts','-o','newinstance,ptmxmode=0666,mode=0620','devpts',str(root/'dev/pts'))
    (root/'dev/ptmx').symlink_to('pts/ptmx')
    console=out/'console.log';console.touch(mode=0o600);(root/'dev/console').touch()
    run('mount','--bind',str(console),str(root/'dev/console'))
    run('ip','link','set','lo','up')
    if len(subprocess.check_output(['ip','-o','link','show']).splitlines())!=1:raise RuntimeError('Non-loopback network in lab')
    (out/'lab-pid.txt').write_text(hostpid+'\n')
    os.chdir(root)
    if libc.syscall(155,b'.',b'oldroot')!=0:raise OSError(ctypes.get_errno(),'pivot_root')
    os.chdir('/');run('umount','-l','/oldroot')
    os.environ['container']='other'
    os.execv('/usr/lib/systemd/systemd',['systemd','--system','--unit=splicore-p9-lab.target','--log-target=console'])

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['start','exec','stop','enter']);p.add_argument('output',type=pathlib.Path);p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
    if sys.platform!='linux' or platform.machine()!='x86_64' or os.geteuid()!=0:p.error('Lab requires Linux amd64 root')
    if a.action=='start':
        out=checked(str(a.output),False);prepare(out)
        run('systemd-run','--unit='+unit(out),'--property=Delegate=yes','--property=KillMode=mixed','--property=TimeoutStopSec=20','--','unshare','--mount','--net','--pid','--uts','--ipc','--fork','--kill-child','python3',str(pathlib.Path(__file__).resolve()),'enter',str(out))
        print(json.dumps({'unit':unit(out),'output':str(out),'state':'starting'}))
    elif a.action=='enter':enter(a.output)
    else:
        out=checked(str(a.output))
        if a.action=='stop':run('systemctl','stop',unit(out));return
        pid=(out/'lab-pid.txt').read_text().strip()
        if not pid.isdecimal() or not os.path.samefile('/proc/'+pid+'/root',out/'rootfs'):raise RuntimeError('Owned lab PID/root no longer matches')
        args=a.command[1:] if a.command and a.command[0]=='--' else a.command
        if not args:p.error('exec requires a command')
        result=subprocess.run(['nsenter','--target',pid,'--mount','--net','--pid','--uts','--ipc','--cgroup','--root','--wd','--',*args])
        sys.exit(result.returncode)

if __name__=='__main__':main()
