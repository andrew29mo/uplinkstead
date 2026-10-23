"""Create a fresh unmounted Colima VM, install docs recipe, run bounded closure.

Deletes only the profile and container-data disk created by this invocation. Raw logs stay local.
"""
import argparse,base64,datetime,io,json,os,secrets,signal,subprocess,sys,tarfile,time
from pathlib import Path
from .evidence import ROOT,manifest,fingerprint
from .dhcp_client_build import digest
from .dhcp_closure_report import verify,controls,render,resource_summary

def main():
    if not __debug__:raise RuntimeError('Validation requires assertions')
    p=argparse.ArgumentParser();p.add_argument('--colima-home',type=Path,required=True);p.add_argument('--toolchain',type=Path,required=True);p.add_argument('--archive',type=Path,required=True);p.add_argument('--wheel',type=Path,required=True);p.add_argument('--profile',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not a.profile.startswith('uplinkclose-') or not all(c.isalnum() or c=='-' for c in a.profile):p.error('Dedicated uplinkclose-* profile required')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):p.error('Fresh output required')
    private=out/'private-logs';private.mkdir();source=manifest();doc=ROOT/'docs/DHCP_INSTALL.md';recipe=doc.read_text().split('```sh\n',1)[1].split('```',1)[0]
    import hashlib
    v=dict(passed=False,run_id=secrets.token_hex(8),recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source=source,source_sha256=fingerprint(source),source_changed=False,stages=[],wheel_sha256=digest(a.wheel),documentation_sha256=digest(doc),recipe_sha256=hashlib.sha256(recipe.encode()).hexdigest(),host_mounts='none',power_loss_tested=False,boot_zero_gap_tested=False)
    env=dict(os.environ,COLIMA_HOME=str(a.colima_home.resolve()),PATH=str(a.toolchain.resolve())+os.pathsep+os.environ.get('PATH',''));colima=a.toolchain.resolve()/'colima';remote='/opt/uplinkstead-close';created=False
    def persist():
        (out/'evidence.json').write_text(json.dumps(v,indent=2,allow_nan=False)+'\n');(out/'report.html').write_text(render(v))
    def run(name,args,timeout=60,stdin=None,cwd=ROOT):
        began=time.monotonic();proc=subprocess.Popen(list(map(str,args)),cwd=cwd,env=env,text=True,stdin=subprocess.PIPE if stdin is not None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);timed=False
        try:stdout,stderr=proc.communicate(stdin,timeout=timeout)
        except subprocess.TimeoutExpired:
            timed=True;os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate(timeout=5)
        except BaseException:
            os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate(timeout=5);(private/(name+'.log')).write_text(stdout+stderr);v['stages'].append(dict(name=name,exit_code=proc.returncode,timed_out=False,interrupted=True,seconds=time.monotonic()-began));persist();raise
        (private/(name+'.log')).write_text(stdout+stderr);v['stages'].append(dict(name=name,exit_code=proc.returncode,timed_out=timed,seconds=time.monotonic()-began));persist()
        if timed or proc.returncode:raise RuntimeError(name+' failed/timed out')
        return stdout
    def ssh(name,args,**kw):return run(name,[colima,'--profile',a.profile,'ssh','--',*args],**kw)
    try:
        profiles=[json.loads(line)['name'] for line in run('initial',[colima,'list','--json']).splitlines()]
        if a.profile in profiles:raise RuntimeError('Refusing existing VM profile')
        data_disk=a.colima_home.resolve()/'_lima/_disks'/('colima-'+a.profile)
        if data_disk.exists():raise RuntimeError('Refusing retained container-data disk; use a fresh name')
        v['data_disk_initially_absent']=True
        v['fresh_profile']=True;created=True
        run('create',[colima,'start',a.profile,'--cpu','2','--memory','3','--disk','15','--mount','none','--activate=false','--ssh-config=false'],timeout=180)
        v['vm']=dict(profile=a.profile,cpu=2,memory_gib=3,disk_gib=15)
        # System dependencies only; no product package/config/user in base image.
        v['baseline']=ssh('clean-baseline',['sudo','sh','-c','test ! -e /etc/uplinkstead && test ! -e /var/lib/uplinkstead-dual && ! getent passwd uplinkstead && cat /etc/os-release'])
        ssh('dependencies',['sudo','sh','-c','apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-pip python3-setuptools gcc make libc6-dev bzip2 dnsmasq-base nftables openssl iproute2 busybox'],timeout=480)
        run('native',[sys.executable,'-m','tools.unit','--output',out/'native-unit.json']);v['native_unit']=json.loads((out/'native-unit.json').read_text())
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
            for f in source:tar.add(ROOT/f,arcname='source/'+f,recursive=False)
            tar.add(doc,arcname='source/docs/DHCP_INSTALL.md',recursive=False);tar.add(a.wheel,arcname=a.wheel.name,recursive=False);tar.add(a.archive,arcname='busybox.tar.bz2',recursive=False)
            data=json.dumps(dict(files=source,sha256=v['source_sha256'])).encode();info=tarfile.TarInfo('manifest.json');info.size=len(data);tar.addfile(info,io.BytesIO(data))
        code='import pathlib,sys,tarfile,io,base64;p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o700);tarfile.open(fileobj=io.BytesIO(base64.b64decode(sys.stdin.read()))).extractall(p,filter="data")'
        ssh('upload',['sudo','python3','-c',code,remote],stdin=base64.b64encode(buffer.getvalue()).decode())
        ssh('linux',['sudo','sh','-c','cd '+remote+'/source && python3 -m tools.unit --output '+remote+'/linux-unit.json'])
        v['linux_unit']=json.loads(ssh('linux-read',['sudo','cat',remote+'/linux-unit.json']))
        ssh('client-build',['sudo','python3',remote+'/source/tools/dhcp_client_build.py','--archive',remote+'/busybox.tar.bz2','--directory',remote+'/client'],timeout=240)
        ssh('closure',['sudo','python3',remote+'/source/tools/dhcp_closure_guest.py','--root',remote],timeout=1080)
        v['guest']=json.loads(ssh('guest-read',['sudo','cat',remote+'/guest.json']));v['resources']=resource_summary(v['guest']['samples']);v['passed']=True
    except BaseException as exc:
        v['error']=type(exc).__name__+': '+str(exc).replace(str(ROOT),'<checkout>')
        if created:
            for name,args in [('guest-failed',['sudo','cat',remote+'/guest.json']),('install-failed',['sudo','cat',remote+'/install-private.log']),('journal-failed',['sudo','journalctl','-u','uplinkstead-dual.service','-u','uplinkstead-dual-policy.service','--no-pager','-n','80'])]:
                try:ssh(name,args)
                except BaseException:pass
    finally:
        if created:
            try:
                run('delete',[colima,'delete',a.profile,'--data','--force'],timeout=150)
                final=[json.loads(line)['name'] for line in run('final',[colima,'list','--json']).splitlines()]
                if a.profile in final:raise RuntimeError('Profile retained')
                v['vm_final']='Deleted';v['data_disk_removed']=not data_disk.exists()
                if not v['data_disk_removed']:raise RuntimeError('Container-data disk retained')
            except BaseException as exc:v.update(passed=False,cleanup_error=type(exc).__name__+': '+str(exc))
        v['source_changed']=manifest()!=source or digest(doc)!=v['documentation_sha256']
        if v['passed']:
            try:verify(v);v['controls']=controls(v)
            except BaseException as exc:v.update(passed=False,verification_error=type(exc).__name__+': '+str(exc))
        persist()
    print(json.dumps({k:v.get(k) for k in ('passed','run_id','error','verification_error','cleanup_error','vm_final')}));raise SystemExit(0 if v['passed'] else 1)
if __name__=='__main__':main()
