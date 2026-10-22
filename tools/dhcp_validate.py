"""Dedicated stopped VM -> identical source/tests -> real DHCP -> cleanup."""
import argparse
import base64
import datetime
import fcntl
import io
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tarfile
import time
from .evidence import ROOT, manifest, fingerprint
from .dhcp_report import verify, controls, render


def main():
    if not __debug__:raise RuntimeError('Validation requires assertions')
    p=argparse.ArgumentParser();p.add_argument('--colima-home',type=Path,required=True);p.add_argument('--toolchain',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):p.error('Fresh output directory required')
    env=dict(os.environ,COLIMA_HOME=str(a.colima_home.resolve()),PATH=str(a.toolchain.resolve())+os.pathsep+os.environ.get('PATH',''))
    lock=os.open(a.colima_home/'.rulemoor-relay.lock',os.O_CREAT|os.O_RDWR,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    colima=str(a.toolchain/'colima');source=manifest()
    v=dict(passed=False,source_changed=False,run_id=secrets.token_hex(8),recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source=source,source_sha256=fingerprint(source),stages=[])
    private=out/'private-logs';private.mkdir()
    def persist():
        (out/'evidence.json').write_text(json.dumps(v,indent=2,allow_nan=False)+'\n');(out/'report.html').write_text(render(v))
    def run(name,args,timeout=60,stdin=None):
        start=time.monotonic();p=subprocess.Popen(list(map(str,args)),cwd=ROOT,env=env,text=True,stdin=subprocess.PIPE if stdin is not None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        timed=False
        try:stdout,stderr=p.communicate(stdin,timeout=timeout)
        except subprocess.TimeoutExpired:
            timed=True;os.killpg(p.pid,signal.SIGKILL);stdout,stderr=p.communicate(timeout=5)
        (private/(name+'.log')).write_text(stdout+stderr)
        v['stages'].append(dict(name=name,exit_code=p.returncode,timed_out=timed,seconds=time.monotonic()-start));persist()
        if timed or p.returncode:raise RuntimeError(name+' failed or timed out')
        return stdout
    def ssh(name,args,**kw):return run(name,[colima,'--profile','relay','ssh','--',*args],**kw)
    def status(name):
        rows=[json.loads(x) for x in run(name,[colima,'list','--json']).splitlines()]
        match=[x for x in rows if x['name']=='relay'];assert len(match)==1
        return match[0]['status']
    started=uploaded=False
    reboot=['sudo','python3','/opt/uplinkstead-dhcp/source/tools/dhcp_reboot.py']
    guest=['sudo','python3','/opt/uplinkstead-dhcp/source/tools/dhcp_guest.py']
    try:
        run('native',[sys.executable,'-m','tools.unit','--output',out/'native-unit.json'])
        v['native_unit']=json.loads((out/'native-unit.json').read_text())
        assert status('initial')=='Stopped'
        started=True
        run('start',[colima,'start','relay','--activate=false','--ssh-config=false'],timeout=180)
        ssh('preflight',['sudo','sh','-c','test ! -e /opt/uplinkstead-dhcp && test ! -e /etc/systemd/system/uplinkstead-dhcp.service && /usr/bin/busybox udhcpc --help >/dev/null 2>&1 && command -v dnsmasq'])
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
            for f in source:tar.add(ROOT/f,arcname='source/'+f,recursive=False)
        code="import pathlib,tarfile,io,sys,base64;p=pathlib.Path('/opt/uplinkstead-dhcp');p.mkdir(mode=0o700);(p/'owner').write_text(sys.argv[1]);tarfile.open(fileobj=io.BytesIO(base64.b64decode(sys.stdin.read()))).extractall(p,filter='data')"
        uploaded=True
        ssh('upload',['sudo','python3','-c',code,v['run_id']],stdin=base64.b64encode(buffer.getvalue()).decode())
        ssh('linux',['sudo','sh','-c','cd /opt/uplinkstead-dhcp/source && python3 -m tools.unit --output /opt/uplinkstead-dhcp/linux.json'])
        v['linux_unit']=json.loads(ssh('linux-read',['sudo','cat','/opt/uplinkstead-dhcp/linux.json']))
        v['guest']=json.loads(ssh('cases',guest+['run'],timeout=240))
        v['reboot_before']=json.loads(ssh('reboot-prepare',reboot+['prepare'],timeout=40))
        run('reboot-stop',[colima,'stop','relay'],timeout=120)
        assert status('reboot-between')=='Stopped'
        run('reboot-start',[colima,'start','relay','--activate=false','--ssh-config=false'],timeout=180)
        v['reboot']=json.loads(ssh('reboot-after',reboot+['after'],timeout=70))
        v['passed']=True
    except BaseException as exc:
        v['error']=type(exc).__name__+': '+str(exc).replace(str(ROOT),'<checkout>')
        if uploaded:
            try:
                ssh('diagnose',['sudo','journalctl','-u','uplinkstead-dhcp.service','--no-pager','-n','40','-b'])
                ssh('diagnose-fixture',['sudo','journalctl','-u','uplinkstead-dhcp-fixture.service','--no-pager','-n','40','-b'])
                ssh('diagnose-reboot-journal',['sudo','cat','/opt/uplinkstead-dhcp/reboot-journal-observed.json'])
                ssh('diagnose-state',['sudo','ip','netns','exec','ud_r','python3','-c',"import sys,json;sys.path.insert(0,'/opt/uplinkstead-dhcp/source');from tools.dhcp_guest import state;from uplinkstead.dhcp import config;from pathlib import Path;from uplinkstead.probe import round; s=state();print(json.dumps(s));c=config(Path('/opt/uplinkstead-dhcp/config.json'));c['links']={'A':{'interface':c['interface'],'source':s['current']['ip']}};print(round(c,'A'))"])
                ssh('diagnose-routes',['sudo','ip','-n','ud_r','route','show','table','all'])
                ssh('diagnose-server',['sudo','cat','/opt/uplinkstead-dhcp/server-private.log'])
            except BaseException:pass
    finally:
        if uploaded:
            try:
                v['reboot_cleanup']=json.loads(ssh('reboot-cleanup',reboot+['cleanup']))
                v['cleanup']=json.loads(ssh('cleanup',guest+['cleanup']))
                code="import pathlib,sys,shutil;p=pathlib.Path('/opt/uplinkstead-dhcp');assert (p/'owner').read_text()==sys.argv[1];shutil.rmtree(p)"
                ssh('remove',['sudo','python3','-c',code,v['run_id']]);v['snapshot_removed']=True
            except BaseException as exc:v.update(passed=False,cleanup_error=type(exc).__name__)
        if started:
            try:run('stop',[colima,'stop','relay'],timeout=120);v['vm_final']=status('final')
            except BaseException as exc:v.update(passed=False,stop_error=type(exc).__name__)
        v['source_changed']=manifest()!=source
        if v['passed']:
            try:verify(v);v['controls']=controls(v)
            except BaseException as exc:v.update(passed=False,verification_error=str(exc))
        persist();os.close(lock)
    print(json.dumps({k:v.get(k) for k in ('passed','run_id','error','verification_error','cleanup_error','vm_final')}))
    raise SystemExit(0 if v['passed'] else 1)


if __name__=='__main__':main()
