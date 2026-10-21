"""Immutable source -> dedicated stopped Colima VM -> sanitized evidence + cleanup."""
import argparse
import base64
import datetime
import fcntl
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import time
from .evidence import ROOT,manifest,fingerprint
from .report import verify,render,controls,test_ids


def main():
    p=argparse.ArgumentParser();p.add_argument('--colima-home',type=Path,required=True);p.add_argument('--toolchain',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    if any(out.iterdir()):p.error('Output must be new and empty')
    env=dict(os.environ,COLIMA_HOME=str(a.colima_home.resolve()),PATH=str(a.toolchain.resolve())+os.pathsep+os.environ.get('PATH',''))
    env.pop('DOCKER_CONTEXT',None)
    colima=str(a.toolchain.resolve()/'colima');profile='relay'
    # Share the existing VM profile lock convention used by prior projects.
    lock=os.open(a.colima_home/('.rulemoor-'+profile+'.lock'),os.O_CREAT|os.O_RDWR,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    source=manifest();v=dict(passed=False,source_changed=False,run_id=secrets.token_hex(8),recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source=source,source_sha256=fingerprint(source),stages=[])
    started=False;uploaded=False
    (out/'private-logs').mkdir()
    def persist():
        (out/'evidence.json').write_text(json.dumps(v,indent=2,allow_nan=False)+'\n');(out/'report.html').write_text(render(v))
    def run(name,args,timeout=45,stdin=None):
        begin=time.monotonic();proc=subprocess.Popen(list(map(str,args)),env=env,cwd=ROOT,text=True,stdin=subprocess.PIPE if stdin is not None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        timed=False
        try:stdout,stderr=proc.communicate(input=stdin,timeout=timeout)
        except subprocess.TimeoutExpired:
            timed=True;os.killpg(proc.pid,signal.SIGKILL);stdout,stderr=proc.communicate(timeout=5)
        (out/'private-logs'/(name+'.log')).write_text(stdout+stderr)
        v['stages'].append(dict(name=name,exit_code=proc.returncode,timed_out=timed,seconds=time.monotonic()-begin));persist()
        if proc.returncode or timed:raise RuntimeError(name+' failed or timed out')
        return stdout
    def ssh(name,args,**kw):return run(name,[colima,'--profile',profile,'ssh','--',*args],**kw)
    def state(name):
        rows=[json.loads(x) for x in run(name,[colima,'list','--json']).splitlines()]
        match=[x for x in rows if x['name']==profile];assert len(match)==1
        return match[0]['status']
    guest=['sudo','python3','/opt/uplinkstead/source/tools/guest.py']
    try:
        run('native-unit',[sys.executable,'-m','tools.unit','--output',out/'native-unit.json'])
        v['native_unit']=json.loads((out/'native-unit.json').read_text())
        v['vm_initial']=state('vm-initial');assert v['vm_initial']=='Stopped','Dedicated VM must be stopped'
        started=True
        run('vm-start',[colima,'start',profile,'--cpu','4','--memory','6','--disk','30','--vm-type','vz','--runtime','docker','--mount','none','--activate=false','--ssh-config=false','--ssh-agent=false','--vz-rosetta=false','--binfmt=false'],timeout=240)
        ssh('upload-preflight',['sudo','test','!','-e','/opt/uplinkstead'])
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
            for f in source:tar.add(ROOT/f,arcname='source/'+f,recursive=False)
        code="import pathlib,tarfile,io,sys,base64;p=pathlib.Path('/opt/uplinkstead');p.mkdir(mode=0o700);(p/'owner').write_text(sys.argv[1]);tarfile.open(fileobj=io.BytesIO(base64.b64decode(sys.stdin.read()))).extractall(p,filter='data')"
        uploaded=True
        ssh('upload',['sudo','python3','-c',code,v['run_id']],stdin=base64.b64encode(buffer.getvalue()).decode())
        ssh('setup',guest+['setup'],timeout=90)
        ssh('linux-unit',['sudo','sh','-c','cd /opt/uplinkstead/source && python3 -m tools.unit --output /opt/uplinkstead/linux-unit.json'])
        v['linux_unit']=json.loads(ssh('linux-unit-read',['sudo','cat','/opt/uplinkstead/linux-unit.json']))
        v['guest']=json.loads(ssh('cases',guest+['cases'],timeout=240))
        v['reboot_before']=json.loads(ssh('prepare',guest+['prepare'],timeout=40))
        run('vm-orderly-stop',[colima,'stop',profile],timeout=120)
        assert state('vm-between')=='Stopped'
        run('vm-restart',[colima,'start',profile,'--activate=false','--ssh-config=false'],timeout=240)
        v['reboot']=json.loads(ssh('after',guest+['after'],timeout=60))
        v['cleanup']=json.loads(ssh('cleanup',guest+['cleanup'],timeout=40))
        v['passed']=True
    except BaseException as exc:
        if uploaded:
            try:v['failure_diagnostics']=json.loads(ssh('failure-diagnostics',guest+['diagnose']))
            except BaseException:pass
        v['error']=type(exc).__name__+': '+str(exc).replace(str(ROOT),'<checkout>').replace(str(a.colima_home),'<vm-home>')
    finally:
        if uploaded:
            try:
                code="import pathlib,sys,subprocess,shutil;p=pathlib.Path('/opt/uplinkstead');assert (p/'owner').read_text()==sys.argv[1];r=subprocess.run(['python3',str(p/'source/tools/guest.py'),'cleanup'],capture_output=True,text=True) if (p/'namespace-owner.json').exists() else None;print(r.stdout if r else '{}');print(r.stderr if r else '',file=sys.stderr);assert r is None or r.returncode==0;shutil.rmtree(p)"
                value=ssh('remove',['sudo','python3','-c',code,v['run_id']],timeout=45)
                v['snapshot_removed']=True
                if 'cleanup' not in v and value.strip():v['cleanup']=json.loads(value)
            except BaseException as exc:v['cleanup_error']=str(exc)
        if started:
            try:
                run('vm-stop',[colima,'stop',profile],timeout=120);v['vm_final']=state('vm-final')
            except BaseException as exc:v['vm_cleanup_error']=str(exc)
        v['source_changed']=manifest()!=source
        if v['passed']:
            try:
                verify(v,source,test_ids());v['controls']=controls(v,source,test_ids())
            except BaseException as exc:v.update(passed=False,verification_error=type(exc).__name__+': '+str(exc))
        persist();os.close(lock)
    print(json.dumps({k:v.get(k) for k in ('passed','run_id','error','verification_error','cleanup_error','vm_final')}))
    raise SystemExit(0 if v['passed'] else 1)
if __name__=='__main__':main()
