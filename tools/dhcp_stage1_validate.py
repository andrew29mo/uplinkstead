"""Same-source portable tests and formal stage-one dual DHCP VM validation.

Run from the checkout. Requires an already provisioned, dedicated relay VM.
Private keys and raw logs stay in ignored results; only sanitized receipts export.
"""
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
from .dhcp_stage1_report import verify, render, controls


def main():
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    p = argparse.ArgumentParser()
    p.add_argument('--colima-home', type=Path, required=True)
    p.add_argument('--toolchain', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()): p.error('Fresh output directory required')
    env = dict(os.environ, COLIMA_HOME=str(a.colima_home.resolve()),
               PATH=str(a.toolchain.resolve())+os.pathsep+os.environ.get('PATH', ''))
    fd = os.open(a.colima_home/'.rulemoor-relay.lock', os.O_CREAT|os.O_RDWR, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
    colima = a.toolchain.resolve()/'colima'
    source = manifest()
    v = dict(passed=False, run_id=secrets.token_hex(8), source=source,
             source_sha256=fingerprint(source), source_changed=False, stages=[],
             recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
    private = out/'private-logs'; private.mkdir()
    remote = '/opt/uplinkstead-stage1'

    def persist():
        (out/'evidence.json').write_text(json.dumps(v, indent=2, allow_nan=False)+'\n')
        (out/'report.html').write_text(render(v))

    def run(name, argv, timeout=60, stdin=None):
        start = time.monotonic()
        proc = subprocess.Popen(list(map(str, argv)), cwd=ROOT, env=env, text=True,
                                stdin=subprocess.PIPE if stdin is not None else None,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        timed = False
        try: stdout, stderr = proc.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed = True; os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate(timeout=5)
        (private/(name+'.log')).write_text(stdout+stderr)
        v['stages'].append(dict(name=name, exit_code=proc.returncode, timed_out=timed,
                                seconds=time.monotonic()-start))
        persist()
        if timed or proc.returncode: raise RuntimeError(name+' failed or timed out')
        return stdout

    def ssh(name, argv, **kw):
        return run(name, [colima, '--profile', 'relay', 'ssh', '--', *argv], **kw)

    def status(name):
        rows = [json.loads(line) for line in run(name, [colima, 'list', '--json']).splitlines()]
        rows = [r for r in rows if r['name'] == 'relay']
        if len(rows) != 1: raise RuntimeError('Dedicated relay VM missing')
        return rows[0]['status']

    uploaded = started = False
    try:
        run('native', [sys.executable, '-m', 'tools.unit', '--output', out/'native-unit.json'])
        v['native_unit'] = json.loads((out/'native-unit.json').read_text())
        if status('initial') != 'Stopped': raise RuntimeError('Dedicated VM must initially be stopped')
        started = True
        run('start', [colima, 'start', 'relay', '--activate=false', '--ssh-config=false'], timeout=180)
        ssh('preflight', ['sudo', 'sh', '-c', 'test ! -e '+remote+' && command -v dnsmasq && busybox udhcpc --help >/dev/null 2>&1'])
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as tar:
            for f in source: tar.add(ROOT/f, arcname='source/'+f, recursive=False)
        code = "import pathlib,tarfile,io,sys,base64;p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o700);(p/'owner').write_text(sys.argv[2]);tarfile.open(fileobj=io.BytesIO(base64.b64decode(sys.stdin.read()))).extractall(p,filter='data')"
        uploaded = True
        ssh('upload', ['sudo', 'python3', '-c', code, remote, v['run_id']], stdin=base64.b64encode(buffer.getvalue()).decode())
        ssh('linux', ['sudo', 'sh', '-c', 'cd '+remote+'/source && python3 -m tools.unit --output '+remote+'/linux.json'])
        v['linux_unit'] = json.loads(ssh('linux-read', ['sudo', 'cat', remote+'/linux.json']))
        v['guest'] = json.loads(ssh('cases', ['sudo', 'python3', remote+'/source/tools/dhcp_stage1_guest.py', '--root', remote], timeout=300))
        v['passed'] = True
    except BaseException as exc:
        v['error'] = type(exc).__name__+': '+str(exc).replace(str(ROOT), '<checkout>')
        if uploaded:
            try: ssh('diagnose', ['sudo', 'cat', remote+'/stage1-guest.json'])
            except BaseException: pass
    finally:
        if uploaded:
            try:
                v['cleanup'] = json.loads(ssh('cleanup', ['sudo', 'python3', remote+'/source/tools/dhcp_stage1_guest.py', '--root', remote, '--cleanup']))
                # Fixture records ownership and must clean partial runs itself;
                # this command independently refuses removal with live namespaces.
                code = "import pathlib,sys,subprocess,shutil;p=pathlib.Path(sys.argv[1]);assert (p/'owner').read_text()==sys.argv[2];names=subprocess.check_output(['ip','netns','list'],text=True);assert not set(names.split())&{'dd_r','dd_c','dd_a','dd_b','dd_s'};shutil.rmtree(p)"
                ssh('remove', ['sudo', 'python3', '-c', code, remote, v['run_id']]); v['snapshot_removed'] = True
            except BaseException as exc: v.update(passed=False, cleanup_error=type(exc).__name__)
        if started:
            try:
                run('stop', [colima, 'stop', 'relay'], timeout=120)
                v['vm_final'] = status('final')
            except BaseException as exc: v.update(passed=False, stop_error=type(exc).__name__)
        v['source_changed'] = manifest() != source
        if v['passed']:
            try: verify(v); v['controls'] = controls(v)
            except BaseException as exc: v.update(passed=False, verification_error=str(exc))
        persist(); os.close(fd)
    print(json.dumps({k:v.get(k) for k in ('passed','run_id','error','verification_error','cleanup_error','vm_final')}))
    raise SystemExit(0 if v['passed'] else 1)


if __name__ == '__main__': main()
