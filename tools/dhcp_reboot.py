"""Orderly VM restart with a frozen installed DHCP service and a live journal.

Fixture-only topology runs before the unchanged transformed production unit.
It never opens Lifecycle, rewrites the journal, or starts a DHCP server at boot.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import dhcp_guest as g
from tools.evidence import manifest, fingerprint
from uplinkstead.writer import boot_id

ROOT = g.ROOT
TOPO = 'uplinkstead-dhcp-fixture.service'
SYSTEM = Path('/etc/systemd/system')
FAULT = Path('/run/systemd/system/uplinkstead-dhcp.service.d/reboot-fault.conf')
FAULT_TEXT = '[Service]\nKillSignal=SIGKILL\n'


def fixture():
    return ('[Unit]\nDescription=Disposable DHCP reboot topology\nBefore='+g.UNIT+
            '\n[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=30\nExecStart=/usr/bin/python3 '+
            str(ROOT/'source/tools/dhcp_reboot.py')+' boot\n')


def journal():
    # Read-only observation, not production recovery or repair.
    with sqlite3.connect('file:'+str(ROOT/'state/journal.sqlite')+'?mode=ro', uri=True) as db:
        return json.loads(db.execute('SELECT value FROM state WHERE id=1').fetchone()[0])


def store(name, value):
    (ROOT/(name+'.json')).write_text(json.dumps(value, indent=2)+'\n')
    return value


def prepare():
    os.kill(int((ROOT/'dnsmasq.pid').read_text()), signal.SIGCONT)
    g.command('systemctl','start',g.UNIT)
    s=g.wait(g.healthy);service=g.identity();request=g.client();net=g.network()
    assert request['ok'] and request['response']['peer']=='10.99.1.1'
    # Freeze the real service and all client callbacks before observing the
    # journal. The runtime-only SIGKILL override below prevents graceful cleanup.
    g.command('systemctl','kill','--kill-whom=all','--signal=SIGSTOP',g.UNIT)
    pid=int(service['MainPID'])
    assert '\nState:\tT' in Path('/proc',str(pid),'status').read_text()
    saved=journal()
    assert saved['current']==s['current'] and saved['boot']==boot_id() and saved['intent'] is None
    assert saved['session']==s['session'] and saved['expires']>time.clock_gettime(time.CLOCK_BOOTTIME)+20
    # systemd resumes stopped processes on SIGTERM; SIGSTOP alone cannot
    # prevent graceful journal cleanup. Inject a runtime-only shutdown kill.
    assert not FAULT.parent.exists()
    store('reboot-fault-owned',dict(path=str(FAULT),text=FAULT_TEXT))
    FAULT.parent.mkdir(parents=True);FAULT.write_text(FAULT_TEXT)
    files={TOPO:fixture()}
    links={g.UNIT+'.requires/'+TOPO:'../'+TOPO,
           'multi-user.target.wants/'+g.UNIT:'../'+g.UNIT}
    # Ledger before mutation allows cleanup after a partial fixture install.
    store('reboot-owned',dict(files=files,links=links))
    for name,text in files.items():
        p=SYSTEM/name;assert not p.exists();p.write_text(text)
    for name,target in links.items():
        p=SYSTEM/name;assert not p.exists() and not p.is_symlink()
        p.parent.mkdir(exist_ok=True);p.symlink_to(target)
    g.command('systemctl','daemon-reload')
    shutdown=dict(line.split('=',1) for line in g.command('systemctl','show',g.UNIT,'-p','KillSignal','-p','DropInPaths').splitlines())
    assert shutdown['KillSignal']=='9' and shutdown['DropInPaths']==str(FAULT)
    return store('reboot-before',dict(boot=boot_id(),state=s,journal=saved,service=service,
                 network=net,request=request,service_frozen=True,shutdown_fault=shutdown,
                 source_sha256=fingerprint(manifest()),fixture_sha256=hashlib.sha256(fixture().encode()).hexdigest()))


def boot():
    before=json.loads((ROOT/'reboot-before.json').read_text())
    assert before['boot']!=boot_id()
    # Must happen before production ExecStart. Full equality rules out graceful
    # pre-shutdown deconfig and any fixture-created replacement lease.
    saved=journal()
    store('reboot-journal-observed',dict(boot=boot_id(),journal=saved))
    assert saved==before['journal'] and saved['current'] is not None
    assert not FAULT.exists()
    g.topology();g.start_tls()
    assert g.command('systemctl','show',g.UNIT,'-p','MainPID','--value').strip()=='0'
    return store('reboot-prestart',dict(boot=boot_id(),journal=saved,network=g.network(),
                 source_sha256=fingerprint(manifest()),captured_boottime=time.clock_gettime(time.CLOCK_BOOTTIME)))


def reject(event, expected):
    # Exact formal IPC error required: setup failures/timeouts cannot pass.
    code="""import sys,json
sys.path.insert(0,'/opt/uplinkstead-dhcp/source')
from uplinkstead.dhcp_service import request
from pathlib import Path
try:request(Path('/opt/uplinkstead-dhcp/run/events.sock'),EVENT)
except RuntimeError as exc:
 if str(exc)!=EXPECTED:raise
 print(json.dumps(dict(rejected=True,error=str(exc))))
else:raise RuntimeError('stale event accepted')
""".replace('EVENT',repr(event)).replace('EXPECTED',repr(expected))
    return json.loads(g.ns('ud_r',['python3','-c',code]).stdout)


def after():
    began=time.monotonic()
    before=json.loads((ROOT/'reboot-before.json').read_text())
    pre=json.loads((ROOT/'reboot-prestart.json').read_text())
    assert boot_id()==pre['boot']!=before['boot'] and pre['journal']==before['journal']
    # The old PID file is meaningless in a new boot; never kill its reused PID.
    (ROOT/'dnsmasq.pid').unlink(missing_ok=True)
    waiting=g.wait(lambda:g.state() if g.state()['current'] is None else None)
    service=g.identity();assert service['InvocationID']!=before['service']['InvocationID']
    assert waiting['boot']==boot_id() and waiting['session']!=before['state']['session'] and not waiting['healthy']
    # Positive control: main-table backup really works; then reset its counter.
    p=g.ns('ud_r',['python3','-c',"import socket;s=socket.create_connection(('203.0.113.2',8443),timeout=1);s.close()"])
    warmup=g.counter();assert p.returncode==0 and warmup>0
    g.nft('ud_b','flush chain ip observe f\nadd rule ip observe f ip daddr 203.0.113.2 counter\n')
    assert not g.command('ip','netns','pids','ud_a').strip()
    observations=[]
    for _ in range(3):
        s=g.state();net=g.network();request=g.client()
        assert s['current'] is None and s['expires']==0 and not s['healthy'] and not request['ok']
        assert not net['data_routes'] and not net['probe_routes'] and not any(r['addr_info'] for r in net['addresses'])
        assert g.counter()==0
        observations.append(dict(state=s,network=net,request=request,backup_packets=g.counter()))
        time.sleep(1)
    # Hold TLS probes unsuccessful while a genuinely new wire lease is acquired,
    # making UNVERIFIED observable rather than inferring it from final health.
    g.nft('ud_a','add table ip reboot_hole\nadd chain ip reboot_hole f { type filter hook forward priority -50; policy accept; }\nadd rule ip reboot_hole f drop\n')
    g.ip('ud_a','route','replace','10.77.0.0/24','via','192.0.2.4')
    g.server(address='192.0.2.4',gateway='192.0.2.5')
    def leased():
        s=g.state();return s if s['current'] and s['current']['ip']=='192.0.2.4' else None
    new=g.wait(leased,timeout=25);unverified_net=g.network();unverified_request=g.client()
    assert not new['healthy'] and not unverified_net['data_routes'] and not unverified_request['ok'] and g.counter()==0
    g.nft('ud_a','delete table ip reboot_hole\n')
    fresh=g.wait(g.healthy);request=g.client();assert request['ok'] and request['response']['peer']=='10.99.1.1'
    # Stop callbacks, not the writer, while checking separate stale authorities.
    os.kill(g.child_pid(),signal.SIGSTOP)
    s=g.state();net=g.network();events=[]
    now=time.clock_gettime(time.CLOCK_BOOTTIME)
    base=dict(session=s['session'],boot=s['boot'],revision=s['revision'],at=now,reason='renew',
              lease=dict(ip='192.0.2.2',subnet='255.255.255.0',router='192.0.2.1',lease='60'))
    for updates,error in ((dict(session=before['state']['session']),'RetiredSession'),
                          (dict(boot=before['boot']),'Blocked'),
                          (dict(revision=before['state']['revision']),'Blocked')):
        q=dict(base,**updates);rejection=reject(q,error)
        assert g.state()==s and g.network()==net
        events.append(dict(event=q,rejection=rejection))
    assert g.counter()==0
    rss=next(x for x in Path('/proc',service['MainPID'],'status').read_text().splitlines() if x.startswith('VmRSS:'))
    return store('reboot-after',dict(passed=True,orderly_vm_restart_tested=True,power_loss_tested=False,
                 boot=boot_id(),before=before,prestart=pre,service=service,waiting=observations,dhcp_server_absent_while_waiting=True,
                 backup_warmup_packets=warmup,unverified=dict(state=new,network=unverified_net,request=unverified_request),
                 fresh=fresh,request=request,stale=dict(state_before=s,state_after=g.state(),
                 network_before=net,network_after=g.network(),events=events),backup_packets=g.counter(),
                 rss_snapshot=rss,seconds=time.monotonic()-began,source_sha256=fingerprint(manifest()),
                 installed_unit_sha256=hashlib.sha256((SYSTEM/g.UNIT).read_bytes()).hexdigest(),
                 fixture_sha256=hashlib.sha256((SYSTEM/TOPO).read_bytes()).hexdigest()))


def cleanup():
    fault=ROOT/'reboot-fault-owned.json'
    if fault.exists() and FAULT.exists():
        assert FAULT.read_text()==FAULT_TEXT
        FAULT.unlink();FAULT.parent.rmdir()
        g.command('systemctl','daemon-reload')
    p=ROOT/'reboot-owned.json'
    if not p.exists():return dict(passed=True,fixture_removed=True)
    ledger=json.loads(p.read_text())
    for name,target in ledger['links'].items():
        path=SYSTEM/name
        if path.is_symlink():
            assert os.readlink(path)==target;path.unlink()
    directory=SYSTEM/(g.UNIT+'.requires')
    if directory.exists():directory.rmdir()
    g.cmd(['systemctl','stop',g.UNIT],check=False)
    for name,text in ledger['files'].items():
        path=SYSTEM/name
        if path.exists():
            assert path.read_text()==text
            g.cmd(['systemctl','stop',name],check=False);path.unlink()
    g.command('systemctl','daemon-reload')
    g.cmd(['systemctl','reset-failed',TOPO],check=False)
    return dict(passed=True,fixture_removed=all(not (SYSTEM/n).exists() for n in ledger['files']) and
                all(not (SYSTEM/n).is_symlink() for n in ledger['links']))


if __name__=='__main__':
    if not __debug__:raise RuntimeError('Validation requires assertions')
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('prepare','boot','after','cleanup'));a=p.parse_args()
    print(json.dumps(globals()[a.operation](),allow_nan=False))
