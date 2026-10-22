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
from tools.dhcp_fixture import monitor_script
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


def assets():
    files={SYSTEM/TOPO:fixture(),FAULT:FAULT_TEXT}
    links={SYSTEM/(g.UNIT+'.requires')/TOPO:'../'+TOPO,
           SYSTEM/'multi-user.target.wants'/g.UNIT:'../'+g.UNIT}
    directories=(FAULT.parent,SYSTEM/(g.UNIT+'.requires'))
    return files,links,directories


def preflight():
    files,links,directories=assets()
    for p in (*files,*links,*directories):
        if p.exists() or p.is_symlink():raise FileExistsError('Foreign reboot fixture object: '+str(p))
    if (ROOT/'reboot-owned.json').exists():raise FileExistsError('Reboot ledger already exists')


def inode(path):
    st=path.lstat();return dict(device=st.st_dev,inode=st.st_ino)


def install():
    preflight()  # Recheck immediately before mutation; exclusive create below.
    files,links,directories=assets()
    ledger=dict(owner=(ROOT/'owner').read_text(),files={},links={},directories={})
    def persist():store('reboot-owned',ledger)
    persist()
    for p in directories:
        p.mkdir();ledger['directories'][str(p)]=inode(p);persist()
    for p,text in files.items():
        with p.open('x') as f:
            ledger['files'][str(p)]=dict(text=text,complete=False,**inode(p));persist()
            f.write(text)
        ledger['files'][str(p)]['complete']=True;persist()
    for p,target in links.items():
        p.symlink_to(target)
        ledger['links'][str(p)]=dict(target=target,**inode(p));persist()


def prepare():
    preflight()  # Refuse conflicts before touching or freezing the running service.
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
    install()
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


def startup_receipt(service):
    def collect():
        rows=[json.loads(line) for line in g.command('journalctl','-b','-u',g.UNIT,'-o','json','--no-pager').splitlines()]
        matched=[]
        for row in rows:
            try:message=json.loads(row.get('MESSAGE',''))
            except (ValueError,TypeError):continue
            if isinstance(message,dict) and message.get('event')=='dhcp_startup_ready' and row.get('_SYSTEMD_INVOCATION_ID')==service['InvocationID']:
                matched.append(dict(message=message,**{k:row[k] for k in ('_PID','_BOOT_ID','_SYSTEMD_INVOCATION_ID','__MONOTONIC_TIMESTAMP')}))
        if len(matched)>1:raise ValueError('Duplicate startup journal receipt')
        return matched[0] if matched else None
    return g.wait(collect,timeout=3)


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
    service=g.identity();startup=startup_receipt(service)
    assert service['InvocationID']!=before['service']['InvocationID']
    assert waiting['boot']==boot_id() and waiting['session']!=before['state']['session'] and not waiting['healthy']
    # Positive control: main-table backup really works; then reset its counter.
    code="import socket,json;s=socket.create_connection(('203.0.113.2',8443),timeout=1);a=s.getsockname();b=s.getpeername();print(json.dumps(dict(local_address=a[0],local_port=a[1],peer_address=b[0],peer_port=b[1])));s.close()"
    p=g.ns('ud_r',['python3','-c',code]);control=json.loads(p.stdout)
    assert control['local_address']=='198.51.100.2' and control['peer_address']=='203.0.113.2' and control['peer_port']==8443
    warmup=g.counter();assert p.returncode==0 and warmup>0
    # Closing a successful TCP control can still emit ACK/FIN/RST afterward.
    # Isolate precisely that tuple; count every other target flow unchanged.
    g.nft('ud_b',monitor_script(control['local_port']))
    monitor=json.loads(g.ns('ud_b',['nft','-j','list','table','ip','observe']).stdout)
    assert not g.command('ip','netns','pids','ud_a').strip()
    observations=[]
    for _ in range(3):
        s=g.state();net=g.network();request=g.client()
        assert s['current'] is None and s['expires']==0 and not s['healthy'] and not request['ok']
        assert not net['data_routes'] and not net['probe_routes'] and not any(r['addr_info'] for r in net['addresses'])
        count=g.counter()
        if count:
            store('reboot-counter-failure',dict(state=s,network=net,request=request,packets=count,control=control,monitor=monitor))
        assert count==0
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
    prior_event=journal()['last_event']
    base=dict(session=s['session'],boot=s['boot'],revision=s['revision'],reason='renew',
              lease=dict(ip='192.0.2.2',subnet='255.255.255.0',router='192.0.2.1',lease='60'))
    for updates,error in ((dict(session=before['state']['session']),'RetiredSession'),
                          (dict(boot=before['boot']),'Blocked'),
                          (dict(revision=before['state']['revision']),'Blocked')):
        at=time.clock_gettime(time.CLOCK_BOOTTIME)
        q=dict(base,at=at,**updates);sent=time.clock_gettime(time.CLOCK_BOOTTIME)
        rejection=reject(q,error);completed=time.clock_gettime(time.CLOCK_BOOTTIME)
        assert prior_event<at<=sent<=completed and completed-at<=3
        assert g.state()==s and g.network()==net
        events.append(dict(event=q,rejection=rejection,sent=sent,completed=completed))
    assert g.counter()==0
    rss_identity_before=g.identity();assert rss_identity_before==service
    rss=next(x for x in Path('/proc',service['MainPID'],'status').read_text().splitlines() if x.startswith('VmRSS:'))
    rss_identity_after=g.identity();assert rss_identity_after==rss_identity_before
    return store('reboot-after',dict(passed=True,orderly_vm_restart_tested=True,power_loss_tested=False,
                 boot=boot_id(),before=before,prestart=pre,service=service,startup=startup,waiting=observations,dhcp_server_absent_while_waiting=True,
                 backup_warmup_packets=warmup,backup_control=control,backup_monitor=monitor,unverified=dict(state=new,network=unverified_net,request=unverified_request),
                 fresh=fresh,request=request,stale=dict(state_before=s,state_after=g.state(),
                 network_before=net,network_after=g.network(),events=events,prior_event=prior_event),backup_packets=g.counter(),
                 rss_snapshot=rss,rss_identity_before=rss_identity_before,rss_identity_after=rss_identity_after,seconds=time.monotonic()-began,source_sha256=fingerprint(manifest()),
                 installed_unit_sha256=hashlib.sha256((SYSTEM/g.UNIT).read_bytes()).hexdigest(),
                 fixture_sha256=hashlib.sha256((SYSTEM/TOPO).read_bytes()).hexdigest()))


def cleanup():
    p=ROOT/'reboot-owned.json'
    if not p.exists():return dict(passed=True,fixture_removed=True)
    ledger=json.loads(p.read_text())
    assert ledger['owner']==(ROOT/'owner').read_text()
    files,links,directories=assets()
    assert set(ledger['files'])<=set(map(str,files)) and set(ledger['links'])<=set(map(str,links))
    assert set(ledger['directories'])<=set(map(str,directories))
    def same(path,entry):
        assert inode(path)=={k:entry[k] for k in ('device','inode')}, 'Replaced fixture object'
    # Only actual creations are owned. Never infer ownership from equal content.
    for name,entry in ledger['links'].items():
        path=Path(name)
        if path.exists() or path.is_symlink():
            same(path,entry);assert path.is_symlink() and os.readlink(path)==entry['target'];path.unlink()
    if str(FAULT) in ledger['files'] and FAULT.exists():
        entry=ledger['files'][str(FAULT)];same(FAULT,entry)
        if entry['complete']:assert FAULT.read_text()==entry['text']
        FAULT.unlink()
        g.command('systemctl','daemon-reload')
    g.cmd(['systemctl','stop',g.UNIT],check=False)
    for name,entry in ledger['files'].items():
        path=Path(name)
        if path.exists() or path.is_symlink():
            same(path,entry);assert path.is_file() and not path.is_symlink()
            if entry['complete']:assert path.read_text()==entry['text']
            g.cmd(['systemctl','stop',path.name],check=False);path.unlink()
    for name,entry in reversed(list(ledger['directories'].items())):
        path=Path(name)
        if path.exists() or path.is_symlink():
            same(path,entry);assert path.is_dir() and not path.is_symlink();path.rmdir()
    g.command('systemctl','daemon-reload');g.cmd(['systemctl','reset-failed',TOPO],check=False)
    return dict(passed=True,fixture_removed=all(not Path(n).exists() and not Path(n).is_symlink()
                for kind in ('files','links','directories') for n in ledger[kind]))


if __name__=='__main__':
    if not __debug__:raise RuntimeError('Validation requires assertions')
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('prepare','boot','after','cleanup'));a=p.parse_args()
    print(json.dumps(globals()[a.operation](),allow_nan=False))
