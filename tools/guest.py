"""All networking actions are confined to owned disposable namespaces in a dedicated VM."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from uplinkstead.config import load
from uplinkstead.writer import Writer,boot_id,now
from uplinkstead.policy import Policy,Settings
from uplinkstead.probe import one,round as probe_round
from uplinkstead.linux import Linux,Blocked,TABLE
from tools.evidence import manifest,fingerprint
from tools.netproof import digest

ROOT=Path('/opt/uplinkstead')
NAMES=['us_r','us_c','us_a','us_b','us_s','us_o']
WORKER='uplinkstead-policy.service'
UNIT='uplinkstead.service';TOPO='uplinkstead-fixture.service';SERVER='uplinkstead-fixture-server.service'
STATE=ROOT/'state';CONF=ROOT/'config.json'


def cmd(args,check=True,timeout=15):
    p=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=timeout)
    if check and p.returncode:raise RuntimeError('Command failed: '+str(args[:4])+': '+p.stderr[:5000])
    return p


def ns(name,args,**kwargs):return cmd(['ip','netns','exec',name,*args],**kwargs)
def ip(name,*args):return cmd(['ip','-n',name,*args])
def nft(name,script):
    p=subprocess.run(['ip','netns','exec',name,'nft','-f','-'],input=script,text=True,capture_output=True,timeout=10)
    if p.returncode:raise RuntimeError(p.stderr)

def system(name,*args):return cmd(['systemctl',*args,name])
def db():
    with sqlite3.connect(STATE/'journal.sqlite') as c:return json.loads(c.execute('SELECT value FROM state').fetchone()[0])

def client(name='us_c',port=8443,address='203.0.113.2'):
    # Real unmarked new TLS flow, using a fresh source port each invocation.
    code="""import socket,ssl,json,secrets
n=secrets.token_hex(12)
c=ssl.create_default_context(cafile='/opt/uplinkstead/ca.crt')
with socket.create_connection(('203.0.113.2',8443),timeout=1) as r:
 with c.wrap_socket(r,server_hostname='probe.test') as s:
  s.sendall(('GET /'+n+' HTTP/1.0\\r\\nHost: probe.test\\r\\n\\r\\n').encode());b=b''
  while True:
   x=s.recv(4096)
   if not x:break
   b+=x
  h,j=b.split(b'\\r\\n\\r\\n',1);v=json.loads(j);assert v['nonce']==n and v['ok'];print(json.dumps(v))
"""
    code=code.replace('8443',str(int(port))).replace('203.0.113.2',address)
    p=ns(name,['python3','-c',code],check=False,timeout=4)
    return dict(ok=p.returncode==0,result=json.loads(p.stdout) if p.returncode==0 else None,error=None if p.returncode==0 else 'request_failed')

def remote(code):
    p=ns('us_r',['python3','-c',"import sys;sys.path.insert(0,'/opt/uplinkstead/source');"+code])
    return json.loads(p.stdout)

def select(target):return remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.writer import Writer;\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w:\n w.switch(w.s['epoch'],"+repr(target)+");print(__import__('json').dumps(w.s))")

def blocked(rule=False):
    code="from pathlib import Path;from uplinkstead.config import load;from uplinkstead.writer import Writer;from uplinkstead.linux import Blocked\ntry:\n with Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w: pass\nexcept (Blocked,BlockingIOError):print('true')\nelse:print('false')"
    return remote(code)

def spawn_local_server():
    p=subprocess.Popen(['ip','netns','exec','us_r','python3',str(ROOT/'source/tools/server.py'),str(ROOT/'ca.crt'),str(ROOT/'server.key'),'--address','10.77.0.1','--ports','9443'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    time.sleep(.2)
    if p.poll() is not None:raise RuntimeError('Local TLS fixture failed')
    return p


@contextmanager
def drive():
    with (ROOT/'driver-private.log').open('a') as err:
        p=subprocess.Popen(['ip','netns','exec','us_r','python3',str(ROOT/'source/tools/drive.py'),str(CONF),str(STATE)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,text=True,bufsize=1)
        try:
            ready=json.loads(p.stdout.readline());assert ready['ready'] is True
            def tick():
                p.stdin.write(json.dumps(dict(command='tick'))+'\n');p.stdin.flush()
                return json.loads(p.stdout.readline())
            yield tick
            p.stdin.close();assert p.wait(timeout=5)==0
        finally:
            if p.poll() is None:kill(p)
            p.stdout.close()


def dump_rules():return json.loads(ip('us_r','-j','rule','show').stdout)
def routes():return json.loads(ip('us_r','-j','route','show','table','41003').stdout)

def wait_stopped(p, helper=False):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if p.poll() is not None:raise RuntimeError('Fault worker exited before boundary')
        if helper:
            children=(Path('/proc')/str(p.pid)/'task'/str(p.pid)/'children').read_text().split()
            if children and 'State:\tT' in Path('/proc',children[0],'status').read_text():return int(children[0])
        status=Path('/proc')/str(p.pid)/'status'
        if 'State:\tT' in status.read_text():return
        time.sleep(.02)
    raise TimeoutError('Fault worker did not stop')

def fault(mode,target='B',epoch=None):
    args=['ip','netns','exec','us_r','python3',ROOT/'source/tools/fault.py',mode,CONF,STATE,target]
    if epoch is not None:args+=['--epoch',str(epoch)]
    p=subprocess.Popen(list(map(str,args)),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    p.held_child=wait_stopped(p,mode=='helper-held');return p


def kill(p):
    p.kill();p.wait(timeout=5)

def holes(link,on=True):
    name='us_a' if link=='A' else 'us_b'
    if on:
        nft(name,'add table ip hole\nadd chain ip hole forward { type filter hook forward priority -50; policy accept; }\nadd rule ip hole forward drop\n')
    else:nft(name,'delete table ip hole\n')


def root_snapshot():
    return dict(rules=json.loads(cmd(['ip','-j','rule']).stdout),
                routes=json.loads(cmd(['ip','-j','route','show','table','all']).stdout),
                nft=cmd(['nft','-j','list','ruleset']).stdout,
                iptables=cmd(['iptables-save']).stdout,ip6tables=cmd(['ip6tables-save']).stdout)


def topology():
    existing={line.split()[0] for line in cmd(['ip','netns','list']).stdout.splitlines() if line}
    if existing.intersection(NAMES):raise RuntimeError('Preexisting namespace')
    # On reboot capture pending journal BEFORE reconstructing namespaces/services.
    before=dict(boot=boot_id(),pending=db().get('pending'),selected=db().get('selected')) if (STATE/'journal.sqlite').exists() else None
    if before:(ROOT/'prestart.json').write_text(json.dumps(before))
    ledger=ROOT/'namespace-owner.json'
    if ledger.exists():
        data=json.loads(ledger.read_text());assert data['owner']==(ROOT/'owner').read_text()
    else:data=dict(owner=(ROOT/'owner').read_text(),names=[])
    data['names']=[];ledger.write_text(json.dumps(data))
    for name in NAMES:
        cmd(['ip','netns','add',name]);data['names'].append(name);ledger.write_text(json.dumps(data))
        ip(name,'link','set','lo','up')
    pairs=[('us_r','lan0','10.77.0.1/24','us_c','eth0','10.77.0.2/24'),
           ('us_r','other0','10.78.0.1/24','us_o','eth0','10.78.0.2/24'),
           ('us_r','wanA','192.0.2.2/30','us_a','edge','192.0.2.1/30'),
           ('us_r','wanB','192.0.2.6/30','us_b','edge','192.0.2.5/30'),
           ('us_a','transit','10.99.1.1/30','us_s','viaA','10.99.1.2/30'),
           ('us_b','transit','10.99.2.1/30','us_s','viaB','10.99.2.2/30')]
    for left,li,la,right,ri,ra in pairs:
        cmd(['ip','link','add','name',li,'netns',left,'type','veth','peer','name',ri,'netns',right])
        for name,iface,addr in ((left,li,la),(right,ri,ra)):
            ip(name,'addr','add',addr,'dev',iface);ip(name,'link','set',iface,'up')
    for name in NAMES:
        ns(name,['sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=2','net.ipv4.conf.default.rp_filter=2'])
        for iface in json.loads(ip(name,'-j','link').stdout):
            ns(name,['sysctl','-qw','net.ipv4.conf.'+iface['ifname']+'.rp_filter=2'])
    for name in ('us_c','us_o'):ip(name,'route','add','default','via','10.77.0.1' if name=='us_c' else '10.78.0.1')
    ip('us_r','route','add','default','via','192.0.2.1')
    ip('us_r','route','add','default','via','192.0.2.5','metric','200')
    ip('us_r','route','add','198.18.0.0/24','via','192.0.2.1')
    ip('us_s','addr','add','203.0.113.2/32','dev','lo')
    for k,num in (('a',1),('b',2)):
        ip('us_'+k,'route','add','203.0.113.2/32','via',f'10.99.{num}.2')
        ip('us_'+k,'route','add','10.77.0.0/24','via','192.0.2.2' if k=='a' else '192.0.2.6')
        ip('us_'+k,'route','add','10.78.0.0/24','via','192.0.2.2' if k=='a' else '192.0.2.6')
        ip('us_s','route','add','192.0.2.0/30' if k=='a' else '192.0.2.4/30','via',f'10.99.{num}.1')
        nft('us_'+k,f'add table ip fixture_nat\nadd chain ip fixture_nat post {{ type nat hook postrouting priority srcnat; policy accept; }}\nadd rule ip fixture_nat post oifname "transit" snat to 10.99.{num}.1\n')
        # A probe source on B's outward path would demonstrate forbidden borrowing.
        nft('us_'+k,'add table ip observe\nadd chain ip observe forward { type filter hook forward priority -100; policy accept; }\nadd rule ip observe forward oifname "transit" ip saddr 192.0.2.2 counter comment "source_A"\nadd rule ip observe forward oifname "transit" ip saddr 192.0.2.6 counter comment "source_B"\n')
    (ROOT/'topology-ready').write_text(boot_id())


def preflight():
    if Path('/proc/1/comm').read_text().strip()!='systemd':raise RuntimeError('systemd required')
    existing={line.split()[0] for line in cmd(['ip','netns','list']).stdout.splitlines() if line}
    if existing.intersection(NAMES):raise RuntimeError('Foreign namespace')
    for unit in (UNIT,WORKER,TOPO,SERVER):
        if Path('/etc/systemd/system',unit).exists():raise RuntimeError('Foreign unit file')
        r=cmd(['systemctl','show',unit,'-p','LoadState','-p','FragmentPath','-p','DropInPaths']).stdout
        if 'LoadState=not-found' not in r or 'FragmentPath=\n' not in r or 'DropInPaths=\n' not in r:raise RuntimeError('Foreign unit definition')
    assert not cmd(['docker','ps','-q']).stdout.strip(),'Dedicated idle VM required'


def setup():
    preflight()
    (ROOT/'root-before.json').write_text(json.dumps(root_snapshot()))
    # Private fixture credentials never leave the VM.
    cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',ROOT/'server.key','-out',ROOT/'ca.crt','-days','2','-subj','/CN=probe.test','-addext','subjectAltName=DNS:probe.test'])
    from tests.test_core import config
    c=config();c['ca']=str(ROOT/'ca.crt');CONF.write_text(json.dumps(c))
    STATE.mkdir(mode=0o700)
    topology()
    # Dedicated policy identity; never reuse or delete a preexisting account.
    import pwd
    try:pwd.getpwnam('uplinkstead')
    except KeyError:pass
    else:raise RuntimeError('Foreign uplinkstead account')
    cmd(['systemd-sysusers',ROOT/'source/deploy/uplinkstead.conf'])
    (ROOT/'user-created').write_text('uplinkstead')
    ROOT.chmod(0o755);CONF.chmod(0o600);(ROOT/'server.key').chmod(0o600)
    original=(ROOT/'source/deploy/uplinkstead.service').read_text()
    # Only executable/source/config/state and network namespace paths differ.
    unit=original.replace('/etc/uplinkstead/config.json',str(CONF)).replace('/var/lib/uplinkstead',str(STATE))
    unit=unit.replace('[Service]','[Service]\nWorkingDirectory=/opt/uplinkstead/source\nNetworkNamespacePath=/run/netns/us_r')
    unit=unit.replace('[Unit]','[Unit]\nRequires=uplinkstead-fixture.service uplinkstead-fixture-server.service\nAfter=uplinkstead-fixture.service uplinkstead-fixture-server.service')
    (ROOT/'service-installed').write_text(unit)
    worker=(ROOT/'source/deploy/uplinkstead-policy.service').read_text().replace('[Service]','[Service]\nWorkingDirectory=/opt/uplinkstead/source')
    units={UNIT:unit,WORKER:worker,TOPO:'[Unit]\nBefore=uplinkstead.service uplinkstead-fixture-server.service\n[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/python3 /opt/uplinkstead/source/tools/guest.py topology\n',
           SERVER:'[Unit]\nRequires=uplinkstead-fixture.service\nAfter=uplinkstead-fixture.service\n[Service]\nNetworkNamespacePath=/run/netns/us_s\nExecStart=/usr/bin/python3 /opt/uplinkstead/source/tools/server.py /opt/uplinkstead/ca.crt /opt/uplinkstead/server.key\nKillMode=control-group\n'}
    # Current boot topology already provisioned; next boot uses the topology unit.
    (ROOT/'unit-hashes.json').write_text(json.dumps({n:hashlib.sha256(b.encode()).hexdigest() for n,b in units.items()}))
    for name,body in units.items():Path('/etc/systemd/system',name).write_text(body)
    cmd(['systemctl','daemon-reload']);cmd(['systemctl','start',SERVER,'--job-mode=ignore-dependencies'])
    # Mark topology active with a temporary no-op start override, then remove it.
    drop=Path('/etc/systemd/system',TOPO+'.d');drop.mkdir();(drop/'current.conf').write_text('[Service]\nExecStart=\nExecStart=/usr/bin/true\n')
    cmd(['systemctl','daemon-reload']);cmd(['systemctl','start',TOPO]);(drop/'current.conf').unlink();drop.rmdir();cmd(['systemctl','daemon-reload'])
    time.sleep(.3)


def counter(link,source):
    j=json.loads(ns('us_'+link.lower(),['nft','-j','list','table','ip','observe']).stdout)
    rows=[x['rule'] for x in j['nftables'] if 'rule' in x]
    row=next(x for x in rows if x.get('comment')=='source_'+source)
    return next(x['counter']['packets'] for x in row['expr'] if 'counter' in x)


def run_cases():
    result=dict(passed=False,source_sha256=fingerprint(manifest()),boot=boot_id(),cases=[])
    def case(name,fn):
        began=time.monotonic();details=fn()
        result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-began,details=details))
        (ROOT/'guest.json').write_text(json.dumps(result,indent=2))
    def probe_checks():
        r=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;from uplinkstead.writer import Writer;import json\nc=load(Path('/opt/uplinkstead/config.json'))\nwith Writer(c,'/opt/uplinkstead/state'):print(json.dumps({k:round(c,k) for k in ('A','B')}))")
        assert r['A'][0]==r['B'][0]==3
        assert all(x['peer_observed']=='10.99.1.1' for x in r['A'][1]);assert all(x['peer_observed']=='10.99.2.1' for x in r['B'][1])
        return r
    case('pinned_healthy_probes',probe_checks)
    def no_borrow():
        checks=[]
        for link in ('A','B'):
            other='B' if link=='A' else 'A';before=counter(other,link);holes(link)
            r=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;c=load(Path('/opt/uplinkstead/config.json'));print(json.dumps({k:round(c,k) for k in ('A','B')}))")
            assert r[link][0]==0 and r[other][0]==3, (link,r)
            assert counter(other,link)==before
            holes(link,False)
            # Delete the fixed probe route while main's default is available.
            ip('us_r','route','del','default','table',TABLE[link])
            v=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;print(json.dumps(round(load(Path('/opt/uplinkstead/config.json')),"+repr(link)+")))")
            assert v[0]==0 and counter(other,link)==before
            # Route lookup also proves the terminal RPDB path, independently of
            # SO_BINDTODEVICE's additional device constraint.
            lookup=cmd(['ip','-n','us_r','route','get','203.0.113.2','mark',hex(0x5101 if link=='A' else 0x5102),'iif','lo'],check=False)
            assert lookup.returncode!=0
            c=load(CONF);vlink=c['links'][link]
            ip('us_r','route','add','default','via',vlink['gateway'],'dev',vlink['interface'],'table',TABLE[link],'metric','100')
            ip('us_r','link','set',vlink['interface'],'down')
            down=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;print(json.dumps(round(load(Path('/opt/uplinkstead/config.json')),"+repr(link)+")))")
            assert down[0]==0 and counter(other,link)==before
            ip('us_r','link','set',vlink['interface'],'up')
            time.sleep(.2)
            # main belongs to the external static-network provisioner. Its own
            # link-down routes are restored by the fixture, never by Uplinkstead.
            if link=='A':ip('us_r','route','replace','default','via','192.0.2.1');ip('us_r','route','replace','198.18.0.0/24','via','192.0.2.1')
            else:ip('us_r','route','replace','default','via','192.0.2.5','metric','200')
            remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.writer import Writer\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state'):print('true')")
            checks.append(dict(link=link,blackhole=r[link],other=r[other],missing_route=v,link_down=down,wrong_egress_packets=counter(other,link)-before,terminal_lookup_rejected=lookup.returncode!=0))
        return checks
    case('probe_blackhole_missing_route_link_down',no_borrow)
    def binding_error():
        r=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;c=load(Path('/opt/uplinkstead/config.json'));c['links']['A']['interface']='absent0';print(json.dumps(round(c,'A')))")
        assert r[0] is None and all(x['infrastructure'] for x in r[1]);return r
    case('binding_error_unknown',binding_error)
    def scope():
        main_before=json.loads(ip('us_r','-j','route','show','table','main').stdout)
        local=spawn_local_server()
        try:
            select('A');a=client();host_a=client('us_r');other_a=client('us_o');local_a=client(port=9443,address='10.77.0.1')
            select('B');b=client();host_b=client('us_r');other_b=client('us_o');local_b=client(port=9443,address='10.77.0.1')
        finally:kill(local)
        assert a['ok'] and a['result']['peer']=='10.99.1.1'
        assert b['ok'] and b['result']['peer']=='10.99.2.1'
        assert all(x['ok'] and x['result']['peer']=='10.99.1.1' for x in (host_a,host_b,other_a,other_b))
        assert all(r['ok'] and r['result']['server']=='10.77.0.1' and r['result']['peer']=='10.77.0.2' for r in (local_a,local_b))
        assert main_before==json.loads(ip('us_r','-j','route','show','table','main').stdout)
        internal=ip('us_r','-j','route','get','198.18.0.1','from','10.77.0.2','iif','lan0').stdout
        assert json.loads(internal)[0]['gateway']=='192.0.2.1'
        denied=cmd(['ip','-n','us_r','route','get','198.18.1.1','from','10.77.0.2','iif','lan0'],check=False)
        # Not excluded -> active B is expected; only declared internal prefixes
        # are protected, not guessed global "private" routes.
        assert denied.returncode==0
        return dict(lan_A=a,lan_B=b,host_before=host_a,host_after=host_b,other_before=other_a,other_after=other_b,main_unchanged=True,internal_route=json.loads(internal),local_before=local_a,local_after=local_b)
    case('lan_scope_new_tls_and_internal_exclusion',scope)
    def rpdb_conflict():
        ip('us_r','rule','add','priority','9990','from','10.77.0.0/24','lookup','main')
        before=dump_rules();assert blocked();after=dump_rules();assert before==after
        ip('us_r','rule','del','priority','9990')
        # A clearly disjoint other-LAN rule is preserved across real mutation.
        ip('us_r','rule','add','priority','9989','iif','other0','lookup','main')
        before=dump_rules();select('A');assert dump_rules()==before;ip('us_r','rule','del','priority','9989')
        return dict(intersecting_rejected=True,no_changes_on_rejection=True,disjoint_preserved=True)
    case('external_rpdb_conflict_and_preservation',rpdb_conflict)
    def forward_block():
        select('B');nft('us_r','add table ip fixture_filter\nadd chain ip fixture_filter forward { type filter hook forward priority filter; policy accept; }\nadd rule ip fixture_filter forward iifname "lan0" drop\n')
        r=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;print(json.dumps(round(load(Path('/opt/uplinkstead/config.json')),'B')))")
        failed=client();assert r[0]==3 and not failed['ok']
        nft('us_r','delete table ip fixture_filter\n');assert client()['ok']
        return dict(exit_probe_successes=r[0],lan_request=failed,not_counted_as_recovery=True)
    case('output_success_does_not_prove_forwarding',forward_block)
    def rpfilter():
        ns('us_r',['sysctl','-qw','net.ipv4.conf.wanA.rp_filter=0','net.ipv4.conf.wanB.rp_filter=0','net.ipv4.conf.all.rp_filter=1']);assert blocked()
        ns('us_r',['sysctl','-qw','net.ipv4.conf.all.rp_filter=2','net.ipv4.conf.wanA.rp_filter=2','net.ipv4.conf.wanB.rp_filter=2']);select('B')
        return dict(strict_all_rejected=True,external_setting_not_rewritten=True)
    case('strict_rp_filter_contract',rpfilter)
    def routed():
        for k in ('a','b'):nft('us_'+k,'delete table ip fixture_nat\n')
        observations=[]
        for k,num in (('A',1),('B',2)):
            ip('us_s','route','replace','10.77.0.0/24','via',f'10.99.{num}.1');select(k);r=client();assert r['ok'] and r['result']['peer']=='10.77.0.2';observations.append(r)
        ip('us_s','route','del','10.77.0.0/24')
        for k,num in (('a',1),('b',2)):
            nft('us_'+k,f'add table ip fixture_nat\nadd chain ip fixture_nat post {{ type nat hook postrouting priority srcnat; policy accept; }}\nadd rule ip fixture_nat post oifname "transit" snat to 10.99.{num}.1\n')
        return dict(requests=observations,return_routes_explicitly_provisioned_by_fixture=True)
    case('routed_without_nat_and_provisioned_return_path',routed)
    def link_recovery():
        select('A');ip('us_r','link','set','wanA','down')
        value=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.writer import Writer;import json\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w:print(json.dumps(w.s))")
        assert value['selected'] is None
        # A is explicitly administratively down; B still has independent TLS evidence.
        observed=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;print(json.dumps(round(load(Path('/opt/uplinkstead/config.json')),'B')))")
        assert observed[0]==3, observed
        select('B');request=client();assert request['ok'] and request['result']['peer']=='10.99.2.1'
        ip('us_r','link','set','wanA','up')
        ip('us_r','route','replace','default','via','192.0.2.1');ip('us_r','route','replace','198.18.0.0/24','via','192.0.2.1')
        remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.writer import Writer\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state'):print('true')")
        repaired=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;print(json.dumps(round(load(Path('/opt/uplinkstead/config.json')),'A')))")
        assert repaired[0]==3 and db()['selected']=='B'
        return dict(actual_route_loss_reconciled=True,backup_request=request,probe_after_link_up=repaired,selection_remains_B=True)
    case('link_down_owned_route_reconstruction',link_recovery)

    def stale_before():
        select('A');old=db()['epoch'];p=fault('before-lock','A',old)
        try:
            select('B');os.kill(p.pid,signal.SIGCONT);rc=p.wait(timeout=8)
            assert rc!=0 and client()['result']['peer']=='10.99.2.1'
        finally:
            if p.poll() is None:kill(p)
        return dict(stale_epoch=old,rejected_exit=rc,selected='B')
    case('delayed_old_operation_rejected',stale_before)
    def holding():
        p=fault('holding-lock','A')
        try:assert blocked();assert p.poll() is None
        finally:kill(p)
        select('B');return dict(successor_blocked_while_owner_alive=True,successor_after_retirement='B')
    case('live_old_writer_blocks_takeover',holding)
    def helper_ownership():
        select('A');p=fault('helper-held','B');child=p.held_child
        assert child and 'State:\tT' in Path('/proc',str(child),'status').read_text()
        kill(p) # SIGKILL parent; the real ip child still owns the inherited lock.
        try:
            assert blocked(), 'Parent death incorrectly released helper ownership'
        finally:os.kill(child,signal.SIGKILL)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            if not blocked():break
            time.sleep(.05)
        else:raise TimeoutError('Inherited lock not released after child retirement')
        select('B');assert client()['result']['peer']=='10.99.2.1'
        return dict(parent_killed=True,live_mutation_child_blocks_successor=True,child_retired_before_successor=True)
    case('inherited_mutation_helper_lock',helper_ownership)

    def crashes():
        rows=[]
        for mode,expected in [('before-route','A'),('after-route','B'),('before-complete','B')]:
            select('A');p=fault(mode,'B')
            before=db();actual=routes();assert before['pending']['target']=='B'
            kill(p)
            recovered=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.writer import Writer;import json\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w:print(json.dumps(w.s))")
            assert recovered['selected']==expected and recovered['pending'] is None
            assert client()['result']['peer']==('10.99.1.1' if expected=='A' else '10.99.2.1')
            rows.append(dict(boundary=mode,pending_before=before['pending'],routes_before=actual,recovered_selected=expected,epoch_before=before['epoch'],epoch_after=recovered['epoch']))
        return rows
    case('sigkill_intent_route_and_receipt_boundaries',crashes)
    def inverted():
        checks=[]
        for action in (['lookup','main'],['prohibit']):
            ip('us_r','rule','add','priority','9990','not','iif','other0',*action)
            before=dump_rules();before_routes=routes()
            try:
                assert blocked();assert dump_rules()==before and routes()==before_routes
                row=next(x for x in before if x['priority']==9990);assert 'not' in row
                checks.append(dict(rule=row,rejected=True,no_mutation=True))
            finally:ip('us_r','rule','del','priority','9990')
        return checks
    case('inverted_rpdb_rules_rejected',inverted)
    def missing_local():
        before_routes=routes();ip('us_r','rule','del','priority','0')
        before=dump_rules()
        try:assert blocked();assert dump_rules()==before and routes()==before_routes
        finally:ip('us_r','rule','add','priority','0','lookup','local')
        local=spawn_local_server()
        try:request=client(port=9443,address='10.77.0.1')
        finally:kill(local)
        assert request['ok'] and request['result']['server']=='10.77.0.1'
        return dict(rejected=True,no_mutation=True,local_request_after_fixture_restore=request)
    case('missing_local_lookup_rejected',missing_local)
    def expired_health():
        select('A');holes('A')
        try:
            value=remote("""from pathlib import Path
from uplinkstead.config import load
from uplinkstead.writer import Writer,now,boot_id
from uplinkstead.policy import Policy,Settings
from uplinkstead.agent import cycle
from uplinkstead.linux import Blocked
import json,time
c=load(Path('/opt/uplinkstead/config.json'))
with Writer(c,'/opt/uplinkstead/state') as w:
 p=Policy(Settings(**c['policy']),c['_hash'],boot_id(),w.s['history'],w.s['latched'])
 rounds=[cycle(w,p,i) for i in (0,1)]
 original=w.switch;original_preflight=w.backend.preflight;captured={}
 def delayed(*args,**kw):
  captured['proof']=args[3]
  def slow():original_preflight();time.sleep(2.1)
  w.backend.preflight=slow
  return original(*args,**kw)
 w.switch=delayed
 try:cycle(w,p,2)
 except Blocked as exc:
  assert 'expired' in str(exc).lower()
  assert w.backend.selected()=='A' and w.s['pending'] is None
  assert p.fresh('B',now())=='UNKNOWN'
  print(json.dumps(dict(rejected=True,selected='A',pending=None,proof=captured['proof'],blocked_at=now(),pre_intent=True,uses_agent_cycle=True,prior_rounds=rounds)))
 else:raise AssertionError('Expired health dispatched mutation')
""")
        finally:holes('A',False)
        assert client()['result']['peer']=='10.99.1.1'
        return value
    case('expired_health_before_mutation',expired_health)
    def malformed_target():
        select('A');bad=ROOT/'bad-body';bad.write_text('null')
        try:
            with drive() as tick:
                rows=[tick() for _ in range(4)]
                assert all(r['probes']['A']['successes']==2 and r['selected']=='A' for r in rows)
                assert rows[-1]['health']['A']=='HEALTHY'
                request=client(port=8444);assert request['ok']
        finally:bad.unlink()
        return dict(rounds=rows,agent_survived=True,uses_agent_cycle=True,lan_request=request)
    case('malformed_target_quorum',malformed_target)

    def flapping():
        history=[];select('A');transitions=[]
        with drive() as tick:
            for stage in ('healthy','single_target','A_down','A_recovers','B_down','A_down_again','B_down_again'):
                if stage=='single_target':
                    nft('us_a','add table ip one_target\nadd chain ip one_target forward { type filter hook forward priority -50; policy accept; }\nadd rule ip one_target forward tcp dport 8443 drop\n')
                if stage=='A_down':nft('us_a','delete table ip one_target\n')
                if stage in ('A_down','A_down_again'):holes('A')
                if stage=='A_recovers':holes('A',False)
                if stage=='B_down':holes('B')
                if stage=='A_down_again':holes('B',False)
                if stage=='B_down_again':holes('A',False);holes('B')
                for _ in range(4):
                    row=tick();row['stage']=stage
                    if row['target']:transitions.append(dict(stage=stage,selected=row['selected']))
                    request=client(port=8444 if stage=='single_target' else 8443)
                    if request['ok']:assert request['result']['peer']==('10.99.1.1' if row['selected']=='A' else '10.99.2.1')
                    row['lan_request']=request;history.append(row)
                if stage=='A_recovers':assert row['selected']=='B','Unexpected preference failback'
            assert len(transitions)==3 and row['latched'] is True and db()['latched'] is True
        assert any(not r['lan_request']['ok'] for r in history if r['stage']=='A_down')
        assert any(r['lan_request']['ok'] and r['selected']=='B' for r in history if r['stage']=='A_down')
        for k in ('A','B'):ns('us_'+k.lower(),['nft','delete','table','ip','hole'],check=False)
        return dict(transitions=transitions,rounds=history,latched=db()['latched'],uses_agent_cycle=True)
    case('real_probe_failover_flapping_and_budget',flapping)
    def single_target():
        nft('us_a','add table ip one_target\nadd chain ip one_target forward { type filter hook forward priority -50; policy accept; }\nadd rule ip one_target forward tcp dport 8443 drop\n')
        r=remote("from pathlib import Path;from uplinkstead.config import load;from uplinkstead.probe import round;import json;print(json.dumps(round(load(Path('/opt/uplinkstead/config.json')),'A')))")
        nft('us_a','delete table ip one_target\n');assert r[0]==2
        return r
    case('single_real_target_failure',single_target)
    from tools.mvp_guest import run_mvp
    for name,fn in run_mvp():case(name,fn)
    result['passed']=True;result['environment']=dict(kernel=cmd(['uname','-r']).stdout.strip(),python=sys.version.split()[0],systemd=cmd(['systemctl','--version']).stdout.splitlines()[0])
    result['service_source_sha256']=hashlib.sha256((ROOT/'source/deploy/uplinkstead.service').read_bytes()).hexdigest()
    result['policy_unit_sha256']=hashlib.sha256(Path('/etc/systemd/system',WORKER).read_bytes()).hexdigest()
    result['installed_unit_sha256']=hashlib.sha256(Path('/etc/systemd/system',UNIT).read_bytes()).hexdigest()
    (ROOT/'guest.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result))


def prepare_reboot():
    # Verify real shipped agent service and automatic process restart first.
    cmd(['systemctl','reset-failed',UNIT,WORKER]);cmd(['systemctl','start',UNIT]);time.sleep(1)
    before=cmd(['systemctl','show',UNIT,'-p','InvocationID','-p','MainPID']).stdout
    system(UNIT,'kill','--signal=SIGKILL','--kill-whom=main');time.sleep(3)
    after=cmd(['systemctl','show',UNIT,'-p','InvocationID','-p','MainPID','-p','ActiveState']).stdout
    props=lambda text:dict(x.split('=',1) for x in text.splitlines() if '=' in x)
    assert props(before)['InvocationID'] != props(after)['InvocationID']
    assert int(props(before)['MainPID'])>0 and int(props(after)['MainPID'])>0
    assert 'ActiveState=active' in after
    # Persisted latch must survive the actual service restart, health is rebuilt.
    assert db()['latched'] is True
    system(UNIT,'stop')
    select('A')
    # Use installed systemd service with external fault-boundary wrapper; the
    # durable intent and actual route mutation are the shipping Writer methods.
    drop=Path('/etc/systemd/system',UNIT+'.d');drop.mkdir()
    (drop/'fault.conf').write_text('[Service]\nExecStart=\nExecStart=/usr/bin/python3 /opt/uplinkstead/source/tools/fault.py after-route /opt/uplinkstead/config.json /opt/uplinkstead/state B\n')
    cmd(['systemctl','daemon-reload']);system(UNIT,'start')
    pid=int(cmd(['systemctl','show',UNIT,'-p','MainPID','--value']).stdout)
    deadline=time.monotonic()+6
    while time.monotonic()<deadline:
        if 'State:\tT' in Path('/proc',str(pid),'status').read_text():break
        time.sleep(.05)
    else:raise TimeoutError('Service fault boundary not reached')
    pending=db();assert pending['pending']['target']=='B'
    assert client()['result']['peer']=='10.99.2.1'
    # Next boot starts the unmodified agent, not the fault wrapper. No ExecStop
    # rollback is provided; prestart journal capture proves pending survived.
    (drop/'fault.conf').unlink();drop.rmdir();cmd(['systemctl','daemon-reload'])
    link=Path('/etc/systemd/system/multi-user.target.wants',UNIT)
    if link.exists() or link.is_symlink():raise RuntimeError('Foreign enablement')
    link.symlink_to('../'+UNIT)
    value=dict(before_boot=boot_id(),pending=pending['pending'],selected_receipt=pending['selected'],actual_route=routes(),
               process_restart_before=before,process_restart_after=after,latched_before=pending['latched'])
    (ROOT/'reboot-before.json').write_text(json.dumps(value))
    print(json.dumps(value))


def after_reboot():
    before=json.loads((ROOT/'reboot-before.json').read_text());pre=json.loads((ROOT/'prestart.json').read_text())
    assert before['before_boot']!=boot_id()==pre['boot']
    assert pre['pending']==before['pending'] and pre['selected']==before['selected_receipt']
    assert db()['pending'] is None and db()['selected']=='B' and db()['latched'] is True
    request=client();assert request['ok'] and request['result']['peer']=='10.99.2.1'
    unit=cmd(['systemctl','show',UNIT,'-p','InvocationID','-p','MainPID','-p','ActiveState']).stdout;assert 'ActiveState=active' in unit
    with sqlite3.connect(STATE/'journal.sqlite') as c:
        events=[json.loads(x[0]) for x in c.execute('SELECT value FROM events ORDER BY id')]
    deadline=time.monotonic()+8
    while not any(x['boot']==boot_id() and x['name']=='tick' for x in events) and time.monotonic()<deadline:
        time.sleep(.2)
        with sqlite3.connect(STATE/'journal.sqlite') as c:events=[json.loads(x[0]) for x in c.execute('SELECT value FROM events ORDER BY id')]
    new_probes=[x for x in events if x['boot']==boot_id() and x['name']=='tick']
    assert new_probes and new_probes[0]['health']=={'A':'RECOVERING','B':'RECOVERING'}
    pid=int(cmd(['systemctl','show',UNIT,'-p','MainPID','--value']).stdout)
    rss=next(x for x in Path('/proc',str(pid),'status').read_text().splitlines() if x.startswith('VmRSS:'))
    result=dict(passed=True,orderly_vm_restart=True,power_loss_tested=False,before=before,pre_agent_journal=pre,
                after=dict(boot=boot_id(),selected=db()['selected'],pending=db()['pending'],latched=db()['latched'],
                           unit=unit,request=request,first_tick=new_probes[0],rss_snapshot=rss))
    (ROOT/'reboot.json').write_text(json.dumps(result,indent=2));print(json.dumps(result))


def cleanup():
    # Only act on resources recorded under this run's owner ledger.
    ledger=ROOT/'namespace-owner.json'
    if not ledger.exists():return
    data=json.loads(ledger.read_text());assert data['owner']==(ROOT/'owner').read_text()
    hashes=json.loads((ROOT/'unit-hashes.json').read_text()) if (ROOT/'unit-hashes.json').exists() else {}
    for name,unit_digest in hashes.items():
        path=Path('/etc/systemd/system',name)
        if path.exists():assert path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==unit_digest
    for name in (WORKER,UNIT,SERVER,TOPO):
        if name in hashes:cmd(['systemctl','stop',name],check=False)
    enable=Path('/etc/systemd/system/multi-user.target.wants',UNIT)
    if enable.is_symlink():
        assert os.readlink(enable)=='../'+UNIT;enable.unlink()
    for name in hashes:
        path=Path('/etc/systemd/system',name)
        if path.exists():path.unlink()
    cmd(['systemctl','daemon-reload']);cmd(['systemctl','reset-failed',UNIT,SERVER,TOPO],check=False)
    for name in reversed(data['names']):
        # Services have stopped; refuse to erase a namespace still containing a process.
        if Path('/run/netns',name).exists():
            for pid in cmd(['ip','netns','pids',name]).stdout.split():
                process=Path('/proc',pid)
                if process.exists():
                    command=(process/'cmdline').read_bytes()
                    assert b'/opt/uplinkstead' in command,'Foreign process in owned namespace'
                    os.kill(int(pid),signal.SIGKILL)
            time.sleep(.05)
            assert not cmd(['ip','netns','pids',name]).stdout.strip()
            cmd(['ip','netns','del',name])
    if (ROOT/'user-created').exists():
        cmd(['userdel','uplinkstead']);(ROOT/'user-created').unlink()
    before=json.loads((ROOT/'root-before.json').read_text())
    after=root_snapshot()
    assert digest(before)==digest(after),'VM root network semantics changed'
    assert not set(NAMES).intersection(x.split()[0] for x in cmd(['ip','netns','list']).stdout.splitlines() if x)
    print(json.dumps(dict(passed=True,root_network_unchanged=True,namespaces_removed=True,units_removed=True,root_before_sha256=digest(before),root_after_sha256=digest(after),ignored_fields=['nft_handles','nft_counter_values','xt_chain_counters','xt_generated_comments'])))



def diagnose():
    value={}
    if Path('/run/netns/us_r').exists():
        value['rules']=dump_rules()
        value['routes']={str(t):cmd(['ip','-n','us_r','-j','route','show','table',str(t)],check=False).stdout for t in TABLE.values()}
    value['service_state']={name:cmd(['systemctl','show',name,'-p','Result','-p','ActiveState','-p','SubState','-p','NRestarts'],check=False).stdout for name in (UNIT,WORKER)}
    for name in ('guest.json','prestart.json'):
        if (ROOT/name).exists():value[name]=json.loads((ROOT/name).read_text())
    print(json.dumps(value))

if __name__=='__main__':
    if not __debug__:
        raise RuntimeError('Optimized execution is unsupported for validation')
    p=argparse.ArgumentParser();p.add_argument('action',choices=['setup','cases','topology','prepare','after','cleanup','diagnose']);a=p.parse_args()
    {'setup':setup,'cases':run_cases,'topology':topology,'prepare':prepare_reboot,'after':after_reboot,'cleanup':cleanup,'diagnose':diagnose}[a.action]()
