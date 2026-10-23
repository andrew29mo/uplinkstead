"""Disposable dual-DHCP topology helpers; only run inside the dedicated Linux VM.

This fixture does not install a service or claim reboot/systemd coverage. DHCP
hooks capture actual wire-client observations; the guest driver decides when to
submit them through the production lifecycle API and records that distinction.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from tools.guest import cmd, ip, ns, nft, root_snapshot
from tools.netproof import digest, semantics

NETNS_ROOT = Path('/run/netns')

NAMES = ['dd_r', 'dd_c', 'dd_a', 'dd_b', 'dd_s']
LINKS = {'A': dict(interface='wanA', namespace='dd_a', gateway='192.0.2.1', address='192.0.2.2', transit=1),
         'B': dict(interface='wanB', namespace='dd_b', gateway='198.51.100.1', address='198.51.100.2', transit=2)}

HOOK = '''#!/usr/bin/python3
import json,os,sys,time
v=dict(link=os.environ['DUAL_LINK'],session=os.environ['DUAL_SESSION'],boot=os.environ['DUAL_BOOT'],at=time.monotonic(),reason=sys.argv[1],
       lease={k:os.environ.get(k,'') for k in ('ip','subnet','router','lease')},
       options=[k for k in ('routes','staticroutes','msstaticroutes') if os.environ.get(k)],
       server_id=os.environ.get('serverid'),origin='real_busybox_hook')
p=os.open(os.environ['DUAL_EVENT_FILE'],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
os.write(p,(json.dumps(v)+'\\n').encode());os.close(p)
'''


def cleanup_owned(root):
    """Timeout recovery: only delete namespaces whose recorded inode still matches."""
    root=Path(root);ledger=root/'ownership.json'
    if not ledger.exists():
        return dict(namespaces_removed=True,root_network_unchanged=True,owned_children_reaped=True,idempotent=True)
    state=json.loads(ledger.read_text())
    for name,inode in reversed(list(state['namespaces'].items())):
        p=NETNS_ROOT/name
        if not p.exists():continue
        if p.stat().st_ino!=inode:raise RuntimeError('Owned namespace replaced; refusing foreign deletion')
        pids=[int(v) for v in cmd(['ip','netns','pids',name]).stdout.split()]
        for pid in pids:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
        began=time.monotonic()
        while time.monotonic()-began<3 and cmd(['ip','netns','pids',name]).stdout.strip():time.sleep(.05)
        if cmd(['ip','netns','pids',name]).stdout.strip():raise RuntimeError('Owned namespace process failed to exit')
        cmd(['ip','netns','del',name])
    after=root_snapshot();before=state['root_before']
    # Retain raw observations even when only counters/comments changed. Semantic
    # equality still preserves every RPDB operand, route, nft rule and rule order.
    (root/'cleanup-baseline-raw.json').write_text(json.dumps(before,indent=2))
    (root/'cleanup-after-raw.json').write_text(json.dumps(after,indent=2))
    old,new=semantics(before),semantics(after)
    differences=dict(raw_changed=[k for k in before if before[k]!=after[k]],
                     semantic_changed=[k for k in old if old[k]!=new[k]],
                     before_sha256=digest(before),after_sha256=digest(after))
    (root/'cleanup-network-diff.json').write_text(json.dumps(differences,indent=2))
    unchanged=differences['before_sha256']==differences['after_sha256']
    if not unchanged:raise RuntimeError('Root network semantics changed during isolated dual DHCP fixture')
    result=dict(namespaces_removed=True,root_network_unchanged=True,owned_children_reaped=True)
    (root/'cleanup.json').write_text(json.dumps(result,indent=2))
    ledger.unlink()
    return result


class Fixture:
    def __init__(self, root, source):
        self.root, self.source = Path(root), Path(source)
        self.processes = []
        self.clients, self.servers, self.offsets = {}, {}, {'A': 0, 'B': 0}
        self.before = None
        self.names = []

    def setup(self, start_servers=True):
        if os.geteuid() != 0 or not Path('/proc/sys/kernel/random/boot_id').exists():
            raise RuntimeError('Dedicated root Linux VM required')
        present = {r.split()[0] for r in cmd(['ip', 'netns', 'list']).stdout.splitlines()}
        if present & set(NAMES):
            raise RuntimeError('Fixture namespace already exists; refusing adoption')
        self.before = root_snapshot()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.discard_previous_phase_events()
        self.ledger=self.root/'ownership.json'
        if self.ledger.exists():raise RuntimeError('Previous ownership ledger requires explicit cleanup')
        self.ledger.write_text(json.dumps(dict(root_before=self.before,namespaces={})))
        self.hook = self.root/'hook.py'
        self.hook.write_text(HOOK); self.hook.chmod(0o700)
        try:
            for name in NAMES:
                cmd(['ip', 'netns', 'add', name]); self.names.append(name)
                ownership=json.loads(self.ledger.read_text());ownership['namespaces'][name]=(NETNS_ROOT/name).stat().st_ino
                self.ledger.write_text(json.dumps(ownership))
                ip(name, 'link', 'set', 'lo', 'up')
            pairs = [('dd_r','lan0','10.77.0.1/24','dd_c','eth0','10.77.0.2/24'),
                     ('dd_r','wanA',None,'dd_a','edge','192.0.2.1/24'),
                     ('dd_r','wanB',None,'dd_b','edge','198.51.100.1/24'),
                     ('dd_a','transit','10.99.1.1/30','dd_s','viaA','10.99.1.2/30'),
                     ('dd_b','transit','10.99.2.1/30','dd_s','viaB','10.99.2.2/30')]
            for left, li, la, right, ri, ra in pairs:
                cmd(['ip','link','add','name',li,'netns',left,'type','veth','peer','name',ri,'netns',right])
                for name, interface, address in ((left,li,la),(right,ri,ra)):
                    if address: ip(name,'addr','add',address,'dev',interface)
                    ip(name,'link','set',interface,'up')
            for name in NAMES:
                ns(name,['sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.default.rp_filter=0'])
                for row in json.loads(ip(name,'-j','link').stdout):
                    ns(name,['sysctl','-qw','net.ipv4.conf.'+row['ifname']+'.rp_filter=0'])
            ip('dd_c','route','add','default','via','10.77.0.1')
            # A viable forbidden main fallback, independent of DHCP-owned tables.
            ip('dd_r','route','add','198.51.100.1/32','dev','wanB','scope','link')
            ip('dd_r','route','add','default','via','198.51.100.1','dev','wanB','onlink')
            ip('dd_s','addr','add','203.0.113.2/32','dev','lo')
            for link, v in LINKS.items():
                n=v['namespace']; t=v['transit']
                ip(n,'route','add','203.0.113.2/32','via',f'10.99.{t}.2')
                self.return_route(link, v['address'])
                ip('dd_s','route','add',v['gateway'].rsplit('.',1)[0]+'.0/24','via',f'10.99.{t}.1')
                nft(n, f'add table ip dual_nat\nadd chain ip dual_nat post {{ type nat hook postrouting priority srcnat; policy accept; }}\nadd rule ip dual_nat post oifname "transit" snat to 10.99.{t}.1\n')
                other=LINKS['B' if link=='A' else 'A']
                nft(n, 'add table ip observe\nadd chain ip observe ingress { type filter hook prerouting priority -100; policy accept; }\n'
                    f'add rule ip observe ingress iifname "edge" udp dport 67 ip daddr {v["gateway"]} counter comment "own_dhcp"\n'
                    f'add rule ip observe ingress iifname "edge" udp dport 67 ip daddr {other["gateway"]} counter comment "wrong_dhcp"\n'
                    'add chain ip observe forward { type filter hook forward priority -100; policy accept; }\n'
                    'add rule ip observe forward ip daddr 203.0.113.2 counter comment "target"\n')
            cmd(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',self.root/'server.key',
                 '-out',self.root/'ca.crt','-days','2','-subj','/CN=probe.test','-addext','subjectAltName=DNS:probe.test'])
            self.spawn('dd_s',['python3',str(self.source/'tools/server.py'),str(self.root/'ca.crt'),str(self.root/'server.key')],'tls')
            time.sleep(.25)
            if start_servers:
                for link in LINKS: self.server(link)
            return self
        except BaseException:
            self.cleanup(); raise

    def spawn(self, namespace, argv, label, env=None):
        with (self.root/(label+'-private.log')).open('a') as log:
            p=subprocess.Popen(['ip','netns','exec',namespace,*map(str,argv)],stdout=log,stderr=log,env=env)
        self.processes.append(p)
        return p

    @staticmethod
    def stop(p):
        if p.poll() is None:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)

    def server(self, link, address=None, gateway=None, extra=(), duration="2m"):
        v=LINKS[link]
        if link in self.servers:self.stop(self.servers[link])
        (self.root/('leases-'+link)).unlink(missing_ok=True)
        p=self.spawn(v['namespace'],['dnsmasq','--no-daemon','--port=0','--interface=edge','--bind-interfaces',
             '--dhcp-authoritative','--dhcp-range='+str(address or v['address'])+','+str(address or v['address'])+',255.255.255.0,'+duration,
             '--dhcp-option=option:router,'+str(gateway or v['gateway']),
             '--dhcp-leasefile='+str(self.root/('leases-'+link)), '--pid-file='+str(self.root/('dnsmasq-'+link+'.pid')),
             '--log-dhcp','--user=root',*extra], 'dnsmasq-'+link)
        self.servers[link]=p;time.sleep(.2)
        if p.poll() is not None:raise RuntimeError('DHCP fixture server failed')

    def discard_pending_events(self, link):
        p=self.root/('events-'+link+'.jsonl')
        self.offsets[link]=p.stat().st_size if p.exists() else 0

    def discard_previous_phase_events(self):
        # Preserve raw observations, but never replay them into a new phase.
        for link in LINKS:self.discard_pending_events(link)

    def start_client(self, link, session, boot):
        if link in self.clients:self.stop(self.clients[link])
        self.discard_pending_events(link)
        env=dict(os.environ, DUAL_LINK=link, DUAL_SESSION=session, DUAL_BOOT=boot, DUAL_EVENT_FILE=str(self.root/('events-'+link+'.jsonl')))
        p=self.spawn('dd_r',['busybox','udhcpc','-f','-i',LINKS[link]['interface'],'-s',str(self.hook),'-p',str(self.root/('client-'+link+'.pid')),
                            '-O','33','-O','121','-O','249','-t','3','-T','1','-A','1'], 'client-'+link,env)
        self.clients[link]=p
        return p

    def events(self, link):
        p=self.root/('events-'+link+'.jsonl')
        if not p.exists():return []
        with p.open() as f:
            f.seek(self.offsets[link]);raw=f.read();self.offsets[link]=f.tell()
        return [json.loads(line) for line in raw.splitlines()]

    def await_event(self, link, reason=('bound','renew'), timeout=15):
        began=time.monotonic()
        while time.monotonic()-began<timeout:
            for event in self.events(link):
                if event['reason'] in reason:return event
            if self.clients[link].poll() is not None:raise RuntimeError('DHCP client exited before observation')
            time.sleep(.05)
        raise TimeoutError('No matching real DHCP hook observation')

    def return_route(self, link, address):
        """External upstream fixture responsibility, never a product operation."""
        ip(LINKS[link]['namespace'],'route','replace','10.77.0.0/24','via',address,'dev','edge')

    def counters(self):
        out={}
        for link,v in LINKS.items():
            rows=json.loads(ns(v['namespace'],['nft','-j','list','table','ip','observe']).stdout)['nftables']
            out[link]={r['rule']['comment']:e['counter']['packets'] for r in rows if 'rule' in r
                       for e in r['rule']['expr'] if 'counter' in e}
        return out

    def client(self, namespace='dd_c', source=None):
        code='''import socket,ssl,json,secrets
n=secrets.token_hex(12);c=ssl.create_default_context(cafile=CA)
with socket.create_connection(('203.0.113.2',8443),timeout=.7,source_address=(SOURCE,0) if SOURCE else None) as r:
 with c.wrap_socket(r,server_hostname='probe.test') as s:
  s.sendall(('GET /'+n+' HTTP/1.0\\r\\nHost: probe.test\\r\\n\\r\\n').encode());b=b''
  while True:
   x=s.recv(4096)
   if not x:break
   b+=x
  v=json.loads(b.split(b'\\r\\n\\r\\n')[1]);assert v['nonce']==n and v['ok'];print(json.dumps(v))
'''.replace('CA',repr(str(self.root/'ca.crt'))).replace('SOURCE',repr(source))
        p=ns(namespace,['python3','-c',code],check=False,timeout=3)
        return dict(ok=p.returncode==0,response=json.loads(p.stdout) if p.returncode==0 else None)

    def fault(self, link, enabled=True):
        n=LINKS[link]['namespace']
        if enabled:
            nft(n,'add table ip fault\nadd chain ip fault forward { type filter hook forward priority -50; policy drop; }\n')
        else:nft(n,'delete table ip fault\n')

    def cleanup(self):
        for p in reversed(self.processes):self.stop(p)
        result=cleanup_owned(self.root)
        self.names=[]
        result['owned_children_reaped']=all(p.poll() is not None for p in self.processes)
        return result
