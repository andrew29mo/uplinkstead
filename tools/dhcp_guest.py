"""Isolated DHCP wire/installed-service checks. Never runs on the host network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.guest import cmd, ip, ns, nft, root_snapshot
from tools.netproof import digest
from tools.evidence import manifest, fingerprint
from tools.dhcp_fixture import unit as fixture_unit
from uplinkstead.writer import boot_id

ROOT = Path('/opt/uplinkstead-dhcp')
NAMES = ['ud_r', 'ud_c', 'ud_a', 'ud_b', 'ud_s']
UNIT = 'uplinkstead-dhcp.service'


def version(*args):
    p=cmd(list(args),check=False)
    return (p.stdout+p.stderr).splitlines()[0]


def command(*args):
    return cmd(args).stdout


def state(q=None):
    code = "import sys;sys.path.insert(0,'/opt/uplinkstead-dhcp/source');from uplinkstead.dhcp_service import request;from pathlib import Path;import json;print(json.dumps(request(Path('/opt/uplinkstead-dhcp/run/events.sock'),"+repr(q or {'op':'status'})+")))"
    return json.loads(ns('ud_r', ['python3', '-c', code], timeout=4).stdout)


def wait(predicate, timeout=20):
    began = time.monotonic()
    while time.monotonic()-began < timeout:
        try:
            value = predicate()
            if value:return value
        except (RuntimeError, KeyError, FileNotFoundError):pass
        time.sleep(.15)
    raise TimeoutError('DHCP fixture observation timed out')


def healthy():
    s = state()
    return s if s['healthy'] else None


def client():
    code = """import socket,ssl,json,secrets
n=secrets.token_hex(12);c=ssl.create_default_context(cafile='/opt/uplinkstead-dhcp/ca.crt')
with socket.create_connection(('203.0.113.2',8443),timeout=.7) as r:
 with c.wrap_socket(r,server_hostname='probe.test') as s:
  s.sendall(('GET /'+n+' HTTP/1.0\\r\\nHost: probe.test\\r\\n\\r\\n').encode());b=b''
  while True:
   x=s.recv(4096)
   if not x:break
   b+=x
  v=json.loads(b.split(b'\\r\\n\\r\\n')[1]);assert v['nonce']==n;print(json.dumps(v))
"""
    p=ns('ud_c', ['python3','-c',code],check=False,timeout=3)
    return dict(ok=p.returncode==0, response=json.loads(p.stdout) if p.returncode==0 else None)


def child_pid():
    pid=int(command('systemctl','show',UNIT,'-p','MainPID','--value'))
    children=Path('/proc',str(pid),'task',str(pid),'children').read_text().split()
    return next(int(p) for p in children if Path('/proc',p,'comm').read_text().strip()=='busybox')


def server(address='192.0.2.2', gateway='192.0.2.1'):
    pidfile=ROOT/'dnsmasq.pid'
    if pidfile.exists():
        pid=int(pidfile.read_text())
        try:os.kill(pid,signal.SIGTERM)
        except ProcessLookupError:pass
        try:os.waitpid(pid, 0)
        except ChildProcessError:wait(lambda: not Path('/proc',str(pid)).exists())
        pidfile.unlink(missing_ok=True)
    (ROOT/'leases').unlink(missing_ok=True)
    args=['ip','netns','exec','ud_a','dnsmasq','--no-daemon','--port=0','--interface=edge','--bind-interfaces',
          '--dhcp-authoritative','--dhcp-range='+address+','+address+',255.255.255.0,2m',
          '--dhcp-option=option:router,'+gateway,'--dhcp-leasefile='+str(ROOT/'leases'),
          '--pid-file='+str(ROOT/'dnsmasq-unused.pid'),'--log-dhcp','--user=root']
    with (ROOT/'dnsmasq-private.log').open('a') as log:
        p=subprocess.Popen(args,stdout=log,stderr=log)
    pidfile.write_text(str(p.pid));time.sleep(.25)
    if p.poll() is not None:raise RuntimeError('DHCP server failed')


def setup():
    assert Path('/proc/1/comm').read_text().strip()=='systemd'
    assert not Path('/etc/systemd/system',UNIT).exists()
    meta=command('systemctl','show',UNIT,'-p','LoadState','-p','FragmentPath','-p','DropInPaths')
    assert 'LoadState=not-found' in meta and 'FragmentPath=\n' in meta and 'DropInPaths=\n' in meta
    assert not {l.split()[0] for l in command('ip','netns','list').splitlines()} & set(NAMES)
    (ROOT/'root-before.json').write_text(json.dumps(root_snapshot()))
    # Ledger is created before any owned object; cleanup can handle partial setup.
    (ROOT/'owner-names.json').write_text(json.dumps(NAMES))
    for n in NAMES:
        command('ip','netns','add',n);ip(n,'link','set','lo','up')
    pairs=[('ud_r','lan0','10.77.0.1/24','ud_c','eth0','10.77.0.2/24'),
           ('ud_r','wan0',None,'ud_a','edge','192.0.2.1/24'),
           ('ud_r','backup0','198.51.100.2/30','ud_b','edge','198.51.100.1/30'),
           ('ud_a','transit','10.99.1.1/30','ud_s','viaA','10.99.1.2/30'),
           ('ud_b','transit','10.99.2.1/30','ud_s','viaB','10.99.2.2/30')]
    for left, li, la, right, ri, ra in pairs:
        command('ip','link','add','name',li,'netns',left,'type','veth','peer','name',ri,'netns',right)
        for n,i,a in ((left,li,la),(right,ri,ra)):
            if a:ip(n,'addr','add',a,'dev',i)
            ip(n,'link','set',i,'up')
    for n in NAMES:
        ns(n,['sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.default.rp_filter=0'])
        for i in json.loads(ip(n,'-j','link').stdout):ns(n,['sysctl','-qw','net.ipv4.conf.'+i['ifname']+'.rp_filter=0'])
    ip('ud_a','addr','add','192.0.2.5/24','dev','edge')
    ip('ud_c','route','add','default','via','10.77.0.1')
    ip('ud_r','route','add','default','via','198.51.100.1')  # Deliberately viable forbidden fallback.
    ip('ud_s','addr','add','203.0.113.2/32','dev','lo')
    for letter,num in (('a',1),('b',2)):
        ip('ud_'+letter,'route','add','203.0.113.2/32','via',f'10.99.{num}.2')
        ip('ud_'+letter,'route','add','10.77.0.0/24','via','192.0.2.2' if letter=='a' else '198.51.100.2')
        nft('ud_'+letter,f'add table ip dhcp_nat\nadd chain ip dhcp_nat post {{ type nat hook postrouting priority srcnat; policy accept; }}\nadd rule ip dhcp_nat post oifname "transit" snat to 10.99.{num}.1\n')
    ip('ud_s','route','add','192.0.2.0/24','via','10.99.1.1')
    ip('ud_s','route','add','198.51.100.0/30','via','10.99.2.1')
    nft('ud_b','add table ip observe\nadd chain ip observe f { type filter hook forward priority -100; policy accept; }\nadd rule ip observe f ip daddr 203.0.113.2 counter\n')
    command('openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',ROOT/'server.key','-out',ROOT/'ca.crt','-days','2','-subj','/CN=probe.test','-addext','subjectAltName=DNS:probe.test')
    c=json.loads((ROOT/'source/deploy/dhcp.example.json').read_text());c['ca']=str(ROOT/'ca.crt')
    (ROOT/'config.json').write_text(json.dumps(c))
    # Use exact shipped service with only fixture paths/namespace additions.
    unit=fixture_unit((ROOT/'source/deploy/uplinkstead-dhcp.service').read_text())
    (ROOT/'installed-unit').write_text(unit)
    Path('/etc/systemd/system',UNIT).write_text(unit)
    (ROOT/'source/deploy/uplinkstead-udhcpc.py').chmod(0o755)
    # Explicit private paths rather than relying on the example unit's directories.
    (ROOT/'state').mkdir(mode=0o700);(ROOT/'run').mkdir(mode=0o700)
    log=(ROOT/'server-private.log').open('a')
    p=subprocess.Popen(['ip','netns','exec','ud_s','python3',str(ROOT/'source/tools/server.py'),str(ROOT/'ca.crt'),str(ROOT/'server.key')],stdout=log,stderr=log)
    (ROOT/'server.pid').write_text(str(p.pid));log.close()
    command('systemctl','daemon-reload');server()
    command('systemctl','start',UNIT)


def counter():
    rows=json.loads(ns('ud_b',['nft','-j','list','table','ip','observe']).stdout)['nftables']
    return next(e['counter']['packets'] for r in rows if 'rule' in r for e in r['rule']['expr'] if 'counter' in e)


def identity():
    raw=command('systemctl','show',UNIT,'-p','MainPID','-p','InvocationID','-p','ActiveState',
                '-p','FragmentPath','-p','DropInPaths','-p','CapabilityBoundingSet')
    value=dict(line.split('=',1) for line in raw.splitlines())
    assert value['ActiveState']=='active' and int(value['MainPID'])>0
    assert value['FragmentPath']=='/etc/systemd/system/'+UNIT and not value['DropInPaths']
    assert set(value['CapabilityBoundingSet'].split())=={'cap_net_admin','cap_net_raw','cap_net_bind_service'}
    return value


def network():
    def table(number):
        p=cmd(['ip','-n','ud_r','-j','route','show','table',str(number)],check=False)
        if p.returncode and 'FIB table does not exist' not in p.stderr:
            raise RuntimeError('route readback failed')
        return json.loads(p.stdout or '[]')
    return dict(data_routes=table(41103),probe_routes=table(41101),
                addresses=json.loads(ip('ud_r','-j','-4','addr','show','dev','wan0').stdout),
                rules=json.loads(ip('ud_r','-j','rule','show').stdout))


def run():
    result=dict(passed=False,source_sha256=fingerprint(manifest()),boot=boot_id(),cases=[])
    def case(name, details, started):
        result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-started,details=details))
        (ROOT/'guest.json').write_text(json.dumps(result,indent=2))
    setup()
    began=time.monotonic();s=wait(healthy);r=client();assert r['ok'] and r['response']['peer']=='10.99.1.1'
    assert s['current']['ip']=='192.0.2.2'
    initial_invocation=command('systemctl','show',UNIT,'-p','InvocationID','--value').strip()
    case('wire_bound_and_pinned_tls',dict(state=s,request=r,invocation=initial_invocation),began)
    began=time.monotonic();before=s['revision'];os.kill(child_pid(),signal.SIGUSR1)
    def renewal():
        t=state();return t if t['revision']>before else None
    renewed=wait(renewal)
    assert not renewed['healthy']
    case('wire_renew',dict(state=renewed,after_healthy=wait(healthy)),began)
    began=time.monotonic();server(gateway='192.0.2.5');os.kill(child_pid(),signal.SIGUSR1)
    def gateway():
        t=state();return t if t['current'] and t['current']['gateway']=='192.0.2.5' else None
    changed=wait(gateway);assert not changed['healthy'];wait(healthy)
    case('wire_gateway_change',dict(state=changed),began)
    began=time.monotonic();old=state();server(address='192.0.2.3',gateway='192.0.2.5')
    os.kill(child_pid(),signal.SIGUSR2);time.sleep(.4);os.kill(child_pid(),signal.SIGUSR1)
    def address():
        t=state();return t if t['current'] and t['current']['ip']=='192.0.2.3' else None
    changed=wait(address);assert not changed['healthy']
    ip('ud_a','route','replace','10.77.0.0/24','via','192.0.2.3')
    wait(healthy);assert client()['ok']
    case('wire_address_change',dict(before=old,current=changed),began)
    assert command('systemctl','show',UNIT,'-p','InvocationID','--value').strip()==initial_invocation
    began=time.monotonic();old=state();old_service=identity()
    command('systemctl','kill','--kill-whom=main','--signal=SIGKILL',UNIT)
    wait(lambda: state()['session']!=old['session'],timeout=15)
    current=wait(healthy);assert current['current']['ip']=='192.0.2.3'
    new_service=identity()
    assert new_service['InvocationID']!=old_service['InvocationID'] and new_service['MainPID']!=old_service['MainPID']
    # Everything but the retired session is current, so rejection cannot be
    # explained by old time/revision/boot or a broken environment.
    q=dict(session=old['session'],boot=current['boot'],revision=current['revision'],
           at=float(ns('ud_r',['python3','-c','import time;print(time.clock_gettime(time.CLOCK_BOOTTIME))']).stdout),reason='deconfig',lease=None)
    before_network=network()
    code="""import sys,json
sys.path.insert(0,'/opt/uplinkstead-dhcp/source')
from uplinkstead.dhcp_service import request
from pathlib import Path
try:request(Path('/opt/uplinkstead-dhcp/run/events.sock'),EVENT)
except RuntimeError as exc:
 if str(exc)!='RetiredSession':raise
 print(json.dumps(dict(rejected=True,error=str(exc))))
else:raise RuntimeError('retired session was accepted')
""".replace('EVENT',repr(q))
    rejection=json.loads(ns('ud_r',['python3','-c',code]).stdout)
    after=state();after_network=network()
    assert after==current and before_network==after_network
    case('service_sigkill_restart_and_old_session_fenced',dict(before=old,state=after,old_service=old_service,
         new_service=new_service,event=q,rejection=rejection,before_network=before_network,after_network=after_network),began)
    began=time.monotonic();before_state=state();before_network=network();before_service=identity()
    bad=dict(session=before_state['session'],boot=before_state['boot'],revision=before_state['revision'],
             at=float(ns('ud_r',['python3','-c','import time;print(time.clock_gettime(time.CLOCK_BOOTTIME))']).stdout),
             reason='renew',lease=dict(ip='192.0.2.4',subnet='255.255.255.0',router='198.51.100.1',lease='120'))
    rejected=state(bad);after_network=network();after_service=identity()
    assert rejected['lease_rejected'] and rejected['current'] is None and not rejected['healthy']
    assert not after_network['data_routes'] and not after_network['probe_routes'] and not after_network['addresses']
    assert before_service==after_service and not client()['ok']
    # Controlled restoration uses only the remaining lifetime of the last real
    # wire lease. Then inject a newer but too-late callback, not an old revision.
    at=float(ns('ud_r',['python3','-c','import time;print(time.clock_gettime(time.CLOCK_BOOTTIME))']).stdout)
    remaining=int(before_state['expires']-at);assert remaining>10
    v=before_state['current']
    restore=dict(session=rejected['session'],boot=rejected['boot'],revision=rejected['revision'],at=at,reason='bound',
                 lease=dict(ip=v['ip'],subnet=v['prefix'].split('/')[1],router=v['gateway'],lease=str(remaining)))
    restored=state(restore);wait(healthy);time.sleep(4.2)
    late_before=state();late_network=network()
    late_at=float(ns('ud_r',['python3','-c','import time;print(time.clock_gettime(time.CLOCK_BOOTTIME))']).stdout)-3.5
    assert late_at>restore['at']
    late_event=dict(session=late_before['session'],boot=late_before['boot'],revision=late_before['revision'],at=late_at,
                    reason='renew',lease=dict(ip='192.0.2.4',subnet='255.255.255.0',router='192.0.2.5',lease='60'))
    late_reply=state(late_event);late_after=network()
    assert late_reply['event_expired'] and late_reply['current'] is None and not late_reply['healthy']
    assert not late_after['data_routes'] and not late_after['probe_routes'] and not late_after['addresses']
    assert identity()==before_service and not client()['ok']
    late=dict(restore_event=restore,restored=restored,before=late_before,before_network=late_network,event=late_event,
              reply=late_reply,after_network=late_after,
              observed=float(ns('ud_r',['python3','-c','import time;print(time.clock_gettime(time.CLOCK_BOOTTIME))']).stdout))
    case('unsupported_current_renew_withdraws_old_lease',dict(before=before_state,before_network=before_network,
         reply=rejected,after_network=after_network,service_before=before_service,service_after=after_service,late=late),began)
    # Explicit fixture restart obtains a new real lease after synthetic invalid
    # option injection; this is not passed off as a wire-issued bad DHCP offer.
    command('systemctl','restart',UNIT);wait(healthy)
    began=time.monotonic()
    # Demonstrate backup reachability independently using the router's main route.
    backup=ns('ud_r',['python3','-c',"import socket;s=socket.create_connection(('203.0.113.2',8443),timeout=1);s.close()"])
    backup_warmup_packets=counter()
    assert backup.returncode==0 and backup_warmup_packets>0
    nft('ud_b','flush chain ip observe f\nadd rule ip observe f ip daddr 203.0.113.2 counter\n')
    before=counter()
    nft('ud_a','add table ip hole\nadd chain ip hole f { type filter hook forward priority -50; policy accept; }\nadd rule ip hole f drop\n')
    wait(lambda: not state()['healthy']);r=client();assert not r['ok'];assert counter()==before
    case('blackhole_no_false_health_or_backup_borrow',dict(state=state(),service=identity(),request=r,backup_warmup_packets=backup_warmup_packets,backup_packets_before=before,backup_packets_after=counter()),began)
    # Expiry must withdraw a genuinely active route, not one already removed by
    # failed health. Restore the path and record successful forwarding first.
    nft('ud_a','delete table ip hole\n');active=wait(healthy);active_network=network();active_request=client()
    assert active_request['ok'] and active_request['response']['peer']=='10.99.1.1'
    assert any(r.get('dst')=='default' for r in active_network['data_routes'])
    began=time.monotonic();serverpid=int((ROOT/'dnsmasq.pid').read_text());os.kill(serverpid,signal.SIGSTOP)
    # Stall callbacks too: only the formal daemon's persisted lease deadline
    # may withdraw this real wire-acquired lease, not an early client deconfig.
    os.kill(child_pid(),signal.SIGSTOP)
    expiry=active['expires']
    wait(lambda: state()['current'] is None,timeout=140)
    observed=float(ns('ud_r',['python3','-c','import time;print(time.clock_gettime(time.CLOCK_BOOTTIME))']).stdout)
    assert observed>=expiry
    r=client();assert not r['ok'];assert counter()==before
    case('lease_deadline_with_stalled_client',dict(before=active,before_network=active_network,before_request=active_request,current=state(),after_network=network(),request=r,deadline=expiry,observed=observed,client_stalled=True,backup_packets=counter()),began)
    rss_identity=identity();pid=int(rss_identity['MainPID'])
    rss=next(l for l in Path('/proc',str(pid),'status').read_text().splitlines() if l.startswith('VmRSS:'))
    began=time.monotonic()
    command('systemctl','stop',UNIT)
    code = """import sys,json
sys.path.insert(0,'/opt/uplinkstead-dhcp/source')
from pathlib import Path
from uplinkstead.dhcp import Lifecycle,config,PROBE_TABLE,DATA_TABLE
from uplinkstead.writer import now,boot_id
from uplinkstead.linux import Blocked
c=config(Path('/opt/uplinkstead-dhcp/config.json'))
def event(w,ip):
 return dict(session=w.s['session'],boot=boot_id(),revision=w.s['revision'],at=now(),reason='bound',lease=dict(ip=ip,subnet='255.255.255.0',router='192.0.2.5',lease='60'))
with Lifecycle(c,'/opt/uplinkstead-dhcp/state') as w:
 w.event(event(w,'192.0.2.3'))
 original=w.backend.run
 def failed(args,**kw):
  result=original(args,**kw)
  if args[:3]==['route','replace','default'] and PROBE_TABLE in args:
   raise OSError('injected after actual successful backend write')
  return result
 w.backend.run=failed
 try:w.event(event(w,'192.0.2.4'))
 except OSError:pass
 else:raise RuntimeError('fault was not exercised')
 pending=json.loads(w.db.execute('SELECT value FROM state WHERE id=1').fetchone()[0])
 assert pending['intent']['old']['ip']=='192.0.2.3' and pending['intent']['new']['ip']=='192.0.2.4'
 actual=json.loads(original(['-j','-4','addr','show','dev','wan0']))
 assert any(a['local']=='192.0.2.4' for r in actual for a in r['addr_info'])
with Lifecycle(c,'/opt/uplinkstead-dhcp/state') as w:
 assert w.s['current'] is None and w.s['intent'] is None and not w.healthy
 assert not w.backend.routes(PROBE_TABLE) and not w.backend.routes(DATA_TABLE)
 assert not json.loads(w.backend.run(['-j','-4','addr','show','dev','wan0']))
 print(json.dumps(dict(fault_after_actual_write=True,intent_retained=True,recovered_unverified=True,owned_addresses_removed=True,owned_tables_empty=True)))
"""
    details=json.loads(ns('ud_r',['python3','-c',code]).stdout)
    assert not client()['ok'] and counter()==before
    case('formal_backend_partial_write_recovery',details,began)
    result.update(passed=True,rss_snapshot=rss,rss_service=rss_identity,db_bytes=(ROOT/'state/journal.sqlite').stat().st_size,
                  service_source_sha256=hashlib.sha256((ROOT/'source/deploy/uplinkstead-dhcp.service').read_bytes()).hexdigest(),
                  installed_unit_sha256=hashlib.sha256(Path('/etc/systemd/system',UNIT).read_bytes()).hexdigest(),
                  environment=dict(kernel=command('uname','-r').strip(),python=sys.version.split()[0],
                      systemd=command('systemctl','--version').splitlines()[0],
                      busybox=version('busybox','--help'),dnsmasq=command('dnsmasq','--version').splitlines()[0]),
                  orderly_vm_restart_tested=False,power_loss_tested=False)
    (ROOT/'guest.json').write_text(json.dumps(result,indent=2));return result


def cleanup():
    before=json.loads((ROOT/'root-before.json').read_text()) if (ROOT/'root-before.json').exists() else None
    path=Path('/etc/systemd/system',UNIT)
    if path.exists():
        assert (ROOT/'installed-unit').exists() and path.read_bytes()==(ROOT/'installed-unit').read_bytes()
        cmd(['systemctl','stop',UNIT],check=False);path.unlink();command('systemctl','daemon-reload');cmd(['systemctl','reset-failed',UNIT],check=False)
    owned=json.loads((ROOT/'owner-names.json').read_text()) if (ROOT/'owner-names.json').exists() else []
    for n in owned:
        p=cmd(['ip','netns','pids',n],check=False)
        for pid in p.stdout.split():
            try:os.kill(int(pid),signal.SIGKILL)
            except ProcessLookupError:pass
        cmd(['ip','netns','del',n],check=False)
    existing={l.split()[0] for l in command('ip','netns','list').splitlines()}
    unchanged=before is not None and digest(before)==digest(root_snapshot())
    assert not existing.intersection(owned) and unchanged
    return dict(passed=True,root_network_unchanged=unchanged,namespaces_removed=True,unit_removed=not path.exists())


if __name__=='__main__':
    if not __debug__:raise RuntimeError('Validation requires assertions')
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('run','cleanup'));a=p.parse_args()
    print(json.dumps(run() if a.operation=='run' else cleanup(),allow_nan=False))
