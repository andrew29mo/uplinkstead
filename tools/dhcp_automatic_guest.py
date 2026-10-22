"""Actual automatic foreground service, wire clients and isolated Linux backend.

The last two cases use an explicitly labelled bounded-delay backend wrapper;
all route mutations and postconditions still use production Backend.select.
"""
import argparse,copy,json,os,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dhcp_p0_guest import Service,wire,summary
from tools.dhcp_stage1_guest import wait,rss
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure,owned_network
from tools.guest import nft,ip
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from uplinkstead.writer import now

class FaultService(Service):
    def __init__(self,root,source,binary):
        self.root=root;self.path=root/'run/events.sock';self.log=(root/'service-private.log').open('a')
        self.p=subprocess.Popen(['ip','netns','exec','dd_r','python3','-m','tools.dhcp_automatic_fault_service',
            '--config',str(root/'config.json'),'--journal',str(root/'state'),'--socket',str(self.path),
            '--hook',str(source/'deploy/uplinkstead-dual-hook.py'),'--client',str(binary)],
            cwd=source,env=dict(os.environ,PYTHONPATH=str(source)),stdout=self.log,stderr=self.log)
        try:wait(lambda:self.path.exists() and self.p.poll() is None,20)
        except BaseException:self.stop();raise

def run(root,source):
    f=Fixture(root,source);service=None
    result=dict(passed=False,source_sha256=fingerprint(manifest()),cases=[],
        client_build=json.loads((root/'client/build.json').read_text()),client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),client_config_sha256=digest(root/'client/busybox-1.36.1/.config'),
        limitations=['Foreground automatic dual-DHCP integration; no installed systemd/reboot, power-loss or boot-zero-gap qualification',
        'Controlled local DHCP servers and namespace paths, not physical WAN or general interoperability',
        'RSS snapshots not peaks; case durations include deliberate waits, not outage SLOs',
        'ACK/loss races use a test-only bounded delay after actual production backend route readback; no atomic ACK/kernel or continuous-forwarding guarantee'])
    def persist():(root/'automatic-guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,start,**details):result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-start,details=details));persist()
    def status():return service.call('status')
    def active(k):return wait(lambda:(lambda s:s if s['state']['active'] and s['state']['active']['link']==k else None)(status()),20)
    def healthy(k):return wait(lambda:(lambda s:s if s['state']['links'][k]['state']=='HEALTHY' else None)(status()),20)
    def traffic(k):
        v=f.client();assert v['ok'] and v['response']['peer']==f'10.99.{LINKS[k]["transit"]}.1',v
        return v
    def tx(s):
        row=s['state']['links']['B'];r=next(r for r in reversed(s['runtime']['recent']) if r['link']=='B' and r['sequence']==row['event_sequence'] and r['reason'] in ('bound','renew'))
        def find():
            packets=wire(root,'B');req=next((p for p in reversed(packets) if p['type']==3 and p['xid']==r['xid']),None);ack=next((p for p in reversed(packets) if p['type']==5 and p['xid']==r['xid']),None)
            return dict(record=r,request=summary(req),ack=summary(ack)) if req and ack else None
        return wait(find,3)
    def setprofile(enabled=True):
        path=root/'automatic-profile.json';temporary=path.with_suffix('.tmp')
        temporary.write_text(json.dumps(dict(reply=enabled,lease=60,**{'58':5,'59':40})));temporary.replace(path)
    try:
        f.setup();configure(root)
        ip('dd_r','route','replace','192.0.2.1/32','dev','wanA','scope','link')
        ip('dd_r','route','replace','default','via','192.0.2.1','dev','wanA','onlink')
        f.server('A',duration='10m',extra=['--dhcp-option-force=58,300i','--dhcp-option-force=59,500i']);f.stop(f.servers['B'])
        nft('dd_b','add table ip automatic\nadd chain ip automatic input { type filter hook input priority -200; policy accept; }\nadd rule ip automatic input udp dport 67 drop\n')
        profile=root/'automatic-profile.json';setprofile(False)
        f.spawn('dd_b',['python3',str(source/'tools/dhcp_timer_server.py'),'--interface','edge','--profile',str(profile),'--log',str(root/'server.jsonl')],'server-B');wait(lambda:profile.with_suffix('.ready').exists(),10)
        for k in LINKS:
            p=root/('wire-'+k+'.jsonl');f.spawn('dd_r',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface',LINKS[k]['interface'],'--output',str(p)],'wire-'+k);wait(lambda p=p:p.with_suffix('.ready').exists(),10)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=2,failure_rounds=3,freshness=5,budget=4,window=600)
        c['runtime']=dict(queue_capacity=8,probe_interval=.15,restart_delay=.2,client_diagnostics=True,automatic_selection=True,selection_hold=.3,failover_delay=.8)
        (root/'config.json').write_text(json.dumps(c));start=time.monotonic();service=Service(root,source)
        initial=active('A');B_enabled_at=now();setprofile()
        healthy('B');first=active('A');assert len(first['state']['history'])==1
        old=dict(op='choose',link='A',epoch=first['state']['epoch'],revision=first['state']['revision'])
        case('automatic_initial_A',start,initial=initial,B_server_enabled_at=B_enabled_at,after=first,client=traffic('A'))
        start=time.monotonic();ready_path=root/'slow-tls-ready.json'
        code="import socket,json,time;from pathlib import Path;s=[socket.create_connection(('203.0.113.2',8443),timeout=.5,source_address=('10.77.0.1',0)) for _ in range(2)];Path("+repr(str(ready_path))+").write_text(json.dumps({'at':time.clock_gettime(time.CLOCK_BOOTTIME)}));time.sleep(3)"
        holder=f.spawn('dd_r',['python3','-c',code],'slow-tls');wait(lambda:ready_path.exists(),3)
        ready_at=json.loads(ready_path.read_text())['at'];client_at=now();data=traffic('A');finished_at=now();assert holder.poll() is None
        f.stop(holder)
        case('TLS_fixture_slow_handshake_isolation',start,ready_at=ready_at,client_at=client_at,finished_at=finished_at,holder_stopped_at=now(),tcp_only=True,client=data)
        start=time.monotonic();before=status();fault_at=now();f.fault('A',True);after=active('B')
        assert len(after['state']['history'])==2
        case('A_blackhole_automatic_B',start,before=before,fault_at=fault_at,after=after,client=traffic('B'))
        f.fault('A',False);healthy('A');start=time.monotonic();before=status();rounds=[];previous=before
        for _ in range(4):
            def renewed():
                s=status();b=s['state']['links']['B'];p=previous['state']['links']['B']
                return s if b['event_sequence']>p['event_sequence'] and s['state']['active'] and s['state']['active']['link']=='B' and s['state']['active']['generation']==b['generation'] and b['state']=='HEALTHY' and not s['runtime']['capture']['B']['pending'] else None
            after=wait(renewed,15);assert after['state']['history']==before['state']['history'];rounds.append(dict(status=after,transaction=tx(after),client=traffic('B')));previous=after
        case('four_natural_B_renewals',start,before=before,rounds=rounds,rss_kib=dict(service=rss(service.p.pid),clients={k:rss(after['runtime']['children'][k]) for k in LINKS}))
        start=time.monotonic();before=status();os.kill(before['runtime']['children']['B'],signal.SIGUSR2)
        after=active('A');assert after['state']['links']['B']['current'] is None and len(after['state']['history'])==3
        rejected=service.raw(old);assert not rejected['ok'];fenced=wait(lambda:(lambda s:s if s['runtime']['as_of']>after['runtime']['as_of'] else None)(status()),3)
        assert fenced['state']['active']==after['state']['active'] and fenced['state']['history']==after['state']['history']
        case('B_loss_automatic_A_stale_request',start,before=before,after=after,network=owned_network(),old_request=old,rejection=rejected,fence=fenced,client=traffic('A'))
        start=time.monotonic();os.kill(after['runtime']['children']['B'],signal.SIGUSR1);healthy('B');before=status()
        f.fault('A',True)
        suspect=wait(lambda:(lambda s:s if s['state']['links']['A']['state']=='SUSPECT' and s['state']['active'] and s['state']['active']['link']=='A' else None)(status()),5)
        f.fault('A',False);healthy('A');time.sleep(1);after=active('A')
        assert after['state']['history']==before['state']['history']
        case('short_flap_and_no_preemption',start,before=before,suspect=suspect,after=after,client=traffic('A'))
        start=time.monotonic();before=status();f.fault('A',True);fourth=active('B');assert len(fourth['state']['history'])==4
        f.fault('B',True);empty=wait(lambda:(lambda s:s if s['state']['active'] is None and all(s['state']['links'][k]['state']=='DOWN' for k in LINKS) else None)(status()),15)
        blocked=f.client();assert not blocked['ok'];f.fault('A',False)
        latched=wait(lambda:(lambda s:s if s['state']['latched'] else None)(status()),15)
        f.fault('B',False)
        os.kill(latched['runtime']['children']['B'],signal.SIGUSR1)
        stopped=wait(lambda:(lambda s:s if s['state']['links']['B']['event_sequence']>latched['state']['links']['B']['event_sequence'] and s['state']['links']['B']['state']=='HEALTHY' else None)(status()),15)
        witness_at=now();witness=f.client('dd_r',source='10.77.0.1');denied=f.client();assert witness['ok'] and witness['response']['peer']=='10.99.1.1' and not denied['ok']
        assert stopped['state']['active'] is None and stopped['state']['history']==fourth['state']['history']
        case('both_down_then_budget_latch',start,before=before,fourth=fourth,empty=empty,blocked=blocked,latched=latched,after=stopped,fallback=dict(at=witness_at,client=witness),denied=denied)
        service.stop();service=None
        # Fresh fixture service journal; previous service cleanly withdrew owned
        # allocations. No live journal is deleted/reset to bypass a latch.
        race=root/'race';race.mkdir(mode=0o700);rc=copy.deepcopy(c);rc['budget']=8;(race/'config.json').write_text(json.dumps(rc))
        setprofile(False)
        service=FaultService(race,source,root/'client/busybox-1.36.1/busybox');active('A')
        # Linux removes interface routes when its last IPv4 address is deleted
        # during the previous service's clean withdrawal. Reprovision fixture
        # main routes only after fresh acquisition; product never adopts them.
        ip('dd_r','route','replace','192.0.2.1/32','dev','wanA','scope','link')
        ip('dd_r','route','replace','default','via','192.0.2.1','dev','wanA','onlink')
        setprofile();healthy('B')
        def barrier(name,inject):
            start=time.monotonic();before=status()
            for p in race.glob('barrier-*'):p.unlink()
            (race/'barrier-arm.json').write_text(json.dumps(dict(link='B')));f.fault('A',True)
            wait(lambda:(race/'barrier-ready.json').exists(),15);ready=json.loads((race/'barrier-ready.json').read_text());inject(status())
            queued=wait(lambda:(lambda s:s if s['runtime']['queue']['per_link_depth']['B']>0 else None)(status()),2)
            release_at=now();(race/'barrier-release').touch()
            invalid=wait(lambda:(lambda s:s if s['runtime']['metrics']['selection_invalidations']>before['runtime']['metrics']['selection_invalidations'] else None)(status()),5)
            done=json.loads((race/'barrier-done.json').read_text())
            return start,dict(before=before,barrier=ready,queued=queued,release_at=release_at,done=done,invalid=invalid)
        start,d=barrier('ACK',lambda s:os.kill(s['runtime']['children']['B'],signal.SIGUSR1))
        after=active('B');case('ACK_during_backend_write',start,**d,after=after,transaction=tx(after),client=traffic('B'))
        # Bring A back, then force a real B loss so automatic routing selects A.
        f.fault('A',False);healthy('A');os.kill(after['runtime']['children']['B'],signal.SIGUSR2);active('A')
        os.kill(status()['runtime']['children']['B'],signal.SIGUSR1);healthy('B')
        start,d=barrier('loss',lambda s:os.kill(s['runtime']['children']['B'],signal.SIGUSR2))
        withdrawn=wait(lambda:(lambda s:s if s['state']['active'] is None and s['state']['links']['B']['current'] is None else None)(status()),5)
        f.fault('A',False);after=active('A');witness=f.client('dd_r',source='10.77.0.1')
        assert witness['ok'] and witness['response']['peer']=='10.99.1.1'
        case('loss_during_backend_write',start,**d,withdrawn=withdrawn,after=after,client=traffic('A'),fallback=witness)
        result['wire_counters']=f.counters();assert all(result['wire_counters'][k]['wrong_dhcp']==0 for k in LINKS)
        result['passed']=True
    except BaseException as exc:
        result.update(passed=False,failure=dict(type=type(exc).__name__,message=str(exc)[:1500]))
        if service:
            try:result['failure_status']=status();result['client_log_tail']=(service.root/'service-private.log').read_text()[-2500:]
            except BaseException:pass
        try:result['fixture_tls_log_tail']=(root/'tls-private.log').read_text()[-2000:];result['failure_network']=owned_network()
        except BaseException:pass
        raise
    finally:
        try:
            if service:service.stop()
        finally:
            try:result['cleanup']=f.cleanup()
            except BaseException:result['passed']=False;raise
            finally:persist()
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();print(json.dumps(run(a.root,Path(__file__).resolve().parents[1]),allow_nan=False))
