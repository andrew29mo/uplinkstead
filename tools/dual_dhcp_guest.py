"""Bounded dual-DHCP explorations, real namespace networking, no service claims."""
import argparse
import copy
import hashlib
import json
import os
import platform
from pathlib import Path
import signal
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dual_dhcp_fixture import Fixture, LINKS, cleanup_owned
from tools.guest import ns, ip, cmd
from tools.evidence import manifest, fingerprint


def drive(root):
    from uplinkstead.dual_dhcp import DualLifecycle
    from uplinkstead.dual_dhcp_linux import Backend
    from uplinkstead.probe import round as probe_round
    c=json.loads((root/'config.json').read_text())
    with DualLifecycle(c,root/'state',Backend) as w:
        print(json.dumps(dict(ready=True,state=w.snapshot())),flush=True)
        for line in sys.stdin:
            q=json.loads(line);op=q.pop('op')
            try:
                extra={}
                if op in ('callback','fault_callback'):
                    if op=='fault_callback':
                        real_run=w.backend.run
                        def fail_after_address(args,**kwargs):
                            value=real_run(args,**kwargs)
                            if args[:2]==['addr','replace']:raise OSError('Fixture failure after actual backend address write')
                            return value
                        w.backend.run=fail_after_address
                    e=q['event'];link=e['link'];s=w.snapshot();v=s['links'][link]
                    w.callback(link,e.get('session',v['session']),e.get('boot',s['boot']),v['revision'],e['at'],e['reason'],e['lease'],e.get('options',[]))
                elif op=='probe':
                    link=q['link'];s=w.snapshot();v=s['links'][link]
                    pc=copy.deepcopy(c);pc['links'][link]['source']=v['current']['ip']
                    began=time.monotonic();votes,rows=probe_round(pc,link)
                    w.observation(link,v['generation'],q['round'],began,votes)
                    extra=dict(votes=votes,rows=rows)
                elif op=='choose':
                    s=w.snapshot();w.choose(q['link'],s['epoch'],s['revision'])
                elif op=='restart_client':w.restart_client(q['link'])
                elif op=='tick':w.tick()
                elif op=='pause':w.pause(q['value'])
                elif op=='raw_callback':w.callback(**q)
                elif op!='status':raise ValueError('Unknown fixture command')
                print(json.dumps(dict(ok=True,state=w.snapshot(),**extra)),flush=True)
            except Exception as exc:
                print(json.dumps(dict(ok=False,error=type(exc).__name__,state=w.snapshot())),flush=True)


class Driver:
    def __init__(self,root,source):
        self.root=root
        self.log=(root/'driver-private.log').open('a')
        self.p=subprocess.Popen(['ip','netns','exec','dd_r','python3',str(source/'tools/dual_dhcp_guest.py'),'--drive','--root',str(root)],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.log,text=True,bufsize=1)
        import select
        if not select.select([self.p.stdout],[],[],20)[0]:
            self.p.kill();self.p.wait(timeout=3);raise TimeoutError('Formal driver startup timed out')
        self.ready=json.loads(self.p.stdout.readline());assert self.ready['ready']
    def call(self,op,**q):
        self.p.stdin.write(json.dumps(dict(op=op,**q))+'\n');self.p.stdin.flush()
        import select
        if not select.select([self.p.stdout],[],[],20)[0]:raise TimeoutError('Formal driver command timed out')
        line=self.p.stdout.readline()
        if not line:raise RuntimeError('Formal driver exited')
        return json.loads(line)
    def stop(self,crash=False):
        if self.p.poll() is None:
            if crash:self.p.kill()
            else:self.p.stdin.close()
            try:self.p.wait(timeout=8)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait(timeout=3)
        self.p.stdout.close();self.log.close()


def configure(root):
    c=dict(links={k:dict(interface=v['interface']) for k,v in LINKS.items()},
           lan=dict(interface='lan0',prefix='10.77.0.0/24'),
           targets=[dict(ip='203.0.113.2',port=p) for p in (8443,8444,8445)],
           ca=str(root/'ca.crt'),server_name='probe.test',success_rounds=2,failure_rounds=2,freshness=5,budget=20,window=120)
    (root/'config.json').write_text(json.dumps(c))


def owned_network():
    return {key:json.loads(ip('dd_r',*args).stdout) for key,args in (
        ('addresses',('-j','-4','addr')),('routes',('-j','route','show','table','all')),
        ('rules',('-j','rule','show')))}


def stale_challenge(driver,link,field,retired):
    """Synthetic isolated-authority challenge: all other fields are current."""
    before=driver.call('status')['state'];network=owned_network();row=before['links'][link]
    event=dict(link=link,session=row['session'],boot=before['boot'],revision=row['revision'],at=time.monotonic(),
               reason='renew',lease=dict(ip=LINKS[link]['address'],subnet='255.255.255.0',router=LINKS[link]['gateway'],lease='120'),options=[])
    assert event[field]!=retired,'Authority challenge would not be stale'
    event[field]=retired
    response=driver.call('raw_callback',**event)
    assert not response['ok'] and response['state']==before,response
    assert owned_network()==network,'Rejected authority challenge modified network'
    return dict(origin='synthetic_isolated_authority_challenge',field=field,link=link,
                rejected=True,snapshot_unchanged=True,network_unchanged=True)


def finalize(root,result,fixture,driver,filename):
    """A cleanup failure invalidates success and is persisted before propagating."""
    try:
        try:
            if driver:driver.stop()
        finally:
            result['cleanup']=fixture.cleanup()
    except BaseException as exc:
        result['passed']=False
        result['cleanup_failure']=dict(type=type(exc).__name__,message=str(exc)[:1500])
        raise
    finally:
        root.mkdir(mode=0o700,parents=True,exist_ok=True)
        (root/filename).write_text(json.dumps(result,indent=2,allow_nan=False))


def run(root,source):
    busybox=cmd(['busybox'],check=False)
    result=dict(passed=False,kind='isolated_linux_dual_dhcp_exploration',cases=[],source_sha256=fingerprint(manifest()),
                environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version(),
                                 busybox=(busybox.stdout+busybox.stderr).splitlines()[0],
                                 dnsmasq=cmd(['dnsmasq','--version']).stdout.splitlines()[0]),
                limitations=['Not an installed dual-DHCP systemd service','No VM reboot in this phase; separate reboot receipt; power-loss untested',
                             'Hook observations submitted by bounded fixture adapter; no production IPC scheduling claim',
                             'Upstream NAT and return routes explicitly provisioned by fixture'])
    f=Fixture(root,source);d=None
    def save():
        (root/'guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,began,**details):
        result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-began,details=details));save()
    def ok(op,**q):
        r=d.call(op,**q);assert r['ok'],r;return r
    def acquire(link,event=None):
        if event is None:event=f.await_event(link)
        r=ok('callback',event=event)
        assert r['state']['links'][link]['current'],r
        return event,r
    def start(link):
        state=ok('status')['state']
        return f.start_client(link,state['links'][link]['session'],state['boot'])
    rounds={'A':0,'B':0}
    def prove(link):
        for _ in range(2):
            rounds[link]+=1;r=ok('probe',link=link,round=rounds[link]);assert r['votes']==3,r
        return r
    try:
        f.setup()
        configure(root);d=Driver(root,source)
        began=time.monotonic()
        for link in LINKS:start(link)
        for link in LINKS:acquire(link)
        for link in LINKS:prove(link)
        ok('choose',link='A');r=f.client();assert r['ok'] and r['response']['peer']=='10.99.1.1',r
        case('two_real_wire_leases_and_A_data_path',began,state=ok('status')['state'],client=r,counts=f.counters())

        began=time.monotonic();fallback=f.client('dd_r')
        assert fallback['ok'] and fallback['response']['peer']=='10.99.2.1',fallback
        before_counts=f.counters()
        ip('dd_r','route','flush','table','41201')
        rounds['A']+=1;missing=ok('probe',link='A',round=rounds['A']);assert missing['votes']==0
        after_counts=f.counters();assert after_counts['B']['target']==before_counts['B']['target']
        # The lookup terminal guard is tested independently of a dead next hop.
        synthetic=dict(link='A',at=time.monotonic(),reason='renew',lease=dict(ip='192.0.2.2',subnet='255.255.255.0',router='192.0.2.1',lease='120'),options=[],origin='synthetic_rebuild_after_missing_route_challenge')
        ok('callback',event=synthetic);prove('A');ok('choose',link='A')
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        case('missing_A_probe_table_terminal_guard_no_B_borrow',began,probe=missing,before=before_counts,after=after_counts,viable_main_fallback=fallback,repair_origin=synthetic['origin'])

        began=time.monotonic();prove('A');before=ok('status')['state'];before_A=copy.deepcopy(before['links']['A'])
        os.kill(f.clients['B'].pid,signal.SIGUSR1);event,r=acquire('B')
        after=r['state'];assert after['links']['A']==before_A,(before,after)
        assert after['active']==before['active'];data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        case('inactive_B_real_renewal_isolation',began,event=event,state=after,client=data)

        began=time.monotonic();prove('A');f.stop(f.clients['B']);ok('restart_client',link='B')
        assert ok('status')['state']['active']['link']=='A';data=f.client();assert data['ok']
        start('B');wire=f.await_event('B');prove('A');acquire('B',wire);prove('B')
        assert ok('status')['state']['active']['link']=='A'
        case('B_client_restart_isolation',began,client=data,state=ok('status')['state'])

        began=time.monotonic();counts=f.counters();f.fault('A')
        for _ in range(2):
            rounds['A']+=1;r=ok('probe',link='A',round=rounds['A']);assert r['votes']==0
        # Failed A probes must not appear as B target packets.
        blocked=f.client();assert not blocked['ok'],blocked
        after_counts=f.counters();assert after_counts['B']['target']==counts['B']['target'],(counts,after_counts)
        prove('B');ok('choose',link='B');data=f.client();assert data['ok'] and data['response']['peer']=='10.99.2.1'
        f.fault('A',False)
        case('A_blackhole_no_borrow_and_explicit_safe_B_selection',began,before=counts,after=after_counts,blocked=blocked,client=data)

        began=time.monotonic();prove('A');counts=f.counters();f.fault('B')
        for _ in range(2):
            rounds['B']+=1;r=ok('probe',link='B',round=rounds['B']);assert r['votes']==0
        blocked=f.client();assert not blocked['ok']
        after_counts=f.counters();assert after_counts['A']['target']==counts['A']['target']
        prove('A');ok('choose',link='A');data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        f.fault('B',False);prove('B');ok('choose',link='B')
        case('B_blackhole_no_borrow_and_explicit_safe_A_selection',began,before=counts,after=after_counts,blocked=blocked,client=data)

        began=time.monotonic();s=ok('status')['state'];beforeB=copy.deepcopy(s['links']['B']);active=copy.deepcopy(s['active'])
        event=dict(link='A',at=time.monotonic(),reason='renew',lease=dict(ip='198.51.100.3',subnet='255.255.255.0',router='198.51.100.1',lease='120'),options=[],origin='synthetic_conflicting_callback')
        r=d.call('callback',event=event);s=r['state']
        assert s['links']['A']['current'] is None and s['links']['B']==beforeB and s['active']==active,r
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.2.1'
        case('synthetic_cross_link_conflict_withdraws_only_proposer',began,result=r,client=data)

        began=time.monotonic()
        # External fixture change: DHCP server A offers a subnet overlapping B.
        # The separate WAN segments can share this address; router never admits it.
        f.stop(f.clients['A']);ok('restart_client',link='A')
        ip('dd_a','addr','add','198.51.100.1/24','dev','edge')
        f.server('A',address='198.51.100.3',gateway='198.51.100.1')
        start('A');conflict_wire=f.await_event('A')
        assert conflict_wire['lease']['ip']=='198.51.100.3',conflict_wire
        prove('B');before_conflict=ok('status')['state']
        rejected=ok('callback',event=conflict_wire)
        assert rejected['state']['links']['A']['current'] is None
        assert rejected['state']['links']['B']==before_conflict['links']['B']
        assert rejected['state']['active']==before_conflict['active']
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.2.1'
        case('real_wire_cross_link_conflict_withdraws_only_proposer',began,
             event=conflict_wire,result=rejected,client=data,
             external_fixture_change='Added overlapping server-side address to isolated A edge and changed A DHCP offer')
        f.stop(f.clients['A']);f.stop(f.servers['A'])
        ip('dd_a','addr','del','198.51.100.1/24','dev','edge')
        f.server('A');ok('restart_client',link='A');start('A')
        restored_wire=f.await_event('A');prove('B');acquire('A',restored_wire)

        began=time.monotonic();os.kill(f.clients['A'].pid,signal.SIGUSR1);acquire('A');prove('A');prove('B')
        # Natural client timers, not SIGUSR1, must demonstrate unicast renewal.
        start_counts=f.counters();natural=[];next_probe=time.monotonic()
        until=time.monotonic()+85
        while time.monotonic()<until and not {e['link'] for e in natural}>={'A','B'}:
            for link in LINKS:
                for event in f.events(link):
                    if event['reason'] in ('renew','bound'):
                        ok('callback',event=event)
                        if event['reason']=='renew':natural.append(event)
            if time.monotonic()>=next_probe:
                for link in LINKS:prove(link)
                if ok('status')['state']['active'] is None:ok('choose',link='B')
                next_probe=time.monotonic()+1
            time.sleep(.1)
        assert {e['link'] for e in natural}>={'A','B'},natural
        end_counts=f.counters()
        for link in LINKS:
            assert end_counts[link]['own_dhcp']>start_counts[link]['own_dhcp']
            assert end_counts[link]['wrong_dhcp']==start_counts[link]['wrong_dhcp']
        case('natural_T1_both_clients_unicast_no_wrong_WAN',began,events=natural,before=start_counts,after=end_counts)

        began=time.monotonic();prove('A');ok('choose',link='A')
        f.server('B',extra=['--dhcp-option=121,10.88.0.0/16,198.51.100.1'])
        os.kill(f.clients['B'].pid,signal.SIGUSR1)
        option_event=f.await_event('B')
        assert 'staticroutes' in option_event['options'],option_event
        before_option=ok('status')['state'];option_result=ok('callback',event=option_event)
        assert option_result['state']['links']['B']['current'] is None
        assert option_result['state']['links']['A']==before_option['links']['A']
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        case('real_wire_option121_detected_and_B_withdrawn',began,event=option_event,result=option_result,client=data)
        f.server('B');f.stop(f.clients['B']);ok('restart_client',link='B');start('B');acquire('B');prove('B');prove('A')

        began=time.monotonic()
        before=ok('status')['state'];old={k:dict(link=k,session=before['links'][k]['session'],boot=before['boot'],revision=before['links'][k]['revision'],at=time.monotonic(),reason='renew',lease=dict(ip=LINKS[k]['address'],subnet='255.255.255.0',router=LINKS[k]['gateway'],lease='120'),options=[]) for k in LINKS}
        d.stop(crash=True);d=Driver(root,source);s=ok('status')['state']
        assert s['active'] is None and all(s['links'][k]['current'] is None for k in LINKS),s
        data=f.client();assert not data['ok'],data
        challenges=[stale_challenge(d,link,'session',old[link]['session']) for link in LINKS]
        for link in LINKS:
            # Restart actual clients so callbacks cannot borrow old adapter authority.
            f.stop(f.clients[link]);start(link)
        for link in LINKS:acquire(link)
        for link in LINKS:prove(link)
        ok('choose',link='A');data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        case('writer_SIGKILL_quarantine_both_and_reject_old_sessions',began,before=before,restarted=s,client=data,authority_challenges=challenges)
        began=time.monotonic()
        fault_event=dict(link='B',at=time.monotonic(),reason='renew',lease=dict(ip='198.51.100.3',subnet='255.255.255.0',router='198.51.100.1',lease='120'),options=[],origin='synthetic_backend_failure_challenge')
        failed=d.call('fault_callback',event=fault_event)
        assert not failed['ok'] and failed['state']['phase']=='RECOVERY_REQUIRED' and failed['state']['pending'],failed
        actual=json.loads(ip('dd_r','-j','-4','addr','show','dev','wanB').stdout)
        assert any(a['local']=='198.51.100.3' for row in actual for a in row['addr_info']),actual
        d.stop();d=Driver(root,source);recovered=ok('status')['state']
        assert recovered['active'] is None and all(recovered['links'][k]['current'] is None for k in LINKS)
        for link in LINKS:
            rows=json.loads(ip('dd_r','-j','-4','addr','show','dev',LINKS[link]['interface']).stdout)
            assert not any(row['addr_info'] for row in rows),rows
        assert not f.client()['ok']
        case('real_backend_partial_address_write_recovery',began,failure=failed,actual_partial_addresses=actual,recovered=recovered)
        status=Path('/proc',str(d.p.pid),'status').read_text()
        rss=next(int(line.split()[1]) for line in status.splitlines() if line.startswith('VmRSS:'))
        result['boot']=recovered['boot']
        result['measurements']=dict(driver_pid=d.p.pid,driver_rss_kib=rss,
            sqlite_main_bytes=(root/'state/journal.sqlite').stat().st_size,
            scope='One post-recovery formal driver VmRSS snapshot; not peak, process tree, host, or whole-VM memory')
        result['passed']=True
    except BaseException as exc:
        result['failure']=dict(type=type(exc).__name__,message=str(exc)[:1500]);raise
    finally:
        finalize(root,result,f,d,'guest.json')
    return result


def reboot(root,source,after=False):
    from uplinkstead.writer import boot_id
    f=Fixture(root,source);d=None
    result=dict(passed=False,kind='manual_formal_core_orderly_VM_reboot',cases=[],
                limitations=['Not an installed service or automatic startup test','No sudden power-loss or boot zero-gap test'])
    prepared=root/'reboot-prepared.json';journal=root/'state/journal.sqlite'
    try:
        old=json.loads(prepared.read_text()) if after else None
        if after:
            assert old['boot']!=boot_id(),'VM boot ID did not change'
            actual=hashlib.sha256(journal.read_bytes()).hexdigest()
            assert actual==old['journal_sha256'],'Journal changed before new-boot lifecycle startup'
            result['pre_core_evidence']=dict(boot=boot_id(),journal_sha256=actual,unchanged_since_before_VM_stop=True)
        f.setup();configure(root);d=Driver(root,source)
        initial=d.ready['state']
        assert initial['active'] is None and all(initial['links'][k]['current'] is None for k in LINKS)
        for link in LINKS:
            rows=json.loads(ip('dd_r','-j','-4','addr','show','dev',LINKS[link]['interface']).stdout)
            assert not any(row['addr_info'] for row in rows)
        assert not f.client()['ok']
        if after:
            result['authority_challenges']=[stale_challenge(d,link,field,old['callbacks'][link][field])
                                            for link in LINKS for field in ('session','boot')]
        for link in LINKS:
            authority=d.call('status')['state'];f.start_client(link,authority['links'][link]['session'],authority['boot'])
        for link in LINKS:
            event=f.await_event(link);response=d.call('callback',event=event);assert response['ok']
        for link in LINKS:
            for round_id in (1,2):
                response=d.call('probe',link=link,round=round_id);assert response['ok'] and response['votes']==3,response
        response=d.call('choose',link='A');assert response['ok'],response
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        state=d.call('status')['state'];callbacks={k:dict(link=k,session=state['links'][k]['session'],boot=state['boot'],revision=state['links'][k]['revision'],at=time.monotonic(),reason='renew',lease=dict(ip=LINKS[k]['address'],subnet='255.255.255.0',router=LINKS[k]['gateway'],lease='120'),options=[]) for k in LINKS}
        d.stop(crash=True);d=None
        digest=hashlib.sha256(journal.read_bytes()).hexdigest()
        if not after:
            prepared.write_text(json.dumps(dict(boot=boot_id(),journal_sha256=digest,state=state,callbacks=callbacks),indent=2))
        result.update(passed=True,initial=initial,state=state,client=data,journal_sha256=digest,boot=boot_id())
    except BaseException as exc:
        result['passed']=False
        result['failure']=dict(type=type(exc).__name__,message=str(exc)[:1500])
        raise
    finally:
        finalize(root,result,f,d,'reboot-after.json' if after else 'reboot-before.json')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,default=Path('/opt/uplinkstead-dual'));p.add_argument('--drive',action='store_true');p.add_argument('--prepare-reboot',action='store_true');p.add_argument('--after-reboot',action='store_true');p.add_argument('--cleanup',action='store_true');a=p.parse_args()
    if a.cleanup:print(json.dumps(cleanup_owned(a.root)))
    elif a.drive:drive(a.root)
    elif a.prepare_reboot or a.after_reboot:print(json.dumps(reboot(a.root,Path(__file__).resolve().parents[1],after=a.after_reboot),allow_nan=False))
    else:print(json.dumps(run(a.root,Path(__file__).resolve().parents[1]),allow_nan=False))
