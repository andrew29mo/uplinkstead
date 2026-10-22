"""Selected-WAN convergence through the formal runtime/client and real packets."""
import argparse,copy,json,os,signal,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dhcp_p0_guest import Service,wire,summary
from tools.dhcp_stage1_guest import wait,immutable_link,rss
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure,owned_network
from tools.guest import nft,ns,ip
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from uplinkstead.writer import now


def run(root,source):
    f=Fixture(root,source);service=None;profile=root/'convergence-profile.json'
    result=dict(passed=False,source_sha256=fingerprint(manifest()),cases=[],client_build=json.loads((root/'client/build.json').read_text()),client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),client_config_sha256=digest(root/'client/busybox-1.36.1/.config'),limitations=['Selected-WAN restoration only; no automatic cross-WAN failover or installed service/reboot qualification','Synthetic local DHCP B server; no general server interoperability, hostile DHCP, zero-gap or power-loss guarantee','VM process RSS snapshots, not peaks/native benchmark; transient renewal interruption remains'])
    def persist():(root/'convergence-guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,start,**details):result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-start,details=details));persist()
    def setprofile(**kw):
        v=dict(lease=60,**{'58':5,'59':40});v.update(kw);p=profile.with_suffix('.tmp');p.write_text(json.dumps(v));p.replace(profile)
    try:
        f.setup();configure(root);f.stop(f.servers['B']);f.server('A',duration='10m',extra=['--dhcp-option-force=58,300i','--dhcp-option-force=59,500i'])
        # Independent fixture fallback must survive both B blackhole and expiry.
        # Never remove/bypass the product's RPDB guards to demonstrate this.
        ip('dd_r','route','replace','192.0.2.1/32','dev','wanA','scope','link')
        ip('dd_r','route','replace','default','via','192.0.2.1','dev','wanA','onlink')
        nft('dd_b','add table ip convergence\nadd chain ip convergence input { type filter hook input priority -200; policy accept; }\nadd rule ip convergence input udp dport 67 drop\n');setprofile()
        f.spawn('dd_b',['python3',str(source/'tools/dhcp_timer_server.py'),'--interface','edge','--profile',str(profile),'--log',str(root/'server.jsonl')],'server-B')
        wait(lambda:profile.with_suffix('.ready').exists(),10)
        for k in LINKS:
            p=root/('wire-'+k+'.jsonl');f.spawn('dd_r',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface',LINKS[k]['interface'],'--output',str(p)],'wire-'+k);wait(lambda p=p:p.with_suffix('.ready').exists(),10)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=2,freshness=10,budget=2,window=600)
        c['runtime']=dict(queue_capacity=8,probe_interval=.2,restart_delay=.2,client_diagnostics=True,restore_selected=True);(root/'config.json').write_text(json.dumps(c));service=Service(root,source)
        def status():return service.call('status')
        def row(s,k='B'):return s['state']['links'][k]
        def ready(k):return wait(lambda:(lambda s:s if row(s,k)['state']=='HEALTHY' else None)(status()),20)
        def traffic(k):
            d=f.client();assert d['ok'] and d['response']['peer']==f'10.99.{LINKS[k]["transit"]}.1',d
            return d
        def choose(k):
            def act():
                s=ready(k);r=service.raw(dict(op='choose',link=k,epoch=s['state']['epoch'],revision=s['state']['revision']))
                if r['ok']:
                    # RPC completion precedes publication; await its revision.
                    rev=r['state']['revision']
                    return wait(lambda:(lambda s:s if s['state']['revision']>=rev and s['state']['active'] and s['state']['active']['link']==k else None)(status()),3)
                if status()['state']['revision']!=s['state']['revision']:return None
                raise RuntimeError('Unexpected choose rejection '+str(r))
            return wait(act,10)
        def restored(before,timeout=20):
            return wait(lambda:(lambda s:s if row(s)['current'] and (row(s)['session']!=row(before)['session'] or row(s)['event_sequence']>row(before)['event_sequence']) and s['state']['active'] and s['state']['active']['link']=='B' and s['state']['active']['generation']==row(s)['generation'] and row(s)['state']=='HEALTHY' and not s['runtime']['capture']['B']['pending'] else None)(status()),timeout)
        def tx(s):
            r=next(r for r in reversed(s['runtime']['recent']) if r['link']=='B' and r['sequence']==row(s)['event_sequence'] and r['reason'] in ('bound','renew'))
            def packets():
                w=wire(root,'B');req=next((p for p in w if p['type']==3 and p['xid']==r['xid']),None);ack=next((p for p in w if p['type']==5 and p['xid']==r['xid']),None)
                return dict(request=summary(req),ack=summary(ack),record=r) if req and ack else None
            return wait(packets,3)
        def isolated(a,b):
            assert immutable_link(row(a,'A'))==immutable_link(row(b,'A'))
            assert a['runtime']['children']['A']==b['runtime']['children']['A']
        def fallback():
            start=now();routes=json.loads(ip('dd_r','-j','route','show','table','main').stdout)
            client=f.client('dd_r',source='10.77.0.1')
            assert client['ok'] and client['response']['peer']=='10.99.1.1',client
            return dict(started_at=start,finished_at=now(),source='10.77.0.1',routes=routes,client=client)
        start=time.monotonic();ready('A');ready('B');unselected=status();assert unselected['state']['active'] is None
        selected=choose('A');before=status();initial_B_seq=row(before)['event_sequence']
        changed=wait(lambda:(lambda s:s if row(s)['event_sequence']>initial_B_seq else None)(status()),15)
        isolated(before,changed);assert changed['state']['active']==before['state']['active']
        old_ack=next(p for p in wire(root,'B') if p['type']==5)
        case('explicit_arm_and_inactive_B_isolation',start,unselected=unselected,before=before,after=changed,transaction=tx(changed),client=traffic('A'))
        start=time.monotonic();before=choose('B');rounds=[];prev=before
        for _ in range(4):
            after=restored(prev);isolated(before,after);assert after['state']['history']==before['state']['history'] and not after['state']['latched']
            rounds.append(dict(status=after,transaction=tx(after),client=traffic('B')));prev=after
        case('four_natural_renewals_restore_without_budget',start,before=before,rounds=rounds,rss_kib=dict(service=rss(service.p.pid),clients={k:rss(status()['runtime']['children'][k]) for k in LINKS}))
        start=time.monotonic();before=status();f.fault('B',True);ip('dd_b','addr','add','198.51.100.254/24','dev','edge');f.return_route('B','198.51.100.3')
        setprofile(address='198.51.100.3',gateway='198.51.100.254');os.kill(before['runtime']['children']['B'],signal.SIGUSR1)
        rejected=wait(lambda:(lambda s:s if row(s)['current'] and row(s)['current']['ip']=='198.51.100.3' and row(s)['state']=='DOWN' and s['state']['active'] is None else None)(status()),15)
        witness=fallback();blocked=f.client();assert not blocked['ok'];blocked_at=now();isolated(before,rejected);unblock_at=now();f.fault('B',False);after=restored(before)
        nak_sent=next(r for r in reversed([json.loads(x) for x in (root/'server.jsonl').read_text().splitlines()]) if r['kind']==6 and r['at']>=before['runtime']['as_of'])
        nak_hook=next(r for r in reversed(after['runtime']['recent']) if r['link']=='B' and r['reason']=='nak' and r['hook_at']>=before['runtime']['as_of'])
        case('address_gateway_change_requires_fresh_health',start,nak_sent=nak_sent,nak_hook=nak_hook,before=before,blocked_state=rejected,fallback=witness,blocked=blocked,blocked_at=blocked_at,unblock_at=unblock_at,after=after,transaction=tx(after),client=traffic('B'))
        start=time.monotonic();before=status();ip('dd_b','addr','add','198.51.100.253/24','dev','edge');setprofile(address='198.51.100.3',gateway='198.51.100.253',lease=20,**{'58':5,'59':10});os.kill(before['runtime']['children']['B'],signal.SIGUSR1);after=restored(before);isolated(before,after)
        case('gateway_only_change_restores',start,before=before,after=after,transaction=tx(after),client=traffic('B'))
        start=time.monotonic();before=status();deadline=row(before)['expires'];setprofile(reply=False);samples=[]
        while True:
            s=status();samples.append(dict(as_of=s['runtime']['as_of'],observed_at=now(),present=row(s)['current'] is not None))
            if row(s)['current'] is None:
                assert s['runtime']['as_of']>=deadline and s['state']['active'] is None;expired=s;break
            if now()>deadline+10:raise TimeoutError('Expiry not observed')
            time.sleep(.1)
        net=owned_network();witness=fallback();blocked=f.client();assert not blocked['ok'];blocked_at=now()
        setprofile(address='198.51.100.4',gateway='198.51.100.253');f.return_route('B','198.51.100.4');after=restored(before,30);isolated(before,after)
        replay_before=status();sent=now();p=root/'replay-private.json';p.write_text(json.dumps(old_ack));ns('dd_b',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface','edge','--replay',str(p)])
        received=wait(lambda:next((p for p in wire(root,'B') if p['at']>=sent and p['frame_sha256']==old_ack['frame_sha256']),None),3)
        fence=wait(lambda:(lambda s:s if s['runtime']['capture']['B']['empty_at']>=received['at'] and any(p['frame_sha256']==old_ack['frame_sha256'] and p['frame_index']>replay_before['runtime']['capture']['B']['frames'] for p in s['runtime']['capture']['B']['seen_frames']) else None)(status()),3)
        replay_after=wait(lambda:(lambda s:s if s['runtime']['as_of']>fence['runtime']['as_of'] else None)(status()),3)
        assert immutable_link(row(replay_before))==immutable_link(row(replay_after)) and row(replay_before)['event_sequence']==row(replay_after)['event_sequence']
        case('expiry_reacquisition_and_old_ACK',start,before=before,samples=samples,expired=expired,network=net,fallback=witness,blocked=blocked,blocked_at=blocked_at,after=after,transaction=tx(after),client=traffic('B'),replay=dict(before=replay_before,received=summary(received),fence=fence,after=replay_after))
        start=time.monotonic();before=status();a=ready('A');rejection=service.raw(dict(op='choose',link='A',epoch=a['state']['epoch'],revision=a['state']['revision']));assert not rejection['ok']
        latched=wait(lambda:(lambda s:s if s['state']['latched'] else None)(status()),3);os.kill(latched['runtime']['children']['B'],signal.SIGUSR1)
        stopped=wait(lambda:(lambda s:s if row(s)['event_sequence']>row(latched)['event_sequence'] and row(s)['state']=='HEALTHY' and s['state']['active'] is None else None)(status()),15)
        case('manual_switch_budget_latch_blocks_restore',start,before=before,rejection=rejection,latched=latched,after=stopped)
        result['wire_counters']=f.counters();assert all(result['wire_counters'][k]['wrong_dhcp']==0 for k in LINKS)
        result['passed']=True
    except BaseException as exc:
        result.update(passed=False,failure=dict(type=type(exc).__name__,message=str(exc)[:1500]))
        if service:
            try:result['failure_status']=status();result['client_log_tail']=(root/'service-private.log').read_text()[-2000:]
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
