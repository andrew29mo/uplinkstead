"""Real client timer integration in owned Linux namespaces; no injected clock."""
import argparse,copy,json,os,signal,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dhcp_p0_guest import Service,wire,summary
from tools.dhcp_stage1_guest import wait,immutable_link,rss
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure,owned_network
from tools.guest import nft,ns
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from tools.dhcp_p0_contract import timer_diagnostics
from uplinkstead.writer import now


def run(root,source):
    import platform
    result=dict(passed=False,kind='formal_absolute_dhcp_timers',source_sha256=fingerprint(manifest()),cases=[],
        environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version()),
        client_build=json.loads((root/'client/build.json').read_text()),client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),
        limitations=['Controlled Ethernet IPv4 fixture, not full DHCP/RFC/server interoperability qualification',
        'No random timer fuzz; finite 1..86400 second leases only; invalid timer ACK ignored',
        'Foreground service/manual selection, not automatic failover/systemd/reboot/power-loss/boot-zero-gap qualification',
        'Linux VM RSS snapshots, not native performance or peak RSS; DHCP remains unauthenticated'])
    f=Fixture(root,source);service=None;profile=root/'timer-profile.json'
    def persist():(root/'timer-guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,start,**details):
        result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-start,details=details));persist()
    def setprofile(**kw):
        p=dict(lease=120);p.update(kw);tmp=profile.with_suffix('.tmp');tmp.write_text(json.dumps(p));tmp.replace(profile)
    try:
        f.setup();configure(root);f.stop(f.servers['B']);f.stop(f.servers['A'])
        f.server('A',extra=['--dhcp-option-force=58,12i','--dhcp-option-force=59,30i'])
        nft('dd_b','add table ip timers\nadd chain ip timers input { type filter hook input priority -200; policy accept; }\nadd rule ip timers input udp dport 67 drop\n')
        setprofile()
        f.spawn('dd_b',['python3',str(source/'tools/dhcp_timer_server.py'),'--interface','edge','--profile',str(profile),'--log',str(root/'server.jsonl')],'timer-server')
        wait(lambda:profile.with_suffix('.ready').exists(),10)
        for k in LINKS:
            path=root/('wire-'+k+'.jsonl');f.spawn('dd_r',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface',LINKS[k]['interface'],'--output',str(path)],'wire-'+k)
            wait(lambda p=path:p.with_suffix('.ready').exists(),10)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=1,freshness=10,budget=30)
        c['runtime']=dict(queue_capacity=8,probe_interval=.2,restart_delay=.2,client_diagnostics=True)
        (root/'config.json').write_text(json.dumps(c));service=Service(root,source)
        def status():return service.call('status')
        def row(s,k='B'):return s['state']['links'][k]
        def diag():return timer_diagnostics((root/'service-private.log').read_text())
        def tx(s,k='B'):
            def complete(candidate):
                r=next((r for r in reversed(candidate['runtime']['recent']) if r['link']==k and r['sequence']==row(candidate,k)['event_sequence'] and r['reason'] in ('bound','renew')),None)
                return candidate if row(candidate,k)['current'] and r and row(candidate,k)['expires']==r['expires'] and not candidate['runtime']['capture'][k]['pending'] else None
            s=complete(s) or wait(lambda:complete(status()),5)
            r=next(r for r in reversed(s['runtime']['recent']) if r['link']==k and r['sequence']==row(s,k)['event_sequence'] and r['reason'] in ('bound','renew'))
            def matched():
                packets=wire(root,k);req=next((p for p in packets if p['type']==3 and p['xid']==r['xid']),None)
                ack=next((p for p in packets if p['type']==5 and p['xid']==r['xid'] and not p.get('timer_error') and req and p['at']>=req['at']),None)
                d=next((d for d in reversed(diag()) if d['event']=='ack' and d['interface']==LINKS[k]['interface'] and d['xid']==r['xid']),None)
                return (req,ack,d) if req and ack and d else None
            req,ack,d=wait(matched,5)
            assert r['request_at']==min(r['wire_request_at'],r['client_origin_ns']/1e9)
            assert r['client_origin_ns']==d['origin'] and row(s,k)['expires']==r['request_at']+int(ack['lease']),(k,r,d,row(s,k))
            assert d['expiry']==d['origin']+int(ack['lease'])*10**9
            return dict(request=summary(req),ack=summary(ack),runtime_record=copy.deepcopy(r),timer=d,status=s)
        def changed(before,k='B',timeout=90):
            return wait(lambda:(lambda s:s if row(s,k)['current'] and row(s,k)['event_sequence']>row(before,k)['event_sequence'] else None)(status()),timeout)
        def bootstrap(**kw):
            setprofile(**kw);before=status();os.kill(before['runtime']['children']['B'],signal.SIGUSR1)
            t=tx(changed(before,timeout=15));wait(lambda:any(d['event']=='bound' and d['xid']==t['ack']['xid'] for d in diag()),5);time.sleep(.15);return t
        def select(k):
            def choose_current():
                s=status()
                if row(s,k)['state']!='HEALTHY':return None
                response=service.raw(dict(op='choose',link=k,epoch=s['state']['epoch'],revision=s['state']['revision']))
                if response['ok']:return s
                latest=status()
                # Another real lease may advance the global token between
                # status and choose. Only changed authority permits a retry.
                if (latest['state']['epoch'],latest['state']['revision'],row(latest,k)['state']) != (s['state']['epoch'],s['state']['revision'],row(s,k)['state']):return None
                raise RuntimeError('Unexplained selection rejection: '+str(response))
            wait(choose_current,15);data=f.client()
            assert data['ok'] and data['response']['peer']==f'10.99.{LINKS[k]["transit"]}.1',data
            return data
        def fence(packet,before):
            def captured():
                s=status();c=s['runtime']['capture']['B']
                return s if c['empty_at']>=packet['at'] and any(p['frame_sha256']==packet['frame_sha256'] and p['frame_index']>before['runtime']['capture']['B']['frames'] for p in c['seen_frames']) else None
            mid=wait(captured,3);after=wait(lambda:(lambda s:s if s['runtime']['as_of']>mid['runtime']['as_of'] else None)(status()),3)
            assert immutable_link(before['state']['links']['B'])==immutable_link(after['state']['links']['B'])
            assert row(before)['event_sequence']==row(after)['event_sequence']
            assert before['runtime']['capture']['B']['version']==after['runtime']['capture']['B']['version']
            return dict(before=before,capture_fence=mid,after=after,received=summary(packet))
        start=time.monotonic()
        wait(lambda:all(row(status(),k)['current'] for k in LINKS),30)
        initial=status();b0=tx(initial);a0=tx(initial,'A');old_ack=next(p for p in wire(root,'B') if p['type']==5 and p['xid']==b0['ack']['xid'])
        b1=tx(changed(initial,timeout=80));a1=tx(status(),'A')
        assert b0['ack']['timer58'] is None and b0['ack']['timer59'] is None
        assert b1['request']['at']>=b0['timer']['t1']/1e9
        case('default_T1_and_independent_A',start,baseline=b0,renewed=b1,A_baseline=a0,A_renewed=a1,client=select('B'),rss_kib=dict(service=rss(service.p.pid),clients={k:rss(status()['runtime']['children'][k]) for k in LINKS}))
        start=time.monotonic();b0=bootstrap(**{'58':10,'59':25});baseline=b0;rounds=[]
        for _ in range(2):
            b1=tx(changed(b0['status'],timeout=20));assert b1['request']['at']>=b0['timer']['t1']/1e9;rounds.append(b1);b0=b1
        case('explicit_T1_two_natural_rounds',start,baseline=baseline,rounds=rounds)
        start=time.monotonic();b0=bootstrap(**{'58':8});b1=tx(changed(b0['status'],timeout=20))
        assert b1['request']['at']>=b0['timer']['t1']/1e9
        case('partial_option_default_T2',start,baseline=b0,renewed=b1)
        start=time.monotonic();invalid=[]
        for opts in ({'58':0,'59':25},{'58':30,'59':25},{'58':10,'59':120},{'58':{'hex':'000001'},'59':25}):
            before=status();setprofile(**opts);sent=now();os.kill(before['runtime']['children']['B'],signal.SIGUSR1)
            for attempt in range(3):
                packet=wait(lambda:next((p for p in reversed(wire(root,'B')) if p['type']==5 and p['at']>=sent and p.get('timer_error')),None),5)
                if any(d['event']=='reject' and d['xid']==packet['xid'] and d['at']/1e9>=sent for d in diag()):break
                time.sleep(.2);os.kill(before['runtime']['children']['B'],signal.SIGUSR1);time.sleep(.2)
            wait(lambda:any(d['event']=='reject' and d['xid']==packet['xid'] and d['at']/1e9>=sent for d in diag()),3)
            evidence=fence(packet,before);wait(lambda:any(d['event']=='reject' and d['at']/1e9>=sent for d in diag()),3)
            rejection=next(d for d in reversed(diag()) if d['event']=='reject' and d['xid']==packet['xid'] and d['at']/1e9>=sent)
            invalid.append(dict(options=opts,client_rejection=rejection,**evidence))
            bootstrap(**{'58':10,'59':25})
        case('invalid_options_do_not_extend_or_replace',start,attempts=invalid)
        start=time.monotonic();base=bootstrap(**{'58':10,'59':25});setprofile(**{'58':10,'59':25,'hold_unicast':True,'release_held':True})
        unicast=wait(lambda:next((p for p in wire(root,'B') if p['type']==3 and p['ciaddr']!='0.0.0.0' and p['destination']=='198.51.100.1' and p['at']>=base['timer']['t1']/1e9),None),20)
        before= status()
        broadcast=wait(lambda:next((p for p in wire(root,'B') if p['type']==3 and p['ciaddr']!='0.0.0.0' and p['destination']=='255.255.255.255' and p['at']>=base['timer']['t2']/1e9),None),25)
        held=wait(lambda:next((p for p in wire(root,'B') if p['type']==5 and p['xid']==unicast['xid'] and p['at']>=broadcast['at']),None),3)
        rejected=fence(held,before);rebound=tx(changed(base['status'],timeout=10))
        assert rebound['request']['xid']==broadcast['xid']!=unicast['xid']
        server=[json.loads(x) for x in (root/'server.jsonl').read_text().splitlines()]
        held_origin=next(x for x in server if x['delayed'] and x['frame_sha256']==held['frame_sha256'])
        case('natural_T2_rebind_and_delayed_real_ACK',start,baseline=base,unicast=summary(unicast),broadcast=summary(broadcast),held_origin=held_origin,rejected=rejected,rebound=rebound,client=select('B'))
        start=time.monotonic();base=bootstrap(lease=240,**{'58':10,'59':25});select('B');setprofile(lease=240,reply=False)
        d=wait(lambda:next((d for d in reversed(diag()) if d['interface']=='wanB' and d['event']=='rebind' and d['attempts']>=3 and d['origin']==base['timer']['origin']),None),220)
        checkpoint=status();assert row(checkpoint)['current'] and now()<base['timer']['expiry']/1e9
        live= f.client();assert live['ok']
        expired=wait(lambda:(lambda s:s if row(s)['current'] is None and s['state']['active'] is None else None)(status()),70)
        expiration=wait(lambda:next((d for d in reversed(diag()) if d['event']=='expire' and d['interface']=='wanB' and d['origin']==base['timer']['origin']),None),5)
        assert expiration['at']>=expiration['expiry']
        network=owned_network();blocked=f.client();assert blocked['ok'] is False
        data_a=select('A');f.return_route('B','198.51.100.3');setprofile(address='198.51.100.3',**{'58':10,'59':25})
        recovered=wait(lambda:(lambda s:s if row(s)['current'] and row(s)['current']['ip']=='198.51.100.3' else None)(status()),30)
        reacquired=tx(recovered);data_b=select('B')
        before=status();sent=now();p=root/'replay-private.json';p.write_text(json.dumps(old_ack));ns('dd_b',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface','edge','--replay',str(p)])
        received=wait(lambda:next((p for p in wire(root,'B') if p['at']>=sent and p['frame_sha256']==old_ack['frame_sha256']),None),3);replay=fence(received,before)
        case('no_early_loss_expiry_withdrawal_and_reacquisition',start,baseline=base,third_retry=d,checkpoint=checkpoint,expiry_requests=[summary(p) for p in wire(root,'B') if p['type']==3 and p['at']>=base['timer']['origin']/1e9 and p['at']<=expiration['at']/1e9],live=live,expired=expired,expiration=expiration,network=network,blocked=blocked,client_A=data_a,reacquired=reacquired,client_B=data_b,replay=replay)
        result['wire_counters']=f.counters();assert all(result['wire_counters'][k]['wrong_dhcp']==0 for k in LINKS)
        result['final']=status();result['passed']=True
    except BaseException as exc:
        result.update(passed=False,failure=dict(type=type(exc).__name__,message=str(exc)[:1500]))
        if service:
            try:result['failure_status']=status();result['timer_diagnostics']=diag();result['client_log_tail']=(root/'service-private.log').read_text()[-12000:]
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
