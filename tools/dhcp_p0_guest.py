"""Natural client lifecycle against the shipped foreground runtime, never core calls."""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dhcp_stage1_guest import Service as StageService, wait, finalize, immutable_link, rss
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure
from tools.guest import nft,ns
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from tools.dhcp_p0_contract import loss_diagnostics
from tools.dhcp_p0_wire import delayed_ack
from uplinkstead.writer import now


class Service(StageService):
    def __init__(self,root,source):
        import subprocess
        self.root=root;self.path=root/'run/events.sock';self.log=(root/'service-private.log').open('a')
        self.p=subprocess.Popen(['ip','netns','exec','dd_r','python3','-m','uplinkstead.dual_dhcp_service',
            '--config',str(root/'config.json'),'--journal',str(root/'state'),'--socket',str(self.path),
            '--hook',str(source/'deploy/uplinkstead-dual-hook.py'),'--client',str(root/'client/busybox-1.36.1/busybox')],
            cwd=source,env=dict(os.environ,PYTHONPATH=str(source)),stdout=self.log,stderr=self.log)
        try:wait(lambda:self.path.exists() and self.p.poll() is None,20)
        except BaseException:self.stop();raise


def wire(root,k):
    path=root/('wire-'+k+'.jsonl')
    # Ignore the incomplete final line while the independent observer appends.
    raw=path.read_text() if path.exists() else ''
    return [json.loads(line) for line in raw.splitlines(keepends=True) if line.endswith('\n')]


def summary(p):return {k:v for k,v in p.items() if k!='frame'}


def run(root,source):
    import platform
    result=dict(passed=False,kind='formal_dhcp_p0',source_sha256=fingerprint(manifest()),cases=[],
                environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version()),
                client_build=json.loads((root/'client/build.json').read_text()),
                client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),
                limitations=['Foreground service, explicit selection; no automatic failover/systemd/reboot/power-loss/zero-gap qualification',
                             'BusyBox natural half-remaining renewal/rebinding algorithm, not DHCP option 58/59 qualification',
                             'DHCP unauthenticated; no hostile server or cross-process xid collision guarantee'])
    binary=root/'client/busybox-1.36.1/busybox'
    if digest(binary)!=result['client_build']['binary_sha256']:raise RuntimeError('Client binary changed')
    f=Fixture(root,source);service=None
    def persist(): (root/'p0-guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,began,**details):
        result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-began,details=details));persist()
    try:
        f.setup();configure(root)
        for k in LINKS:
            path=root/('wire-'+k+'.jsonl')
            f.spawn('dd_r',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface',LINKS[k]['interface'],'--output',str(path)],'wire-'+k)
            wait(lambda p=path:p.with_suffix('.ready').exists(),10)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=1,freshness=10,budget=30)
        c['runtime']=dict(queue_capacity=8,probe_interval=.2,restart_delay=.2,client_diagnostics=True)
        (root/'config.json').write_text(json.dumps(c));service=Service(root,source)
        def status():return service.call('status')
        def leased(k):
            s=status();return s if s['state']['links'][k]['current'] else None
        def newer(k,before):
            s=status();r=s['state']['links'][k];old=before['state']['links'][k]
            return s if r['current'] and r['expires']>old['expires']+10 else None
        def select(k):
            def healthy():
                s=status();return s if s['state']['links'][k]['state']=='HEALTHY' else None
            s=wait(healthy,20);service.call('choose',link=k,epoch=s['state']['epoch'],revision=s['state']['revision'])
            data=f.client();assert data['ok'] and data['response']['peer']==f'10.99.{LINKS[k]["transit"]}.1',data
            return data
        def unchanged_identity(k,before,after):
            assert before['state']['links'][k]['session']==after['state']['links'][k]['session']
            assert before['runtime']['children'][k]==after['runtime']['children'][k]
        def transaction(k,s):
            row=s['state']['links'][k]
            record=next(r for r in reversed(s['runtime']['recent']) if r['link']==k and r['sequence']==row['event_sequence'] and r['reason'] in ('bound','renew'))
            def packets():
                rows=wire(root,k);req=next((p for p in rows if p['type']==3 and p['xid']==record['xid']),None)
                ack=next((p for p in rows if p['type']==5 and p['xid']==record['xid'] and req and p['at']>=req['at']),None)
                return (req,ack) if req and ack else None
            req,ack=wait(packets,5)
            effective=max((p for p in wire(root,k) if p['type']==3 and p['xid']==record['xid'] and p['at']<=ack['at']),key=lambda p:p['at'])
            assert record['expires']==row['expires']==record['request_at']+int(ack['lease'])
            assert record['request_at']<=record['observed_at']<=record['hook_at']<=record['processed_at']
            assert record['request_at']<=req['at'] and record['observed_at']<=ack['at']
            return dict(request=summary(req),effective_request=summary(effective),ack=summary(ack),runtime_record=copy.deepcopy(record),observer_completed_at=now())
        def replay(packet):
            path=root/'replay-private.json';path.write_text(json.dumps(packet))
            before=status();sent_at=now()
            ns('dd_b',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface','edge','--replay',str(path)])
            received=wait(lambda:next((p for p in wire(root,'B') if p['at']>=sent_at and p['frame_sha256']==packet['frame_sha256']),None),5)
            def captured():
                s=status();c=s['runtime']['capture']['B']
                return s if c['empty_at']>=received['at'] and any(p['frame_sha256']==packet['frame_sha256'] and p['frame_index']>before['runtime']['capture']['B']['frames'] for p in c['seen_frames']) else None
            fence=wait(captured,3)
            # A subsequent full writer step must process dirty/version changes
            # observed by Capture after the previous step began.
            after=wait(lambda:(lambda s:s if s['runtime']['as_of']>fence['runtime']['as_of'] else None)(status()),3);observed_at=now()
            assert after['runtime']['capture']['B']['version']==before['runtime']['capture']['B']['version']
            assert after['runtime']['capture']['B']['pending'] is False
            assert immutable_link(before['state']['links']['B'])==immutable_link(after['state']['links']['B'])
            assert before['state']['links']['B']['event_sequence']==after['state']['links']['B']['event_sequence']
            return dict(sent_at=sent_at,received=summary(received),capture_fence=fence,observed_at=observed_at,packet=summary(packet),before=before,after=after)
        began=time.monotonic()
        for k in LINKS:wait(lambda k=k:leased(k),30)
        initial=status();old_ack=wait(lambda:next((p for p in wire(root,'B') if p['type']==5),None),5)
        data=select('A');before=status();os.kill(before['runtime']['children']['B'],signal.SIGKILL)
        replaced=wait(lambda:(lambda s:s if s['state']['links']['B']['session']!=before['state']['links']['B']['session'] and s['state']['links']['B']['current'] else None)(status()),20)
        assert immutable_link(before['state']['links']['A'])==immutable_link(replaced['state']['links']['A'])
        bound_xid=next(r['xid'] for r in reversed(replaced['runtime']['recent']) if r['link']=='B' and r['reason']=='bound')
        old_ack=wait(lambda:next((p for p in wire(root,'B') if p['type']==5 and p['xid']==bound_xid),None),5)
        case('real_acquisition_and_B_crash_isolation',began,initial=initial,before=before,after=replaced,client=data,
             rss_kib=dict(service=rss(service.p.pid),clients={k:rss(replaced['runtime']['children'][k]) for k in LINKS}))
        # Two naturally timed renewals on each link: no SIGUSR1, clock injection,
        # direct lifecycle callback, or fabricated ACK is used to extend leases.
        began=time.monotonic();before=status();rounds=[];transactions=[]
        baseline={k:transaction(k,before) for k in LINKS}
        for _ in range(2):
            start=status()
            for k in LINKS:wait(lambda k=k:newer(k,start),90)
            after=status()
            for k in LINKS:unchanged_identity(k,before,after)
            rounds.append(after)
            transactions.append({k:transaction(k,after) for k in LINKS})
        records={k:[summary(p) for p in wire(root,k) if p['type']==3 and p['ciaddr']!='0.0.0.0'] for k in LINKS}
        for k in LINKS:
            assert len({p['xid'] for p in records[k]})>=2,records
            assert all(p['destination']==LINKS[k]['gateway'] for p in records[k]),records
        case('two_natural_T1_rounds_both_links',began,before=before,rounds=rounds,after=after,requests=records,baseline=baseline,transactions=transactions,client=select('A'))
        began=time.monotonic();before=status();fault_at=now()
        # Drop only B's unicast DHCP REQUEST. Broadcast rebinding remains possible.
        nft('dd_b','add table ip p0_dhcp\nadd chain ip p0_dhcp input { type filter hook input priority -200; policy accept; }\nadd rule ip p0_dhcp input ip daddr 198.51.100.1 udp dport 67 counter drop\n')
        request=wait(lambda:next((p for p in wire(root,'B') if p['type']==3 and p['at']>fault_at and p['destination']==LINKS['B']['gateway']),None),90)
        replay_evidence=replay(old_ack)
        # A reply to the earlier unanswered unicast transaction is synthesized
        # from the real captured ACK, then delivered after the next REQUEST.
        # This is labelled fault injection, not an original historical reply.
        next_request=wait(lambda:next((p for p in wire(root,'B') if p['type']==3 and p['at']>request['at'] and p['xid']!=request['xid'] and p['destination']==LINKS['B']['gateway']),None),60)
        synthetic=delayed_ack(old_ack,request['xid']);delayed=replay(synthetic)
        delayed.update(synthetic=True,template_frame_sha256=old_ack['frame_sha256'],older_request=summary(request),newer_request=summary(next_request))
        rebound=wait(lambda:newer('B',before),90)
        bcasts=[summary(p) for p in wire(root,'B') if p['type']==3 and p['at']>fault_at and p['ciaddr']!='0.0.0.0' and p['destination']=='255.255.255.255']
        assert bcasts and request['xid']!=old_ack['xid']
        unchanged_identity('A',before,rebound);unchanged_identity('B',before,rebound)
        counters=json.loads(ns('dd_b',['nft','-j','list','table','ip','p0_dhcp']).stdout)
        case('old_ACK_during_new_request_and_natural_rebinding',began,before=before,after=rebound,
             unicast=summary(request),broadcasts=bcasts,replay=replay_evidence,delayed_unanswered_reply=delayed,
             transaction=transaction('B',rebound),fault_counters=counters,client=select('A'))
        nft('dd_b','delete table ip p0_dhcp\n')
        began=time.monotonic();before=status();f.stop(f.servers['B'])
        expired=wait(lambda:(lambda s:s if s['state']['links']['B']['current'] is None else None)(status()),150)
        loss_wire=[summary(p) for p in wire(root,'B') if p['at']>=before['runtime']['as_of']]
        diagnostics=[d for d in loss_diagnostics((root/'service-private.log').read_text()) if d['interface']=='wanB' and d['pid']==before['runtime']['children']['B']]
        assert diagnostics and diagnostics[-1]['remaining']>0 and diagnostics[-1]['attempts']==3,diagnostics
        assert sum(p['type']==3 and p['ciaddr']!='0.0.0.0' and p['destination']=='255.255.255.255' and p['xid']==diagnostics[-1]['xid'] for p in loss_wire)==3,loss_wire
        loss_hook=next(r for r in reversed(expired['runtime']['recent']) if r['link']=='B' and r['reason']=='deconfig' and r['hook_at']>=before['runtime']['as_of'])
        unchanged_identity('A',before,expired)
        # A independently renewed while B was offline; it must remain usable.
        data_a=select('A')
        f.return_route('B','198.51.100.3');restart_at=now();f.server('B',address='198.51.100.3')
        recovered=wait(lambda:(lambda s:s if s['state']['links']['B']['current'] and s['state']['links']['B']['current']['ip']=='198.51.100.3' else None)(status()),30)
        unchanged_identity('A',before,recovered)
        case('B_lease_loss_and_changed_address_reacquisition',began,before=before,expired=expired,after=recovered,
             server_restarted_at=restart_at,client_A=data_a,client_B=select('B'),wire=[summary(p) for p in wire(root,'B') if p['at']>=restart_at])
        result['cases'][-1]['details'].update(loss_wire=loss_wire,loss_diagnostic=diagnostics[-1],loss_hook=loss_hook,transaction=transaction('B',recovered))
        persist()
        began=time.monotonic();before=status();final_replay=replay(old_ack);after=final_replay['after']
        assert immutable_link(before['state']['links']['B'])==immutable_link(after['state']['links']['B'])
        assert before['state']['active']==after['state']['active']
        case('old_ACK_cannot_overwrite_reacquired_address',began,before=before,after=after,packet=summary(old_ack),replay=final_replay,client=select('B'))
        result['wire_counters']=f.counters()
        assert all(result['wire_counters'][k]['wrong_dhcp']==0 for k in LINKS)
        result['final']=status();result['passed']=True
    except BaseException as exc:
        result['passed']=False;result['failure']=dict(type=type(exc).__name__,message=str(exc)[:1500])
        if service:
            try:result['failure_status']=status()
            except BaseException:pass
        raise
    finally:
        try:
            if service:service.stop()
        except BaseException:
            result['passed']=False
            raise
        finally:
            try:result['cleanup']=f.cleanup()
            except BaseException:result['passed']=False;raise
            finally:persist()
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args()
    print(json.dumps(run(a.root,Path(__file__).resolve().parents[1]),allow_nan=False))
