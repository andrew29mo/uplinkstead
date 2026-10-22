"""Stage 1 checks against the actual dual DHCP service in owned namespaces.

This runner never drives DualLifecycle directly. Real DHCP packets and the
service's own supervisors produce the lease lifecycle being measured.
"""
import argparse
import copy
import errno
import json
import os
from pathlib import Path
import platform
import signal
import secrets
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.dual_dhcp_fixture import Fixture, LINKS, cleanup_owned
from tools.dual_dhcp_guest import configure, owned_network
from tools.evidence import manifest, fingerprint
from tools.guest import cmd
from uplinkstead.writer import now


def wait(predicate, timeout=20, interval=.05):
    """Only an observed truth succeeds; timeout and predicate errors propagate."""
    deadline=time.monotonic()+timeout
    while True:
        value=predicate()
        if value:return value
        if time.monotonic()>=deadline:raise TimeoutError('Stage 1 observation deadline exceeded')
        time.sleep(min(interval,max(0,deadline-time.monotonic())))


def exchange(path, payload, timeout=3, allow_connect_backpressure=False):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(timeout)
        try:peer.connect(str(path))
        except BlockingIOError as exc:
            if allow_connect_backpressure and exc.errno in (errno.EAGAIN,errno.EWOULDBLOCK):
                return dict(ok=False,transport_rejected=True,error='ConnectBacklogFull')
            raise
        peer.sendall(json.dumps(payload,allow_nan=False).encode())
        raw=peer.recv(65537)
        if not raw or len(raw)>65536:raise RuntimeError('Invalid service reply size')
        return json.loads(raw)


def rss(pid):
    lines=Path('/proc',str(pid),'status').read_text().splitlines()
    return int(next(line for line in lines if line.startswith('VmRSS:')).split()[1])


def immutable_link(row):
    return {key:copy.deepcopy(row[key]) for key in ('session','generation','current','expires')}


def persist(root, result):
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=root/'stage1-guest.json';temporary=root/'stage1-guest.json.tmp'
    temporary.write_text(json.dumps(result,indent=2,allow_nan=False));temporary.replace(path)


def finalize(root,result,fixture,service):
    """Never leave a successful receipt when service or network cleanup fails."""
    try:
        try:
            if service:service.stop()
        finally:result['cleanup']=fixture.cleanup()
    except BaseException as exc:
        result['passed']=False
        result['cleanup_failure']=dict(type=type(exc).__name__,message=str(exc)[:1500])
        raise
    finally:persist(root,result)


class Service:
    def __init__(self, root, source):
        self.root=root;self.path=root/'run/events.sock';self.log=(root/'service-private.log').open('a')
        self.p=subprocess.Popen(['ip','netns','exec','dd_r','python3','-m','uplinkstead.dual_dhcp_service',
                                 '--config',str(root/'config.json'),'--journal',str(root/'state'),
                                 '--socket',str(self.path),'--hook',str(source/'deploy/uplinkstead-dual-hook.py')],cwd=source,env=dict(os.environ,PYTHONPATH=str(source)),stdout=self.log,stderr=self.log)
        try:wait(lambda:self.path.exists() and self.p.poll() is None,20)
        except BaseException:self.stop();raise
    def raw(self, q):
        if self.p.poll() is not None:raise RuntimeError('Formal dual DHCP service exited')
        return exchange(self.path,q)
    def call(self,op,**q):
        response=self.raw(dict(op=op,**q))
        if not response['ok']:raise RuntimeError('Formal service rejected '+op+': '+str(response.get('error')))
        return response
    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:self.p.wait(timeout=10)
            except subprocess.TimeoutExpired:self.p.kill();self.p.wait(timeout=3)
        self.log.close()
        if self.p.returncode != 0:raise RuntimeError('Formal service did not exit cleanly: '+str(self.p.returncode))


def run(root,source):
    result=dict(passed=False,kind='isolated_linux_formal_dual_dhcp_stage1',cases=[],
                source_sha256=fingerprint(manifest()),
                environment=dict(kernel=platform.release(),machine=platform.machine(),python=platform.python_version()),
                limitations=['Foreground formal service in isolated namespaces; no installed systemd or VM reboot claim',
                             'No sudden power-loss or boot zero-gap test',
                             'Stage 1 has explicit operator selection, not automatic failover',
                             'External NAT and return routes are fixture responsibilities'])
    f=Fixture(root,source);service=None
    def case(name,began,**details):
        result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-began,details=details));persist(root,result)
    try:
        busybox=cmd(['busybox'],check=False)
        result['environment'].update(busybox=(busybox.stdout+busybox.stderr).splitlines()[0],
                                     dnsmasq=cmd(['dnsmasq','--version']).stdout.splitlines()[0])
        f.setup();configure(root)
        config=json.loads((root/'config.json').read_text())
        config['runtime']=dict(queue_capacity=4,probe_interval=.1,restart_delay=.2)
        config.update(success_rounds=1,freshness=10,budget=30)
        (root/'config.json').write_text(json.dumps(config))
        service=Service(root,source)
        def status():return service.call('status')
        def leased(k):
            observed=status();return observed if observed['state']['links'][k]['current'] else None
        def healthy(k):
            observed=status();return observed if observed['state']['links'][k]['state']=='HEALTHY' else None
        def choose(k):
            observed=status()['state']
            return service.call('choose',link=k,epoch=observed['epoch'],revision=observed['revision'])
        began=time.monotonic()
        for link in LINKS:wait(lambda k=link:leased(k),30)
        for link in LINKS:wait(lambda k=link:healthy(k),15)
        choose('A');data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1',data
        initial=status()
        wire_records=[record for record in initial['runtime']['recent'] if record['reason'] in ('bound','renew')]
        assert {record['link'] for record in wire_records}==set(LINKS),wire_records
        for record in wire_records:
            assert record['request_at']<=record['observed_at']<=record['hook_at']<=record['processed_at'],record
            assert record['expires']==record['request_at']+120,record
            assert record['expires']<=record['hook_at']+120,record
        case('formal_service_two_real_leases_and_A_data',began,observation=initial,client=data,
             rss_kib=dict(service=rss(service.p.pid),clients={k:rss(initial['runtime']['children'][k]) for k in LINKS}))

        began=time.monotonic();before=status();a=immutable_link(before['state']['links']['A'])
        old_pid=before['runtime']['children']['B'];old_session=before['state']['links']['B']['session']
        os.kill(old_pid,signal.SIGKILL)
        replacement=wait(lambda:(lambda observed: observed if observed['runtime']['children']['B']!=old_pid and observed['state']['links']['B']['session']!=old_session and observed['state']['links']['B']['current'] else None)(status()),20)
        assert immutable_link(replacement['state']['links']['A'])==a,(before,replacement)
        assert replacement['state']['active']==before['state']['active'],(before,replacement)
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1',data
        assert service.p.poll() is None
        case('B_SIGKILL_supervised_replacement_preserves_A',began,before=before,after=replacement,client=data)

        began=time.monotonic()
        f.fault('B');inflight=wait(lambda:(lambda observed:observed if observed['runtime']['inflight']['B'] else None)(status()),10)
        generation=inflight['state']['links']['B']['generation'];renew_sent=now()
        os.kill(inflight['runtime']['children']['B'],signal.SIGUSR1)
        renewed=wait(lambda:(lambda observed:observed if observed['state']['links']['B']['generation']>generation and observed['state']['links']['B']['current'] else None)(status()),10)
        elapsed=now()-renew_sent
        assert immutable_link(renewed['state']['links']['A'])==a
        # Raw inflight flags and elapsed observation are retained. A stronger
        # overlap claim requires an actual inflight flag at processing time.
        matching=[record for record in renewed['runtime']['recent'] if record['link']=='B' and record['reason']=='renew' and record['hook_at']>=renew_sent]
        assert matching,renewed
        overlap=matching[-1]['probe_inflight']['B']
        assert overlap,matching[-1]
        assert renewed['state']['links']['B']['expires']==inflight['state']['links']['B']['expires']
        case('slow_B_probe_real_renewal_event_intake',began,before=inflight,after=renewed,
             renewal_observed_seconds=elapsed,probe_still_inflight_at_observation=overlap,
             interpretation='Observed real renewal while slow probe work was scheduled; no hard scheduling bound')
        f.fault('B',False)
        wait(lambda:healthy('B'),15)

        began=time.monotonic();before=status();generation=before['state']['links']['B']['generation']
        pause_at=now();os.kill(service.p.pid,signal.SIGSTOP)
        try:
            wait(lambda:next(line for line in Path('/proc',str(service.p.pid),'status').read_text().splitlines() if line.startswith('State:')).split()[1]=='T',2)
            request_sent=now();os.kill(before['runtime']['children']['B'],signal.SIGUSR1)
            time.sleep(1)
        finally:
            resumed_at=now();os.kill(service.p.pid,signal.SIGCONT)
        renewed=wait(lambda:(lambda observed:observed if observed['state']['links']['B']['generation']>generation and observed['state']['links']['B']['current'] else None)(status()),15)
        records=[record for record in renewed['runtime']['recent'] if record['link']=='B' and record['reason']=='renew' and record['hook_at']>=request_sent]
        assert records,renewed
        record=records[-1]
        assert record['request_at']<=record['observed_at']<=record['hook_at']<=record['processed_at'],record
        assert record['processed_at']>=resumed_at,record
        assert record['request_at']<=resumed_at,record
        assert record['expires']==record['request_at']+120,record
        assert record['expires']<=resumed_at+120,record
        assert renewed['state']['links']['B']['expires']==before['state']['links']['B']['expires']
        assert pause_at<=request_sent<=resumed_at<=record['processed_at']
        assert immutable_link(renewed['state']['links']['A'])==a
        case('real_backlogged_wire_renew_keeps_REQUEST_deadline',began,before=before,after=renewed,
             service_paused_at=pause_at,renew_requested_at=request_sent,service_resumed_at=resumed_at,wire_record=record,
             interpretation='Whole-service pause intentionally creates capture/intake backlog; not an availability benchmark')

        began=time.monotonic();before=status();row=before['state']['links']['B']
        event=dict(op='event',link='B',session=old_session,boot=before['state']['boot'],id=secrets.token_hex(16),at=now(),reason='renew',
                   lease=dict(ip=LINKS['B']['address'],subnet='255.255.255.0',router=LINKS['B']['gateway'],lease='120'),options=[])
        old_expiry=row['expires'];network=owned_network();response=service.raw(event);after=status()
        assert not response['ok'],response
        assert immutable_link(after['state']['links']['B'])==immutable_link(row),(before,after)
        assert after['state']['active']==before['state']['active']
        assert owned_network()==network
        case('retired_client_event_cannot_extend_lease',began,event=event,response=response,before=before,after=after,
             unchanged_expiry=after['state']['links']['B']['expires']==old_expiry)

        began=time.monotonic();before=status();a_before=immutable_link(before['state']['links']['A'])
        forged=dict(event,session=before['state']['links']['B']['session'],id=secrets.token_hex(16),at=now())
        response=service.raw(forged);after=status()
        assert not response['ok'],response
        after=wait(lambda:(lambda observed: observed if observed['state']['links']['B']['session']!=before['state']['links']['B']['session'] else None)(status()),10)
        assert immutable_link(after['state']['links']['A'])==a_before
        assert after['state']['active']==before['state']['active']
        data=f.client();assert data['ok'] and data['response']['peer']=='10.99.1.1'
        restored=wait(lambda:leased('B'),20)
        case('current_authority_without_wire_ACK_revokes_only_B',began,event=forged,response=response,
             before=before,after=after,restored=restored,client=data)

        began=time.monotonic();before=status()
        from concurrent.futures import ThreadPoolExecutor
        def stale_request(_):return exchange(service.path,event,timeout=10,allow_connect_backpressure=True)
        with ThreadPoolExecutor(max_workers=12) as executor:responses=list(executor.map(stale_request,range(48)))
        after=status()
        assert all(not response['ok'] for response in responses)
        for link in LINKS:assert immutable_link(after['state']['links'][link])==immutable_link(before['state']['links'][link])
        queue=after['runtime']['queue'];assert 0<=queue['depth']<=queue['capacity']==4
        case('concurrent_retired_event_flood_cannot_refresh_lease',began,requests=len(responses),server_rejected=sum(not response['ok'] and not response.get('transport_rejected',False) for response in responses),
             transport_rejected=sum(response.get('transport_rejected',False) for response in responses),accepted=sum(response['ok'] for response in responses),
             before=before,after=after,
             interpretation='Live stale-authority flood; overflow is claimed only if the recorded counter increased')

        began=time.monotonic();before=status();b=before['state']['links']['B']
        def loss_request(_):
            q=dict(op='event',link='B',session=b['session'],boot=before['state']['boot'],
                   id=secrets.token_hex(16),at=now(),reason='deconfig',lease=None,options=[])
            return exchange(service.path,q,timeout=10,allow_connect_backpressure=True)
        with ThreadPoolExecutor(max_workers=12) as executor:responses=list(executor.map(loss_request,range(48)))
        after=wait(lambda:(lambda observed:observed if observed['state']['links']['B']['session']!=b['session'] else None)(status()),10)
        assert immutable_link(after['state']['links']['A'])==immutable_link(before['state']['links']['A'])
        assert after['state']['active']==before['state']['active']
        queue=after['runtime']['queue']
        assert queue['peak']<=queue['capacity']==4
        assert queue['overflow']['B']>before['runtime']['queue']['overflow']['B'],(before,after)
        assert any(not response['ok'] for response in responses)
        restored=wait(lambda:leased('B'),20)
        case('bounded_live_loss_queue_overflow_retires_only_B',began,before=before,after=after,
             requests=len(responses),queued=sum(bool(response['ok']) for response in responses),
             server_rejected=sum(not response['ok'] and not response.get('transport_rejected',False) for response in responses),
             transport_rejected=sum(response.get('transport_rejected',False) for response in responses),
             restored=restored,origin='Synthetic current-authority loss callbacks through formal service IPC')

        began=time.monotonic()
        # Live lease expiry is measured from the actual wire-derived service
        # deadline. Stopped clients cannot generate deconfig as a shortcut.
        before=status();deadlines={k:before['state']['links'][k]['expires'] for k in LINKS}
        stopped=[before['runtime']['children'][k] for k in LINKS]
        for child in stopped:os.kill(child,signal.SIGSTOP)
        try:
            for server in f.servers.values():f.stop(server)
            expired=wait(lambda:(lambda observed:observed if all(observed['state']['links'][k]['current'] is None for k in LINKS) else None)(status()),max(deadlines.values())-now()+15,interval=.2)
            at=now()
            assert at>=max(deadlines.values()),(at,deadlines)
            assert expired['state']['active'] is None
            data=f.client();assert not data['ok'],data
            assert all(expired['runtime']['children'][k]==before['runtime']['children'][k] for k in LINKS)
            states={k:next(line for line in Path('/proc',str(expired['runtime']['children'][k]),'status').read_text().splitlines() if line.startswith('State:')).split()[1] for k in LINKS}
            assert all(state=='T' for state in states.values()),states
            case('wire_deadline_expires_without_client_cleanup',began,before=before,after=expired,
                 original_deadlines=deadlines,observed_at=at,client=data,
                 stopped_clients_remained_same=True,stopped_client_states=states)
        finally:
            for child in stopped:
                try:os.kill(child,signal.SIGCONT)
                except ProcessLookupError:pass
        result['final']=status();result['passed']=True
    except BaseException as exc:
        result['passed']=False;result['failure']=dict(type=type(exc).__name__,message=str(exc)[:1500])
        if service:
            try:result['failure_status']=service.raw(dict(op='status'))
            except Exception as observation_error:
                result['failure_status_error']=dict(type=type(observation_error).__name__,message=str(observation_error)[:500])
            try:
                service.log.flush()
                result['failure_service_log_tail']=(root/'service-private.log').read_text(errors='replace')[-8000:].replace(str(source),'<SOURCE>').replace(str(root),'<RUN>')
            except OSError as observation_error:
                result['failure_log_error']=type(observation_error).__name__
        raise
    finally:finalize(root,result,f,service)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,default=Path('/opt/uplinkstead-stage1'))
    parser.add_argument('--cleanup',action='store_true');args=parser.parse_args()
    if args.cleanup:print(json.dumps(cleanup_owned(args.root)))
    else:print(json.dumps(run(args.root,Path(__file__).resolve().parents[1]),allow_nan=False))
