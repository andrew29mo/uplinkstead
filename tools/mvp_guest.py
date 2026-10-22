"""Installed MVP service qualification in the disposable namespace fixture."""
import json
import os
from pathlib import Path
import signal
import sqlite3
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from tools.guest import ROOT,STATE,UNIT,WORKER,cmd,system,ip,ns,client,holes,db


def cli(op,**fields):
    args=['env','PYTHONPATH=/opt/uplinkstead/source','python3','-m','uplinkstead.cli',op]
    if op!='status':
        s=cli('status');args+=['--epoch',str(s['epoch']),'--revision',str(s['revision'])]
    for k,v in fields.items():args+=['--'+k.replace('_','-'),str(v)]
    return json.loads(cmd(args).stdout)


def wait_status(test,timeout=12):
    deadline=time.monotonic()+timeout;last=None
    while time.monotonic()<deadline:
        try:
            last=cli('status')
            if test(last):return last
        except (RuntimeError,json.JSONDecodeError):pass
        time.sleep(.1)
    raise TimeoutError('MVP state not reached: '+json.dumps(last))


def rejected(op,**fields):
    try:cli(op,**fields)
    except RuntimeError:return True
    return False


def start_service():
    # Independent scenarios intentionally start/stop more often than production.
    # Clear only the fixture's prior rate counter between these scenarios.
    cmd(['systemctl','reset-failed',UNIT,WORKER]);system(UNIT,'start')


def props(unit):
    return dict(x.split('=',1) for x in cmd(['systemctl','show',unit,'-p','MainPID','-p','InvocationID','-p','ActiveState']).stdout.splitlines())


def proc(unit):
    p=props(unit);pid=int(p['MainPID']);rows=Path('/proc',str(pid),'status').read_text().splitlines()
    values=dict(x.split(':',1) for x in rows if ':' in x)
    return dict(uid=[int(x) for x in values['Uid'].split()],cap_eff=values['CapEff'].strip(),
                no_new_privs=values['NoNewPrivs'].strip(),rss_kib=int(values['VmRSS'].split()[0]),
                invocation=p['InvocationID'],pid=pid)


def run_mvp():
    def privileges():
        # Retire the exploration layout, then qualify a genuinely fresh service
        # journal. The archived exploration DB is fixture-only and not uploaded.
        from tools.guest import remote
        remote("from uplinkstead.writer import Writer;from uplinkstead.config import load;from pathlib import Path\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w:\n w.lifecycle('disable');print('true')")
        STATE.rename(ROOT/'exploration-state');STATE.mkdir(mode=0o700)
        start_service();s=wait_status(lambda s:s['mode']=='DISABLED')
        assert s['selected'] is None and not s['latched']
        w,p=proc(UNIT),proc(WORKER)
        assert w['uid']==[0]*4 and p['uid'][0]!=0 and int(p['cap_eff'],16)==0 and p['no_new_privs']=='1'
        deny=cmd(['runuser','-u','uplinkstead','--','env','PYTHONPATH=/opt/uplinkstead/source','python3','-m','uplinkstead.cli','pause','--epoch',str(s['epoch']),'--revision',str(s['revision'])],check=False)
        foreign=cmd(['runuser','-u','nobody','--','env','PYTHONPATH=/opt/uplinkstead/source','python3','-m','uplinkstead.cli','status'],check=False)
        read=cmd(['runuser','-u','uplinkstead','--','cat',STATE/'journal.sqlite'],check=False)
        before=ip('us_r','-j','route','show','table','main').stdout
        mutation=ns('us_r',['runuser','-u','uplinkstead','--','ip','route','replace','blackhole','198.19.0.0/24'],check=False)
        assert all(x.returncode!=0 for x in (deny,foreign,read,mutation))
        assert ip('us_r','-j','route','show','table','main').stdout==before
        rejected_packets=[]
        for payload in (b'x'*4097,b'{"op":"status","op":"disable"}',b'[]',b'{"op":"exec","command":"false"}'):
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
                peer.settimeout(4);peer.connect('/run/uplinkstead/control.sock');peer.sendall(payload)
                rejected_packets.append(json.loads(peer.recv(32768))['ok'] is False)
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as peer:
            peer.connect('/run/uplinkstead/control.sock');time.sleep(2.2)
        assert all(rejected_packets) and props(UNIT)['MainPID']==str(w['pid'])
        return dict(initial_mode=s['mode'],protocol_rejections=rejected_packets,idle_peer_survived=True,writer=w,worker=p,worker_operator_denied=True,foreign_peer_denied=True,state_read_denied=True,direct_mutation_denied=True,main_unchanged=True)
    yield 'mvp_privilege_boundary',privileges

    def lifecycle():
        main=ip('us_r','-j','route','show','table','main').stdout
        disabled=cli('status')
        assert disabled['mode']=='DISABLED' and rejected('disable',ack='restore-main-routing')
        assert client()['result']['peer']=='10.99.1.1'
        system(WORKER,'stop')
        enabled=cli('enable',ack='attach-owned-routing');assert enabled['mode']=='PAUSED' and enabled['selected'] is None
        assert rejected('resume',target='A',ack='reset-budget')
        system(WORKER,'start');wait_status(lambda s:all(v=='HEALTHY' for v in s['health'].values()))
        resumed=cli('resume',target='A',ack='reset-budget');assert resumed['mode']=='ENABLED'
        old=dict(epoch=resumed['epoch'],revision=resumed['revision'])
        paused=cli('pause');holes('A')
        try:
            wait_status(lambda s:s['health']['A']=='DOWN' and s['health']['B']=='HEALTHY')
            held=cli('status');assert held['mode']=='PAUSED' and held['selected']=='A'
            assert not client()['ok']
            selected=cli('select',target='B');assert selected['selected']=='B'
            assert client()['result']['peer']=='10.99.2.1'
            # Cached revision cannot override a later operator decision.
            stale=cmd(['env','PYTHONPATH=/opt/uplinkstead/source','python3','-m','uplinkstead.cli','resume','--epoch',str(old['epoch']),'--revision',str(old['revision']),'--target','A','--ack','reset-budget'],check=False)
            assert stale.returncode!=0 and cli('status')['selected']=='B'
            resumed=cli('resume',target='B',ack='reset-budget')
        finally:holes('A',False)
        assert ip('us_r','-j','route','show','table','main').stdout==main
        # Stop retains last routing; restart reconstructs health, not automatic credit.
        system(UNIT,'stop');stopped=props(UNIT);assert int(stopped['MainPID'])==0
        assert client()['result']['peer']=='10.99.2.1'
        start_service();restored=wait_status(lambda s:s['selected']=='B')
        assert restored['mode']=='ENABLED' and restored['epoch']>resumed['epoch']
        stale=cmd(['env','PYTHONPATH=/opt/uplinkstead/source','python3','-m','uplinkstead.cli','pause','--epoch',str(resumed['epoch']),'--revision',str(resumed['revision'])],check=False)
        assert stale.returncode!=0 and 'Stale operation token' in stale.stderr
        return dict(disabled_mode=disabled['mode'],enabled_mode=enabled['mode'],premature_resume_denied=True,
                    paused_selected=held['selected'],manual_selected=selected['selected'],stale_revision_denied=True,
                    retained_route_while_stopped=True,stale_epoch_denied=True,restarted_mode=restored['mode'],epoch_changed=True,main_unchanged=True)
    yield 'mvp_safe_lifecycle_and_resume',lifecycle

    def oversized_peer():
        wait_status(lambda s:all(v=='HEALTHY' for v in s['health'].values()))
        cli('pause');cli('select',target='A');cli('resume',target='A',ack='reset-budget')
        original=props(UNIT)['InvocationID'];bad=ROOT/'bad-body';bad.write_text('large-peer')
        def sample_event():
            with sqlite3.connect(STATE/'journal.sqlite') as c:
                row=c.execute("SELECT value FROM events WHERE json_extract(value,'$.name')='service_sample' ORDER BY id DESC LIMIT 1").fetchone()
            return json.loads(row[0]) if row else None
        fault=False
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                event=sample_event()
                if event and all(event['probes'][k]['successes']==2 for k in ('A','B')):break
                time.sleep(.1)
            else:raise TimeoutError('Oversized peer quorum sample missing')
            assert all(event['probes'][k]['results'][0]['ok'] is False and event['probes'][k]['results'][0]['infrastructure'] is False for k in ('A','B'))
            assert len(json.dumps(event).encode())<32768
            holes('A');fault=True
            state=wait_status(lambda s:s['selected']=='B' and s['health']['B']=='HEALTHY')
            request=client(port=8444);assert request['ok'] and request['result']['peer']=='10.99.2.1'
            assert props(UNIT)['InvocationID']==original
        finally:
            if fault:holes('A',False)
            bad.unlink(missing_ok=True)
        return dict(quorum_event=event,selected=state['selected'],request=request,
                    invocation_unchanged=True,optional_peer_bytes=12000,wire_body_under_limit=True)
    yield 'mvp_oversized_peer_quorum',oversized_peer

    def delayed_resume():
        wait_status(lambda s:all(v=='HEALTHY' for v in s['health'].values()))
        cli('pause');system(UNIT,'stop')
        from tools.guest import remote
        result=remote("""from pathlib import Path
import json,time
from uplinkstead.config import load
from uplinkstead.writer import Writer,now
from uplinkstead.control import Controller,dispatch
c=load(Path('/opt/uplinkstead/config.json'));state='/opt/uplinkstead/state'
with Writer(c,state) as w:
 ctl=Controller(w,65534)
 for _ in range(3):ctl.sample();time.sleep(.9)
 target=w.s['selected'];assert target=='B' and w.s['mode']=='PAUSED'
 proof=ctl.policy.proof(target,now());actual=w.save
 def slow_save():actual();time.sleep(2.1)
 w.save=slow_save
 q=dict(op='resume',epoch=w.s['epoch'],revision=w.s['revision'],target=target,ack='reset-budget')
 try:dispatch(ctl,q,0)
 except ValueError:
  assert now()>proof['expires_at'] and w.s['mode']=='PAUSED' and w.backend.selected()==target
  observed=dict(blocked_at=now(),proof=proof,mode=w.s['mode'],selected=target,pending=w.s['pending'])
 else:raise AssertionError('Expired same-selected resume enabled automation')
with Writer(c,state) as w:
 assert w.s['mode']=='PAUSED' and w.backend.selected()=='B'
 observed.update(durable_mode=w.s['mode'],reopened_selected=w.s['selected'])
print(json.dumps(observed))
""")
        start_service();wait_status(lambda s:all(v=='HEALTHY' for v in s['health'].values()))
        cli('resume',target='B',ack='reset-budget')
        return result
    yield 'mvp_delayed_same_selected_resume',delayed_resume

    def bounded_storage():
        # Use the formal Writer on the service's actual DB while both units stop.
        system(UNIT,'stop')
        from tools.guest import remote
        r=remote("""from uplinkstead.writer import Writer
from uplinkstead.config import load
from pathlib import Path
import json,shutil
from unittest.mock import patch
with Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w:
 for i in range(350):w.event('retention_validation',index=i)
 count=w.db.execute('SELECT count(*) FROM events').fetchone()[0]
 before=w.backend.selected()
 with patch('uplinkstead.writer.shutil.disk_usage',return_value=shutil._ntuple_diskusage(100,99,1)):
  try:w.switch(w.s['epoch'],'A')
  except Exception as exc:
   assert 'reserve' in str(exc)
  else:raise AssertionError('Low disk admitted route write')
 assert w.backend.selected()==before
 print(json.dumps(dict(events=count,page_count=w.db.execute('PRAGMA page_count').fetchone()[0],max_pages=w.db.execute('PRAGMA max_page_count').fetchone()[0],page_size=w.db.execute('PRAGMA page_size').fetchone()[0],low_space_blocked=True,selected_unchanged=True)))
""")
        assert r['events']==128 and r['page_count']<=r['max_pages']==2048
        start_service();wait_status(lambda s:s['selected']=='B')
        return r
    yield 'mvp_storage_bounds',bounded_storage

    def io_failures():
        system(UNIT,'stop')
        from tools.guest import remote
        r=remote("""from uplinkstead.writer import Writer
from uplinkstead.config import load
from pathlib import Path
from unittest.mock import patch
from uplinkstead.linux import Blocked
import json,sqlite3
c=load(Path('/opt/uplinkstead/config.json'));state='/opt/uplinkstead/state'
with Writer(c,state) as w:
 before=w.backend.selected();actual=w.backend.run
 def fail(args,**kw):
  if args[:2]==['rule','del']:raise Blocked('injected actual backend write failure')
  return actual(args,**kw)
 with patch.object(w.backend,'run',side_effect=fail):
  try:w.lifecycle('disable')
  except Blocked:pass
  else:raise AssertionError('disable unexpectedly completed')
 assert w.s['lifecycle']=='disable' and w.backend.selected()==before
with Writer(c,state) as w:
 assert w.s['mode']=='DISABLED' and w.s['lifecycle'] is None
 actual=w.backend.run;writes=[]
 def fail(args,**kw):
  if args[:2]==['rule','add']:
   writes.append(args)
   if len(writes)==2:raise Blocked('injected partial enable failure')
  return actual(args,**kw)
 with patch.object(w.backend,'run',side_effect=fail):
  try:w.lifecycle('enable')
  except Blocked:pass
  else:raise AssertionError('enable unexpectedly completed')
 assert w.s['lifecycle']=='enable' and len(writes)==2
with Writer(c,state) as w:
 assert w.s['mode']=='PAUSED' and w.s['lifecycle'] is None
 # Actual ip helper timeout, not a fake completed result.
 import subprocess
 try:w.backend.run(['monitor','route'])
 except Blocked as exc:assert 'timeout' in str(exc)
 else:raise AssertionError('monitor did not time out')
 # Failing SQLite commit must not dispatch a route write.
 before=w.backend.selected();w.db.execute('PRAGMA query_only=ON')
 try:w.switch(w.s['epoch'],'A')
 except sqlite3.OperationalError:pass
 else:raise AssertionError('query-only journal admitted mutation')
 assert w.backend.selected()==before
print(json.dumps(dict(disable_write_failure_recovered=True,partial_enable_recovered_paused=True,real_helper_timeout_reaped=True,sqlite_write_failure_no_mutation=True)))
""")
        start_service();wait_status(lambda s:all(v=='HEALTHY' for v in s['health'].values()))
        cli('resume',target='A',ack='reset-budget')
        return r
    yield 'mvp_lifecycle_failure_recovery',io_failures

    def restart_limit():
        system(UNIT,'stop');start_service();wait_status(lambda s:s['mode']=='ENABLED')
        invocations=[]
        for index in range(3):
            p=props(UNIT);assert int(p['MainPID'])>0;invocations.append(p['InvocationID'])
            system(UNIT,'kill','--signal=SIGKILL','--kill-whom=main')
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                p=props(UNIT)
                if index==2 and p['ActiveState']=='failed':break
                if index<2 and int(p['MainPID'])>0 and p['InvocationID']!=invocations[-1]:break
                time.sleep(.1)
            else:raise TimeoutError('Expected bounded restart transition missing')
        result=cmd(['systemctl','show',UNIT,'-p','Result','--value']).stdout.strip()
        # systemd may preserve Result=signal for the killed instance. Establish
        # the actual limiter from its journal and stable absence beyond RestartSec.
        time.sleep(2.5)
        log=cmd(['journalctl','-u',UNIT,'--since','-30 seconds','--no-pager','-o','cat']).stdout
        limited='Start request repeated too quickly' in log
        no_writer=[]
        for _ in range(8):
            no_writer.append(int(props(UNIT)['MainPID'])==0);time.sleep(.5)
        assert limited and all(no_writer) and len(set(invocations))==3
        # No live writer exists to repair routing until explicit operator action.
        assert int(props(UNIT)['MainPID'])==0
        start_service();wait_status(lambda s:s['mode']=='ENABLED')
        return dict(invocations=invocations,failed_result=result,limit_message_observed=limited,no_writer_samples=no_writer,no_live_writer=True,manual_reset_recovered=True)
    yield 'mvp_bounded_restart',restart_limit

    def benchmark():
        # Fixed-primary and active mode replay identical intended offsets and fault
        # windows. Every scheduled request, including late/failed work, is retained.
        modes=[]
        for automatic in (False,True):
            wait_status(lambda s:all(v=='HEALTHY' for v in s['health'].values()))
            if cli('status')['mode']=='ENABLED':cli('pause')
            cli('select',target='A');cli('resume',target='A',ack='reset-budget')
            if not automatic:cli('pause')
            processes_before={k:proc(unit) for k,unit in [('writer',UNIT),('worker',WORKER)]}
            journal_before=(STATE/'journal.sqlite').stat().st_size
            began=time.monotonic();rows=[];fault=False;fault_window=None
            def arrival(i,offset):
                started=time.monotonic()-began;r=client();finished=time.monotonic()-began
                return dict(index=i,scheduled=offset,started=started,finished=finished,
                            latency=finished-started,end_to_end=finished-offset,late=started-offset>.1,
                            ok=r['ok'],peer=r['result']['peer'] if r['ok'] else None)
            try:
                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures=[]
                    for i in range(20):
                        offset=i*.5;time.sleep(max(0,began+offset-time.monotonic()))
                        if i==4:
                            fault_start=time.monotonic()-began;holes('A');fault=True
                            fault_window=dict(started=fault_start,finished=time.monotonic()-began)
                        futures.append(pool.submit(arrival,i,offset))
                    rows=[f.result() for f in futures]
                elapsed=time.monotonic()-began
                final=cli('status');processes_after={k:proc(unit) for k,unit in [('writer',UNIT),('worker',WORKER)]}
                memory={k:p['rss_kib'] for k,p in processes_after.items()}
                assert all(processes_before[k]['pid']==processes_after[k]['pid'] and processes_before[k]['invocation']==processes_after[k]['invocation'] for k in processes_before)
                assert all(r['ok'] and r['peer']=='10.99.1.1' for r in rows[:4])
                assert all(r['peer']==('10.99.2.1' if automatic and r['index']>=4 else '10.99.1.1') for r in rows if r['ok'])
                assert final['selected']==('B' if automatic else 'A')
                if automatic:assert any(r['ok'] and r['peer']=='10.99.2.1' for r in rows)
                else:assert all(not r['ok'] for r in rows[4:])
            finally:
                if fault:holes('A',False)
            modes.append(dict(mode='automatic' if automatic else 'fixed_primary',rows=rows,elapsed=elapsed,
                              successes=sum(r['ok'] for r in rows),failures=sum(not r['ok'] for r in rows),
                              throughput=sum(r['ok'] for r in rows)/elapsed,rss_kib=memory,
                              fault_window=fault_window,processes_before=processes_before,processes_after=processes_after,journal_bytes_before=journal_before,
                              journal_bytes=(STATE/'journal.sqlite').stat().st_size,final_selected=final['selected']))
        assert [r['scheduled'] for r in modes[0]['rows']]==[r['scheduled'] for r in modes[1]['rows']]
        # Leave a durable latch for the original reboot qualification. This is an
        # explicit fixture write, not used as evidence of budget exhaustion here.
        system(UNIT,'stop')
        from tools.guest import remote
        remote("from uplinkstead.writer import Writer;from uplinkstead.config import load;from pathlib import Path\nwith Writer(load(Path('/opt/uplinkstead/config.json')),'/opt/uplinkstead/state') as w:\n w.s['latched']=True;w.save();print('true')")
        return dict(schedule=dict(requests=20,interval=.5,blackhole_from_index=4),modes=modes,
                    vm_only=True,repeated_trials=False,load_generator='open-loop scheduled arrivals, eight workers; all lateness retained')
    yield 'mvp_identical_schedule_benchmark',benchmark
