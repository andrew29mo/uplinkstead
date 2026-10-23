"""Real UID/capability boundary and root CLI against the formal dual-DHCP writer."""
import argparse,copy,json,os,shutil,signal,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dhcp_p0_guest import Service,wire,summary
from tools.dhcp_stage1_guest import wait,rss
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure
from tools.guest import ns,ip
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from tools import dhcp_automatic_guest
from uplinkstead.writer import now
UID=61001
GID=61001

class ControlService(Service):
    def __init__(self,root,source,control):
        self.root=root;self.path=root/'run/events.sock';self.log=(root/'service-private.log').open('a')
        self.p=subprocess.Popen(['ip','netns','exec','dd_r','python3','-m','uplinkstead.dual_dhcp_service',
            '--config',str(root/'config.json'),'--journal',str(root/'state'),'--socket',str(self.path),
            '--hook',str(source/'deploy/uplinkstead-dual-hook.py'),'--client',str(root/'client/busybox-1.36.1/busybox'),
            '--policy-uid',str(UID),'--policy-gid',str(GID),'--control-socket',str(control)],cwd=source,
            env=dict(os.environ,PYTHONPATH=str(source)),stdout=self.log,stderr=self.log)
        try:wait(lambda:self.path.exists() and control.exists() and self.p.poll() is None,20)
        except BaseException:self.stop();raise

def run(root,source):
    f=Fixture(root,source);service=None;worker=None;control_dir=None
    result=dict(passed=False,source_sha256=fingerprint(manifest()),cases=[],
        client_build=json.loads((root/'client/build.json').read_text()),client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),client_config_sha256=digest(root/'client/busybox-1.36.1/.config'),
        limitations=['Foreground root writer and actual capability-free UID worker, not installed systemd or whole-writer/reboot recovery qualification',
        'DHCP clients/capture remain trusted privileged components; policy-process separation is not a full root/client sandbox',
        'No boot-zero-gap, power-loss, physical WAN or long-history qualification; RSS snapshots not peaks'])
    def persist():(root/'control-guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,start,**details):result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-start,details=details));persist()
    def status():return service.call('status')
    def healthy(k):return wait(lambda:(lambda s:s if s['state']['links'][k]['state']=='HEALTHY' else None)(status()),20)
    def active(k):return wait(lambda:(lambda s:s if s['state']['active'] and s['state']['active']['link']==k else None)(status()),20)
    def cli(kind,*extra):
        p=ns('dd_r',['env','PYTHONPATH='+str(source),'python3','-m','uplinkstead.dual_dhcp_cli','--socket',str(control),kind,*extra],check=False,timeout=10)
        return dict(exit_code=p.returncode,answer=json.loads(p.stdout) if p.stdout.strip() else None)
    def published(reply):
        revision=reply['answer']['status']['revision']
        return wait(lambda:(lambda s:s if s['state']['revision']>=revision else None)(status()),3)
    def actor(q,uid=UID,gid=GID):
        code="import runpy,json,os;f=runpy.run_path("+repr(str(worker_file))+")['request'];q="+repr(q)+"\ntry:r=f("+repr(str(control))+",q)\nexcept OSError as e:r={'ok':False,'transport_error':type(e).__name__}\nprint(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'reply':r}))"
        p=ns('dd_r',['setpriv','--reuid='+str(uid),'--regid='+str(gid),'--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','python3','-c',code],check=False)
        if p.returncode:raise RuntimeError('Actor launch failed '+p.stderr[-400:])
        return json.loads(p.stdout)
    def proposal(k,s):return dict(op='propose',target=k,epoch=s['state']['epoch'],revision=s['state']['revision'],generation=s['state']['links'][k]['generation'])
    def start_worker():return f.spawn('dd_r',['setpriv','--reuid='+str(UID),'--regid='+str(GID),'--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','python3',str(worker_file),'--socket',str(control)],'policy')
    def traffic(k):
        v=f.client();assert v['ok'] and v['response']['peer']==f'10.99.{LINKS[k]["transit"]}.1'
        return v
    try:
        f.setup();configure(root)
        for k in LINKS:
            f.server(k,duration='10m',extra=['--dhcp-option-force=58,300i','--dhcp-option-force=59,500i'])
            p=root/('wire-'+k+'.jsonl');f.spawn('dd_r',['python3',str(source/'tools/dhcp_p0_wire.py'),'--interface',LINKS[k]['interface'],'--output',str(p)],'wire-'+k);wait(lambda p=p:p.with_suffix('.ready').exists(),10)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=2,failure_rounds=3,freshness=5,budget=1,window=600)
        c['runtime']=dict(queue_capacity=8,probe_interval=.15,restart_delay=.2,client_diagnostics=True,automatic_selection=True,selection_hold=.3,failover_delay=.8)
        (root/'config.json').write_text(json.dumps(c))
        control_dir=Path('/run/uplinkstead-dual-'+root.name);assert not control_dir.exists();control_dir.mkdir(mode=0o750);os.chown(control_dir,0,GID);inode=control_dir.stat().st_ino
        control=control_dir/'control.sock';worker_file=control_dir/'worker.py';shutil.copyfile(source/'uplinkstead/dual_dhcp_worker.py',worker_file);worker_file.chmod(0o644)
        result['worker_file_sha256']=digest(worker_file);result['cli_file_sha256']=digest(source/'uplinkstead/dual_dhcp_cli.py')
        start=time.monotonic();service=ControlService(root,source,control);healthy('A');healthy('B');time.sleep(.4);before=status();assert before['state']['active'] is None
        worker=start_worker();after=active('A')
        proc=Path('/proc',str(worker.pid),'status').read_text();creds={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in proc.splitlines() if line.split(':',1)[0] in ('Uid','Gid','CapEff','CapPrm','CapInh','CapAmb','CapBnd','NoNewPrivs')}
        assert [int(n) for n in creds['Uid'].split()]==[UID]*4 and all(int(creds[n],16)==0 for n in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')) and creds['NoNewPrivs']=='1'
        code="""import socket,subprocess,json,os
r={'uid':os.geteuid()}
try:s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.close();r['raw_socket_denied']=False
except PermissionError:r['raw_socket_denied']=True
try:open(JOURNAL,'rb').close();r['journal_denied']=False
except PermissionError:r['journal_denied']=True
p=subprocess.run(['/usr/sbin/ip','route','add','blackhole','203.0.113.199/32'],capture_output=True,text=True);r['route_denied']=p.returncode!=0 and 'Operation not permitted' in p.stderr
try:s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.connect(EVENT);r['event_socket_denied']=False
except PermissionError:r['event_socket_denied']=True
print(json.dumps(r))
""".replace('JOURNAL',repr(str(root/'state/journal.sqlite'))).replace('EVENT',repr(str(service.path)))
        p=ns('dd_r',['setpriv','--reuid='+str(UID),'--regid='+str(GID),'--clear-groups','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','python3','-c',code]);denials=json.loads(p.stdout);assert all(denials[k] for k in ('raw_socket_denied','journal_denied','route_denied','event_socket_denied'))
        case('real_unprivileged_worker_and_kernel_boundary',start,before=before,after=after,credentials=creds,denials=denials,client=traffic('A'))
        start=time.monotonic();before=status();rejected=[]
        rejected.append(actor(proposal('B',before)))
        q=proposal('B',before);q.update(health={'B':'HEALTHY'},uid=0);rejected.append(actor(q))
        for op in ('pause','resume','reset-budget'):
            q=dict(op=op,epoch=before['state']['epoch'],revision=before['state']['revision'],id='a'*32)
            if op=='reset-budget':q['ack']='reset-switch-budget'
            rejected.append(actor(q))
        rejected.append(actor(dict(op='status'),uid=UID+1))
        after=status();assert all(r['reply']['ok'] is False for r in rejected) and after['state']['history']==before['state']['history'] and after['state']['active']==before['state']['active'] and after['state']['operations']==before['state']['operations']
        case('writer_rejects_rogue_worker',start,before=before,after=after,rejections=rejected)
        start=time.monotonic();before=status();paused=cli('pause');assert paused['exit_code']==0;published(paused)
        stale=cli('resume','--epoch',str(before['state']['epoch']),'--revision',str(before['state']['revision']));assert stale['exit_code']!=0
        f.stop(worker);worker=None;f.fault('A',True)
        withdrawn=wait(lambda:(lambda s:s if s['state']['active'] is None and s['state']['links']['A']['state']=='DOWN' else None)(status()),15)
        witness=f.client('dd_r',source='10.77.0.1');blocked=f.client();assert witness['ok'] and witness['response']['peer']=='10.99.2.1' and not blocked['ok']
        case('pause_stale_resume_and_safety_withdrawal',start,before=before,pause=paused,stale_resume=stale,withdrawn=withdrawn,fallback=witness,blocked=blocked)
        start=time.monotonic();resumed=cli('resume');assert resumed['exit_code']==0
        absent_start=now();time.sleep(1.3);absent=status();assert absent['state']['active'] is None and not absent['state']['paused'] and absent['state']['history']==before['state']['history']
        worker=start_worker();latched=wait(lambda:(lambda s:s if s['state']['latched'] else None)(status()),15);assert latched['state']['active'] is None
        case('absent_worker_no_bypass_then_latch',start,resume=resumed,absent_start=absent_start,absent=absent,latched=latched)
        start=time.monotonic();pause=cli('pause');assert pause['exit_code']==0;published(pause)
        bad_resume=cli('resume');noack=cli('reset-budget');assert bad_resume['exit_code']!=0 and noack['exit_code']!=0
        before_reset=status();reset=cli('reset-budget','--ack-reset-budget');assert reset['exit_code']==0
        reset_state=published(reset);assert reset_state['state']['paused'] and not reset_state['state']['latched'] and reset_state['state']['history']==[] and reset_state['state']['active'] is None
        old_token={k:reset_state['state'][k] for k in ('epoch','revision')};oldseq=reset_state['state']['links']['B']['event_sequence'];os.kill(reset_state['runtime']['children']['B'],signal.SIGUSR1)
        renewed=wait(lambda:(lambda s:s if s['state']['links']['B']['event_sequence']>oldseq and s['state']['links']['B']['state']=='HEALTHY' else None)(status()),15)
        assert renewed['state']['active'] is None and renewed['state']['paused']
        resume=cli('resume');assert resume['exit_code']==0;after=active('B')
        stale_pause=cli('pause','--epoch',str(old_token['epoch']),'--revision',str(old_token['revision']));assert stale_pause['exit_code']!=0
        final=status();r=next(r for r in reversed(final['runtime']['recent']) if r['link']=='B' and r['sequence']==final['state']['links']['B']['event_sequence'] and r['reason']=='renew')
        def tx():
            packets=wire(root,'B');req=next((p for p in packets if p['type']==3 and p['xid']==r['xid']),None);ack=next((p for p in packets if p['type']==5 and p['xid']==r['xid']),None)
            return dict(record=r,request=summary(req),ack=summary(ack)) if req and ack else None
        case('explicit_reset_resume_new_lease_authority',start,pause=pause,bad_resume=bad_resume,no_ack=noack,before_reset=before_reset,reset=reset,reset_state=reset_state,renewed=renewed,resume=resume,after=after,stale_pause=stale_pause,final=final,transaction=wait(tx,3),client=traffic('B'),rss_kib=dict(writer=rss(service.p.pid),worker=rss(worker.pid)))
        result['wire_counters']=f.counters();assert all(result['wire_counters'][k]['wrong_dhcp']==0 for k in LINKS)
    except BaseException as exc:
        result['failure']=dict(type=type(exc).__name__,message=str(exc)[:1000])
        if service:
            try:result['failure_status']=status();result['client_log_tail']=(root/'service-private.log').read_text()[-1500:]
            except BaseException:pass
        raise
    finally:
        try:
            if worker:f.stop(worker)
            if service:service.stop()
        finally:
            try:result['cleanup']=f.cleanup()
            finally:
                if control_dir:
                    if control_dir.is_symlink() or control_dir.stat().st_ino!=inode or control_dir.stat().st_uid!=0:raise RuntimeError('Control ownership changed')
                    shutil.rmtree(control_dir)
                result['control_directory_removed']=control_dir is None or not control_dir.exists();persist()
    # Separate phase: rerun the full prior automatic-service/race regression with
    # the same frozen tree and same compiled binary. No prior journal is reset.
    regression_root=root/'automatic-regression';regression_root.mkdir(mode=0o700)
    (regression_root/'client').symlink_to(root/'client',target_is_directory=True)
    result['regression']=dhcp_automatic_guest.run(regression_root,source)
    result['passed']=True;persist();return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();print(json.dumps(run(a.root,Path(__file__).resolve().parents[1]),allow_nan=False))
