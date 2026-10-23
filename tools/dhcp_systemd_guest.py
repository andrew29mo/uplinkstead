"""Installed unmodified units + explicit namespace/path-only drop-ins in a Linux VM.

A separate helper-fault case changes only ExecStart to a documented bounded
pre-exec shim around the same production service/Linux.run. No reboot claim.
"""
import argparse,copy,fcntl,json,os,pwd,shutil,signal,sqlite3,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure
from tools.dhcp_stage1_guest import wait,exchange,rss
from tools.guest import cmd,ns,ip
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from tools import dhcp_control_guest
from uplinkstead.writer import now
UNIT='uplinkstead-dual.service';WORKER='uplinkstead-dual-policy.service'
STATE=Path('/var/lib/uplinkstead-dual');RUN=Path('/run/uplinkstead-dual');CONFIG=Path('/etc/uplinkstead/dual-dhcp.json')


def props(unit):
    keys=('MainPID','InvocationID','ActiveState','SubState','Result','NRestarts','ControlGroup','Type','KillMode','TimeoutStopUSec','StartLimitBurst','StartLimitIntervalUSec','Restart','RestartUSec')
    return dict(row.split('=',1) for row in cmd(['systemctl','show',unit,*sum((['-p',k] for k in keys),[])]).stdout.splitlines())

def process(pid):
    rows=dict(line.split(':',1) for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line)
    return dict(pid=pid,uid=[int(x) for x in rows['Uid'].split()],gid=[int(x) for x in rows['Gid'].split()],
        caps={k:rows[k].strip() for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')},no_new_privs=rows['NoNewPrivs'].strip(),rss_kib=rss(pid),
        state=rows['State'].strip(),cgroup=Path('/proc',str(pid),'cgroup').read_text().strip(),start_ticks=Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split()[19])

def alive(p):
    path=Path('/proc',str(p['pid']),'stat')
    if not path.exists():return False
    row=path.read_text().rsplit(')',1)[1].split()
    return row[0]!='Z' and row[19]==p['start_ticks']

def tree(unit):
    path=Path('/sys/fs/cgroup'+props(unit)['ControlGroup'])
    if not path.exists():return []
    ids={int(n) for f in path.rglob('cgroup.procs') for n in f.read_text().split()}
    return [process(n) for n in sorted(ids) if Path('/proc',str(n)).exists()]

def cleanup_install(root):
    ledger=root/'installation.json'
    if not ledger.exists():return True
    owned=json.loads(ledger.read_text())
    allowed={str(Path('/etc/systemd/system')/u) for u in (UNIT,WORKER)}|{str(CONFIG),'/usr/libexec/uplinkstead-dual-worker.py','/usr/libexec/uplinkstead-dual-hook.py','/usr/libexec/uplinkstead-busybox'}
    allowed|={str(Path('/etc/systemd/system')/(u+'.d/fixture.conf')) for u in (UNIT,WORKER)}|{str(Path('/etc/systemd/system')/(UNIT+'.d/fault.conf'))}
    for row in owned['files']:
        p=Path(row['path'])
        if str(p) not in allowed:raise RuntimeError('Foreign installation cleanup target')
        if p.exists() or p.is_symlink():
            st=p.lstat()
            if st.st_uid!=0 or st.st_ino!=row['inode']:raise RuntimeError('Installation inode changed')
    cmd(['systemctl','stop',UNIT,WORKER],check=False)
    if any(int(props(u)['MainPID']) for u in (UNIT,WORKER)):raise RuntimeError('Installed process retained')
    for row in reversed(owned['files']):Path(row['path']).unlink(missing_ok=True)
    for name in reversed(owned['dirs']):
        p=Path(name)
        if p.exists():p.rmdir()
    cmd(['systemctl','daemon-reload']);cmd(['systemctl','reset-failed',UNIT,WORKER],check=False)
    if STATE.exists():
        if STATE.is_symlink() or STATE.stat().st_uid!=0 or (owned.get('state_inode') is not None and STATE.stat().st_ino!=owned['state_inode']):raise RuntimeError('State ownership changed')
        shutil.rmtree(STATE)
    if RUN.exists():raise RuntimeError('systemd runtime directory retained')
    if owned['created_user']:
        identity=pwd.getpwnam('uplinkstead')
        if identity.pw_uid!=owned['uid']:raise RuntimeError('User ownership changed')
        cmd(['userdel','uplinkstead'])
    ledger.unlink()
    return True

def run(root,source):
    f=Fixture(root,source);installed=[];dirs=[];created_user=False;state_inode=None
    ledger=root/'installation.json'
    ownership=dict(files=[],dirs=[],created_user=False,uid=None,state_inode=None)
    def own():ledger.write_text(json.dumps(ownership))
    result=dict(passed=False,source_sha256=fingerprint(manifest()),cases=[],client_build=json.loads((root/'client/build.json').read_text()),client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),client_config_sha256=digest(root/'client/busybox-1.36.1/.config'),
        limitations=['Installed service process restart, not VM reboot, boot-zero-gap or power loss', 'Controlled SIGKILL and stopped pre-exec helper, not every kernel/helper interleaving or disk-full recovery','VM process RSS snapshots, not peak or physical-WAN performance'])
    def persist():(root/'systemd-guest.json').write_text(json.dumps(result,indent=2,allow_nan=False))
    def case(name,began,**d):result['cases'].append(dict(name=name,passed=True,seconds=time.monotonic()-began,details=d));persist()
    def system(*args,check=True):return cmd(['systemctl',*args],check=check)
    def state():return exchange(RUN/'private/events.sock',{'op':'status'})
    def observed(test,timeout=25):
        def poll():
            try:
                s=state();return s if test(s) else None
            except (OSError,ValueError,RuntimeError):return None
        return wait(poll,timeout)
    def selected():return observed(lambda s:s['state']['active'] is not None)
    def ctl(q,uid=None):
        code='import json;from uplinkstead.dual_dhcp_worker import request;print(json.dumps(request('+repr(str(RUN/'control.sock'))+','+repr(q)+')))'
        if uid is None:return json.loads(cmd(['env','PYTHONPATH='+str(source),'python3','-c',code]).stdout)
        # Standalone installed file, since the source/state is intentionally private.
        code="import json,runpy;request=runpy.run_path('/usr/libexec/uplinkstead-dual-worker.py')['request'];print(json.dumps(request("+repr(str(RUN/'control.sock'))+','+repr(q)+')))'
        return json.loads(cmd(['runuser','-u','uplinkstead','--','python3','-c',code]).stdout)
    def operation(kind,s=None,**extra):
        s=s or state();q=dict(op=kind,epoch=s['state']['epoch'],revision=s['state']['revision'],id=os.urandom(16).hex());q.update(extra);return ctl(q)
    def stale(old):
        before=state();answers=[]
        for kind in ('pause','resume','reset-budget'):
            answers.append(operation(kind,old,**({'ack':'reset-switch-budget'} if kind=='reset-budget' else {})))
        answers.append(ctl(dict(op='propose',target='A',epoch=old['state']['epoch'],revision=old['state']['revision'],generation=old['state']['links']['A']['generation']),uid=True))
        row=old['state']['links']['A']
        answers.append(exchange(RUN/'private/events.sock',dict(op='event',link='A',session=row['session'],boot=old['state']['boot'],id=os.urandom(16).hex(),at=now(),reason='deconfig',lease=None,options=[])))
        after=state();assert all(a['ok'] is False for a in answers)
        for key in ('epoch','history','latched','paused','active','operations'):assert before['state'][key]==after['state'][key]
        assert before['state']['epoch']>old['state']['epoch'] and after['state']['revision']>=before['state']['revision']
        return dict(before=before,after=after,replies=answers,submitted=dict(epoch=old['state']['epoch'],revision=old['state']['revision']))
    def net():
        tables={}
        for t in (41201,41202,41203):
            p=ns('dd_r',['ip','-j','route','show','table',str(t)],check=False)
            if p.returncode and 'FIB table does not exist' not in p.stderr:raise RuntimeError('Route readback failed')
            tables[str(t)]=json.loads(p.stdout or '[]')
        return tables
    def servers(on):
        for k in LINKS:
            if on:f.server(k,duration='10m',extra=['--dhcp-option-force=58,300i','--dhcp-option-force=59,500i'])
            elif k in f.servers:f.stop(f.servers.pop(k))
    def ready(old=None):
        def check():
            p=props(UNIT);w=props(WORKER)
            if p['ActiveState']!='active' or w['ActiveState']!='active' or int(p['MainPID'])<=0 or int(w['MainPID'])<=0:return
            if old and p['InvocationID']==old['InvocationID']:return
            try:return dict(writer=p,worker=w,status=state())
            except OSError:return
        return wait(check,30)
    def assert_empty(s):
        assert s['state']['active'] is None and all(r['current'] is None and r['state']=='WAITING' and r['good']==r['bad']==r['until']==0 and r['round']==-1 for r in s['state']['links'].values())
        assert all(not rows for rows in net().values())
    def start():system('start',UNIT);return ready()
    def write(path,value,mode=0o644):
        assert not path.exists();path.write_text(value);path.chmod(mode);installed.append(path)
        ownership['files'].append(dict(path=str(path),inode=path.lstat().st_ino));own()
    try:
        # Refuse adoption of installed services, files or state from another run.
        paths=[Path('/etc/systemd/system')/u for u in (UNIT,WORKER)]+[CONFIG,STATE,RUN,Path('/usr/libexec/uplinkstead-dual-worker.py'),Path('/usr/libexec/uplinkstead-dual-hook.py'),Path('/usr/libexec/uplinkstead-busybox')]
        assert all(not p.exists() and not p.is_symlink() for p in paths)
        try:identity=pwd.getpwnam('uplinkstead')
        except KeyError:
            cmd(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','uplinkstead']);created_user=True;identity=pwd.getpwnam('uplinkstead')
        assert identity.pw_uid>0 and identity.pw_gid>0
        ownership.update(created_user=created_user,uid=identity.pw_uid);own()
        f.setup();configure(root)
        # Independent non-DHCP fallback: deleting the last IPv4 address on
        # wanB also removes kernel routes/neighbours tied to that interface.
        # A third fixture-only NIC keeps the forbidden main path viable without
        # reinstalling a product route or retaining a withdrawn DHCP address.
        cmd(['ip','link','add','name','bypass0','netns','dd_r','type','veth','peer','name','bypass','netns','dd_b'])
        for namespace,dev,address in (('dd_r','bypass0','198.18.0.2/30'),('dd_b','bypass','198.18.0.1/30')):
            ip(namespace,'addr','add',address,'dev',dev);ip(namespace,'link','set',dev,'up')
            ns(namespace,['sysctl','-qw','net.ipv4.conf.'+dev+'.rp_filter=0'])
        ip('dd_r','route','replace','default','via','198.18.0.1','dev','bypass0')
        result['fallback_fixture']='Third fixture-only static NIC keeps a viable independent main default through upstream B'
        servers(True)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=2,failure_rounds=3,freshness=5,budget=16,window=600)
        c['runtime']=dict(queue_capacity=8,probe_interval=.15,restart_delay=.2,client_diagnostics=False,automatic_selection=True,selection_hold=.3,failover_delay=.8)
        if not CONFIG.parent.exists():CONFIG.parent.mkdir();dirs.append(CONFIG.parent);ownership['dirs'].append(str(CONFIG.parent));own()
        write(CONFIG,json.dumps(c),0o600)
        for name in ('uplinkstead-dual-worker.py','uplinkstead-dual-hook.py'):
            write(Path('/usr/libexec')/name,(source/('uplinkstead/dual_dhcp_worker.py' if 'worker' in name else 'deploy/uplinkstead-dual-hook.py')).read_text(),0o644 if 'worker' in name else 0o755)
        p=Path('/usr/libexec/uplinkstead-busybox');p.symlink_to(root/'client/busybox-1.36.1/busybox');installed.append(p);ownership['files'].append(dict(path=str(p),inode=p.lstat().st_ino));own()
        result['units']={}
        for u in (UNIT,WORKER):
            p=Path('/etc/systemd/system')/u;write(p,(source/'deploy'/u).read_text());result['units'][u]=dict(source_sha256=digest(source/'deploy'/u),installed_sha256=digest(p))
            drop=p.with_name(u+'.d');assert not drop.exists();drop.mkdir();dirs.append(drop);ownership['dirs'].append(str(drop));own()
            write(drop/'fixture.conf','[Service]\nNetworkNamespacePath=/run/netns/dd_r\nEnvironment=PYTHONPATH='+str(source)+'\n')
        system('daemon-reload');system('reset-failed',UNIT,WORKER,check=False)
        began=time.monotonic();started=start();state_inode=STATE.stat().st_ino;ownership['state_inode']=state_inode;own();s=selected()
        writer=process(int(started['writer']['MainPID']));worker=process(int(started['worker']['MainPID']))
        assert worker['uid']==[identity.pw_uid]*4 and all(int(v,16)==0 for v in worker['caps'].values()) and worker['no_new_privs']=='1'
        assert writer['uid']==[0]*4 and writer['no_new_privs']=='1' and all(int(writer['caps'][k],16)==0x3400 for k in ('CapEff','CapPrm','CapBnd')) and all(int(writer['caps'][k],16)==0 for k in ('CapInh','CapAmb')) and started['writer']['Type']=='notify' and started['writer']['KillMode']=='control-group'
        denied=cmd(['runuser','-u','uplinkstead','--','cat',str(STATE/'journal.sqlite')],check=False);assert denied.returncode!=0
        response=f.client();assert response['ok']
        case('installed_units_readiness_and_worker',began,start=started,selected=s,writer=writer,worker=worker,worker_journal_denied=True,client=response)
        began=time.monotonic();assert operation('pause')['ok'];old=state();children=tree(UNIT)+tree(WORKER);servers(False);system('stop',UNIT)
        assert props(UNIT)['ActiveState']=='inactive' and props(WORKER)['ActiveState']=='inactive' and not RUN.exists() and all(not alive(p) for p in children)
        with sqlite3.connect(STATE/'journal.sqlite') as db:stopped=json.loads(db.execute('select value from state where id=1').fetchone()[0])
        assert stopped['active'] is None and all(r['current'] is None for r in stopped['links'].values()) and stopped['history']==old['state']['history'] and stopped['paused']
        routes=net();assert all(not rows for rows in routes.values());blocked=f.client();fallback=f.client('dd_r',source='198.18.0.2')
        result['stop_witness']=dict(blocked=blocked,fallback=fallback,routes=routes,main=json.loads(ip('dd_r','-j','route','show','table','main').stdout),neighbours=json.loads(ip('dd_r','-j','neigh','show').stdout));persist()
        assert not blocked['ok'] and fallback['ok']
        restarted=start();assert_empty(restarted['status']);reject=stale(old);servers(True)
        fresh=observed(lambda s:all(r['state']=='HEALTHY' for r in s['state']['links'].values()))
        assert fresh['state']['paused'] and fresh['state']['active'] is None and operation('resume')['ok'];after=selected();late=stale(old)
        case('orderly_stop_start_quarantines_and_cleans',began,old=old,children=children,stopped=stopped,routes=routes,blocked=blocked,fallback=fallback,restarted=restarted,stale=reject,stale_after=late,fresh=fresh,after=after,all_old_processes_gone=True,socket_removed=True)
        began=time.monotonic();old=state();before=props(UNIT);old_processes=tree(UNIT)+tree(WORKER);servers(False);killed_at=now();os.kill(int(before['MainPID']),signal.SIGKILL)
        recovered=ready(before);ready_at=now();assert_empty(recovered['status']);assert all(not alive(p) for p in old_processes)
        assert recovered['status']['state']['history']==old['state']['history'] and recovered['status']['state']['epoch']>old['state']['epoch']
        reject=stale(old);servers(True);after=selected();late=stale(old);client=f.client();assert client['ok']
        case('writer_SIGKILL_supervised_recovery',began,old=old,previous=before,old_processes=old_processes,killed_at=killed_at,ready_observed_at=ready_at,recovered=recovered,stale=reject,stale_after=late,after=after,client=client,all_old_processes_gone=True,rss_kib=dict(writer=rss(int(props(UNIT)['MainPID'])),worker=rss(int(props(WORKER)['MainPID']))))
        # Independent fault case uses actual Linux.run helper inheritance and a
        # stopped pre-exec helper. No fake backend result or state recovery.
        system('stop',UNIT);fault=Path('/etc/systemd/system')/(UNIT+'.d/fault.conf')
        original_exec=next(l.split('=',1)[1] for l in (source/'deploy'/UNIT).read_text().splitlines() if l.startswith('ExecStart='))
        write(fault,'[Service]\nExecStart=\nExecStart='+original_exec.replace('-m uplinkstead.dual_dhcp_service',str(source/'tools/dhcp_systemd_fault_service.py'))+'\nEnvironment=UPLINKSTEAD_TEST_BARRIER='+str(root)+'\nReadWritePaths='+str(root)+'\nTimeoutStopSec=3\n')
        system('daemon-reload');system('reset-failed',UNIT,WORKER,check=False);start();selected()
        began=time.monotonic();(root/'helper-arm').touch();f.fault('A',True)
        wait(lambda:(root/'helper-ready.json').exists(),20);helper=json.loads((root/'helper-ready.json').read_text());wait(lambda:process(helper['pid'])['state'].startswith('T'),2);helper_proc=process(helper['pid']);assert helper['lock_fds']
        old=state();before=props(UNIT);servers(False);os.kill(int(before['MainPID']),signal.SIGKILL)
        wait(lambda:props(UNIT)['MainPID']=='0',3)
        lock_denied=False
        fd=os.open(STATE/'writer.lock',os.O_RDWR)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:lock_denied=True
        finally:os.close(fd)
        result['helper_lock_observation']=dict(alive=alive(helper_proc),lock_denied=lock_denied);persist()
        assert alive(helper_proc) and lock_denied
        recovered=ready(before);assert_empty(recovered['status']);assert not alive(helper_proc) and not (root/'helper-executed').exists()
        reject=stale(old);servers(True);after=selected();late=stale(old);client=f.client();assert client['ok'] and after['state']['active']['link']=='B'
        case('delayed_old_ip_helper_killed_before_takeover',began,helper=helper,helper_process=helper_proc,lock_denied_while_old_helper=True,old=old,previous=before,recovered=recovered,stale=reject,stale_after=late,after=after,client=client,old_helper_gone=True,old_helper_never_executed_ip=True)
        system('stop',UNIT);fault.unlink();installed.remove(fault);system('daemon-reload');f.fault('A',False)
        began=time.monotonic()
        with sqlite3.connect(STATE/'journal.sqlite') as db:before_failure=json.loads(db.execute('select value from state where id=1').fetchone()[0])
        journal_before=json.loads(cmd(['journalctl','-b','-u',UNIT,'-n','1','--no-pager','-o','json']).stdout)
        journal_fields=('__CURSOR','__MONOTONIC_TIMESTAMP','_BOOT_ID','UNIT','_SYSTEMD_UNIT','MESSAGE')
        journal_before={k:journal_before[k] for k in journal_fields if k in journal_before}
        saved=CONFIG.read_text();CONFIG.write_text('{invalid-json');system('reset-failed',UNIT,WORKER,check=False);system('start',UNIT,check=False)
        wait(lambda:props(UNIT)['ActiveState']=='failed',25);failed=props(UNIT);failed_worker=props(WORKER)
        time.sleep(3);stable_failure=props(UNIT)
        messages=cmd(['journalctl','-b','-u',UNIT,'--after-cursor='+journal_before['__CURSOR'],'--no-pager','-o','json']).stdout
        entries=[json.loads(row) for row in messages.splitlines()]
        limit_entries=[{k:r[k] for k in journal_fields if k in r} for r in entries if r.get('MESSAGE','').endswith('Start request repeated too quickly.')]
        limit_observed=bool(limit_entries)
        assert all(r['_BOOT_ID']==journal_before['_BOOT_ID'] and int(r['__MONOTONIC_TIMESTAMP'])>int(journal_before['__MONOTONIC_TIMESTAMP']) and r['__CURSOR']!=journal_before['__CURSOR'] for r in limit_entries)
        assert limit_observed and stable_failure['ActiveState']=='failed' and stable_failure['NRestarts']==failed['NRestarts'] and 1<=int(failed['NRestarts'])<=3
        assert failed_worker['ActiveState']!='active' and not net()['41203']
        CONFIG.write_text(saved);retry=system('start',UNIT,check=False);assert retry.returncode!=0
        system('reset-failed',UNIT);system('reset-failed',WORKER,check=False);start();after=selected();assert f.client()['ok']
        assert after['state']['history'][:-1]==before_failure['history'] and after['state']['paused']==before_failure['paused'] and after['state']['latched']==before_failure['latched']
        case('bounded_restart_failure_and_explicit_repair',began,failed=failed,failed_worker=failed_worker,stable_failure=stable_failure,start_limit_observed=limit_observed,journal_before=journal_before,limit_entries=limit_entries,before=before_failure,repair_without_reset_exit=retry.returncode,after=after,explicit_reset_recovered=True)
        result['worker_file_sha256']=digest(Path('/usr/libexec/uplinkstead-dual-worker.py'));result['wire_counters']=f.counters()
    except BaseException as exc:
        result['failure']=dict(type=type(exc).__name__,message=str(exc)[:1500]);persist()
        (root/'systemd-private.log').write_text(cmd(['journalctl','-u',UNIT,'-u',WORKER,'-n','120','--no-pager'],check=False).stdout)
        try:result['failure_status']=state();persist()
        except BaseException:pass
        raise
    finally:
        # Units stopped before namespace removal, including failure paths.
        try:result['installation_removed']=cleanup_install(root)
        finally:result['cleanup']=f.cleanup();persist()
    regression=root/'control-regression';regression.mkdir(mode=0o700);(regression/'client').symlink_to(root/'client',target_is_directory=True)
    result['regression']=dhcp_control_guest.run(regression,source)
    result['passed']=True;persist();return result
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--cleanup',action='store_true');a=p.parse_args()
    if a.cleanup:
        from tools.dual_dhcp_fixture import cleanup_owned
        cleanup_install(a.root)
        for child in (a.root/'control-regression/automatic-regression',a.root/'control-regression'):
            if child.exists():cleanup_owned(child)
        print(json.dumps(cleanup_owned(a.root)))
    else:print(json.dumps(run(a.root,Path(__file__).resolve().parents[1]),allow_nan=False))
