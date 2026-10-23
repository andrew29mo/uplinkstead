"""Isolated boot fixture: constructs prerequisites, never runs recovery itself.

The unchanged installed production ExecStart owns all journal/kernel recovery.
One labelled runtime shutdown override preserves stale durable state; no power-loss claim.
"""
import argparse,copy,hashlib,json,os,pwd,shutil,signal,sqlite3,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import dhcp_systemd_guest as installed
from tools.dual_dhcp_fixture import Fixture,LINKS,cleanup_owned,NAMES
from tools.dual_dhcp_guest import configure
from tools.dhcp_stage1_guest import wait,exchange
from tools.guest import cmd,ip,ns,nft,root_snapshot
from tools.netproof import digest as network_digest
from tools.dhcp_storage_guest import cleanup_volume
from tools.evidence import manifest,fingerprint
from tools.dhcp_client_build import digest
from tools.dhcp_boot_checks import authority,charged
from uplinkstead.writer import boot_id,now
from uplinkstead.dual_dhcp_service import notify_ready
UNIT,WORKER,STATE,RUN,CONFIG=installed.UNIT,installed.WORKER,installed.STATE,installed.RUN,installed.CONFIG
TOPO='uplinkstead-dual-topology.service'
TIMER='uplinkstead-dual-boot.timer'
SYSTEM=Path('/etc/systemd/system')
FAULT=Path('/run/systemd/system')/(UNIT+'.d/reboot-fault.conf')
KINDS=('normal','preserved','paused','latched','capacity')
FAULT_TEXT='[Service]\nKillSignal=SIGKILL\nExecStopPost=\n'

def save(path,value):
    temporary=path.with_name(path.name+'.tmp');temporary.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n');temporary.replace(path)
def read(path):return json.loads(path.read_text())
def system(*args,check=True):return cmd(['systemctl',*args],check=check)
def journal_path(root):return root/'storage-volume/state/journal.sqlite' if read(root/'phase.json')['kind']=='capacity' else STATE/'journal.sqlite'
def stored(path):
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
    try:return json.loads(db.execute('SELECT value FROM state WHERE id=1').fetchone()[0])
    finally:db.close()
def state():return exchange(RUN/'private/events.sock',dict(op='status'))
def observed(test,timeout=30):
    def poll():
        try:
            s=state();return s if test(s) else None
        except (OSError,RuntimeError,ValueError):return None
    return wait(poll,timeout)
def ready():
    s=observed(lambda s:installed.props(UNIT)['ActiveState']=='active' and installed.props(WORKER)['ActiveState']=='active')
    return dict(status=s,writer=installed.props(UNIT),worker=installed.props(WORKER))
def selected():return observed(lambda s:s['state']['active'] is not None)
def ctl(q,worker=False):
    code="import json,runpy;f=runpy.run_path('/usr/libexec/uplinkstead-dual-worker.py')['request'];print(json.dumps(f("+repr(str(RUN/'control.sock'))+','+repr(q)+')))'
    argv=['runuser','-u','uplinkstead','--','python3','-c',code] if worker else ['python3','-c',code]
    return json.loads(cmd(argv).stdout)
def operation(op,s=None,**extra):
    s=s or state();return ctl(dict(op=op,epoch=s['state']['epoch'],revision=s['state']['revision'],id=os.urandom(16).hex(),**extra))
def net():
    rows={}
    for t in (41201,41202,41203):
        p=ns('dd_r',['ip','-j','route','show','table',str(t)],check=False)
        if p.returncode:
            if 'FIB table does not exist' not in p.stderr:raise RuntimeError('Route observation failed')
            rows[str(t)]=[]
        else:rows[str(t)]=json.loads(p.stdout)
    return rows
def outside():return dict(main=json.loads(ip('dd_r','-j','route','show','table','main').stdout),rules=json.loads(ip('dd_r','-j','rule').stdout),foreign=json.loads(ip('dd_r','-j','route','show','table','49999').stdout))
def topology_command(root,servers=False,holes=()):
    token=os.urandom(8).hex();save(root/'desired.json',dict(token=token,servers=servers,holes=list(holes)))
    wait(lambda:(root/'topology-ack.json').exists() and read(root/'topology-ack.json').get('token')==token,8)
def client(root,source=None):return Fixture(root,root/'source').client('dd_r' if source else 'dd_c',source)
def witness(root):
    blocked=client(root);fallback=client(root,'198.18.0.2');assert not blocked['ok'] and fallback['ok'] and fallback['response']['peer']=='10.99.2.1'
    return dict(blocked=blocked,fallback=fallback,counters=Fixture(root,root/'source').counters())
def stale(old):
    before=state();routes=net();answers=[]
    for op in ('pause','resume','reset-budget'):answers.append(operation(op,old,**({'ack':'reset-switch-budget'} if op=='reset-budget' else {})))
    answers.append(ctl(dict(op='propose',target='A',epoch=old['state']['epoch'],revision=old['state']['revision'],generation=old['state']['links']['A']['generation']),True))
    row=old['state']['links']['A'];answers.append(exchange(RUN/'private/events.sock',dict(op='event',link='A',session=row['session'],boot=old['state']['boot'],id=os.urandom(16).hex(),at=now(),reason='deconfig',lease=None,options=[])))
    after=state();assert all(a['ok'] is False for a in answers)
    for k in ('epoch','history','paused','latched','active','operations'):assert before['state'][k]==after['state'][k]
    assert routes==net() and before['state']['epoch']>old['state']['epoch']
    return dict(before=before,after=after,replies=answers,submitted=dict(epoch=old['state']['epoch'],revision=old['state']['revision']),routes_before=routes,routes_after=net())
def stop_commands():
    path='/org/freedesktop/systemd1/unit/'+UNIT.replace('-','_2d').replace('.','_2e')
    return json.loads(cmd(['busctl','--json=short','get-property','org.freedesktop.systemd1',path,'org.freedesktop.systemd1.Service','ExecStopPost']).stdout)

def faults():
    rows=[]
    for line in cmd(['journalctl','-b','-u',UNIT,'--no-pager','-o','json']).stdout.splitlines():
        r=json.loads(line)
        try:m=json.loads(r.get('MESSAGE',''))
        except (ValueError,TypeError):continue
        if isinstance(m,dict) and m.get('event')=='storage_failure':rows.append(dict(message=m,boot=r['_BOOT_ID'],invocation=r.get('_SYSTEMD_INVOCATION_ID'),at=r['__MONOTONIC_TIMESTAMP']))
    return rows

def topology(root):
    phase=read(root/'phase.json');old=phase.get('before');boot=boot_id();f=Fixture(root,root/'source');stop=False
    def finish(*_):nonlocal stop;stop=True
    signal.signal(signal.SIGTERM,finish);signal.signal(signal.SIGINT,finish)
    # Across a boot the old namespace inode ledger is historical, never a licence
    # to adopt or kill reused PIDs. Require no names and a genuinely changed boot.
    if (root/'ownership.json').exists():
        assert old and old['boot']!=boot
        assert not {r.split()[0] for r in cmd(['ip','netns','list']).stdout.splitlines()}&set(NAMES)
        (root/'ownership.json').rename(root/('ownership-'+old['boot']+'.json'))
    try:
        if phase['kind']=='capacity':
            mount=root/'storage-volume';image=root/'storage.img'
            device=cmd(['losetup','--find','--show',str(image)]).stdout.strip()
            save(root/'storage-volume.json',dict(mount=str(mount),image=str(image),device=device));cmd(['mount','-t','ext4',device,str(mount)])
        saved=stored(journal_path(root)) if old else None
        pre=dict(boot=boot,at=now(),writer=installed.props(UNIT),journal=saved,source_sha256=fingerprint(manifest()),runtime_fault_present=FAULT.exists())
        save(root/'prestart.json',pre)
        assert installed.props(UNIT)['MainPID']=='0'
        if old:
            assert old['boot']!=boot and not FAULT.exists()
            if phase['kind'] in ('preserved','capacity'):assert saved==old['journal']
        # This Colima fixture must snapshot after the VM's own networking is
        # initialized, not count Docker/Lima startup as product scope drift.
        wait(lambda:Path('/sys/class/net/docker0').exists(),10)
        f.setup(start_servers=False)
        cmd(['ip','link','add','name','bypass0','netns','dd_r','type','veth','peer','name','bypass','netns','dd_b'])
        for namespace,dev,address in (('dd_r','bypass0','198.18.0.2/30'),('dd_b','bypass','198.18.0.1/30')):
            ip(namespace,'addr','add',address,'dev',dev);ip(namespace,'link','set',dev,'up');ns(namespace,['sysctl','-qw','net.ipv4.conf.'+dev+'.rp_filter=0'])
        ip('dd_r','route','replace','default','via','198.18.0.1','dev','bypass0');ip('dd_r','route','add','blackhole','198.19.250.0/24','table','49999')
        pre.update(topology_at=now(),initial_routes=net(),root_before_sha256=network_digest(root_snapshot()));save(root/'prestart.json',pre)
        last=None;holes=set();notify_ready()
        while not stop:
            desired=read(root/'desired.json')
            if desired!=last:
                for k in LINKS:
                    if desired['servers'] and k not in f.servers:f.server(k,duration='10m',extra=['--dhcp-option-force=58,300i','--dhcp-option-force=59,500i'])
                    if not desired['servers'] and k in f.servers:f.stop(f.servers.pop(k))
                    if (k in desired['holes'])!=(k in holes):
                        if k in desired['holes']:nft(LINKS[k]['namespace'],'add table ip boot_hole\nadd chain ip boot_hole forward { type filter hook forward priority -50; policy accept; }\nadd rule ip boot_hole forward iifname "edge" drop\n')
                        else:nft(LINKS[k]['namespace'],'delete table ip boot_hole\n')
                holes=set(desired['holes']);last=desired;save(root/'topology-ack.json',dict(token=desired['token'],boot=boot,at=now()))
            time.sleep(.03)
    finally:
        try:
            save(root/('topology-cleanup-'+boot+'.json'),f.cleanup())
        finally:cleanup_volume(root)

def fault_absent():
    if FAULT.parent.is_symlink() or (FAULT.parent.exists() and not FAULT.parent.is_dir()):raise RuntimeError('Foreign runtime fault parent')
    if FAULT.exists() or FAULT.is_symlink():raise FileExistsError('Refusing existing runtime fault')

def install_fault(root):
    fault_absent();FAULT.parent.mkdir(parents=True,exist_ok=True)
    ownership=read(root/'installation.json')
    if ownership.get('runtime_fault'):raise RuntimeError('Uncleared runtime fault ownership')
    fd=os.open(FAULT,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as file:
        st=os.fstat(file.fileno())
        ownership['runtime_fault']=dict(path=str(FAULT),device=st.st_dev,inode=st.st_ino,uid=st.st_uid,boot=boot_id(),sha256=hashlib.sha256(b'').hexdigest())
        save(root/'installation.json',ownership)
        file.write(FAULT_TEXT);file.flush()
        ownership['runtime_fault']['sha256']=hashlib.sha256(FAULT_TEXT.encode()).hexdigest();save(root/'installation.json',ownership)

def remove_fault(root):
    if FAULT.parent.is_symlink():raise RuntimeError('Foreign runtime fault parent')
    ledger=root/'installation.json';ownership=read(ledger) if ledger.exists() else {};owned=ownership.get('runtime_fault')
    if FAULT.exists() or FAULT.is_symlink():
        if not owned or owned['path']!=str(FAULT) or owned['boot']!=boot_id():raise RuntimeError('Unowned runtime fault')
        st=FAULT.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_dev!=owned['device'] or st.st_ino!=owned['inode'] or st.st_uid!=owned['uid'] or st.st_uid!=os.geteuid() or hashlib.sha256(FAULT.read_bytes()).hexdigest()!=owned['sha256']:raise RuntimeError('Runtime fault ownership/content changed')
        FAULT.unlink()
    if owned:ownership.pop('runtime_fault');save(ledger,ownership)

def install(root):
    fault_absent()
    source=root/'source';paths=[SYSTEM/u for u in (UNIT,WORKER,TOPO,TIMER)]+[CONFIG,STATE,RUN,Path('/usr/libexec/uplinkstead-dual-worker.py'),Path('/usr/libexec/uplinkstead-dual-hook.py'),Path('/usr/libexec/uplinkstead-busybox'),SYSTEM/'multi-user.target.wants'/UNIT,SYSTEM/'timers.target.wants'/TIMER]
    assert all(not p.exists() and not p.is_symlink() for p in paths)
    ownership=dict(files=[],dirs=[],created_user=False,uid=None,state_inode=None)
    def own():save(root/'installation.json',ownership)
    def write(p,text,mode=0o644):
        with p.open('x') as file:ownership['files'].append(dict(path=str(p),inode=p.lstat().st_ino));own();file.write(text)
        p.chmod(mode)
    try:identity=pwd.getpwnam('uplinkstead')
    except KeyError:cmd(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','uplinkstead']);ownership['created_user']=True;identity=pwd.getpwnam('uplinkstead')
    ownership['uid']=identity.pw_uid;own();assert identity.pw_uid>0
    configure(root);c=read(root/'config.json');c.update(budget=8,window=600)
    c['runtime']=dict(queue_capacity=8,probe_interval=.15,restart_delay=.2,client_diagnostics=False,automatic_selection=True,selection_hold=.3,failover_delay=.8)
    if not CONFIG.parent.exists():CONFIG.parent.mkdir();ownership['dirs'].append(str(CONFIG.parent));own()
    write(CONFIG,json.dumps(c),0o600)
    for name in ('uplinkstead-dual-worker.py','uplinkstead-dual-hook.py'):write(Path('/usr/libexec')/name,(source/('uplinkstead/dual_dhcp_worker.py' if 'worker' in name else 'deploy/uplinkstead-dual-hook.py')).read_text(),0o644 if 'worker' in name else 0o755)
    p=Path('/usr/libexec/uplinkstead-busybox');p.symlink_to(root/'client/busybox-1.36.1/busybox');ownership['files'].append(dict(path=str(p),inode=p.lstat().st_ino));own()
    for u in (UNIT,WORKER):
        write(SYSTEM/u,(source/'deploy'/u).read_text());d=SYSTEM/(u+'.d');assert not d.exists();d.mkdir();ownership['dirs'].append(str(d));own();write(d/'fixture.conf','[Service]\nNetworkNamespacePath=/run/netns/dd_r\nEnvironment=PYTHONPATH='+str(source)+'\n')
    write(SYSTEM/TOPO,'[Unit]\nDescription=Isolated reboot topology, no product recovery\nWants=docker.service lima-guestagent.service\nAfter=network-online.target docker.service lima-guestagent.service\nBefore='+UNIT+'\n[Service]\nType=notify\nNotifyAccess=main\nExecStart=/usr/bin/python3 '+str(source/'tools/dhcp_boot_guest.py')+' --root '+str(root)+' topology\nEnvironment=PYTHONPATH='+str(source)+'\nTimeoutStartSec=40\nTimeoutStopSec=15\nKillMode=control-group\n')
    write(SYSTEM/(UNIT+'.d/boot.conf'),'[Unit]\nRequires='+TOPO+'\nAfter='+TOPO+'\n')
    write(SYSTEM/TIMER,'[Unit]\nDescription=Delayed isolated reboot fixture start, not a product boot gate\n[Timer]\nOnBootSec=25s\nAccuracySec=1ms\nRandomizedDelaySec=0\nUnit='+UNIT+'\n[Install]\nWantedBy=timers.target\n')
    link=SYSTEM/'timers.target.wants'/TIMER;link.symlink_to('../'+TIMER);ownership['files'].append(dict(path=str(link),inode=link.lstat().st_ino));own()
    save(root/'phase.json',dict(kind='initial'));save(root/'desired.json',dict(token='initial',servers=False,holes=[]))
    system('daemon-reload');system('reset-failed',UNIT,WORKER,TOPO,check=False);system('start',UNIT);r=ready();ownership['state_inode']=STATE.stat().st_ino;own()
    topology_command(root,True);selected();return dict(passed=True,ready=r,boot_trigger=dict(timer_text=(SYSTEM/TIMER).read_text(),timer_sha256=digest(SYSTEM/TIMER),enabled_target=os.readlink(SYSTEM/'timers.target.wants'/TIMER)),units={u:dict(source_sha256=digest(source/'deploy'/u),installed_sha256=digest(SYSTEM/u)) for u in (UNIT,WORKER)},client_build=read(root/'client/build.json'),client_binary_sha256=digest(root/'client/busybox-1.36.1/busybox'),worker_file_sha256=digest(Path('/usr/libexec/uplinkstead-dual-worker.py')))

def prepare(root,kind):
    assert kind in KINDS
    remove_fault(root)
    if (root/'desired.json').exists():topology_command(root,True)
    if kind=='paused':
        assert operation('pause')['ok'];observed(lambda s:s['state']['paused'])
    if kind=='latched':
        # Reach the real budget through genuine alternating blackholes, never edit journal.
        while not state()['state']['latched']:
            s=state();k=s['state']['active']['link'] if s['state']['active'] else None
            if k is None:observed(lambda s:s['state']['active'] is not None or s['state']['latched']);continue
            topology_command(root,True,(k,))
            observed(lambda s:s['state']['latched'] or (s['state']['active'] is not None and s['state']['active']['link']!=k))
        topology_command(root,True);assert operation('pause')['ok'];observed(lambda s:s['state']['paused'])
    pressure=None
    if kind=='capacity':
        system('stop',UNIT);system('stop',TOPO)
        mount=root/'storage-volume';mount.mkdir();image=root/'storage.img'
        with image.open('wb') as file:file.truncate(32*1024*1024)
        device=cmd(['losetup','--find','--show',str(image)]).stdout.strip();save(root/'storage-volume.json',dict(mount=str(mount),image=str(image),device=device))
        cmd(['mkfs.ext4','-q','-F','-m','0',device]);cmd(['mount','-t','ext4',device,str(mount)])
        directory=mount/'state';directory.mkdir(mode=0o700);shutil.copyfile(STATE/'journal.sqlite',directory/'journal.sqlite')
        # The topology service remounts the existing image at every later boot.
        cleanup_volume(root)
        p=SYSTEM/(UNIT+'.d/capacity.conf');ownership=read(root/'installation.json')
        with p.open('x') as file:
            ownership['files'].append(dict(path=str(p),inode=p.lstat().st_ino));save(root/'installation.json',ownership)
            unit=(root/'source/deploy'/UNIT).read_text();start=next(l.split('=',1)[1] for l in unit.splitlines() if l.startswith('ExecStart='));stop=next(l.split('=',1)[1] for l in unit.splitlines() if l.startswith('ExecStopPost='))
            file.write('[Service]\nExecStart=\nExecStart='+start.replace('--journal /var/lib/uplinkstead-dual','--journal '+str(directory))+'\nExecStopPost=\nExecStopPost='+stop.replace('--journal /var/lib/uplinkstead-dual','--journal '+str(directory))+'\nReadWritePaths='+str(root)+'\n')
        save(root/'phase.json',dict(kind='capacity'));save(root/'desired.json',dict(token='capacity',servers=False,holes=[]));system('daemon-reload');system('reset-failed',UNIT,WORKER,check=False);system('start',UNIT);ready();topology_command(root,True);selected()
        # Real fill happens after capturing old formal authority below.
    old=state();topology_command(root,False);time.sleep(.1)
    if kind=='preserved':
        system('kill','--kill-whom=all','--signal=SIGSTOP',UNIT)
        assert installed.process(int(installed.props(UNIT)['MainPID']))['state'].startswith('T')
    if kind=='capacity':
        count=0
        with (root/'storage-volume/filler').open('wb',buffering=0) as file:
            try:
                while True:count+=file.write(b'x'*4096)
            except OSError as exc:assert exc.errno==28
        pressure=dict(write_errno=28,filler_bytes=count,free_bytes=shutil.disk_usage(root/'storage-volume').free)
        p=cmd(['env','PYTHONPATH='+str(root/'source'),'python3','-m','uplinkstead.dual_dhcp_cli','--socket',str(RUN/'control.sock'),'pause'],check=False)
        assert p.returncode!=0;pressure.update(api=dict(exit_code=p.returncode,answer=json.loads(p.stdout)))
        wait(lambda:installed.props(UNIT)['ActiveState']=='failed',25);pressure['faults']=faults();assert pressure['faults']
    if kind in ('preserved','capacity'):
        install_fault(root);system('daemon-reload')
    before=dict(boot=boot_id(),state=old,journal=stored(journal_path(root)),writer=installed.props(UNIT),worker=installed.props(WORKER),net=net(),at=now(),pressure=pressure,shutdown_fault=cmd(['systemctl','show',UNIT,'--all','-p','KillSignal','-p','ExecStopPost','-p','DropInPaths']).stdout,shutdown_exec_stop_post=stop_commands())
    if kind=='preserved':assert before['journal']['active'] is not None
    save(root/'before.json',before);save(root/'phase.json',dict(kind=kind,before=before));save(root/'desired.json',dict(token='boot',servers=False,holes=[]))
    return before

def after(root):
    phase=read(root/'phase.json');kind=phase['kind'];before=phase['before'];began=now()
    pre=wait(lambda:(lambda p:p if p['boot']==boot_id() and 'initial_routes' in p else None)(read(root/'prestart.json')),35)
    assert boot_id()==pre['boot']!=before['boot'] and pre['writer']['MainPID']=='0' and not pre['runtime_fault_present']
    assert all(pre['journal'][k]==before['journal'][k] for k in ('config_hash','history','operations','paused','latched'))
    failure=None
    if kind=='capacity':
        wait(lambda:installed.props(UNIT)['ActiveState']=='failed',30);time.sleep(3);failed=installed.props(UNIT);time.sleep(3);stable=installed.props(UNIT)
        assert failed['ActiveState']==stable['ActiveState']=='failed' and failed['NRestarts']==stable['NRestarts'] and 1<=int(failed['NRestarts'])<=3 and installed.props(WORKER)['ActiveState']!='active'
        records=faults();assert records and all(r['message']['quarantined'] and not r['message']['durable'] and r['message']['lock_held'] for r in records)
        p=cmd(['env','PYTHONPATH='+str(root/'source'),'python3','-m','uplinkstead.dual_dhcp_cli','--socket',str(RUN/'control.sock'),'resume'],check=False);assert p.returncode!=0
        failure=dict(failed=failed,stable=stable,worker=installed.props(WORKER),faults=records,denied=dict(exit_code=p.returncode,answer=json.loads(p.stdout)),routes=net(),traffic=witness(root),journal=stored(journal_path(root)),free_bytes=shutil.disk_usage(root/'storage-volume').free)
        assert all(not rows for rows in net().values()) and failure['journal']==before['journal']
        (root/'storage-volume/filler').unlink();system('reset-failed',UNIT,WORKER,check=False);system('start',UNIT)
    r=ready();ready_at=now();r['boot_trigger']=dict(line.split('=',1) for line in cmd(['systemctl','show',TIMER,'-p','Unit','-p','LastTriggerUSecMonotonic','-p','ActiveState']).stdout.splitlines());r['timestamps']=cmd(['systemctl','show',UNIT,'-p','ExecMainStartTimestampMonotonic','-p','ActiveEnterTimestampMonotonic']).stdout;waiting=r['status'];s=waiting['state'];assert s['boot']==boot_id() and s['epoch']>before['state']['state']['epoch']
    assert s['active'] is None and all(v['current'] is None and v['state']=='WAITING' and v['good']==v['bad']==v['until']==0 and v['round']==-1 for v in s['links'].values())
    assert all(s[k]==before['journal'][k] for k in ('paused','latched','history','operations','config_hash'))
    for k in LINKS:assert s['links'][k]['session']!=before['state']['state']['links'][k]['session']
    assert r['writer']['InvocationID']!=before['writer']['InvocationID']
    routes=net();assert all(not row for row in routes.values());baseline=outside();traffic=witness(root);reject=stale(before['state'])
    # Admit new leases but blackhole probe traffic: old health must not select.
    topology_command(root,True,('A','B'));new=observed(lambda s:all(v['current'] for v in s['state']['links'].values()));time.sleep(.5);unhealthy=state();assert unhealthy['state']['active'] is None
    assert all(v['state']!='HEALTHY' for v in unhealthy['state']['links'].values());unhealthy_traffic=witness(root)
    topology_command(root,True);fresh=observed(lambda s:all(v['state']=='HEALTHY' for v in s['state']['links'].values()))
    fresh_at=now();authority(fresh,waiting,before['state'],boot_id(),fresh_at,all_links=True);intervention=[]
    if kind in ('paused','latched'):
        assert fresh['state']['active'] is None and fresh['state']['paused']==before['journal']['paused'] and fresh['state']['latched']==before['journal']['latched']
        blocked=witness(root)
        if kind=='latched':
            denied=operation('resume');assert denied['ok'] is False;intervention.append(dict(kind='resume_denied',reply=denied))
            reset=operation('reset-budget',ack='reset-switch-budget');assert reset['ok'];intervention.append(dict(kind='reset-budget',reply=reset))
        resume=operation('resume');assert resume['ok'];intervention.append(dict(kind='resume',reply=resume))
    else:blocked=None
    final=selected();final_at=now();authority(final,waiting,before['state'],boot_id(),final_at);charged(final,before['journal'],boot_id(),ready_at,final_at,reset=kind=='latched');response=client(root);assert response['ok'];late=stale(before['state']);assert outside()==baseline
    worker=installed.process(int(installed.props(WORKER)['MainPID']));writer=installed.process(int(installed.props(UNIT)['MainPID']));assert all(int(n,16)==0 for n in worker['caps'].values()) and worker['uid'][0]>0 and worker['no_new_privs']=='1'
    result=dict(passed=True,kind=kind,source_sha256=fingerprint(manifest()),boot=boot_id(),before=before,prestart=pre,ready=r,waiting=waiting,routes=routes,traffic=traffic,scope_before=baseline,scope_after=outside(),stale_before=reject,new_lease_unhealthy=unhealthy,new_lease_traffic=unhealthy_traffic,fresh=fresh,policy_blocked=blocked,intervention=intervention,final=final,client=response,stale_after=late,writer=writer,worker=worker,capacity=failure,case_seconds=now()-began,checkpoints=dict(prestart=pre['at'],ready_observed=ready_at,fresh_observed=fresh_at,final_observed=final_at,driver_completed=now()),wire_counters=Fixture(root,root/'source').counters(),power_loss_tested=False,boot_zero_gap_tested=False,previous_boot_cleanup=read(root/('topology-cleanup-'+before['boot']+'.json')))
    save(root/('after-'+kind+'.json'),result);return result

def cleanup(root):
    remove_fault(root);system('daemon-reload')
    system('stop',TIMER,UNIT,WORKER,TOPO,check=False)
    cleanup_volume(root);installed.cleanup_install(root);result=cleanup_owned(root)
    result.update(fixture_removed=not (SYSTEM/TOPO).exists(),enabled_link_removed=not (SYSTEM/'timers.target.wants'/TIMER).exists() and not (SYSTEM/TIMER).exists(),loop_detached=not cmd(['losetup','-j',str(root/'storage.img')]).stdout.strip(),volume_unmounted=cmd(['mountpoint','-q',str(root/'storage-volume')],check=False).returncode!=0)
    return result
if __name__=='__main__':
    if not __debug__:raise RuntimeError('Validation requires assertions')
    p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('operation',choices=('install','topology','prepare','after','cleanup'));p.add_argument('--kind',choices=KINDS);a=p.parse_args()
    answer=prepare(a.root,a.kind) if a.operation=='prepare' else globals()[a.operation](a.root)
    if answer is not None:print(json.dumps(answer,allow_nan=False))
