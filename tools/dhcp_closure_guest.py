"""Clean wheel installation + bounded soak of shipped services in an isolated VM.

The fixture provides networks, servers and faults. Never calls product recovery.
"""
import argparse,hashlib,json,os,platform,shutil,sqlite3,subprocess,sys,threading,time,traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.dual_dhcp_fixture import Fixture,LINKS
from tools.dual_dhcp_guest import configure
from tools.dhcp_stage1_guest import wait,exchange
from tools.dhcp_systemd_guest import props,process,tree,alive,UNIT,WORKER,STATE,RUN,CONFIG
from tools.guest import cmd,ip,ns
from tools.dhcp_client_build import digest
from tools.dhcp_closure_report import fresh_pair
from tools.dhcp_automatic_report import chosen
from uplinkstead.writer import now


def group_process_count(directory):
    """Count cgroup membership without inspecting transient helper /proc data."""
    if not directory.is_dir():raise RuntimeError('Active service cgroup missing')
    pids=set()
    for path in directory.rglob('cgroup.procs'):
        try:values=path.read_text().split()
        except FileNotFoundError:continue
        for value in values:
            pid=int(value)
            if pid<=0:raise ValueError('Invalid cgroup member')
            pids.add(pid)
    if not directory.is_dir():raise RuntimeError('Active service cgroup disappeared')
    return len(pids)


def run(root):
    source=root/'source';v=dict(passed=False,source_sha256=json.loads((root/'manifest.json').read_text())['sha256'],environment=dict(os=platform.platform(),python=platform.python_version()),samples=[],cycles=[],operations=[])
    f=Fixture(root,source);halt=threading.Event();sampler=None;phase='setup';sample_errors=[]
    def persist(): (root/'guest.json').write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
    def system(*args,check=True):return cmd(['systemctl',*args],check=check)
    def state():return exchange(RUN/'private/events.sock',dict(op='status'))
    def observed(test,timeout=30):
        def check():
            try:s=state();return s if test(s) else None
            except (OSError,RuntimeError):return None
        return wait(check,timeout)
    def qualified(s,k=None,pair=False):
        try:
            chosen(s,k or s['state']['active']['link'])
            if pair:fresh_pair(s)
            return True
        except (ValueError,TypeError):return False
    def selected(k=None):return observed(lambda s:qualified(s,k))
    def healthy():return observed(lambda s:qualified(s,pair=True))
    def traffic(k=None):
        r=f.client()
        if not r['ok'] or (k and r['response']['peer']!='10.99.'+str(LINKS[k]['transit'])+'.1'):raise RuntimeError('Fresh LAN TLS failed/wrong uplink')
        return r
    def ctl(op,**extra):
        args=['/usr/bin/python3','-I','-m','uplinkstead.dual_dhcp_cli','--socket',str(RUN/'control.sock'),op,*sum(([k,str(x)] for k,x in extra.items()),[])]
        if op=='reset-budget':args.append('--ack-reset-budget')
        p=cmd(args,check=False);r=dict(operation=op,arguments=extra,exit_code=p.returncode,answer=json.loads(p.stdout));v['operations'].append(r);return r
    def okay(op,**extra):
        r=ctl(op,**extra)
        if r['exit_code'] or not r['answer']['ok']:raise RuntimeError('Operator command failed: '+op)
        return r
    def network():
        return dict(main=json.loads(ip('dd_r','-j','route','show','table','main').stdout),rules=json.loads(ip('dd_r','-j','rule').stdout))
    def samples():
        while not halt.is_set():
            try:
                s=state();pids={k:int(props(u)['MainPID']) for k,u in (('writer',UNIT),('worker',WORKER))};row=dict(at=now(),phase=phase,processes={},state={k:s['state'][k] for k in ('boot','epoch','history','latched','paused','active')},links={k:{q:r[q] for q in ('session','generation','event_sequence','last_event','expires','state','until','good')} for k,r in s['state']['links'].items()},queue=s['runtime']['queue'],recent_count=len(s['runtime']['recent']),selection_count=len(s['runtime']['selection_events']),errors=s['runtime']['last_errors'])
                pids.update({'client'+k:pid for k,pid in s['runtime']['children'].items()})
                for k,pid in pids.items():
                    p=process(pid);row['processes'][k]={q:p[q] for q in ('pid','start_ticks','rss_kib')};row['processes'][k].update(fd=len(list(Path('/proc',str(pid),'fd').iterdir())),threads=len(list(Path('/proc',str(pid),'task').iterdir())))
                row['cgroup_processes']=sum(group_process_count(Path('/sys/fs/cgroup'+props(u)['ControlGroup'])) for u in (UNIT,WORKER));row['disk_bytes']=sum(p.stat().st_size for p in STATE.iterdir() if p.is_file());row['db_bytes']=(STATE/'journal.sqlite').stat().st_size
                v['samples'].append(row)
            except BaseException as exc:sample_errors.append(traceback.format_exc())
            halt.wait(2)
    try:
        if Path('/etc/systemd/system/'+UNIT).exists() or STATE.exists() or RUN.exists():raise RuntimeError('Not a clean installation')
        clean=cmd(['/usr/bin/python3','-I','-c','import importlib.util; assert importlib.util.find_spec("uplinkstead") is None; print("absent")'])
        v['initial_package']=clean.stdout.strip();v['initial_account_absent']=cmd(['getent','passwd','uplinkstead'],check=False).returncode!=0
        if not v['initial_account_absent']:raise RuntimeError('Existing account')
        f.setup(start_servers=False);configure(root)
        # A distinct, fixture-only main path remains viable after DHCP withdrawal.
        cmd(['ip','link','add','name','bypass0','netns','dd_r','type','veth','peer','name','bypass','netns','dd_b'])
        for n,d,a in (('dd_r','bypass0','198.18.0.2/30'),('dd_b','bypass','198.18.0.1/30')):
            ip(n,'addr','add',a,'dev',d);ip(n,'link','set',d,'up');ns(n,['sysctl','-qw','net.ipv4.conf.'+d+'.rp_filter=0'])
        ip('dd_r','route','replace','default','via','198.18.0.1','dev','bypass0')
        f.server('A',duration='2m',extra=['--dhcp-option-force=58,20i','--dhcp-option-force=59,90i'])
        # Controlled B server enables repeated natural 15s renewals without signals.
        profile=root/'b-profile.json';profile.write_text(json.dumps(dict(reply=True,lease=120,**{'58':15,'59':90})))
        f.spawn('dd_b',['python3',str(source/'tools/dhcp_timer_server.py'),'--interface','edge','--profile',str(profile),'--log',str(root/'b-server.jsonl')],'B-server');wait(lambda:profile.with_suffix('.ready').exists(),10)
        c=json.loads((root/'config.json').read_text());c.update(success_rounds=2,failure_rounds=3,freshness=5,budget=32,window=3600)
        c['runtime']=dict(queue_capacity=8,probe_interval=.3,restart_delay=.3,client_diagnostics=False,automatic_selection=True,selection_hold=.3,failover_delay=.8)
        (root/'config.json').write_text(json.dumps(c))
        for u in (UNIT,WORKER):
            d=Path('/etc/systemd/system')/(u+'.d');d.mkdir();(d/'isolation.conf').write_text('[Service]\nNetworkNamespacePath=/run/netns/dd_r\n')
        text=(source/'docs/DHCP_INSTALL.md').read_text();recipe=text.split('```sh\n',1)[1].split('```',1)[0]
        script=root/'documented-install.sh';script.write_text(recipe)
        with (root/'install-private.log').open('w') as log:
            subprocess.run(['bash','-eu',str(script)],env=dict(os.environ,WHEEL=str(next(root.glob('*.whl'))),CLIENT=str(root/'client/busybox-1.36.1/busybox'),SOURCE=str(source),CONFIG=str(root/'config.json')),stdout=log,stderr=log,check=True,timeout=90)
        expected=json.loads((root/'manifest.json').read_text())['files']
        v['installation']=dict(recipe_sha256=digest(script),documentation_sha256=digest(source/'docs/DHCP_INSTALL.md'),wheel_sha256=digest(next(root.glob('*.whl'))),units={u:dict(source=expected['deploy/'+u],installed=digest(Path('/etc/systemd/system')/u)) for u in (UNIT,WORKER)},client=json.loads((root/'client/build.json').read_text()),client_installed=digest('/usr/libexec/uplinkstead-busybox'),hook_installed=digest('/usr/libexec/uplinkstead-dual-hook.py'),worker_installed=digest('/usr/libexec/uplinkstead-dual-worker.py'))
        # Stronger than an import-path assertion: product source absent for all services.
        (source/'uplinkstead').rename(root/'retired-product-source')
        code='import uplinkstead,hashlib,json,pathlib; p=pathlib.Path(uplinkstead.__file__).parent; print(json.dumps(dict(location=str(p),files={"uplinkstead/"+str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() for f in p.rglob("*.py")})))'
        v['installation']['package']=json.loads(subprocess.run(['/usr/bin/python3','-I','-c',code],cwd='/',check=True,capture_output=True,text=True,timeout=10).stdout)
        v['installation']['source_package_absent']=not (source/'uplinkstead').exists()
        for k,h in v['installation']['package']['files'].items():
            if expected.get(k)!=h:raise RuntimeError('Installed module differs from release')
        v['installation']['namespace_only_dropins']={u:(Path('/etc/systemd/system')/(u+'.d/isolation.conf')).read_text() for u in (UNIT,WORKER)}
        system('enable','--now',UNIT)
        observed(lambda s:s['state']['phase']=='READY');healthy();initial=selected();traffic()
        v['initial']=initial;v['writer']=process(int(props(UNIT)['MainPID']));v['worker']=process(int(props(WORKER)['MainPID']));v['service']=props(UNIT)
        v['service_environment']=cmd(['systemctl','show',UNIT,'-p','Environment','-p','WorkingDirectory','-p','ExecStart']).stdout
        if 'PYTHONPATH' in v['service_environment']:raise RuntimeError('Service depends on checkout')
        phase='baseline';sampler=threading.Thread(target=samples,daemon=True);sampler.start();time.sleep(40)
        baseline=state();v['baseline']=baseline;v['scope_before']=network()
        # Six complete fault/recovery cycles; no systemd restart or budget reset.
        for i in range(6):
            phase='cycle-'+str(i+1)+'-steady';before=selected();healthy();time.sleep(15);before=selected();history=before['state']['history'];k=before['state']['active']['link'];other='B' if k=='A' else 'A'
            phase='cycle-'+str(i+1)+'-fault';began=now();f.fault(k,True);after=selected(other);response=traffic(other)
            if len(after['state']['history'])!=len(history)+1:raise RuntimeError('Failover not charged once')
            f.fault(k,False);healthy();phase='cycle-'+str(i+1)+'-recovered';time.sleep(15);end=selected(other);healthy();end=selected(other)
            if end['state']['history']!=after['state']['history'] or end['state']['latched']:raise RuntimeError('Renewal consumed budget/preempted/latch')
            v['cycles'].append(dict(index=i+1,fault_link=k,started_at=began,selected_at=now(),before=before,after=after,settled=end,client=response));persist()
        phase='tail';time.sleep(300);v['soak_final']=healthy();v['scope_after']=network()
        halt.set();sampler.join(5);v['sample_errors']=sample_errors
        if sampler.is_alive() or sample_errors:raise RuntimeError('Resource sampler failed')
        if v['scope_after']!=v['scope_before']:raise RuntimeError('Main/RPDB scope changed')
        for k in LINKS:
            if v['soak_final']['state']['links'][k]['event_sequence']-baseline['state']['links'][k]['event_sequence']<10:raise RuntimeError('Insufficient natural lease events')
        # Actual documented operator CLI and formal stop/start after the soak.
        okay('status');okay('pause');old=state();paused=state();okay('reset-budget');reset=state()
        stale=ctl('resume',**{'--epoch':old['state']['epoch'],'--revision':old['state']['revision']})
        if stale['exit_code']==0 or stale['answer']['ok']:raise RuntimeError('Old operation accepted')
        okay('resume');selected();old=state();groups=[Path('/sys/fs/cgroup'+props(u)['ControlGroup']) for u in (UNIT,WORKER)];old_tree=[process(int(props(u)['MainPID'])) for u in (UNIT,WORKER)]+[process(pid) for pid in old['runtime']['children'].values()];system('stop',UNIT)
        cgroups_empty=all(not path.exists() or group_process_count(path)==0 for path in groups)
        if not cgroups_empty:raise RuntimeError('Stopped service cgroup retained processes')
        with sqlite3.connect(STATE/'journal.sqlite') as db:stopped=json.loads(db.execute('select value from state where id=1').fetchone()[0])
        blocked=f.client();fallback=f.client('dd_r',source='198.18.0.2')
        if RUN.exists() or any(alive(p) for p in old_tree) or stopped['active'] is not None or any(r['current'] for r in stopped['links'].values()) or blocked['ok'] or not fallback['ok']:raise RuntimeError('Stop lifecycle failed')
        system('start',UNIT);new=healthy();new_traffic=traffic(new['state']['active']['link'])
        if new['state']['epoch']<=old['state']['epoch'] or any(new['state']['links'][k]['session']==old['state']['links'][k]['session'] for k in LINKS):raise RuntimeError('Restart reused authority')
        rejected={}
        for dimension in ('epoch','revision'):
            before=selected();request=dict(epoch=old['state']['epoch'] if dimension=='epoch' else before['state']['epoch'],revision=before['state']['revision'] if dimension=='epoch' else old['state']['revision'])
            reply=ctl('pause',**{'--epoch':request['epoch'],'--revision':request['revision']});after=selected()
            rejected['stale_'+dimension]=dict(request=request,before=before,reply=reply,after=after)
        v['handoff']=dict(paused=paused,reset=reset,stopped=stopped,blocked=blocked,fallback=fallback,new=new,traffic=new_traffic,old=old,old_processes_gone=True,cgroups_empty=cgroups_empty,**rejected)
        v['wire_counters']=f.counters();v['passed']=True
    except BaseException as exc:
        v['error']=type(exc).__name__+': '+str(exc);raise
    finally:
        halt.set()
        if sampler:sampler.join(5)
        try:
            system('disable','--now',UNIT,check=False)
            if int(props(UNIT)['MainPID']) or int(props(WORKER)['MainPID']):raise RuntimeError('Services retained')
            v['cleanup']=f.cleanup();v['cleanup']['services_stopped']=True
        except BaseException as exc:v.update(passed=False,cleanup_error=type(exc).__name__+': '+str(exc));raise
        finally:persist()
    return v

if __name__=='__main__':
    if not __debug__:raise RuntimeError('Guest requires assertions')
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);a=p.parse_args();print(json.dumps(run(a.root)))
