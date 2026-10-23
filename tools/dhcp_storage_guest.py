"""Real ext4 ENOSPC/EROFS and SQLite FULL against installed dual-DHCP units.

Only path/resource/restart fault-fixture drop-ins; admission, storage retirement,
quarantine and repair are the production service/core/backend. No VM reboot.
"""
import argparse,errno,json,os,shutil,signal,sqlite3,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import dhcp_systemd_guest as installed
from tools.guest import cmd,ns,ip
from tools.dhcp_stage1_guest import wait,rss
from tools.dhcp_client_build import digest
UNIT=installed.UNIT;WORKER=installed.WORKER;CONFIG=installed.CONFIG;RUN=installed.RUN

def cleanup_volume(root):
    ledger=root/'storage-volume.json'
    if not ledger.exists():return
    r=json.loads(ledger.read_text());mount=root/'storage-volume';image=root/'storage.img'
    if r['mount']!=str(mount) or r['image']!=str(image):raise RuntimeError('Foreign storage cleanup target')
    if cmd(['mountpoint','-q',str(mount)],check=False).returncode==0:
        actual=json.loads(cmd(['findmnt','--json','--mountpoint',str(mount)]).stdout)['filesystems'][0]
        if actual['source']!=r['device']:raise RuntimeError('Storage mount replaced')
        cmd(['umount',str(mount)])
    linked=cmd(['losetup','-j',str(image)]).stdout
    if linked:
        if not linked.startswith(r['device']+':'):raise RuntimeError('Loop ownership changed')
        cmd(['losetup','-d',r['device']])
    ledger.unlink()


def storage_tests(ctx):
    root,source,f=ctx['root'],ctx['source'],ctx['fixture'];system,state,selected=ctx['system'],ctx['state'],ctx['selected']
    servers,ready,stale,net=ctx['servers'],ctx['ready'],ctx['stale'],ctx['net']
    out=dict(passed=False,cases=[]);original_config=CONFIG.read_text();mount=root/'storage-volume';image=root/'storage.img'
    drop=Path('/etc/systemd/system')/(UNIT+'.d/storage.conf');holder=None
    def persist():(root/'storage-guest.json').write_text(json.dumps(out,indent=2,allow_nan=False))
    def journal():return json.loads(cmd(['journalctl','-b','-u',UNIT,'-n','1','--no-pager','-o','json']).stdout)
    def fault_records(before):
        messages=cmd(['journalctl','-b','-u',UNIT,'--after-cursor='+before['__CURSOR'],'--no-pager','-o','json']).stdout;found=[]
        for line in messages.splitlines():
            record=json.loads(line)
            try:value=json.loads(record.get('MESSAGE',''))
            except ValueError:continue
            if isinstance(value,dict) and value.get('event')=='storage_failure':
                found.append(dict(at=record['__MONOTONIC_TIMESTAMP'],boot=record['_BOOT_ID'],cursor=record['__CURSOR'],receipt=value))
        return found
    def witness():
        blocked=f.client();fallback=f.client('dd_r',source='198.18.0.2')
        assert not blocked['ok'] and fallback['ok'] and fallback['response']['peer']=='10.99.2.1'
        return dict(blocked=blocked,fallback=fallback)
    def outside():
        return dict(main=json.loads(ip('dd_r','-j','route','show','table','main').stdout),rules=json.loads(ip('dd_r','-j','rule','show').stdout),foreign=json.loads(ip('dd_r','-j','route','show','table','49999').stdout))
    def stored(path):
        db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)
        try:return json.loads(db.execute('select value from state where id=1').fetchone()[0])
        finally:db.close()
    def cli(kind,s=None):
        args=['env','PYTHONPATH='+str(source),'python3','-m','uplinkstead.dual_dhcp_cli','--socket',str(RUN/'control.sock'),kind]
        if s:args+=['--epoch',str(s['state']['epoch']),'--revision',str(s['state']['revision'])]
        p=cmd(args,check=False)
        return dict(exit_code=p.returncode,answer=json.loads(p.stdout) if p.stdout.strip() else None)
    def poststop(path):
        p=ns('dd_r',['env','PYTHONPATH='+str(source),'python3','-m','uplinkstead.dual_dhcp_stop','--config',str(CONFIG),'--journal',str(path)],check=False)
        receipts=[]
        for line in p.stderr.splitlines():
            try:r=json.loads(line)
            except ValueError:continue
            if isinstance(r,dict) and r.get('event')=='storage_failure':receipts.append(r)
        return dict(exit_code=p.returncode,receipts=receipts,lock_blocked='BlockingIOError' in p.stderr)
    def fill():
        count=0;observed=None
        with (mount/'filler').open('wb',buffering=0) as file:
            try:
                while True:count+=file.write(b'x'*4096)
            except OSError as exc:observed=exc.errno
        try:
            with (mount/'enospc-probe').open('wb',buffering=0) as file:file.write(b'x'*4096)
        except OSError as exc:probe=exc.errno
        else:raise RuntimeError('ENOSPC not observed')
        free=os.statvfs(mount).f_bavail*os.statvfs(mount).f_frsize
        assert observed==errno.ENOSPC and probe==errno.ENOSPC and free<4096
        return dict(filler_bytes=count,write_errno=observed,probe_errno=probe,free_bytes=free)
    def configure(kind,barrier=False):
        directory=mount/kind;directory.mkdir(mode=0o700)
        c=json.loads(original_config);c['storage']=dict(max_pages=2 if kind=='sqlite_full' else 2048);CONFIG.write_text(json.dumps(c))
        unit=(source/'deploy'/UNIT).read_text();start=next(l.split('=',1)[1] for l in unit.splitlines() if l.startswith('ExecStart='));stop=next(l.split('=',1)[1] for l in unit.splitlines() if l.startswith('ExecStopPost='))
        start=start.replace('--journal /var/lib/uplinkstead-dual','--journal '+str(directory));stop=stop.replace('--journal /var/lib/uplinkstead-dual','--journal '+str(directory))
        if barrier:stop=stop.replace('-m uplinkstead.dual_dhcp_stop',str(source/'tools/dhcp_storage_stop_barrier.py'))
        value='[Service]\nExecStart=\nExecStart='+start+'\nExecStopPost=\nExecStopPost='+stop+'\nReadWritePaths='+str(root)+'\nRestart=no\nEnvironment=UPLINKSTEAD_STORAGE_BARRIER='+str(root)+'\n'
        if not drop.exists():ctx['write'](drop,value)
        else:drop.write_text(value)
        system('daemon-reload');system('reset-failed',UNIT,WORKER,check=False);servers(True);system('start',UNIT);ready();s=selected()
        return directory,s
    def repair(path,old,before):
        c=json.loads(CONFIG.read_text());c['storage']['max_pages']=2048;CONFIG.write_text(json.dumps(c))
        system('reset-failed',UNIT,WORKER,check=False);system('start',UNIT);r=ready();installed_status=r['status'];assert installed_status['state']['active'] is None
        assert all(v['current'] is None and v['state']=='WAITING' and v['good']==v['bad']==v['until']==0 and v['round']==-1 for v in installed_status['state']['links'].values())
        assert installed_status['state']['config_hash']==before['config_hash'] and installed_status['state']['history']==before['history'] and installed_status['state']['operations']==before['operations']
        assert all(installed_status['state'][k]==before[k] for k in ('paused','latched'))
        rejected=stale(old);servers(True)
        fresh=ctx['observed'](lambda s:all(v['state']=='HEALTHY' for v in s['state']['links'].values()))
        assert all(fresh['state'][k]==before[k] for k in ('paused','latched'))
        resume=cli('resume') if fresh['state']['paused'] else None
        if resume:assert resume['exit_code']==0
        after=selected();again=stale(old);client=f.client();assert client['ok']
        assert after['state']['history'][:-1]==before['history'] and after['state']['epoch']>old['state']['epoch']
        return dict(ready=r,stale_before=rejected,stale_after=again,fresh=fresh,resume=resume,after=after,client=client,rss_kib=dict(writer=rss(int(installed.props(UNIT)['MainPID'])),worker=rss(int(installed.props(WORKER)['MainPID']))))
    try:
        system('stop',UNIT,WORKER);mount.mkdir(mode=0o700)
        with image.open('wb') as file:file.truncate(32*1024*1024)
        device=cmd(['losetup','--find','--show',str(image)]).stdout.strip()
        (root/'storage-volume.json').write_text(json.dumps(dict(mount=str(mount),image=str(image),device=device)))
        cmd(['mkfs.ext4','-q','-F','-m','0',device]);cmd(['mount','-t','ext4',device,str(mount)])
        ip('dd_r','route','add','blackhole','198.19.250.0/24','table','49999')
        out['volume']=dict(bytes=32*1024*1024,filesystem='ext4',root_reserve_percent=0)
        for kind in ('enospc','sqlite_full'):
            began=time.monotonic();directory,old=configure(kind);path=directory/'journal.sqlite';servers(False);baseline=outside();cursor=journal();triggered_at=time.monotonic();pressure=fill() if kind=='enospc' else dict(max_pages=2)
            attempts=[];before=stored(path)
            for _ in range(40 if kind=='sqlite_full' else 1):
                before=stored(path);answer=cli('pause',state());attempts.append(answer)
                if answer['exit_code']!=0:break
                revision=answer['answer']['status']['revision'];ctx['observed'](lambda s:s['state']['revision']>=revision)
            else:
                if kind=='sqlite_full':raise RuntimeError('No SQLite FULL within bounded receipt growth')
            assert attempts[-1]['exit_code']!=0 and attempts[-1]['answer']['ok'] is False
            wait(lambda:installed.props(UNIT)['ActiveState']=='failed',25);failed=installed.props(UNIT)
            routes=net();after_fault=stored(path)
            assert all(not r for r in routes.values()) and outside()==baseline
            assert all(after_fault[k]==before[k] for k in ('history','operations','paused','latched','config_hash'))
            if kind=='enospc':assert after_fault==before
            elif after_fault!=before:assert after_fault['active'] is None and all(r['current'] is None for r in after_fault['links'].values()) and after_fault['epoch']>before['epoch']
            after_fault=stored(path);scope_after=outside()
            proofs=fault_records(cursor);expected='reserve' if kind=='enospc' else 'sqlite_full'
            assert any(r['receipt']['kind']==expected and r['receipt']['quarantined'] is True and r['receipt']['durable'] is False and r['receipt']['lock_held'] is True for r in proofs)
            denied=cli('resume');assert denied['exit_code']!=0;traffic=witness()
            retired_at=time.monotonic()
            if kind=='enospc':(mount/'filler').unlink();(mount/'enospc-probe').unlink(missing_ok=True)
            recovered=repair(directory,old,before)
            out['cases'].append(dict(name=kind,passed=True,seconds=time.monotonic()-began,triggered_at=triggered_at,retired_at=retired_at,pressure=pressure,old=old,before=before,after_fault=after_fault,scope_before=baseline,scope_after=scope_after,fault_records=proofs,cursor={k:cursor[k] for k in ('__CURSOR','__MONOTONIC_TIMESTAMP','_BOOT_ID')},failed=failed,attempts=attempts,denied_after_fault=denied,routes=routes,scope_preserved=True,traffic=traffic,recovered=recovered));persist()
            system('stop',UNIT,WORKER)
        # Read-only after old writer/cgroup exit but before production post-stop
        # cleanup. Remount needs all writer RW file descriptors closed first.
        began=time.monotonic();directory,old=configure('readonly',barrier=True);path=directory/'journal.sqlite';servers(False);before=stored(path);baseline=outside();cursor=journal();triggered_at=time.monotonic()
        os.kill(int(installed.props(UNIT)['MainPID']),signal.SIGKILL);wait(lambda:(root/'stop-ready.json').exists(),10)
        cmd(['mount','-o','remount,ro',str(mount)])
        try:(mount/'readonly-probe').write_text('must fail')
        except OSError as exc:ro_errno=exc.errno
        else:raise RuntimeError('Readonly mount accepted a write')
        assert ro_errno==errno.EROFS
        lockcode="import fcntl,os,time;from pathlib import Path;p=Path("+repr(str(root))+");fd=os.open("+repr(str(directory/'writer.lock'))+",os.O_RDONLY);fcntl.flock(fd,fcntl.LOCK_EX);(p/'lock-ready').touch();until=time.monotonic()+10\nwhile not (p/'lock-release').exists():\n if time.monotonic()>=until:raise TimeoutError('Lock fixture release absent')\n time.sleep(.01)"
        holder=f.spawn('dd_r',['python3','-c',lockcode],'storage-lock');wait(lambda:(root/'lock-ready').exists(),3)
        locked_before=net();lock_denial=poststop(directory);locked_after=net();assert lock_denial['exit_code']!=0 and lock_denial['lock_blocked'] and not lock_denial['receipts'] and locked_after==locked_before
        (root/'lock-release').touch();holder.wait(timeout=3);holder=None
        ip('dd_r','route','add','blackhole','198.19.7.0/24','table','41202');foreign_before=net();scope_denial=poststop(directory);foreign_after=net()
        assert scope_denial['exit_code']!=0 and any(r['quarantined'] is False and r['lock_held'] is True for r in scope_denial['receipts']) and foreign_after==foreign_before
        ip('dd_r','route','del','blackhole','198.19.7.0/24','table','41202')
        (root/'stop-release').touch();wait(lambda:installed.props(UNIT)['ActiveState']=='failed',25)
        routes=net();assert all(not r for r in routes.values()) and outside()==baseline and stored(path)==before
        after_fault=stored(path);scope_after=outside()
        proofs=fault_records(cursor);assert any(r['receipt']['kind']=='sqlite_readonly' and r['receipt']['quarantined'] is True and r['receipt']['lock_held'] is True and r['receipt']['durable'] is False for r in proofs)
        denied=cli('resume');assert denied['exit_code']!=0;traffic=witness();retired_at=time.monotonic()
        cmd(['mount','-o','remount,rw',str(mount)]);recovered=repair(directory,old,before)
        out['cases'].append(dict(name='readonly',passed=True,seconds=time.monotonic()-began,triggered_at=triggered_at,retired_at=retired_at,write_errno=ro_errno,old=old,before=before,after_fault=after_fault,scope_before=baseline,scope_after=scope_after,cursor={k:cursor[k] for k in ('__CURSOR','__MONOTONIC_TIMESTAMP','_BOOT_ID')},fault_records=proofs,routes=routes,denied_after_fault=denied,scope_preserved=True,lock_denial=lock_denial,locked_before=locked_before,locked_after=locked_after,lock_preserved_routes=True,scope_denial=scope_denial,foreign_before=foreign_before,foreign_after=foreign_after,foreign_preserved=True,traffic=traffic,recovered=recovered));persist()
        out['passed']=True
    finally:
        (root/'stop-release').touch();(root/'lock-release').touch()
        if holder:f.stop(holder)
        system('stop',UNIT,WORKER,check=False)
        if drop.exists():drop.unlink()
        CONFIG.write_text(original_config);system('daemon-reload');cleanup_volume(root)
        out['volume_unmounted']=cmd(['mountpoint','-q',str(mount)],check=False).returncode!=0
        out['loop_detached']=not cmd(['losetup','-j',str(image)]).stdout.strip();persist()
    return out

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('--cleanup',action='store_true');a=p.parse_args()
    if a.cleanup:
        # The ordinary installer cleanup stops services before any state removal;
        # unmount this owned volume before the outer runner removes the snapshot.
        cmd(['systemctl','stop',UNIT,WORKER],check=False);cleanup_volume(a.root);installed.cleanup_install(a.root)
        from tools.dual_dhcp_fixture import cleanup_owned
        for child in (a.root/'control-regression/automatic-regression',a.root/'control-regression'):
            if child.exists():cleanup_owned(child)
        print(json.dumps(cleanup_owned(a.root)))
    else:print(json.dumps(installed.run(a.root,Path(__file__).resolve().parents[1],extension=storage_tests),allow_nan=False))
