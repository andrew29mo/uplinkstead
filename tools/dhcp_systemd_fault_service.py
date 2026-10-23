"""VM-only bounded ip-exec delay. All recovery/admission remains production code.

Linux.run still creates the real helper with its inherited writer lock. The shim
stops before exec(ip), allowing systemd cgroup cleanup and lock takeover to be
observed. It does not replace backend results, lease/health checks or fencing.
"""
import json,os,subprocess,sys
from pathlib import Path
from uplinkstead import dual_dhcp_service as service
root=Path(sys.argv[sys.argv.index('--config')+1]).resolve().parent
# The fixture explicitly supplies its own private barrier directory.
barrier=Path(os.environ['UPLINKSTEAD_TEST_BARRIER'])
original=subprocess.Popen

def delayed(argv,*a,**kw):
    arm=barrier/'helper-arm'
    if list(map(str,argv[:4]))==['/usr/sbin/ip','route','replace','default'] and '41203' in list(map(str,argv)) and arm.exists():
        arm.unlink()
        code="""import json,os,signal,sys,time
from pathlib import Path
p=Path(sys.argv[1]);fds=[int(v) for v in sys.argv[2].split(',') if v]
signal.signal(signal.SIGTERM,signal.SIG_IGN)
(p/'helper-ready.json').write_text(json.dumps(dict(pid=os.getpid(),at=time.monotonic(),lock_fds=fds)))
os.kill(os.getpid(),signal.SIGSTOP)
until=time.monotonic()+8
while not (p/'helper-release').exists():
 if time.monotonic()>=until:raise TimeoutError('Fault helper release absent')
 time.sleep(.01)
(p/'helper-executed').write_text(str(time.monotonic()))
os.execv('/usr/sbin/ip',['/usr/sbin/ip']+sys.argv[3:])
"""
        argv=[sys.executable,'-c',code,str(barrier),','.join(map(str,kw.get('pass_fds',()))),*map(str,argv[1:])]
    return original(argv,*a,**kw)
subprocess.Popen=delayed
if __name__=='__main__':service.main()
