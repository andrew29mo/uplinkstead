"""VM-only post-cgroup barrier; delegates to the production stop module by exec.

This allows a filesystem remount after writer file descriptors have closed, with
old kernel allocations still present. It implements no quarantine or admission.
"""
import json,os,sys,time
from pathlib import Path
root=Path(os.environ['UPLINKSTEAD_STORAGE_BARRIER'])
(root/'stop-ready.json').write_text(json.dumps(dict(pid=os.getpid(),at=time.monotonic())))
until=time.monotonic()+20
while not (root/'stop-release').exists():
    if time.monotonic()>=until:raise TimeoutError('Stop barrier release absent')
    time.sleep(.01)
os.execv(sys.executable,[sys.executable,'-m','uplinkstead.dual_dhcp_stop',*sys.argv[1:]])
