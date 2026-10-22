"""External fault injector wrapping real method boundaries; never installed as an agent."""
import argparse
import os
from pathlib import Path
import signal
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from uplinkstead.config import load
from uplinkstead.writer import Writer

p=argparse.ArgumentParser();p.add_argument('mode');p.add_argument('config');p.add_argument('state');p.add_argument('target');p.add_argument('--epoch',type=int);a=p.parse_args()
if a.mode=='before-lock':os.kill(os.getpid(),signal.SIGSTOP)
with Writer(load(Path(a.config)),a.state) as w:
    if a.mode=='holding-lock':os.kill(os.getpid(),signal.SIGSTOP)
    if a.mode in ('before-route','after-route'):
        actual=w.backend.select
        def wrapped(target,**kw):
            if a.mode=='before-route':os.kill(os.getpid(),signal.SIGSTOP)
            actual(target,**kw)
            if a.mode=='after-route':os.kill(os.getpid(),signal.SIGSTOP)
        w.backend.select=wrapped
    if a.mode=='before-complete':
        actual_save=w.save
        def wrapped_save():
            if w.s['selected']==a.target and w.s['pending'] is None:
                os.kill(os.getpid(),signal.SIGSTOP)
            actual_save()
        w.save=wrapped_save
    if a.mode=='helper-held':
        import uplinkstead.linux as backend
        actual_popen=backend.subprocess.Popen
        def held_popen(argv,**kwargs):
            if 'replace' in argv:
                kwargs['preexec_fn']=lambda:os.kill(os.getpid(),signal.SIGSTOP)
            return actual_popen(argv,**kwargs)
        backend.subprocess.Popen=held_popen
    w.switch(a.epoch if a.epoch is not None else w.s['epoch'],a.target)
