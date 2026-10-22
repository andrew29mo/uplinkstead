"""Unprivileged policy client. Writer owns observations and independently admits proposals."""
import argparse
from pathlib import Path
import signal
import threading
from .control import request
from .linux import Blocked
from .policy import Policy,Settings
from .writer import now


def step(path,policy=None):
    sample=request(path,dict(op='sample'));s=sample['status']
    if policy is None or policy.boot!=s['boot'] or policy.hash!=s['config_hash']:
        policy=Policy(Settings(**s['policy']),s['config_hash'],s['boot'])
    policy.history=s['history'];policy.latched=s['latched']
    for k,p in sample['probes'].items():
        policy.observe(k,s['round'],p['started'],p['finished'],now(),p['successes'],s['config_hash'],s['boot'])
    target,_=policy.candidate(s['selected'],now())
    if target and s['mode']=='ENABLED':
        request(path,dict(op='automatic',epoch=s['epoch'],revision=s['revision'],round=s['round'],target=target))
    return policy


def main():
    p=argparse.ArgumentParser();p.add_argument('--socket',type=Path,required=True);a=p.parse_args();stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    policy=None
    while not stop.is_set():
        start=now()
        try:policy=step(a.socket,policy)
        except (Blocked,OSError):policy=None
        stop.wait(max(.2,1-(now()-start)))


if __name__=='__main__':main()
