"""Test transport only: invokes the core exploration cycle while retaining the real writer."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from uplinkstead.agent import cycle
from uplinkstead.config import load
from uplinkstead.policy import Policy,Settings
from uplinkstead.writer import Writer,boot_id

p=argparse.ArgumentParser();p.add_argument('config',type=Path);p.add_argument('state',type=Path);a=p.parse_args()
c=load(a.config)
with Writer(c,a.state) as w:
    policy=Policy(Settings(**c['policy']),c['_hash'],boot_id(),w.s['history'],w.s['latched'])
    print(json.dumps(dict(ready=True,epoch=w.s['epoch'],selected=w.s['selected'])),flush=True)
    for rid,line in enumerate(sys.stdin):
        if json.loads(line)!={'command':'tick'}:raise ValueError('Unsupported fixture command')
        print(json.dumps(cycle(w,policy,rid)),flush=True)
