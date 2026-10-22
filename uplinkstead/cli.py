"""Local root operator CLI. Tokens must be copied from a prior status response."""
import argparse
import json
from pathlib import Path
from .control import request


def main():
    p=argparse.ArgumentParser();p.add_argument('--socket',type=Path,default=Path('/run/uplinkstead/control.sock'))
    p.add_argument('operation',choices=('status','pause','enable','disable','resume','select'))
    p.add_argument('--epoch',type=int);p.add_argument('--revision',type=int);p.add_argument('--target',choices=('A','B'));p.add_argument('--ack')
    a=p.parse_args();q=dict(op=a.operation)
    if a.operation!='status':
        if a.epoch is None or a.revision is None:p.error('Copy --epoch and --revision from status; no automatic retry')
        q.update(epoch=a.epoch,revision=a.revision)
    if a.operation in ('resume','select'):
        if a.target is None:p.error('--target required')
        q['target']=a.target
    if a.operation in ('enable','disable','resume'):
        if a.ack is None:p.error('--ack required')
        q['ack']=a.ack
    print(json.dumps(request(a.socket,q),indent=2,allow_nan=False))


if __name__=='__main__':main()
