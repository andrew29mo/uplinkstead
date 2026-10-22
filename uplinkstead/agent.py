import argparse
import json
from pathlib import Path
import time
from .config import load
from .policy import Policy, Settings
from .probe import round
from .writer import Writer, boot_id, now


def cycle(w, policy, rid):
    """Core exploration iteration; the deployed MVP uses worker/control RPC."""
    w.reconcile()
    before=w.s['selected']
    probes={}
    for link in ('A','B'):
        began=now()
        successes, rows=round(w.c,link)
        finished=now()
        policy.observe(link,rid,began,finished,finished,successes,w.c['_hash'],boot_id())
        probes[link]=dict(started=began,finished=finished,successes=successes,results=rows)
        w.event('probe',link=link,round=rid,**probes[link])
    decision_at=now()
    target,state=policy.candidate(w.s['selected'],decision_at)
    if policy.latched and not w.s['latched']:
        w.s['latched']=True
        w.save()
    proof=None
    if target:
        proof=policy.proof(target,now())
        admission=policy.admit(now())
        w.s['history']=policy.history[:-1]
        w.switch(w.s['epoch'],target,admission,proof)
    result=dict(state=state,selected=w.s['selected'],before=before,target=target,
                health={k:v.state for k,v in policy.links.items()},round=rid,
                probes=probes,decision_at=decision_at,boot=boot_id(),config_hash=w.c['_hash'],
                proof=proof,history=w.s['history'],latched=w.s['latched'])
    w.event('tick',**{k:v for k,v in result.items() if k!='boot'})
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--state',type=Path,required=True)
    p.add_argument('--once',action='store_true')
    a=p.parse_args()
    config=load(a.config)
    with Writer(config,a.state) as w:
        policy=Policy(Settings(**config['policy']),config['_hash'],boot_id(),w.s['history'],w.s['latched'])
        rid=0
        while True:
            start=now()
            print(json.dumps(cycle(w,policy,rid)),flush=True)
            if a.once:break
            rid+=1
            time.sleep(max(0,1-(now()-start)))


if __name__=='__main__':main()
