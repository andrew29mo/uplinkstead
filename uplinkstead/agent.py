import argparse
import json
from pathlib import Path
import time
from .config import load
from .policy import Policy, Settings
from .probe import round
from .writer import Writer, boot_id, now


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--once', action='store_true')
    a = p.parse_args()
    config = load(a.config)
    with Writer(config, a.state) as w:
        policy = Policy(Settings(**config['policy']), config['_hash'], boot_id(), w.s['history'], w.s['latched'])
        rid = 0
        while True:
            start = now()
            w.reconcile()
            for link in ('A','B'):
                began = now()
                successes, rows = round(config, link)
                finished = now()
                policy.observe(link, rid, began, finished, finished, successes, config['_hash'], boot_id())
                w.event('probe', link=link, round=rid, successes=successes, results=rows)
            target, state = policy.candidate(w.s['selected'], now())
            if policy.latched and not w.s['latched']:
                w.s['latched'] = True
                w.save()
            if target:
                admission = policy.admit(now())
                w.switch(w.s['epoch'], target, admission)
            w.event('tick', state=state, selected=w.s['selected'], health={k:v.state for k,v in policy.links.items()})
            print(json.dumps(dict(state=state, selected=w.s['selected'])), flush=True)
            if a.once:
                break
            rid += 1
            time.sleep(max(0, 1-(now()-start)))


if __name__ == '__main__':
    main()
