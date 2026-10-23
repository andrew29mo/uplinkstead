"""Post-cgroup-stop quarantine using the same exclusive production recovery core.

Failure is a failed service stop, never a successful forwarding/safety receipt.
No journal reset, client spawn, operator budget reset or foreign-route cleanup.
"""
import argparse,json
from pathlib import Path
from .dual_dhcp import DualLifecycle
from .dual_dhcp_linux import Backend

def quarantine(config,journal,backend=Backend):
    with DualLifecycle(config,journal,backend) as writer:
        s=writer.snapshot()
        if s['active'] is not None or any(r['current'] is not None for r in s['links'].values()):
            raise RuntimeError('Stop quarantine incomplete')
        return dict(epoch=s['epoch'],revision=s['revision'],paused=s['paused'],latched=s['latched'],quarantined=True)

def main():
    p=argparse.ArgumentParser();p.add_argument('--config',required=True,type=Path);p.add_argument('--journal',required=True,type=Path);a=p.parse_args()
    print(json.dumps(quarantine(json.loads(a.config.read_text()),a.journal),allow_nan=False))
if __name__=='__main__':main()
