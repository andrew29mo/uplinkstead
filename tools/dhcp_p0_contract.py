"""Bounded evidence projections for the formal P0 VM runner."""
import re


def loss_diagnostics(text):
    pattern=r'uplinkstead_loss if=(wan[AB]) pid=(\d+) xid=(\d+) remaining=(-?\d+) attempts=(\d+)'
    return [dict(interface=m[0],pid=int(m[1]),xid=int(m[2]),remaining=int(m[3]),attempts=int(m[4])) for m in re.findall(pattern,text)]
