"""Bounded evidence projections for the formal P0 VM runner."""
import re


def loss_diagnostics(text):
    pattern=r'uplinkstead_loss if=(wan[AB]) pid=(\d+) xid=(\d+) remaining=(-?\d+) attempts=(\d+)'
    return [dict(interface=m[0],pid=int(m[1]),xid=int(m[2]),remaining=int(m[3]),attempts=int(m[4])) for m in re.findall(pattern,text)]


def timer_diagnostics(text):
    pattern=r'uplinkstead_timer if=(wan[AB]) pid=(\d+) event=(ack|bound|renew|rebind|expire|reject) xid=(\d+) origin=(\d+) t1=(\d+) t2=(\d+) expiry=(\d+) at=(\d+) attempts=(\d+)'
    keys=('pid','xid','origin','t1','t2','expiry','at','attempts')
    return [dict(interface=m[0],event=m[2],**dict(zip(keys,map(int,(m[1],*m[3:]))))) for m in re.findall(pattern,text)]
