"""Strict finite IPv4 lease timer policy shared by wire admission and reports."""
def timer_values(lease, renewal=None, rebinding=None):
    if type(lease) is not int or not 1<=lease<=86400:raise ValueError('Unsupported finite lease')
    for value in (renewal,rebinding):
        if value is not None and (type(value) is not int or not 0<=value<=0xffffffff):raise ValueError('Invalid timer option')
    duration=lease*1_000_000_000
    t1=duration//2 if renewal is None else renewal*1_000_000_000
    t2=duration*7//8 if rebinding is None else rebinding*1_000_000_000
    if not 0<t1<t2<duration:raise ValueError('Require 0 < T1 < T2 < lease')
    return t1,t2
