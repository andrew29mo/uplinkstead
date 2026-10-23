"""Bind observed forwarding evidence to this writer, boot, session and clock."""
import math
from tools.dhcp_stage1_report import require

def number(value):return type(value) in (int,float) and math.isfinite(value) and value>=0

def authority(snapshot,waiting,old,boot,observed_at,all_links=False):
    s=snapshot['state'];w=waiting['state'];prior=old['state']
    require(number(observed_at) and s['boot']==w['boot']==boot!=prior['boot'] and s['phase']=='READY' and s['epoch']==w['epoch']>prior['epoch'] and s['revision']>=w['revision'] and s['config_hash']==w['config_hash'],'Not this boot/writer authority')
    require(set(s['links'])==set(w['links'])==set(prior['links'])=={'A','B'},'Missing link authority')
    for k,row in s['links'].items():
        require(row['session']==w['links'][k]['session']!=prior['links'][k]['session'] and row['generation']>w['links'][k]['generation'] and row['generation']>prior['links'][k]['generation'],'Old lease session/generation')
        require(row['current'] is not None and number(row['last_event']) and row['last_event']<=observed_at and number(row['expires']) and row['expires']>observed_at,'Invalid/expired new lease')
    active=s['active']
    if active is not None:
        require(active['link'] in s['links'],'Unknown selected link');row=s['links'][active['link']]
        require(active['generation']==row['generation'] and active['value']==row['current'],'Selection uses another allocation')
    checked=('A','B') if all_links else (active['link'],) if active is not None else ()
    require(bool(checked),'Missing selected authority')
    for k in checked:
        row=s['links'][k]
        require(row['state'] in (('HEALTHY',) if all_links else ('HEALTHY','SUSPECT')) and type(row['round']) is int and row['round']>=0 and number(row['until']) and observed_at<row['until']<=row['expires'],'Missing unexpired health evidence')
        if all_links:require(type(row['good']) is int and row['good']>=2,'Missing fresh quorum')
    return True

def charged(final,before,boot,ready_at,final_at,reset=False):
    history=final['state']['history'];prior=[] if reset else before['history']
    require(history[:-1]==prior and len(history)==len(prior)+1,'New selection not charged/preserved')
    tail=history[-1]
    require(set(tail)=={'boot','at'} and tail['boot']==boot and number(tail['at']) and ready_at<=tail['at']<=final_at,'Switch charged to wrong boot/clock')
    return True
