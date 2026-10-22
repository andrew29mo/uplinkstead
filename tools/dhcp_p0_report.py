"""Cross-check P0 formal-service evidence without assertions (also under -O)."""
import copy
import json
import math
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require,identity,render as base_render
from tools.dhcp_client_build import TARBALL_SHA256

CASES={'real_acquisition_and_B_crash_isolation','two_natural_T1_rounds_both_links',
       'old_ACK_during_new_request_and_natural_rebinding','B_lease_loss_and_changed_address_reacquisition',
       'old_ACK_cannot_overwrite_reacquired_address'}


def stable(k,before,after):
    require(before['state']['links'][k]['session']==after['state']['links'][k]['session'] and before['runtime']['children'][k]==after['runtime']['children'][k],'Unrelated client authority changed')


def verify(v):
    require(v['passed'] is True and v['source_changed'] is False and v['source_sha256']==fingerprint(v['source']),'Source/failed run')
    expected={'native','initial','start','preflight','upload','build','linux','linux-read','cases','cleanup','remove','stop','final'}
    require(len(v['stages'])==len(expected) and {s['name'] for s in v['stages']}==expected,'Missing/duplicate stage')
    for s in v['stages']:
        require(s['exit_code']==0 and s['timed_out'] is False and type(s['seconds']) in (int,float) and math.isfinite(s['seconds']) and s['seconds']>=0,'Stage failed')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==platform and r['source_sha256']==v['source_sha256'] and r['count']>=200 and r['count']==len(r['tests'])==len(set(r['tests'])) and r['errors']==r['failures']==r['skipped']==0,'Portable tests mismatch')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different test IDs')
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'],'Guest failed/source')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Scenario missing')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Scenario failed')
    for c in (g['cleanup'],v['cleanup']):require(all(c[k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Cleanup failed')
    require(v['snapshot_removed'] is True and v['vm_final']=='Stopped','VM/source not cleaned')
    require(g['client_build']['source_tar_sha256']==TARBALL_SHA256 and all(len(g['client_build'][k])==64 for k in ('binary_sha256','patched_dhcpc_sha256','config_sha256')),'Client provenance missing')
    cases={c['name']:c['details'] for c in g['cases']}
    d=cases['real_acquisition_and_B_crash_isolation']
    stable('A',d['before'],d['after'])
    require(identity(d['before']['state']['links']['A'])==identity(d['after']['state']['links']['A']) and d['before']['state']['links']['B']['session']!=d['after']['state']['links']['B']['session'] and d['after']['state']['links']['B']['current'] and d['client']['ok'] is True,'B crash isolation not proved')
    d=cases['two_natural_T1_rounds_both_links'];require(len(d['rounds'])==2,'Missing repeated renewal')
    previous=d['before']
    for s in d['rounds']:
        for k in ('A','B'):
            stable(k,d['before'],s)
            require(s['state']['links'][k]['expires']>previous['state']['links'][k]['expires']+10 and s['state']['links'][k]['current'],'Lease did not extend')
        previous=s
    for k in ('A','B'):
        req=d['requests'][k];require(len({p['xid'] for p in req})>=2 and all(p['ciaddr']!='0.0.0.0' and p['destination']==('192.0.2.1' if k=='A' else '198.51.100.1') for p in req),'No independent unicast renewal')
    d=cases['old_ACK_during_new_request_and_natural_rebinding'];r=d['replay']
    require(identity(r['before']['state']['links']['B'])==identity(r['after']['state']['links']['B']) and r['before']['state']['links']['B']['event_sequence']==r['after']['state']['links']['B']['event_sequence'],'Replayed ACK changed lease')
    require(d['unicast']['xid']!=r['packet']['xid'] and d['broadcasts'] and all(p['destination']=='255.255.255.255' and p['ciaddr']!='0.0.0.0' for p in d['broadcasts']) and d['after']['state']['links']['B']['expires']>d['before']['state']['links']['B']['expires']+10,'Natural rebinding not observed')
    for k in ('A','B'):stable(k,d['before'],d['after'])
    d=cases['B_lease_loss_and_changed_address_reacquisition']
    stable('A',d['before'],d['after'])
    require(d['expired']['state']['links']['B']['current'] is None and d['after']['state']['links']['B']['current']['ip']=='198.51.100.3' and all(d[k]['ok'] is True for k in ('client_A','client_B')),'Loss/reacquisition not established')
    require(any(p['type']==3 and p['at']>=d['server_restarted_at'] for p in d['wire']) and any(p['type']==5 and p['ip']=='198.51.100.3' for p in d['wire']),'No real reacquisition packets')
    d=cases['old_ACK_cannot_overwrite_reacquired_address']
    require(identity(d['before']['state']['links']['B'])==identity(d['after']['state']['links']['B']) and d['before']['state']['active']==d['after']['state']['active'] and d['client']['ok'] is True,'Old ACK overwrote recovered allocation')
    require(all(g['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'DHCP borrowed other path')
    return True


def controls(v):
    def alter(name,fn):return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==name))
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),lambda x:x.update(source_sha256='0'*64),
        lambda x:x['native_unit'].update(skipped=1),lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),
        lambda x:x['guest']['cases'].pop(),lambda x:x['cleanup'].update(root_network_unchanged=False),lambda x:x.update(vm_final='Running'),
        lambda x:x.update(snapshot_removed=False),lambda x:x['guest']['client_build'].update(source_tar_sha256='0'*64),
        alter('two_natural_T1_rounds_both_links',lambda d:d['rounds'][-1]['state']['links']['B'].update(expires=0)),
        alter('two_natural_T1_rounds_both_links',lambda d:d['requests']['B'][0].update(destination='192.0.2.1')),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d.update(broadcasts=[])),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['after']['state']['links']['B'].update(expires=99999)),
        alter('B_lease_loss_and_changed_address_reacquisition',lambda d:d['after']['state']['links']['B']['current'].update(ip='198.51.100.2')),
        alter('old_ACK_cannot_overwrite_reacquired_address',lambda d:d['client'].update(ok=False)),
        lambda x:x['guest']['wire_counters']['B'].update(wrong_dhcp=1)]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted P0 report accepted')
    return dict(passed=True,rejected=len(changes))


def render(v):
    text=base_render(v)
    return text.replace('Uplinkstead DHCP stage 1','Uplinkstead DHCP P0').replace('Formal dual-DHCP stage-one service','Natural DHCP transaction lifecycle exploration').replace('Linux VM foreground service;','Experimental externally built BusyBox GPL-2.0 client; natural client timer algorithm, not option 58/59 qualification. Linux VM foreground service;')
