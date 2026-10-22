"""Cross-check P0 formal-service evidence without assertions (also under -O)."""
import copy
import json
import math
import re
import ipaddress
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require,identity,render as base_render
from tools.dhcp_client_build import TARBALL_SHA256,UPSTREAM_DHCPC_SHA256,PATCHED_DHCPC_SHA256

CASES={'real_acquisition_and_B_crash_isolation','two_natural_T1_rounds_both_links',
       'old_ACK_during_new_request_and_natural_rebinding','B_lease_loss_and_changed_address_reacquisition',
       'old_ACK_cannot_overwrite_reacquired_address'}


def stable(k,before,after):
    require(before['state']['links'][k]['session']==after['state']['links'][k]['session'] and before['runtime']['children'][k]==after['runtime']['children'][k],'Unrelated client authority changed')


def number(v):return type(v) in (int,float) and math.isfinite(v) and v>=0


def packet(p,kind,mac=None):
    require(p['type']==kind and type(p['type']) is int and type(p['xid']) is int and 0<=p['xid']<=0xffffffff and number(p['at']),'Invalid packet identity/time')
    require(re.fullmatch('[0-9a-f]{12}',p['chaddr']) and re.fullmatch('[0-9a-f]{64}',p['frame_sha256']),'Invalid packet MAC/hash')
    if mac is not None:require(p['chaddr']==mac,'Wrong client MAC')


def transaction(t,s,k,mac=None,renew=False):
    req,ack,r=t['request'],t['ack'],t['runtime_record'];row=s['state']['links'][k];current=row['current']
    packet(req,3,mac);packet(ack,5,req['chaddr'])
    effective=t['effective_request'];packet(effective,3,req['chaddr'])
    require(req['xid']==ack['xid']==r['xid'] and req['at']<=ack['at'],'Unmatched wire transaction')
    require(effective['xid']==req['xid'] and req['at']<=effective['at']<=ack['at']<=t['observer_completed_at'] and number(t['observer_completed_at']),'Invalid effective request')
    require(r['link']==k and r['sequence']==row['event_sequence'] and r['reason'] in ('bound','renew'),'Wrong runtime transaction')
    require(all(number(r[x]) for x in ('request_at','observed_at','hook_at','processed_at','expires')),'Invalid authority time')
    require(r['request_at']<=r['observed_at']<=r['hook_at']<=r['processed_at']<=s['runtime']['as_of'] and r['request_at']<=req['at'] and r['observed_at']<=ack['at'],'Authority/observer clock mismatch')
    require(r['expires']==r['request_at']+int(ack['lease'])==row['expires'] and int(ack['lease'])==current['seconds'],'Actual deadline detached from ACK')
    require(ack['ip']==current['ip'] and ack['router']==current['gateway'] and ipaddress.IPv4Network('0.0.0.0/'+ack['subnet']).prefixlen==ipaddress.IPv4Network(current['prefix']).prefixlen,'ACK allocation mismatch')
    require(r in s['runtime']['recent'],'Detached runtime record')
    if renew:require(req['ciaddr']==current['ip'] and r['reason']=='renew','Not a renewal')
    return req['xid']


def replay(r,mac):
    p,received=r['packet'],r['received'];packet(p,5,mac);packet(received,5,mac)
    require(number(r['sent_at']) and number(r['observed_at']) and r['before']['runtime']['as_of']<=r['sent_at']<=received['at']<=r['observed_at'] and r['after']['runtime']['as_of']>=received['at'],'No receiver-side replay ordering')
    require(p['frame_sha256']==received['frame_sha256'] and p['xid']==received['xid'],'Replay packet not received')
    fence=r['capture_fence'];c=fence['runtime']['capture']['B'];after=r['after']['runtime']['capture']['B'];before=r['before']['runtime']['capture']['B']
    require(c['empty_at']>=received['at'] and fence['runtime']['as_of']<r['after']['runtime']['as_of'] and any(x['frame_sha256']==p['frame_sha256'] and x['frame_index']>before['frames'] for x in c['seen_frames']) and after['version']==before['version'] and after['pending'] is False,'Production capture/writer replay fence missing')
    require(identity(r['before']['state']['links']['B'])==identity(r['after']['state']['links']['B']) and r['before']['state']['links']['B']['event_sequence']==r['after']['state']['links']['B']['event_sequence'],'Replay changed actual allocation')


def verify(v):
    require(v['passed'] is True and v['source_changed'] is False and v['source_sha256']==fingerprint(v['source']),'Source/failed run')
    expected={'native','initial','start','preflight','upload','build','linux','linux-read','cases','cleanup','remove','stop','final'}
    require(len(v['stages'])==len(expected) and {s['name'] for s in v['stages']}==expected,'Missing/duplicate stage')
    for s in v['stages']:
        require(s['exit_code']==0 and s['timed_out'] is False and type(s['seconds']) in (int,float) and math.isfinite(s['seconds']) and s['seconds']>=0,'Stage failed')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==platform and r['source_sha256']==v['source_sha256'] and r['count']>=206 and r['count']==len(r['tests'])==len(set(r['tests'])) and r['errors']==r['failures']==r['skipped']==0,'Portable tests mismatch')
        require({'test_dhcp_client_build.ClientBoundaryTests.test_unanswered_old_transaction_cannot_roll_back_newer_ACK',
                 'test_dual_dhcp_service.CaptureTests.test_unanswered_old_ACK_cannot_dirty_or_ambiguate_current_proof'}<=set(r['tests']),'Missing delayed transaction regression')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different test IDs')
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'],'Guest failed/source')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Scenario missing')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Scenario failed')
    for c in (g['cleanup'],v['cleanup']):require(all(c[k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Cleanup failed')
    require(v['snapshot_removed'] is True and v['vm_final']=='Stopped','VM/source not cleaned')
    b=g['client_build']
    require(b['source_tar_sha256']==TARBALL_SHA256 and b['upstream_dhcpc_sha256']==UPSTREAM_DHCPC_SHA256 and b['patched_dhcpc_sha256']==PATCHED_DHCPC_SHA256 and b['recipe_sha256']==v['source']['tools/dhcp_client_build.py'] and g['client_binary_sha256']==b['binary_sha256'] and all(re.fullmatch('[0-9a-f]{64}',b[k]) for k in ('binary_sha256','config_sha256')) and isinstance(b['compiler'],str) and b['compiler'].startswith('gcc '),'Client provenance mismatch')
    cases={c['name']:c['details'] for c in g['cases']}
    d=cases['real_acquisition_and_B_crash_isolation']
    stable('A',d['before'],d['after'])
    require(identity(d['before']['state']['links']['A'])==identity(d['after']['state']['links']['A']) and d['before']['state']['links']['B']['session']!=d['after']['state']['links']['B']['session'] and d['after']['state']['links']['B']['current'] and d['client']['ok'] is True,'B crash isolation not proved')
    d=cases['two_natural_T1_rounds_both_links'];require(len(d['rounds'])==2,'Missing repeated renewal')
    previous=d['before'];baseline=d['baseline'];macs={k:baseline[k]['ack']['chaddr'] for k in ('A','B')}
    seen={k:{transaction(baseline[k],previous,k)} for k in ('A','B')}
    require(len(d['transactions'])==2,'Missing renewal wire proof')
    for index,s in enumerate(d['rounds']):
        for k in ('A','B'):
            stable(k,d['before'],s)
            xid=transaction(d['transactions'][index][k],s,k,macs[k],renew=True)
            require(d['transactions'][index][k]['request'] in d['requests'][k] and d['transactions'][index][k]['request']['at']>=previous['runtime']['as_of'],'Renewal request detached or predates round')
            require(xid not in seen[k],'Renewal reused transaction')
            seen[k].add(xid)
            require(s['state']['links'][k]['expires']>previous['state']['links'][k]['expires']+10 and s['state']['links'][k]['current'],'Lease did not extend')
        previous=s
    for k in ('A','B'):
        req=d['requests'][k]
        for p in req:packet(p,3,macs[k])
        require(len({p['xid'] for p in req})>=2 and all(p['ciaddr']!='0.0.0.0' and p['destination']==('192.0.2.1' if k=='A' else '198.51.100.1') for p in req),'No independent unicast renewal')
    d=cases['old_ACK_during_new_request_and_natural_rebinding'];r=d['replay']
    replay(r,macs['B']);packet(d['unicast'],3,macs['B'])
    require(d['unicast']['at']<r['sent_at'],'Replay did not follow new request')
    require(r['packet']['frame_sha256']==baseline['B']['ack']['frame_sha256'],'Replay was not this client original ACK')
    transaction(d['transaction'],d['after'],'B',macs['B'],renew=True)
    require(d['transaction']['effective_request'] in d['broadcasts'] and r['received']['at']<d['transaction']['effective_request']['at'],'Rebinding not linked to broadcast after replay')
    late=d['delayed_unanswered_reply'];replay(late,macs['B'])
    packet(late['newer_request'],3,macs['B'])
    require(late['synthetic'] is True and late['packet']['xid']==d['unicast']['xid'] and late['older_request']==d['unicast'] and late['newer_request']==d['transaction']['request'] and late['newer_request']['xid']!=late['packet']['xid'] and late['newer_request']['at']<late['sent_at']<d['transaction']['effective_request']['at'],'Unanswered-old-transaction injection not proved')
    require(identity(r['before']['state']['links']['B'])==identity(r['after']['state']['links']['B']) and r['before']['state']['links']['B']['event_sequence']==r['after']['state']['links']['B']['event_sequence'],'Replayed ACK changed lease')
    require(d['unicast']['xid']!=r['packet']['xid'] and d['broadcasts'] and all(p['destination']=='255.255.255.255' and p['ciaddr']!='0.0.0.0' for p in d['broadcasts']) and d['after']['state']['links']['B']['expires']>d['before']['state']['links']['B']['expires']+10,'Natural rebinding not observed')
    for k in ('A','B'):stable(k,d['before'],d['after'])
    d=cases['B_lease_loss_and_changed_address_reacquisition']
    stable('A',d['before'],d['after'])
    transaction(d['transaction'],d['after'],'B',macs['B'])
    diag=d['loss_diagnostic'];hook=d['loss_hook']
    require(diag['interface']=='wanB' and diag['pid']==d['before']['runtime']['children']['B'] and diag['remaining']>0 and diag['attempts']==3 and hook['reason']=='deconfig' and hook in d['expired']['runtime']['recent'] and d['before']['runtime']['as_of']<=hook['hook_at']<=hook['processed_at']<d['before']['state']['links']['B']['expires'],'Early loss cause not observed')
    broadcasts=[p for p in d['loss_wire'] if p['type']==3 and p['destination']=='255.255.255.255' and p['ciaddr']!='0.0.0.0' and p['xid']==diag['xid']]
    require(len(broadcasts)==3 and all(d['before']['runtime']['as_of']<=p['at']<=hook['hook_at'] for p in broadcasts),'Early loss retry evidence missing')
    require(d['expired']['state']['links']['B']['current'] is None and d['after']['state']['links']['B']['current']['ip']=='198.51.100.3' and all(d[k]['ok'] is True for k in ('client_A','client_B')),'Loss/reacquisition not established')
    require(any(p['type']==3 and p['at']>=d['server_restarted_at'] for p in d['wire']) and any(p['type']==5 and p['ip']=='198.51.100.3' for p in d['wire']),'No real reacquisition packets')
    d=cases['old_ACK_cannot_overwrite_reacquired_address']
    replay(d['replay'],macs['B'])
    require(d['replay']['packet']['frame_sha256']==baseline['B']['ack']['frame_sha256'],'Final replay source mismatch')
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
    changes += [alter('two_natural_T1_rounds_both_links',lambda d:d['rounds'][0]['state']['links']['B'].update(expires=d['rounds'][0]['state']['links']['B']['expires']+3600)),
        alter('two_natural_T1_rounds_both_links',lambda d:d['requests']['B'][0].update(type=1)),
        alter('two_natural_T1_rounds_both_links',lambda d:d['requests']['B'][0].update(at=0)),
        alter('two_natural_T1_rounds_both_links',lambda d:d['requests']['B'][0].update(chaddr='000000000000')),
        alter('two_natural_T1_rounds_both_links',lambda d:d['transactions'][0]['B']['ack'].update(lease='9999')),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['after']['runtime'].update(recent=[])),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['received'].update(frame_sha256='0'*64)),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay'].update(sent_at=999999)),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['packet'].update(type=3)),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['delayed_unanswered_reply'].update(synthetic=False)),
        alter('old_ACK_cannot_overwrite_reacquired_address',lambda d:d['replay']['received'].update(frame_sha256='0'*64)),
        alter('B_lease_loss_and_changed_address_reacquisition',lambda d:d.update(loss_wire=[])),
        alter('B_lease_loss_and_changed_address_reacquisition',lambda d:d['loss_diagnostic'].update(remaining=0)),
        alter('B_lease_loss_and_changed_address_reacquisition',lambda d:d['loss_diagnostic'].update(attempts=4)),
        alter('B_lease_loss_and_changed_address_reacquisition',lambda d:d['loss_diagnostic'].update(pid=-1)),
        lambda x:x['guest']['client_build'].update(binary_sha256='x'*64),
        lambda x:x['guest']['client_build'].update(patched_dhcpc_sha256='0'*64),
        lambda x:x['guest']['client_build'].update(upstream_dhcpc_sha256='0'*64),
        lambda x:x['guest']['client_build'].update(recipe_sha256='0'*64),
        lambda x:x['guest']['client_build'].update(compiler=None)]
    changes += [alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['capture_fence']['runtime']['capture']['B'].update(empty_at=0)),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['capture_fence']['runtime']['capture']['B'].update(seen_frames=[])),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['after']['runtime']['capture']['B'].update(pending=True)),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['capture_fence']['runtime'].update(as_of=d['replay']['after']['runtime']['as_of'])),
        alter('old_ACK_during_new_request_and_natural_rebinding',lambda d:d['replay']['after']['runtime']['capture']['B'].update(version=d['replay']['before']['runtime']['capture']['B']['version']+1))]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted P0 report accepted')
    return dict(passed=True,rejected=len(changes))


def render(v):
    text=base_render(v)
    return text.replace('Uplinkstead DHCP stage 1','Uplinkstead DHCP P0').replace('Formal dual-DHCP stage-one service','Natural DHCP transaction lifecycle exploration').replace('Linux VM foreground service;','Experimental externally built BusyBox GPL-2.0 client; natural client timer algorithm, not option 58/59 qualification. Linux VM foreground service;')
