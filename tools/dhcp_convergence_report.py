"""Validate selected-WAN convergence evidence without assertion dependence."""
import copy,math,re
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require,identity,render as base_render
from tools.dhcp_p0_report import packet
from tools.dhcp_client_build import TARBALL_SHA256,UPSTREAM_DHCPC_SHA256,PATCHED_DHCPC_SHA256
CASES={'explicit_arm_and_inactive_B_isolation','four_natural_renewals_restore_without_budget','address_gateway_change_requires_fresh_health','gateway_only_change_restores','expiry_reacquisition_and_old_ACK','manual_switch_budget_latch_blocks_restore'}

def isolated(a,b):
    require(identity(a['state']['links']['A'])==identity(b['state']['links']['A']) and a['runtime']['children']['A']==b['runtime']['children']['A'],'B changed A authority')

def traffic(value,link):
    return value['ok'] is True and value['response']['peer']==('10.99.1.1' if link=='A' else '10.99.2.1')

def restored(before,after,t):
    a=after['state']['active'];r=after['state']['links']['B'];record=t['record'];req,ack=t['request'],t['ack']
    packet(req,3);packet(ack,5,req['chaddr'])
    require(req['xid']==ack['xid']==record['xid'] and req['at']<=ack['at'] and record in after['runtime']['recent'] and record['sequence']==r['event_sequence'],'Restoration wire/sequence detached')
    require(r['current']['ip']==ack['ip'] and r['current']['gateway']==ack['router'] and r['expires']==record['request_at']+int(ack['lease']) and record['request_at']==min(record['wire_request_at'],record['client_origin_ns']/1e9),'Wrong admitted configuration/deadline')
    require(a and a['link']=='B' and a['generation']==r['generation']>before['state']['links']['B']['generation'] and a['value']==r['current'],'No new-generation B selection')
    require(r['state']=='HEALTHY' and r['good']>=2 and r['last_event']==record['hook_at']<=record['processed_at']<=after['runtime']['as_of']<r['until']<=r['expires'] and r['until']<r['expires'] and r['until']-10>=record['hook_at'] and not after['runtime']['capture']['B']['pending'],'Fresh current health not established')
    require(after['state']['history']==before['state']['history'] and after['state']['latched'] is False and after['runtime']['restoration']['enabled'] is True and after['runtime']['restoration']['status']=='SELECTED' and after['runtime']['restoration']['target']=='B' and after['runtime']['metrics']['lease_restores']>before['runtime']['metrics']['lease_restores'],'Restoration spent budget or was manual')
    isolated(before,after)

def verify(v):
    require(v['passed'] is True and v['source_changed'] is False and v['source_sha256']==fingerprint(v['source']),'Failed/source changed')
    expected={'native','initial','start','preflight','upload','build','linux','linux-read','cases','cleanup','remove','stop','final'}
    require(len(v['stages'])==len(expected) and {s['name'] for s in v['stages']}==expected,'Missing stage')
    for s in v['stages']:require(s['exit_code']==0 and s['timed_out'] is False and math.isfinite(s['seconds']) and s['seconds']>=0,'Failed/timed-out stage')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==platform and r['source_sha256']==v['source_sha256'] and r['count']>=224 and r['count']==len(r['tests'])==len(set(r['tests'])) and r['errors']==r['failures']==r['skipped']==0,'Portable suite mismatch')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different test IDs')
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'],'Guest failed/source')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Missing case')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Case failed')
    for c in (g['cleanup'],v['cleanup']):require(all(c[k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Cleanup failed')
    require(v['snapshot_removed'] is True and v['vm_final']=='Stopped','Resources retained')
    b=g['client_build'];require(b['source_tar_sha256']==TARBALL_SHA256 and b['upstream_dhcpc_sha256']==UPSTREAM_DHCPC_SHA256 and b['patched_dhcpc_sha256']==PATCHED_DHCPC_SHA256 and b['recipe_sha256']==v['source']['tools/dhcp_client_build.py'] and g['client_binary_sha256']==b['binary_sha256'] and g['client_config_sha256']==b['config_sha256'],'Client build detached')
    ds={c['name']:c['details'] for c in g['cases']}
    d=ds['explicit_arm_and_inactive_B_isolation'];require(d['unselected']['state']['active'] is None and d['unselected']['runtime']['restoration']['target'] is None,'Automatic initial selection')
    isolated(d['before'],d['after']);require(d['before']['state']['active']==d['after']['state']['active'] and traffic(d['client'],'A'),'Inactive B disrupted A')
    d=ds['four_natural_renewals_restore_without_budget'];require(len(d['before']['state']['history'])==2 and len(d['rounds'])==4,'Budget/rounds wrong');previous=d['before']
    for r in d['rounds']:
        restored(previous,r['status'],r['transaction']);require(r['transaction']['request']['at']>=previous['state']['links']['B']['expires']-60+5 and r['transaction']['request']['destination']=='198.51.100.1' and traffic(r['client'],'B'),'Not natural renewal/traffic');previous=r['status']
    require(d['rss_kib']['service']>0 and all(d['rss_kib']['clients'][k]>0 for k in ('A','B')),'RSS missing')
    d=ds['address_gateway_change_requires_fresh_health'];blocked=d['blocked_state'];r=blocked['state']['links']['B']
    require(r['current']['ip']=='198.51.100.3' and r['current']['gateway']=='198.51.100.254' and r['state']=='DOWN' and r['good']==0 and blocked['state']['active'] is None and d['blocked']['ok'] is False and blocked['runtime']['as_of']<=d['unblock_at']<=d['after']['runtime']['as_of'],'Old health reused or borrowed')
    require(d['nak_sent']['kind']==6 and d['before']['runtime']['as_of']<=d['nak_sent']['at']<=d['nak_hook']['hook_at']<=d['after']['runtime']['as_of'] and d['nak_hook'] in d['after']['runtime']['recent'] and d['transaction']['request']['ciaddr']=='0.0.0.0','No NAK/new acquisition for address change')
    isolated(d['before'],blocked);restored(d['before'],d['after'],d['transaction']);require(traffic(d['client'],'B'),'Changed allocation traffic failed')
    d=ds['gateway_only_change_restores'];restored(d['before'],d['after'],d['transaction']);require(d['before']['state']['links']['B']['current']['ip']==d['after']['state']['links']['B']['current']['ip'] and d['after']['state']['links']['B']['current']['gateway']=='198.51.100.253' and traffic(d['client'],'B'),'Gateway change not exercised')
    d=ds['expiry_reacquisition_and_old_ACK'];deadline=d['before']['state']['links']['B']['expires'];samples=d['samples']
    require(len(samples)>2 and samples[-1]['present'] is False and samples[-1]['as_of']==d['expired']['runtime']['as_of']>=deadline and all(s['present'] is True for s in samples[:-1]) and all(0<=b['observed_at']-a['observed_at']<=2 for a,b in zip(samples,samples[1:])),'Early withdrawal/observation gap')
    require(d['expired']['state']['active'] is None and d['blocked']['ok'] is False and not any(str(r.get('table')) in ('41202','41203') for r in d['network']['routes']) and not any(a.get('local')=='198.51.100.3' for link in d['network']['addresses'] for a in link.get('addr_info',[])),'Expiry did not remove actual configuration')
    restored(d['before'],d['after'],d['transaction']);require(d['after']['state']['links']['B']['current']['ip']=='198.51.100.4' and traffic(d['client'],'B'),'Reacquisition failed')
    replay=d['replay'];c=replay['fence']['runtime']['capture']['B'];p=replay['received'];before=replay['before'];after=replay['after']
    require(c['empty_at']>=p['at'] and replay['fence']['runtime']['as_of']<after['runtime']['as_of'] and any(x['frame_sha256']==p['frame_sha256'] and x['frame_index']>before['runtime']['capture']['B']['frames'] for x in c['seen_frames']) and before['runtime']['capture']['B']['version']==after['runtime']['capture']['B']['version'] and identity(before['state']['links']['B'])==identity(after['state']['links']['B']) and before['state']['links']['B']['event_sequence']==after['state']['links']['B']['event_sequence'],'Replay affected new configuration or no processing fence')
    d=ds['manual_switch_budget_latch_blocks_restore'];require(d['rejection']['ok'] is False and d['latched']['state']['latched'] is True and d['after']['state']['latched'] is True and d['after']['state']['history']==d['before']['state']['history'] and d['after']['state']['active'] is None and d['after']['state']['links']['B']['state']=='HEALTHY' and d['after']['state']['links']['B']['event_sequence']>d['latched']['state']['links']['B']['event_sequence'],'Budget/latch bypass')
    require(all(g['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'DHCP borrowed other WAN')
    return True

def controls(v):
    def alter(name,fn):return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==name))
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),lambda x:x['stages'].pop(),lambda x:x['native_unit'].update(skipped=1),lambda x:x['linux_unit'].update(source_sha256='0'*64),lambda x:x['guest']['cases'].pop(),lambda x:x['cleanup'].update(root_network_unchanged=False),lambda x:x.update(vm_final='Running'),lambda x:x.update(snapshot_removed=False),lambda x:x['guest']['client_build'].update(binary_sha256='0'*64)]
    changes += [alter('explicit_arm_and_inactive_B_isolation',lambda d:d['after']['state']['links']['A'].update(expires=0)),alter('four_natural_renewals_restore_without_budget',lambda d:d['rounds'][0]['status']['state']['history'].pop()),alter('four_natural_renewals_restore_without_budget',lambda d:d['rounds'][0]['status']['state']['active'].update(generation=0)),alter('four_natural_renewals_restore_without_budget',lambda d:d['rounds'][0]['transaction']['ack'].update(router='198.51.100.9')),alter('address_gateway_change_requires_fresh_health',lambda d:d['blocked_state']['state']['links']['B'].update(state='HEALTHY')),alter('address_gateway_change_requires_fresh_health',lambda d:d['blocked'].update(ok=True)),alter('gateway_only_change_restores',lambda d:d['after']['state']['links']['B']['current'].update(gateway='198.51.100.254')),alter('expiry_reacquisition_and_old_ACK',lambda d:d['expired']['runtime'].update(as_of=0)),alter('expiry_reacquisition_and_old_ACK',lambda d:d['network']['routes'].append(dict(table='41203',dst='default'))),alter('expiry_reacquisition_and_old_ACK',lambda d:d['replay']['fence']['runtime']['capture']['B'].update(seen_frames=[])),alter('manual_switch_budget_latch_blocks_restore',lambda d:d['after']['state'].update(latched=False)),lambda x:x['guest']['wire_counters']['B'].update(wrong_dhcp=1)]
    changes += [alter('four_natural_renewals_restore_without_budget',lambda d:d['rounds'][0]['client']['response'].update(peer='10.99.1.1')),alter('address_gateway_change_requires_fresh_health',lambda d:d['client']['response'].update(peer='10.99.1.1')),alter('four_natural_renewals_restore_without_budget',lambda d:d['rounds'][0]['status']['runtime']['restoration'].update(enabled=False))]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted convergence evidence accepted')
    return dict(passed=True,rejected=len(changes))

def render(v):
    return base_render(v).replace('Uplinkstead DHCP stage 1','Uplinkstead selected-WAN DHCP convergence').replace('Formal dual-DHCP stage-one service','Selected-WAN DHCP convergence').replace('Lease origin is a conservative REQUEST receive-queue-empty lower bound, not hook or processing time.','Manual initial selection; same-WAN restoration requires new-generation fresh health. No automatic cross-WAN failover or continuous-forwarding claim. RSS is a Linux VM snapshot, not a peak.')
