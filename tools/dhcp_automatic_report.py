"""Fail-closed correspondence checks for automatic dual-DHCP VM evidence."""
import copy,math
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require,render as base_render
from tools.dhcp_convergence_report import admitted,traffic
from tools.dhcp_client_build import TARBALL_SHA256,UPSTREAM_DHCPC_SHA256,PATCHED_DHCPC_SHA256
CASES={'automatic_initial_A','TLS_fixture_slow_handshake_isolation','A_blackhole_automatic_B','four_natural_B_renewals','B_loss_automatic_A_stale_request','short_flap_and_no_preemption','both_down_then_budget_latch','ACK_during_backend_write','loss_during_backend_write'}

def chosen(s,k):
    a=s['state']['active'];r=s['state']['links'][k]
    require(s['runtime']['automatic']['enabled'] is True and a and a['link']==k and a['generation']==r['generation'] and a['value']==r['current'] and r['state']=='HEALTHY' and s['runtime']['as_of']<r['until']<=r['expires'] and not s['runtime']['capture'][k]['pending'],'No fresh admitted route')

def race(d,kind):
    b=d['barrier'];i=d['invalid'];events=i['runtime']['selection_events']
    require(b['active']['link']=='B' and b['at']<=d['release_at']<=d['done']['at'] and d['done']['at']-b['at']<=3.5 and d['queued']['runtime']['queue']['per_link_depth']['B']>0,'Race was not held with actual queued evidence')
    require(i['runtime']['metrics']['selection_invalidations']>d['before']['runtime']['metrics']['selection_invalidations'],'Write race not invalidated')
    require(any(e['link']=='B' and e['outcome']=='INVALIDATED' and e['current'] is None and e['active'] is None and e['pending'] is True and e['before']!=e['after'] and d['done']['at']<=e['at']<=i['runtime']['as_of'] for e in events),'Invalidated write did not withdraw')
    if kind=='ACK':
        chosen(d['after'],'B');admitted(d['after'],d['transaction'])
        require(b['at']<=d['transaction']['request']['at']<=d['transaction']['ack']['at']<=d['release_at'] and d['after']['state']['active']['generation']>b['active']['generation'] and traffic(d['client'],'B'),'ACK did not overlap write or fresh B failed')
        r=d['after']['state']['links']['B']
        require(type(r['good']) is int and r['good']>=2 and r['until']-5>=r['last_event'],'ACK recovery lacks new-generation health quorum')
        require(d['after']['state']['history']==i['state']['history'] and d['after']['runtime']['metrics']['lease_restores']>i['runtime']['metrics']['lease_restores'],'ACK recovery charged budget or did not use lease restoration')
    else:
        require(d['withdrawn']['state']['active'] is None and d['withdrawn']['state']['links']['B']['current'] is None,'Lease loss kept allocation')
        require(any(r['link']=='B' and r['reason']=='deconfig' and b['at']<=r['hook_at']<=d['release_at'] for r in d['withdrawn']['runtime']['recent']),'No real loss event during write')
        chosen(d['after'],'A');require(traffic(d['client'],'A') and traffic(d['fallback'],'A'),'Recovery A data failed')

def verify(v):
    require(v['passed'] is True and v['source_changed'] is False and v['source_sha256']==fingerprint(v['source']),'Failed/source changed')
    expected={'native','initial','start','preflight','upload','build','linux','linux-read','cases','cleanup','remove','stop','final'}
    require(len(v['stages'])==len(expected) and {s['name'] for s in v['stages']}==expected,'Missing stage')
    for s in v['stages']:require(s['exit_code']==0 and s['timed_out'] is False and math.isfinite(s['seconds']) and s['seconds']>=0,'Failed/timed-out stage')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==platform and r['source_sha256']==v['source_sha256'] and r['count']>=240 and r['count']==len(r['tests'])==len(set(r['tests'])) and r['errors']==r['failures']==r['skipped']==0,'Portable suite mismatch')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different test IDs')
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'],'Guest failed/source')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Missing case')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Case failed')
    for c in (g['cleanup'],v['cleanup']):require(all(c[k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Cleanup failed')
    require(v['snapshot_removed'] is True and v['vm_final']=='Stopped','Resources retained')
    b=g['client_build'];require(b['source_tar_sha256']==TARBALL_SHA256 and b['upstream_dhcpc_sha256']==UPSTREAM_DHCPC_SHA256 and b['patched_dhcpc_sha256']==PATCHED_DHCPC_SHA256 and b['recipe_sha256']==v['source']['tools/dhcp_client_build.py'] and g['client_binary_sha256']==b['binary_sha256'] and g['client_config_sha256']==b['config_sha256'],'Client build detached')
    require({'test_dhcp_automatic.AutomaticTests.'+n for n in ('test_hold_initial_preference_sticky_failover_no_preemption','test_renewal_requires_new_health_does_not_spend_budget','test_latch_and_pause_never_bypassed','test_new_ACK_during_real_runtime_selection_invalidates_before_publish','test_lease_loss_enqueued_during_selection_invalidates','test_delayed_operator_and_old_probe_cannot_override_new_generation','test_restore_rate_limit_cannot_fall_through_to_charged_same_WAN_choose','test_one_failed_round_then_success_preserves_qualified_selected_route','test_suspect_recovery_exception_cannot_qualify_backup_or_new_lease','test_expired_SUSPECT_cannot_reuse_qualification_or_free_restore')}<=set(v['native_unit']['tests']),'Missing formal regression')
    ds={c['name']:c['details'] for c in g['cases']}
    d=ds['automatic_initial_A'];chosen(d['after'],'A');require(len(d['after']['state']['history'])==1 and d['after']['runtime']['metrics']['automatic_choices']==1 and traffic(d['client'],'A'),'Initial choice not automatic/charged')
    d=ds['TLS_fixture_slow_handshake_isolation'];require(d['tcp_only'] is True and d['ready_at']<=d['client_at']<=d['finished_at']<=d['holder_stopped_at'] and traffic(d['client'],'A'),'Slow TLS client blocked the fixture')
    d=ds['A_blackhole_automatic_B'];chosen(d['before'],'A');chosen(d['after'],'B');require(len(d['after']['state']['history'])==2 and d['before']['runtime']['as_of']<=d['fault_at']<=d['after']['runtime']['as_of'] and d['after']['state']['links']['A']['state']=='DOWN' and traffic(d['client'],'B'),'No A failure/B failover')
    d=ds['four_natural_B_renewals'];previous=d['before'];require(len(d['rounds'])==4 and len(previous['state']['history'])==2,'Renewal rounds missing')
    for r in d['rounds']:
        s=r['status'];chosen(s,'B');admitted(s,r['transaction']);b=s['state']['links']['B'];p=previous['state']['links']['B']
        require(b['generation']>p['generation'] and b['event_sequence']>p['event_sequence'] and s['state']['history']==d['before']['state']['history'] and not s['state']['latched'] and b['until']-5>=b['last_event'] and r['transaction']['record']['reason']=='renew' and r['transaction']['request']['destination']=='198.51.100.1' and r['transaction']['request']['at']>=p['expires']-60+5 and traffic(r['client'],'B'),'Renewal used old health/budget or wrong WAN')
        require(s['state']['links']['A']['current']==d['before']['state']['links']['A']['current'] and s['runtime']['children']['A']==d['before']['runtime']['children']['A'],'B renewal disturbed A')
        previous=s
    require(d['rss_kib']['service']>0 and all(d['rss_kib']['clients'][k]>0 for k in ('A','B')),'RSS missing')
    d=ds['B_loss_automatic_A_stale_request'];chosen(d['before'],'B');chosen(d['after'],'A');require(d['after']['state']['links']['B']['current'] is None and len(d['after']['state']['history'])==3 and d['rejection']['ok'] is False and d['old_request']['revision']!=d['after']['state']['revision'] and d['fence']['state']['active']==d['after']['state']['active'] and d['fence']['state']['history']==d['after']['state']['history'] and d['fence']['runtime']['as_of']>d['after']['runtime']['as_of'] and traffic(d['client'],'A'),'Loss/stale selection failed')
    require(not any(str(r.get('table'))=='41202' for r in d['network']['routes']),'Lost B probe route retained')
    d=ds['short_flap_and_no_preemption'];chosen(d['before'],'A');chosen(d['after'],'A');require(d['before']['state']['links']['B']['state']==d['after']['state']['links']['B']['state']=='HEALTHY' and d['before']['state']['history']==d['after']['state']['history'] and traffic(d['client'],'A'),'Short flap/preemption spent budget')
    require(d['suspect']['state']['links']['A']['state']=='SUSPECT' and 1<=d['suspect']['state']['links']['A']['bad']<3 and d['suspect']['state']['active']==d['before']['state']['active']==d['after']['state']['active'],'No qualified SUSPECT recovery without route churn')
    d=ds['both_down_then_budget_latch'];chosen(d['fourth'],'B');require(len(d['fourth']['state']['history'])==4 and d['empty']['state']['active'] is None and all(d['empty']['state']['links'][k]['state']=='DOWN' for k in ('A','B')) and d['blocked']['ok'] is False,'Both-down route retained')
    require(d['latched']['state']['latched'] is True and d['after']['state']['latched'] is True and d['after']['state']['active'] is None and d['after']['state']['links']['B']['state']=='HEALTHY' and d['after']['state']['links']['B']['event_sequence']>d['latched']['state']['links']['B']['event_sequence'] and d['after']['state']['history']==d['fourth']['state']['history'] and traffic(d['fallback']['client'],'A') and d['denied']['ok'] is False,'Latch bypass or unavailable fallback')
    race(ds['ACK_during_backend_write'],'ACK');race(ds['loss_during_backend_write'],'loss')
    require(all(g['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'DHCP borrowed other WAN')
    return True

def controls(v):
    def case(name,fn):return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==name))
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),lambda x:x['stages'].pop(),lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),lambda x:x['native_unit'].update(skipped=1),lambda x:x['linux_unit'].update(source_sha256='0'*64),lambda x:x['guest']['client_build'].update(binary_sha256='0'*64),lambda x:x['guest']['cases'].pop(),lambda x:x['cleanup'].update(root_network_unchanged=False),lambda x:x.update(vm_final='Running'),lambda x:x.update(snapshot_removed=False),lambda x:x['guest']['wire_counters']['B'].update(wrong_dhcp=1)]
    changes += [case('automatic_initial_A',lambda d:d['after']['runtime']['automatic'].update(enabled=False)),case('A_blackhole_automatic_B',lambda d:d['after']['state']['links']['A'].update(state='HEALTHY')),case('four_natural_B_renewals',lambda d:d['rounds'].pop()),case('four_natural_B_renewals',lambda d:d['rounds'][0]['status']['state']['history'].pop()),case('four_natural_B_renewals',lambda d:d['rounds'][0]['transaction']['ack'].update(at=1e12)),case('four_natural_B_renewals',lambda d:d['rounds'][0]['status']['state']['links']['B'].update(until=0)),case('four_natural_B_renewals',lambda d:d['rounds'][0]['client']['response'].update(peer='10.99.1.1')),case('B_loss_automatic_A_stale_request',lambda d:d['rejection'].update(ok=True)),case('short_flap_and_no_preemption',lambda d:d['after']['state']['history'].pop()),case('both_down_then_budget_latch',lambda d:d['after']['state'].update(latched=False)),case('both_down_then_budget_latch',lambda d:d['fallback']['client'].update(ok=False)),case('both_down_then_budget_latch',lambda d:d['denied'].update(ok=True))]
    changes += [case('short_flap_and_no_preemption',lambda d:d['suspect']['state']['links']['A'].update(bad=0))]
    for name in ('ACK_during_backend_write','loss_during_backend_write'):
        changes += [case(name,lambda d:d['queued']['runtime']['queue']['per_link_depth'].update(B=0)),case(name,lambda d:d['invalid']['runtime'].update(selection_events=[])),case(name,lambda d:d['barrier'].update(at=1e12))]
    changes += [case('ACK_during_backend_write',lambda d:d['after']['state']['links']['B'].update(good=0)),case('ACK_during_backend_write',lambda d:d['after']['state']['links']['B'].update(until=d['after']['runtime']['as_of']+.001)),case('ACK_during_backend_write',lambda d:d['after']['state']['history'].append(dict(boot=d['after']['state']['boot'],at=d['after']['runtime']['as_of']))),case('ACK_during_backend_write',lambda d:d['after']['runtime']['metrics'].update(lease_restores=d['invalid']['runtime']['metrics']['lease_restores']))]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted automatic evidence accepted')
    return dict(passed=True,rejected=len(changes))

def render(v):
    return base_render(v).replace('Uplinkstead DHCP stage 1','Uplinkstead automatic dual-DHCP selection').replace('Formal dual-DHCP stage-one service','Automatic dual-DHCP foreground service').replace('No systemd, VM reboot, power-loss, zero-gap or automatic failover claim.','Automatic failover is qualified only in this foreground fixture; no installed systemd, VM reboot, power-loss or zero-gap qualification.').replace('Lease origin is a conservative REQUEST receive-queue-empty lower bound, not hook or processing time.','Non-preemptive automatic selection; fresh generation-bound health; charged cross-WAN changes and free same-WAN renewal. Two race cases use a bounded test-only delay around real backend writes. No installed-service, reboot, power-loss or zero-gap qualification. RSS is a VM snapshot, not a peak.')
