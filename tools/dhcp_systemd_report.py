"""Installed-service evidence correspondence; no reboot/power-loss inference."""
import copy,html,json,math
from tools import dhcp_control_report as control
from tools.dhcp_stage1_report import require,render as base_render
from tools.dhcp_automatic_report import chosen
CASES={'installed_units_readiness_and_worker','orderly_stop_start_quarantines_and_cleans','writer_SIGKILL_supervised_recovery','delayed_old_ip_helper_killed_before_takeover','bounded_restart_failure_and_explicit_repair'}

def view(v):return dict(v,guest=v['guest']['regression'])
def empty(s):
    require(s['state']['active'] is None and all(r['current'] is None and r['state']=='WAITING' for r in s['state']['links'].values()),'Old lease/health survived recovery')
def stale(d):
    require(len(d['replies'])==5 and all(r['ok'] is False for r in d['replies']),'Old operator/proposal/hook admitted')
    require(d['before']['state']['epoch']>d['submitted']['epoch'] and d['after']['state']['revision']>=d['before']['state']['revision'],'No retired epoch evidence')
    for k in ('epoch','history','latched','paused','active','operations'):require(d['before']['state'][k]==d['after']['state'][k],'Stale operation changed authority')
def verify(v):
    control.verify(view(v));g=v['guest']
    require(g['passed'] is True and g['source_sha256']==v['source_sha256'] and v['native_unit']['count']>=263,'Installed source/suite failed')
    require(all(g[k]==g['regression'][k] for k in ('client_build','client_binary_sha256','client_config_sha256')),'Installed client build detached')
    require({'test_dhcp_systemd.DeploymentTests.'+n for n in ('test_named_client_uses_busybox_dispatch_without_changing_executable','test_poststop_uses_formal_recovery_preserves_limits_retires_authority','test_failed_poststop_cannot_report_quarantine_success','test_notify_failure_is_not_silent_readiness','test_readiness_uses_real_datagram_and_no_socket_is_foreground')}<=set(v['native_unit']['tests']),'Missing formal deployment tests')
    require(g['worker_file_sha256']==v['source']['uplinkstead/dual_dhcp_worker.py'],'Installed worker detached')
    require(g['installation_removed'] is True and all(g['cleanup'][k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Installation/network cleanup failed')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Installed cases missing')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Installed case failed')
    require(set(g['units'])=={'uplinkstead-dual.service','uplinkstead-dual-policy.service'},'Missing installed units')
    for name,r in g['units'].items():require(r['source_sha256']==r['installed_sha256']==v['source']['deploy/'+name],'Shipped unit detached')
    ds={c['name']:c['details'] for c in g['cases']};d=ds['installed_units_readiness_and_worker'];w=d['worker']
    require(w['uid'][0]>0 and len(set(w['uid']))==1 and all(int(v,16)==0 for v in w['caps'].values()) and w['no_new_privs']=='1' and d['worker_journal_denied'] is True,'Installed worker privilege failed')
    require(d['writer']['uid']==[0]*4 and d['start']['writer']['Type']=='notify' and d['start']['writer']['KillMode']=='control-group' and d['client']['ok'] is True,'Installed readiness/traffic failed')
    d=ds['orderly_stop_start_quarantines_and_cleans'];empty(d['restarted']['status']);stale(d['stale']);stale(d['stale_after'])
    require(d['all_old_processes_gone'] is True and d['socket_removed'] is True and all(not r for r in d['routes'].values()) and d['blocked']['ok'] is False and d['fallback']['ok'] is True and d['fallback']['response']['peer']=='10.99.2.1','Stop leaked processes/routes or borrowed main')
    require(d['stopped']['paused'] is True and d['stopped']['active'] is None and all(r['current'] is None for r in d['stopped']['links'].values()) and d['stopped']['history']==d['old']['state']['history'] and d['fresh']['state']['paused'] is True and d['fresh']['state']['active'] is None,'Stop/start lost pause/budget')
    for name in ('writer_SIGKILL_supervised_recovery','delayed_old_ip_helper_killed_before_takeover'):
        d=ds[name];empty(d['recovered']['status']);stale(d['stale']);stale(d['stale_after'])
        require(d['previous']['InvocationID']!=d['recovered']['writer']['InvocationID'] and d['recovered']['status']['state']['epoch']>d['old']['state']['epoch'] and d['client']['ok'] is True,'No actual replacement/traffic')
        a=d['after']['state']['active'];chosen(d['after'],a['link'])
    d=ds['writer_SIGKILL_supervised_recovery'];require(d['all_old_processes_gone'] is True and d['recovered']['status']['state']['history']==d['old']['state']['history'] and d['killed_at']<=d['ready_observed_at'] and all(n>0 for n in d['rss_kib'].values()),'SIGKILL recovery lost authority or metrics')
    d=ds['delayed_old_ip_helper_killed_before_takeover'];require(d['helper']['lock_fds'] and d['helper_process']['state'].startswith('T') and d['lock_denied_while_old_helper'] is True and d['old_helper_gone'] is True and d['old_helper_never_executed_ip'] is True and d['after']['state']['active']['link']=='B','Delayed helper fenced incorrectly')
    d=ds['bounded_restart_failure_and_explicit_repair'];require(d['failed']['ActiveState']=='failed' and d['failed']['Restart']=='on-failure' and d['start_limit_observed'] is True and 1<=int(d['failed']['NRestarts'])<=3 and d['stable_failure']['ActiveState']=='failed' and d['stable_failure']['NRestarts']==d['failed']['NRestarts'] and d['failed_worker']['ActiveState']!='active' and d['failed']['StartLimitBurst']=='3' and d['repair_without_reset_exit']!=0 and d['explicit_reset_recovered'] is True and d['after']['state']['history'][:-1]==d['before']['history'] and all(d['after']['state'][k]==d['before'][k] for k in ('paused','latched')),'Restart loop unbounded or recovery implicit')
    require(all(g['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'Installed DHCP borrowed WAN')
    return True

def controls(v):
    inherited=control.controls(view(v))
    def case(n,fn):return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==n))
    changes=[lambda x:x['guest'].update(installation_removed=False),lambda x:x['guest']['units']['uplinkstead-dual.service'].update(installed_sha256='0'*64),lambda x:x['guest'].update(client_binary_sha256='0'*64),lambda x:x['guest']['cases'].pop(),case('installed_units_readiness_and_worker',lambda d:d['worker'].update(uid=[0]*4)),case('installed_units_readiness_and_worker',lambda d:d['worker']['caps'].update(CapEff='1')),case('orderly_stop_start_quarantines_and_cleans',lambda d:d['blocked'].update(ok=True)),case('orderly_stop_start_quarantines_and_cleans',lambda d:d.update(all_old_processes_gone=False)),case('orderly_stop_start_quarantines_and_cleans',lambda d:d['stopped'].update(paused=False)),case('writer_SIGKILL_supervised_recovery',lambda d:d['recovered']['status']['state']['links']['A'].update(state='HEALTHY')),case('writer_SIGKILL_supervised_recovery',lambda d:d['stale']['replies'][0].update(ok=True)),case('delayed_old_ip_helper_killed_before_takeover',lambda d:d.update(lock_denied_while_old_helper=False)),case('delayed_old_ip_helper_killed_before_takeover',lambda d:d.update(old_helper_never_executed_ip=False)),case('bounded_restart_failure_and_explicit_repair',lambda d:d.update(start_limit_observed=False))]
    for change in changes:
        b=copy.deepcopy(v);change(b)
        try:verify(b)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted installed-service evidence accepted')
    return dict(passed=True,rejected=inherited['rejected']+len(changes),regression=inherited['rejected'],installed=len(changes))

def render(v):
    return base_render(v).replace('Uplinkstead DHCP stage 1','Uplinkstead installed dual-DHCP service').replace('Formal dual-DHCP stage-one service','Installed dual-DHCP service and writer takeover').replace('Linux VM foreground service; native macOS portable tests are separate. No systemd, VM reboot, power-loss, zero-gap or automatic failover claim.','Real systemd in an isolated Linux VM; native macOS portable tests are separate. No VM reboot, power-loss, boot-zero-gap or capacity-exhaustion qualification.').replace('Lease origin is a conservative REQUEST receive-queue-empty lower bound, not hook or processing time. Stage durations are not outage guarantees.','Five installed-service cases; nested regression contains five control plus nine automatic cases. One documented case delays a real ip helper before exec. VM RSS snapshots are not peaks. Case durations/readiness are not WAN outage guarantees.')
