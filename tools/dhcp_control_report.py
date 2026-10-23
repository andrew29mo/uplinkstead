"""Verify actual policy UID/root operator receipts and prior automatic regressions."""
import copy,math
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require
from tools import dhcp_automatic_report as automatic
from tools.dhcp_convergence_report import admitted,traffic
CASES={'real_unprivileged_worker_and_kernel_boundary','writer_rejects_rogue_worker','pause_stale_resume_and_safety_withdrawal','absent_worker_no_bypass_then_latch','explicit_reset_resume_new_lease_authority'}

def regression_view(v):
    return dict(v,guest=v['guest']['regression'])

def verify(v):
    automatic.verify(regression_view(v))
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256']==fingerprint(v['source']) and v['native_unit']['count']>=258,'Control source/suite mismatch')
    require(all(g[key]==g['regression'][key] for key in ('client_build','client_binary_sha256','client_config_sha256')),'Control/regression client build detached')
    require(g['worker_file_sha256']==v['source']['uplinkstead/dual_dhcp_worker.py'] and g['cli_file_sha256']==v['source']['uplinkstead/dual_dhcp_cli.py'],'Installed worker/CLI detached')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Missing control case')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Control case failed')
    require(all(g['cleanup'][k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')) and g['control_directory_removed'] is True,'Control cleanup failed')
    require({'test_dhcp_control.ControlTests.'+n for n in ('test_worker_required_and_writer_owns_hold_initial_and_sticky_decision','test_only_exact_uid_can_propose_no_operator_or_proof_injection','test_pause_reset_resume_are_separate_and_old_operations_reject','test_ACK_during_resume_persistence_repauses_and_quarantines','test_resume_expiring_during_save_cannot_report_success','test_operation_receipts_bounded_durable_and_replay_rejected','test_budget_latch_advances_revision_and_invalidates_old_operator')}<=set(v['native_unit']['tests']),'Control tests missing')
    ds={c['name']:c['details'] for c in g['cases']}
    d=ds['real_unprivileged_worker_and_kernel_boundary'];c=d['credentials']
    require([int(n) for n in c['Uid'].split()]==[61001]*4 and [int(n) for n in c['Gid'].split()]==[61001]*4 and c['NoNewPrivs']=='1' and all(int(c[k],16)==0 for k in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')),'Worker is not capability-free UID')
    require(d['denials']['uid']==61001 and all(d['denials'][k] is True for k in ('raw_socket_denied','journal_denied','route_denied','event_socket_denied')),'Kernel boundary missing')
    require(d['before']['state']['active'] is None and d['before']['state']['history']==[],'Writer selected without a worker')
    automatic.chosen(d['after'],'A');require(len(d['after']['state']['history'])==1 and traffic(d['client'],'A'),'Worker initial selection failed')
    d=ds['writer_rejects_rogue_worker'];require(len(d['rejections'])==6 and all(r['reply']['ok'] is False for r in d['rejections']) and d['rejections'][-1]['uid']==61002 and d['rejections'][-1]['gid']==61001 and d['rejections'][-1]['reply'].get('error')=='PermissionError','Wrong peer or forged proposal admitted')
    require(d['before']['state']['active']==d['after']['state']['active'] and d['before']['state']['history']==d['after']['state']['history'] and d['before']['state']['operations']==d['after']['state']['operations'],'Rejected worker changed durable state')
    d=ds['pause_stale_resume_and_safety_withdrawal'];require(d['pause']['exit_code']==0 and d['pause']['answer']['status']['paused'] is True and d['stale_resume']['exit_code']!=0 and d['stale_resume']['answer']['ok'] is False,'Pause/stale resume failed')
    require(d['withdrawn']['state']['paused'] is True and d['withdrawn']['state']['active'] is None and d['withdrawn']['state']['links']['A']['state']=='DOWN' and traffic(d['fallback'],'B') and d['blocked']['ok'] is False,'Pause blocked withdrawal or LAN borrowed main')
    d=ds['absent_worker_no_bypass_then_latch'];require(d['resume']['exit_code']==0 and d['absent']['runtime']['as_of']>=d['absent_start']+1 and d['absent']['state']['active'] is None and d['absent']['state']['paused'] is False and d['absent']['state']['latched'] is False and d['absent']['runtime']['automatic']['enabled'] is True,'Writer bypassed absent worker')
    require(d['latched']['state']['latched'] is True and d['latched']['state']['active'] is None and len(d['latched']['state']['history'])==1 and d['latched']['state']['revision']>d['absent']['state']['revision'],'Proposal bypassed budget or latch token stayed current')
    d=ds['explicit_reset_resume_new_lease_authority'];require(d['pause']['exit_code']==0 and d['bad_resume']['exit_code']!=0 and d['no_ack']['exit_code']!=0 and d['before_reset']['state']['paused'] is True and d['before_reset']['state']['latched'] is True and len(d['before_reset']['state']['history'])==1,'Resume/reset implicitly cleared latch')
    r=d['reset_state'];require(d['reset']['exit_code']==0 and r['state']['paused'] is True and r['state']['latched'] is False and r['state']['history']==[] and r['state']['active'] is None,'Reset forwarded or unpaused')
    n=d['renewed'];b=n['state']['links']['B'];require(n['state']['paused'] is True and n['state']['active'] is None and b['generation']>r['state']['links']['B']['generation'] and b['event_sequence']>r['state']['links']['B']['event_sequence'] and b['good']>=2 and b['until']-5>=b['last_event'],'Paused ACK reused old health/authority')
    require(d['resume']['exit_code']==0 and d['stale_pause']['exit_code']!=0 and not d['final']['state']['paused'] and d['final']['state']['active']==d['after']['state']['active'],'Stale operator overwrote new state')
    automatic.chosen(d['final'],'B');admitted(d['final'],d['transaction']);require(len(d['final']['state']['history'])==1 and traffic(d['client'],'B'),'Resumed B selection/deadline failed')
    ops=d['final']['state']['operations'];require([e['kind'] for e in ops]==['pause','resume','pause','reset-budget','resume'] and all(e['uid']==0 and e['outcome']=='APPLIED' for e in ops) and len({e['id'] for e in ops})==len(ops),'Operator receipts missing/forged')
    for reply,kind in ((d['pause'],'pause'),(d['reset'],'reset-budget'),(d['resume'],'resume')):
        receipt=reply['answer']['status']['operations'][-1];require(receipt['kind']==kind and receipt in ops,'CLI receipt detached')
    require(d['rss_kib']['writer']>0 and d['rss_kib']['worker']>0,'Worker/writer RSS missing')
    require(all(g['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'Control probes borrowed WAN')
    return True

def controls(v):
    inherited=automatic.controls(regression_view(v))
    def case(name,fn):return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==name))
    changes=[lambda x:x['guest'].update(worker_file_sha256='0'*64),lambda x:x['guest'].update(control_directory_removed=False),lambda x:x['guest']['cases'].pop(),case('real_unprivileged_worker_and_kernel_boundary',lambda d:d['credentials'].update(Uid='0 0 0 0')),case('real_unprivileged_worker_and_kernel_boundary',lambda d:d['credentials'].update(CapEff='1')),case('real_unprivileged_worker_and_kernel_boundary',lambda d:d['denials'].update(route_denied=False)),case('real_unprivileged_worker_and_kernel_boundary',lambda d:d['denials'].update(event_socket_denied=False)),case('writer_rejects_rogue_worker',lambda d:d['rejections'][0]['reply'].update(ok=True)),case('writer_rejects_rogue_worker',lambda d:d['rejections'][-1].update(uid=61001)),case('pause_stale_resume_and_safety_withdrawal',lambda d:d['stale_resume'].update(exit_code=0)),case('pause_stale_resume_and_safety_withdrawal',lambda d:d['blocked'].update(ok=True)),case('pause_stale_resume_and_safety_withdrawal',lambda d:d['fallback']['response'].update(peer='10.99.1.1')),case('absent_worker_no_bypass_then_latch',lambda d:d['absent']['state'].update(paused=True)),case('absent_worker_no_bypass_then_latch',lambda d:d['latched']['state'].update(latched=False)),case('explicit_reset_resume_new_lease_authority',lambda d:d['reset_state']['state'].update(paused=False)),case('explicit_reset_resume_new_lease_authority',lambda d:d['renewed']['state']['links']['B'].update(good=0)),case('explicit_reset_resume_new_lease_authority',lambda d:d['stale_pause'].update(exit_code=0)),case('explicit_reset_resume_new_lease_authority',lambda d:d['final']['state'].update(operations=[]))]
    changes += [lambda x:x['guest'].update(client_build={}),lambda x:x['guest'].update(client_binary_sha256='0'*64),lambda x:x['guest'].update(client_config_sha256='0'*64)]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted control receipt accepted')
    return dict(passed=True,rejected=inherited['rejected']+len(changes),automatic=inherited['rejected'],control=len(changes))

def render(v):
    value=automatic.render(v).replace('Uplinkstead automatic dual-DHCP selection','Uplinkstead dual-DHCP privilege and operator boundary').replace('Automatic dual-DHCP foreground service','Dual-DHCP privilege and operator boundary')
    return value.replace('<h2>Complete JSON evidence</h2>','<p>The table lists control cases. The nested regression JSON contains the separate nine-case automatic-service suite. Capability-free policy worker; trusted privileged writer/client/capture. No installed-service/reboot qualification.</p><h2>Complete JSON evidence</h2>')
