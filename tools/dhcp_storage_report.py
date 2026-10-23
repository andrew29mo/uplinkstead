"""Storage fault evidence is non-durable quarantine, never a successful mutation."""
import copy,html,math
from tools import dhcp_systemd_report as installed
from tools.dhcp_stage1_report import require

def verify(v):
    installed.verify(v);require(v['syntax_checked'] is True,'Source syntax not checked');s=v['guest']['storage']
    require(s['passed'] is True and s['volume_unmounted'] is True and s['loop_detached'] is True,'Storage/volume cleanup failed')
    require(s['volume']==dict(bytes=32*1024*1024,filesystem='ext4',root_reserve_percent=0),'Unexpected storage fault scope')
    require(v['native_unit']['count']>=273 and {'test_dhcp_storage.StorageTests.'+n for n in ('test_real_sqlite_readonly_retires_and_quarantines_without_commit','test_real_sqlite_full_and_restart_only_capacity_repair','test_competing_readonly_lock_cannot_reach_backend','test_partial_actual_write_uses_both_durable_and_memory_authority','test_scope_failure_is_not_reported_as_success','test_fresh_storage_failure_cannot_invent_durable_ownership','test_failed_first_create_empty_database_recovers_without_invented_authority','test_empty_database_with_sidecar_is_not_treated_as_fresh','test_nonempty_missing_schema_is_not_treated_as_fresh')}<=set(v['native_unit']['tests']),'Missing formal storage tests')
    require(len(s['cases'])==3 and {c['name'] for c in s['cases']}=={'enospc','sqlite_full','readonly'},'Storage cases missing')
    for c in s['cases']:
        kind=c['name'];require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0 and c['triggered_at']<=c['retired_at'],'Storage case failed/time invalid')
        require(all(not r for r in c['routes'].values()) and c['scope_preserved'] is True and c['scope_before']==c['scope_after'] and c['scope_before']['foreign'],'Unsafe scope/withdrawal')
        require(all(c['before'][k]==c['after_fault'][k] for k in ('history','operations','paused','latched','config_hash')),'Fault reset policy/receipts or recorded failed API')
        if kind!='sqlite_full':require(c['before']==c['after_fault'],'Unwritable storage changed durable state')
        elif c['before']!=c['after_fault']:require(c['after_fault']['active'] is None and all(r['current'] is None for r in c['after_fault']['links'].values()) and c['after_fault']['epoch']>c['before']['epoch'],'Capacity cleanup committed unsafe state')
        require(c['denied_after_fault']['exit_code']!=0 and c['traffic']['blocked']['ok'] is False and c['traffic']['fallback']['ok'] is True and c['traffic']['fallback']['response']['peer']=='10.99.2.1','Fault accepted forwarding/operation or invalid witness')
        expected={'enospc':'reserve','sqlite_full':'sqlite_full','readonly':'sqlite_readonly'}[kind]
        proofs=[p for p in c['fault_records'] if p['receipt']['kind']==expected]
        require(proofs,'Storage error not actually observed')
        for p in proofs:
            r=p['receipt'];require(r['quarantined'] is True and r['durable'] is False and r['lock_held'] is True and p['boot']==c['cursor']['_BOOT_ID']==c['before']['boot'].replace('-','') and int(p['at'])>int(c['cursor']['__MONOTONIC_TIMESTAMP']) and p['cursor']!=c['cursor']['__CURSOR'],'False/old quarantine receipt')
            if kind!='enospc':require(r['sqlite_code']&255==({'sqlite_full':13,'readonly':8}[kind]),'No actual SQLite FULL/READONLY')
        if kind=='enospc':require(c['pressure']['write_errno']==28 and c['pressure']['probe_errno']==28 and c['pressure']['free_bytes']<4096,'No real filesystem ENOSPC')
        if kind=='readonly':
            require(c['write_errno']==30 and c['lock_denial']['exit_code']!=0 and c['lock_denial']['lock_blocked'] is True and not c['lock_denial']['receipts'] and c['locked_before']==c['locked_after'] and c['lock_preserved_routes'] is True,'Readonly/lock not qualified')
            require(c['scope_denial']['exit_code']!=0 and any(r['quarantined'] is False and r['lock_held'] is True and 'Foreign' in r['quarantine_error'] for r in c['scope_denial']['receipts']) and c['foreign_before']==c['foreign_after'] and c['foreign_preserved'] is True and any(r.get('type')=='blackhole' and r.get('dst')=='198.19.7.0/24' for r in c['foreign_before']['41202']),'Foreign scope mutated or not challenged')
        else:require(c['attempts'][-1]['exit_code']!=0 and c['attempts'][-1]['answer']['ok'] is False and c['failed']['ActiveState']=='failed','API falsely acknowledged failed storage')
        r=c['recovered'];q=r['ready']['status'];installed.empty(q);installed.stale(r['stale_before']);installed.stale(r['stale_after']);installed.fresh(r['after'],c['old']['state'])
        require(all(q['state'][k]==r['fresh']['state'][k]==c['before'][k] for k in ('paused','latched')) and r['after']['state']['latched']==c['before']['latched'],'Repair cleared pause/latch')
        require((r['resume'] is not None and r['resume']['exit_code']==0 and r['resume']['answer']['ok'] is True) if c['before']['paused'] else r['resume'] is None,'Missing explicit resume or unexpected policy operation')
        require(q['state']['config_hash']==c['before']['config_hash'] and q['state']['operations']==c['before']['operations'] and q['state']['history']==c['before']['history'] and r['after']['state']['history'][:-1]==c['before']['history'] and r['after']['state']['epoch']>c['old']['state']['epoch'] and r['client']['ok'] is True and all(n>0 for n in r['rss_kib'].values()),'Repair reused old authority/reset limits or missing measurements')
    return True

def controls(v):
    inherited=installed.controls(v)
    def case(kind,fn):return lambda x:fn(next(c for c in x['guest']['storage']['cases'] if c['name']==kind))
    changes=[lambda x:x['guest']['storage'].update(passed=False),lambda x:x['guest']['storage'].update(volume_unmounted=False),lambda x:x['guest']['storage'].update(loop_detached=False),case('enospc',lambda c:c['pressure'].update(probe_errno=0)),case('readonly',lambda c:c.update(write_errno=0)),case('sqlite_full',lambda c:c['fault_records'][0]['receipt'].update(sqlite_code=0)),case('enospc',lambda c:c['fault_records'][0]['receipt'].update(durable=True)),case('enospc',lambda c:c['fault_records'][0]['receipt'].update(quarantined=False)),case('enospc',lambda c:c['attempts'][-1]['answer'].update(ok=True)),case('enospc',lambda c:c['traffic']['blocked'].update(ok=True)),case('readonly',lambda c:c['lock_denial'].update(lock_blocked=False)),case('readonly',lambda c:c.update(foreign_preserved=False)),case('sqlite_full',lambda c:c['recovered']['ready']['status']['state'].update(history=[])),case('readonly',lambda c:c['recovered']['stale_after']['replies'][0].update(ok=True))]
    changes += [case('sqlite_full',lambda c:c['recovered']['ready']['status']['state'].update(paused=False)),case('enospc',lambda c:c['recovered']['fresh']['state'].update(latched=True)),case('sqlite_full',lambda c:c['recovered'].update(resume=None))]
    for change in changes:
        b=copy.deepcopy(v);change(b)
        try:verify(b)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted storage evidence accepted')
    return dict(passed=True,rejected=inherited['rejected']+len(changes),regression=inherited['rejected'],storage=len(changes))

def render(v):
    rows=''.join('<tr><td>'+html.escape(c['name'])+'</td><td>'+str(c['passed'])+'</td><td>'+format(c['seconds'],'.3f')+'</td></tr>' for c in v.get('guest',{}).get('storage',{}).get('cases',[]))
    section='<h2>Storage failure cases</h2><p>Bounded ext4 ENOSPC; SQLite page capacity; readonly post-cgroup recovery with a test-only pre-stop barrier. Non-durable quarantine is a failed mutation, not READY or durable success. No power loss or VM reboot qualification.</p><table><tr><th>Case</th><th>Passed</th><th>Seconds</th></tr>'+rows+'</table>'
    return installed.render(v).replace('No VM reboot, power-loss, boot-zero-gap or capacity-exhaustion qualification.','Bounded storage failures are qualified below; no VM reboot, power-loss, boot-zero-gap or capacity-longevity qualification.').replace('Installed dual-DHCP service and writer takeover','Installed dual-DHCP storage failure and recovery').replace('<h2>Complete JSON evidence</h2>',section+'<h2>Complete JSON evidence</h2>')
