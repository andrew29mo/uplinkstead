"""Same-source installed boot evidence, with strict pre-Agent and policy gates."""
import copy,hashlib,html,json,math
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require
from tools.dhcp_systemd_report import empty,stale,writer_privilege
KINDS=('normal','preserved','paused','latched','capacity')

def verify(v):
    require(v['passed'] is True and v['source_changed'] is False and v['syntax_checked'] is True,'Failed/changed-source run')
    require(fingerprint(v['source'])==v['source_sha256'],'Invalid source fingerprint')
    expected={'native','initial','start','preflight','upload','build','linux','linux-read','install','cleanup','remove','stop','final'}
    for kind in KINDS:expected|={kind+'-'+s for s in ('prepare','stop','between','start','after')}
    require({s['name'] for s in v['stages']}==expected and len(v['stages'])==len(expected),'Missing/duplicate stages')
    require(all(s['exit_code']==0 and s['timed_out'] is False and math.isfinite(s['seconds']) and s['seconds']>=0 for s in v['stages']),'Failed/timed-out stage')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==platform and r['source_sha256']==v['source_sha256'] and r['count']==len(r['tests'])==len(set(r['tests'])) and r['count']>=276 and r['errors']==r['failures']==r['skipped']==0,'Different/failed portable suite')
        require({'test_dhcp_boot.BootTests.'+n for n in ('test_changed_boot_retires_old_authority_and_requires_new_evidence','test_old_boot_budget_cannot_age_out_or_unlock_on_reboot','test_storage_failure_on_new_boot_never_becomes_ready_then_repairs')}<=set(r['tests']),'Formal boot tests missing')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different platform tests')
    i=v['installation'];require(i['passed'] is True and i['client_binary_sha256']==i['client_build']['binary_sha256'],'Client provenance mismatch')
    trigger=i['boot_trigger'];require('OnBootSec=25s' in trigger['timer_text'] and 'Unit=uplinkstead-dual.service' in trigger['timer_text'] and trigger['enabled_target']=='../uplinkstead-dual-boot.timer' and hashlib.sha256(trigger['timer_text'].encode()).hexdigest()==trigger['timer_sha256'],'Boot trigger not qualified')
    for u,row in i['units'].items():require(row['source_sha256']==row['installed_sha256']==v['source']['deploy/'+u],'Installed units changed')
    require(set(i['units'])=={'uplinkstead-dual.service','uplinkstead-dual-policy.service'} and i['worker_file_sha256']==v['source']['uplinkstead/dual_dhcp_worker.py'],'Unit/worker provenance missing')
    require(len(v['cases'])==5 and [c['kind'] for c in v['cases']]==list(KINDS),'Reboot cases missing')
    boots=[]
    for c in v['cases']:
        b=c['before'];p=c['prestart'];old=b['state']['state'];s=c['waiting']['state'];kind=c['kind'];boots.append(c['boot'])
        require(c['passed'] is True and c['source_sha256']==p['source_sha256']==v['source_sha256'] and c['boot']==p['boot']==s['boot']!=b['boot'],'Not a new VM boot/source')
        require(p['writer']['MainPID']=='0' and p['runtime_fault_present'] is False and all(not r for r in p['initial_routes'].values()),'Pre-Agent observation missing or fixture wrote product routes')
        if kind in ('preserved','capacity'):require(p['journal']==b['journal'] and b['shutdown_exec_stop_post']==dict(type='a(sasbttttuii)',data=[]) and 'KillSignal=9' in b['shutdown_fault'],'Shutdown cleanup not excluded')
        if kind=='preserved':require(b['journal']['active'] is not None and all(r['current'] for r in b['journal']['links'].values()),'No retained old allocation to challenge recovery')
        if kind=='normal':require(b['shutdown_exec_stop_post']['data'] and 'uplinkstead.dual_dhcp_stop' in json.dumps(b['shutdown_exec_stop_post']) and p['journal']['active'] is None and all(r['current'] is None for r in p['journal']['links'].values()) and p['journal']['epoch']>b['journal']['epoch'],'Normal stop cleanup not observed')
        require(all(p['journal'][k]==b['journal'][k]==s[k] for k in ('config_hash','history','operations','paused','latched')),'Boot reset policy/history/receipts')
        require(c['ready']['boot_trigger']['Unit']=='uplinkstead-dual.service' and c['ready']['boot_trigger']['LastTriggerUSecMonotonic'] not in ('','0'),'Boot timer did not trigger formal service')
        empty(c['waiting']);require(s['epoch']>old['epoch'] and c['ready']['writer']['InvocationID']!=b['writer']['InvocationID'] and c['ready']['writer']['Type']=='notify','Old writer authority reused')
        require(all(s['links'][k]['session']!=old['links'][k]['session'] and s['links'][k]['generation']>old['links'][k]['generation'] for k in ('A','B')),'Old client authority retained')
        for rows in (c['routes'],):require(all(not r for r in rows.values()),'Forwarding before lease')
        require(c['scope_before']==c['scope_after'] and bool(c['scope_before']['foreign']),'Foreign/main scope changed or no foreign witness')
        for t in (c['traffic'],c['new_lease_traffic']):require(t['blocked']['ok'] is False and t['fallback']['ok'] is True and t['fallback']['response']['peer']=='10.99.2.1','Borrowing/unqualified negative traffic')
        new=c['new_lease_unhealthy']['state'];require(new['active'] is None and all(r['current'] is not None and r['state']!='HEALTHY' for r in new['links'].values()),'New lease inherited healthy selection')
        fresh=c['fresh']['state'];require(all(r['current'] is not None and r['state']=='HEALTHY' and r['good']>=2 and r['session']!=old['links'][k]['session'] and r['generation']>old['links'][k]['generation'] for k,r in fresh['links'].items()),'No fresh quorum')
        for d in (c['stale_before'],c['stale_after']):stale(d);require(d['routes_before']==d['routes_after'],'Stale route mutation')
        if kind in ('paused','latched'):
            require(fresh['active'] is None and fresh['paused']==b['journal']['paused'] is True and fresh['latched']==b['journal']['latched'] and c['policy_blocked']['blocked']['ok'] is False,'Policy lost after health')
            actions=c['intervention'];require([r['kind'] for r in actions]==(['resume_denied','reset-budget','resume'] if kind=='latched' else ['resume']),'Missing explicit policy repair')
            require(all(r['reply']['ok'] is (r['kind']!='resume_denied') for r in actions),'Policy operation failed or unlocked implicitly')
            if kind=='latched':require(b['journal']['latched'] is True and len(b['journal']['history'])==8,'No real budget latch')
        else:require(not c['intervention'],'Unexpected policy reset')
        final=c['final']['state'];require(final['active'] is not None and c['client']['ok'] is True and c['client']['response']['peer']==('10.99.1.1' if final['active']['link']=='A' else '10.99.2.1'),'New data path missing')
        require(final['history']==[dict(boot=c['boot'],at=final['history'][0]['at'])] if kind=='latched' else final['history'][:-1]==b['journal']['history'],'New selection not charged/preserved')
        writer_privilege(c['writer']);w=c['worker'];require(w['uid'][0]>0 and len(set(w['uid']))==1 and all(int(n,16)==0 for n in w['caps'].values()) and w['no_new_privs']=='1' and c['writer']['rss_kib']>0 and w['rss_kib']>0,'Worker privilege/RSS invalid')
        require(all(c['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'DHCP borrowed other WAN')
        ts=c['checkpoints'];require(all(math.isfinite(n) and n>=0 for n in ts.values()) and ts['prestart']<=ts['ready_observed']<=ts['fresh_observed']<=ts['final_observed'] and math.isfinite(c['case_seconds']) and c['case_seconds']>=0,'Invalid observation clock')
        require(c['power_loss_tested'] is False and c['boot_zero_gap_tested'] is False,'Untested claim')
        require(all(c['previous_boot_cleanup'][k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Prior boot cleanup failed')
        if kind=='capacity':
            f=c['capacity'];require(b['pressure']['write_errno']==28 and b['pressure']['free_bytes']<4096 and b['pressure']['api']['exit_code']!=0 and b['pressure']['api']['answer']['ok'] is False,'No real preboot ENOSPC/rejection')
            require(f['failed']['ActiveState']==f['stable']['ActiveState']=='failed' and 1<=int(f['failed']['NRestarts'])<=3 and f['failed']['NRestarts']==f['stable']['NRestarts'] and f['worker']['ActiveState']!='active' and f['denied']['exit_code']!=0 and f['denied']['answer']['ok'] is False and all(not row for row in f['routes'].values()) and f['traffic']['blocked']['ok'] is False and f['traffic']['fallback']['ok'] is True and f['journal']==b['journal'] and f['free_bytes']<4096,'Capacity reboot falsely ready or reset durable state')
            require(f['faults'] and all(r['boot']==c['boot'].replace('-','') and r['message']['kind']=='reserve' and r['message']['lock_held'] is True and r['message']['quarantined'] is True and r['message']['durable'] is False for r in f['faults']),'Missing current boot failed-persistence proof')
    require(len(set(boots))==5,'Repeated boot IDs')
    require(all(v['cleanup'][k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped','fixture_removed','enabled_link_removed','loop_detached','volume_unmounted')) and v['snapshot_removed'] is True and v['vm_final']=='Stopped','Incomplete cleanup')
    return True

def controls(v):
    def case(kind,fn):return lambda x:fn(next(c for c in x['cases'] if c['kind']==kind))
    changes=[lambda x:x.update(source_changed=True),lambda x:x['stages'][0].update(exit_code=1),lambda x:x['stages'][0].update(timed_out=True),lambda x:x['installation']['boot_trigger'].update(timer_text=''),lambda x:x.update(vm_final='Running'),lambda x:x['cleanup'].update(loop_detached=False),lambda x:x['installation']['units']['uplinkstead-dual.service'].update(installed_sha256='0'*64),case('preserved',lambda c:c['prestart']['journal'].update(active=None)),case('preserved',lambda c:c['before']['shutdown_exec_stop_post'].update(data=['not-empty'])),case('normal',lambda c:c.update(boot=c['before']['boot'])),case('normal',lambda c:c['waiting']['state']['links']['A'].update(state='HEALTHY')),case('normal',lambda c:c['traffic']['blocked'].update(ok=True)),case('normal',lambda c:c['new_lease_unhealthy']['state'].update(active=c['final']['state']['active'])),case('normal',lambda c:c['stale_before']['replies'][0].update(ok=True)),case('paused',lambda c:c['fresh']['state'].update(paused=False)),case('latched',lambda c:c['fresh']['state'].update(latched=False)),case('latched',lambda c:c.update(intervention=[])),case('capacity',lambda c:c['capacity']['denied']['answer'].update(ok=True)),case('capacity',lambda c:c['capacity']['faults'][0]['message'].update(durable=True)),case('capacity',lambda c:c['capacity'].update(free_bytes=10000000)),case('normal',lambda c:c.update(power_loss_tested=True)),case('normal',lambda c:c['checkpoints'].update(prestart=1e99))]
    for change in changes:
        b=copy.deepcopy(v);change(b)
        try:verify(b)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted boot evidence accepted')
    return dict(passed=True,rejected=len(changes))

def render(v):
    rows=''.join('<tr><td>'+html.escape(c['kind'])+'</td><td>'+format(c['case_seconds'],'.3f')+'</td><td>'+str(c['writer']['rss_kib'])+'</td><td>'+str(c['worker']['rss_kib'])+'</td></tr>' for c in v.get('cases',[]))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Uplinkstead installed VM reboot recovery</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Installed dual-DHCP orderly VM reboot</h1><p>Passed: '+str(v.get('passed',False))+'</p><p>Actual shipped writer/worker, isolated topology prerequisites. Preserved-journal case uses a labelled runtime-only shutdown override. No sudden power loss, boot-zero-gap, physical WAN, or recovery upper-bound qualification. Post-boot driver seconds include waits, probes and explicit repair; RSS is a Linux VM process snapshot, not peak or macOS comparison.</p><table><tr><th>Case</th><th>Post-boot driver seconds</th><th>Writer RSS KiB</th><th>Worker RSS KiB</th></tr>'+rows+'</table><h2>Complete JSON evidence</h2><pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre></html>'
