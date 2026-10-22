"""Fail-closed evidence verifier and deterministic, escaped HTML renderer."""
import argparse
import copy
import html
import json
from pathlib import Path
import unittest
from .evidence import ROOT, manifest, fingerprint
from uplinkstead.policy import Policy,Settings
import hashlib
import re
CASES = {'pinned_healthy_probes', 'probe_blackhole_missing_route_link_down', 'binding_error_unknown', 'lan_scope_new_tls_and_internal_exclusion', 'external_rpdb_conflict_and_preservation', 'output_success_does_not_prove_forwarding', 'strict_rp_filter_contract', 'routed_without_nat_and_provisioned_return_path', 'delayed_old_operation_rejected', 'live_old_writer_blocks_takeover', 'inherited_mutation_helper_lock', 'sigkill_intent_route_and_receipt_boundaries', 'real_probe_failover_flapping_and_budget', 'single_real_target_failure', 'link_down_owned_route_reconstruction','inverted_rpdb_rules_rejected','missing_local_lookup_rejected','expired_health_before_mutation','malformed_target_quorum','mvp_privilege_boundary','mvp_safe_lifecycle_and_resume','mvp_storage_bounds','mvp_lifecycle_failure_recovery','mvp_identical_schedule_benchmark','mvp_bounded_restart','mvp_oversized_peer_quorum','mvp_delayed_same_selected_resume'}

def require(condition, message='Evidence validation failed'):
    if not condition:
        raise AssertionError(message)


def test_ids():

    def walk(t):
        if isinstance(t, unittest.TestSuite):
            return [i for x in t for i in walk(x)]
        return [t.id()]
    return sorted(walk(unittest.defaultTestLoader.discover('tests')))

def verify_cycle_trace(rows):
    require(rows and [r['round'] for r in rows]==list(range(len(rows))))
    first=rows[0]
    p=Policy(Settings(),first['config_hash'],first['boot'])
    selected=first['before'];transitions=[]
    for row in rows:
        require(row['before']==selected and row['boot']==p.boot and row['config_hash']==p.hash)
        for link in ('A','B'):
            observation=row['probes'][link]
            require(0 <= observation['started'] <= observation['finished'] <= row['decision_at'])
            samples=observation['results'];require(len(samples)==3)
            require(all(r['link']==link and type(r['ok']) is bool and type(r['infrastructure']) is bool for r in samples))
            require(observation['finished']-observation['started']+0.001 >= max(r['seconds'] for r in samples))
            count=None if any(r['infrastructure'] for r in samples) else sum(r['ok'] for r in samples)
            require(observation['successes']==count)
            p.observe(link,row['round'],observation['started'],observation['finished'],observation['finished'],count,p.hash,p.boot)
        target,state=p.candidate(selected,row['decision_at'])
        require(row['target']==target and row['state']==state and row['latched']==p.latched)
        require(row['health']=={k:v.state for k,v in p.links.items()})
        if target:
            require(row['proof']==p.proof(target,row['decision_at']))
            entry=row['history'][-1]
            require(entry['boot']==p.boot and row['decision_at'] <= entry['at'] <= row['proof']['expires_at'])
            p.admit(entry['at']);selected=target
            transitions.append(dict(stage=row['stage'],selected=selected))
        else:require(row['proof'] is None)
        require(row['history']==p.history and row['selected']==selected)
        if row['lan_request']['ok']:
            require(row['lan_request']['result']['peer']==('10.99.1.1' if selected=='A' else '10.99.2.1'))
    require(p.latched is True and len(transitions)==3)
    require(any(r['stage']=='A_down' and not r['lan_request']['ok'] for r in rows))
    require(any(r['stage']=='A_down' and r['selected']=='B' and r['lan_request']['ok'] for r in rows))
    require(all(r['selected']=='B' for r in rows if r['stage']=='A_recovers'))
    return transitions


def verify_mvp(d):
    priv=d['mvp_privilege_boundary']
    require(priv['initial_mode']=='DISABLED' and priv['idle_peer_survived'] is True)
    require(len(priv['protocol_rejections'])==4 and all(x is True for x in priv['protocol_rejections']))
    require(priv['writer']['uid']==[0]*4 and priv['worker']['uid'][0]!=0)
    require(int(priv['worker']['cap_eff'],16)==0 and priv['worker']['no_new_privs']=='1')
    require(all(priv[k] is True for k in ('worker_operator_denied','foreign_peer_denied','state_read_denied','direct_mutation_denied','main_unchanged')))
    for k in ('writer','worker'):require(priv[k]['rss_kib']>0 and priv[k]['pid']>0)
    life=d['mvp_safe_lifecycle_and_resume']
    require(life['disabled_mode']=='DISABLED' and life['enabled_mode']=='PAUSED' and life['restarted_mode']=='ENABLED')
    require(life['paused_selected']=='A' and life['manual_selected']=='B')
    require(all(life[k] is True for k in ('premature_resume_denied','stale_revision_denied','retained_route_while_stopped','epoch_changed','stale_epoch_denied','main_unchanged')))
    storage=d['mvp_storage_bounds']
    require(storage['events']==128 and storage['page_count']<=storage['max_pages']==2048 and storage['page_size']==4096)
    require(storage['low_space_blocked'] is True and storage['selected_unchanged'] is True)
    failure=d['mvp_lifecycle_failure_recovery']
    require(set(failure)=={'disable_write_failure_recovered','partial_enable_recovered_paused','real_helper_timeout_reaped','sqlite_write_failure_no_mutation'})
    require(all(v is True for v in failure.values()))
    restart=d['mvp_bounded_restart']
    require(len(restart['invocations'])==len(set(restart['invocations']))==3 and restart['failed_result'] in ('signal','start-limit-hit'))
    require(restart['limit_message_observed'] is True and len(restart['no_writer_samples'])==8 and all(x is True for x in restart['no_writer_samples']))
    require(restart['no_live_writer'] is True and restart['manual_reset_recovered'] is True)
    large=d['mvp_oversized_peer_quorum']
    require(large['invocation_unchanged'] is True and large['optional_peer_bytes']==12000 and large['wire_body_under_limit'] is True)
    require(large['selected']=='B' and large['request']['ok'] is True and large['request']['result']['peer']=='10.99.2.1')
    event=large['quorum_event'];require(event['name']=='service_sample' and len(json.dumps(event).encode())<32768)
    for link in ('A','B'):
        observation=event['probes'][link];samples=observation['results']
        require(observation['successes']==2 and len(samples)==3 and sum(r['ok'] for r in samples)==2)
        require(samples[0]['ok'] is False and samples[0]['infrastructure'] is False and samples[0]['error']=='ValueError')
    delayed=d['mvp_delayed_same_selected_resume']
    require(delayed['blocked_at']>delayed['proof']['expires_at'])
    require(delayed['mode']==delayed['durable_mode']=='PAUSED' and delayed['selected']==delayed['reopened_selected']=='B' and delayed['pending'] is None)
    verify_benchmark(d['mvp_identical_schedule_benchmark'])


def verify_benchmark(bench):
    require(bench['vm_only'] is True and bench['repeated_trials'] is False)
    require(bench['schedule']==dict(requests=20,interval=.5,blackhole_from_index=4))
    require([m['mode'] for m in bench['modes']]==['fixed_primary','automatic'])
    for m in bench['modes']:
        before,after=m['processes_before'],m['processes_after']
        require(set(before)==set(after)=={'writer','worker'})
        for role in before:
            require(before[role]['pid']==after[role]['pid']>0 and before[role]['invocation']==after[role]['invocation'] and re.fullmatch('[0-9a-f]{32}',before[role]['invocation']) is not None)
            require(m['rss_kib'][role]==after[role]['rss_kib']>0)
        fault=m['fault_window'];require(2<=fault['started']<=fault['finished']<=m['elapsed'])
        require(0<m['journal_bytes_before']<=8388608)
        rows=m['rows'];require(len(rows)==20 and [r['index'] for r in rows]==list(range(20)))
        require([r['scheduled'] for r in rows]==[i*.5 for i in range(20)])
        require(all(0<=r['scheduled']<=r['started']<=r['finished']<=m['elapsed'] for r in rows))
        require(all(r['ok'] is True and r['peer']=='10.99.1.1' for r in rows[:4]))
        require(all(r['started']>=fault['finished'] for r in rows[4:]))
        for r in rows:
            require(abs(r['latency']-(r['finished']-r['started']))<1e-8)
            require(abs(r['end_to_end']-(r['finished']-r['scheduled']))<1e-8)
            require(r['late']==(r['started']-r['scheduled']>.1) and type(r['ok']) is bool)
            expected_peer='10.99.2.1' if m['mode']=='automatic' and r['index']>=4 else '10.99.1.1'
            require(r['peer']==expected_peer if r['ok'] else r['peer'] is None)
        require(m['successes']==sum(r['ok'] for r in rows) and m['failures']==20-m['successes'])
        require(abs(m['throughput']-m['successes']/m['elapsed'])<1e-8)
        require(all(v>0 for v in m['rss_kib'].values()) and 0<m['journal_bytes']<=8388608)
    fixed,auto=bench['modes']
    require(fixed['final_selected']=='A' and all(not r['ok'] for r in fixed['rows'][4:]))
    require(auto['final_selected']=='B' and any(r['ok'] and r['peer']=='10.99.2.1' for r in auto['rows']))


def verify_restart(restart):
    require(restart['passed'] is True and restart['orderly_vm_restart'] is True and (restart['power_loss_tested'] is False))
    require(restart['before']['before_boot'] != restart['after']['boot'] == restart['pre_agent_journal']['boot'])
    require(restart['before']['pending'] == restart['pre_agent_journal']['pending'])
    require(restart['before']['selected_receipt']==restart['pre_agent_journal']['selected']==restart['before']['pending']['before']=='A')
    require(restart['before']['latched_before'] is restart['pre_agent_journal']['latched'] is True)
    require(restart['before']['mode_before']==restart['pre_agent_journal']['mode']==restart['after']['mode']=='ENABLED')
    require(type(restart['before']['epoch_before']) is int and restart['before']['epoch_before']>0 and restart['pre_agent_journal']['epoch']==restart['before']['epoch_before'])
    require(type(restart['after']['epoch']) is int and restart['after']['epoch']>restart['before']['epoch_before'])
    defaults=[r for r in restart['before']['actual_route'] if r['dst']=='default']
    require(len(defaults)==1 and defaults[0]['gateway']=='192.0.2.5' and defaults[0]['dev']=='wanB' and defaults[0]['metric']==100)
    require(restart['pre_agent_journal']['pending']['target'] == 'B')
    require(restart['after']['selected'] == 'B' and restart['after']['pending'] is None and (restart['after']['latched'] is True))
    require(restart['after']['request']['ok'] is True and restart['after']['request']['result']['peer'] == '10.99.2.1')
    require(restart['after']['first_tick']['health'] == {'A': 'RECOVERING', 'B': 'RECOVERING'})
    units=[restart['before']['process_restart_before'],restart['before']['process_restart_after'],restart['after']['unit']]
    ids=[]
    for index,text in enumerate(units):
        rows=[x.split('=',1) for x in text.splitlines() if '=' in x]
        require(len(rows)==len({x[0] for x in rows}))
        props=dict(rows);require(int(props['MainPID'])>0 and re.fullmatch('[0-9a-f]{32}',props['InvocationID']) is not None)
        if index:require(props['ActiveState']=='active')
        ids.append(props['InvocationID'])
    require(len(set(ids))==3)
    require(restart['after']['first_tick']['boot']==restart['after']['boot'])

def verify(v, source=None, ids=None):
    expected = fingerprint(source) if source is not None else v['source_sha256']
    require(v['passed'] is True and v['source_changed'] is False)
    require(fingerprint(v['source']) == v['source_sha256'] == expected)
    require(v['vm_initial'] == 'Stopped' and v['vm_final'] == 'Stopped' and (v['snapshot_removed'] is True))
    required = {'native-unit', 'vm-start', 'upload', 'setup', 'linux-unit', 'cases', 'prepare', 'vm-orderly-stop', 'vm-restart', 'after', 'cleanup', 'remove', 'vm-stop'}
    stages = v['stages']
    require(len({x['name'] for x in stages}) == len(stages))
    require(required <= {x['name'] for x in stages})
    require(all((x['exit_code'] == 0 and x['timed_out'] is False and (x['seconds'] >= 0) for x in stages)))
    (native, linux) = (v['native_unit'], v['linux_unit'])
    require(native['platform'] == 'Darwin' and linux['platform'] == 'Linux')
    require(native['tests'] == linux['tests'] and len(native['tests']) == len(set(native['tests'])))
    if ids is not None:
        require(sorted(native['tests']) == sorted(ids))
    for r in (native, linux):
        require(r['passed'] is True and r['count'] == len(r['tests']) and (r['count'] > 0))
        require(r['failures'] == r['errors'] == r['skipped'] == 0 and r['source_sha256'] == expected)
    guest = v['guest']
    require(guest['passed'] is True and guest['source_sha256'] == expected)
    rows = guest['cases']
    require({r['name'] for r in rows} == CASES and len(rows) == len(CASES))
    require(all((r['passed'] is True and r['seconds'] >= 0 for r in rows)))
    d = {r['name']: r['details'] for r in rows}
    require(set(d['pinned_healthy_probes'])=={'A','B'})
    for link,peer in [('A','10.99.1.1'),('B','10.99.2.1')]:
        count,samples=d['pinned_healthy_probes'][link]
        require(count==3 and len(samples)==3)
        require(all(r['ok'] is True and r['infrastructure'] is False and r['link']==link and r['peer_observed']==peer for r in samples))
    require({r['link'] for r in d['probe_blackhole_missing_route_link_down']}=={'A','B'})
    for r in d['probe_blackhole_missing_route_link_down']:
        require(r['wrong_egress_packets'] == 0 and r['terminal_lookup_rejected'] is True)
        require(r['blackhole'][0] == r['missing_route'][0] == r['link_down'][0] == 0 and r['other'][0] == 3)
    require(len(d['probe_blackhole_missing_route_link_down']) == 2)
    require(d['binding_error_unknown'][0] is None)
    for r in d['binding_error_unknown'][1]:
        require(r['infrastructure'] is True and r['ok'] is False)
    scope = d['lan_scope_new_tls_and_internal_exclusion']
    for (k, peer) in [('lan_A', '10.99.1.1'), ('lan_B', '10.99.2.1'), ('host_before', '10.99.1.1'), ('host_after', '10.99.1.1'), ('other_before', '10.99.1.1'), ('other_after', '10.99.1.1')]:
        require(scope[k]['ok'] and scope[k]['result']['peer'] == peer)
    require(scope['main_unchanged'] is True)
    require(len(scope['internal_route'])==1 and scope['internal_route'][0]['gateway']=='192.0.2.1' and scope['internal_route'][0]['dev']=='wanA')
    for key in ('local_before','local_after'):
        require(scope[key]['ok'] is True and scope[key]['result']['server']=='10.77.0.1' and scope[key]['result']['peer']=='10.77.0.2')
    inverted=d['inverted_rpdb_rules_rejected'];require(len(inverted)==2)
    require(all(r['rejected'] is True and r['no_mutation'] is True and 'not' in r['rule'] for r in inverted))
    local=d['missing_local_lookup_rejected']
    require(local['rejected'] is True and local['no_mutation'] is True and local['local_request_after_fixture_restore']['ok'] is True)
    expired=d['expired_health_before_mutation']
    require(expired['rejected'] is True and expired['uses_agent_cycle'] is True and expired['pre_intent'] is True and expired['selected']=='A' and expired['pending'] is None)
    require(expired['blocked_at']>expired['proof']['expires_at'])
    malformed=d['malformed_target_quorum']
    require(malformed['agent_survived'] is True and malformed['uses_agent_cycle'] is True and malformed['lan_request']['ok'] is True)
    require(len(malformed['rounds'])==4 and all(r['probes']['A']['successes']==2 and r['selected']=='A' for r in malformed['rounds']))
    require(malformed['rounds'][-1]['health']['A']=='HEALTHY')
    require(all(d['external_rpdb_conflict_and_preservation'].values()))
    require(d['output_success_does_not_prove_forwarding']['exit_probe_successes'] == 3)
    require(d['output_success_does_not_prove_forwarding']['lan_request']['ok'] is False)
    require(d['single_real_target_failure'][0] == 2)
    require(d['delayed_old_operation_rejected']['rejected_exit'] != 0)
    require(d['live_old_writer_blocks_takeover']['successor_blocked_while_owner_alive'] is True)
    require(all(d['inherited_mutation_helper_lock'].values()))
    crash = d['sigkill_intent_route_and_receipt_boundaries']
    require(len(crash) == 3)
    require({r['boundary']: r['recovered_selected'] for r in crash} == {'before-route': 'A', 'after-route': 'B', 'before-complete': 'B'})
    flap = d['real_probe_failover_flapping_and_budget']
    require(flap['latched'] is True and len(flap['transitions']) == 3)
    require(flap['uses_agent_cycle'] is True)
    require(verify_cycle_trace(flap['rounds'])==flap['transitions'])
    verify_mvp(d)
    verify_restart(v['reboot'])
    require(all((v['cleanup'][k] is True for k in ('passed', 'root_network_unchanged', 'namespaces_removed', 'units_removed'))))
    require(guest['service_source_sha256'] == v['source']['deploy/uplinkstead.service'])
    text=(ROOT/'deploy/uplinkstead.service').read_text().replace('/etc/uplinkstead/config.json','/opt/uplinkstead/config.json').replace('/var/lib/uplinkstead','/opt/uplinkstead/state')
    text=text.replace('[Service]','[Service]\nWorkingDirectory=/opt/uplinkstead/source\nNetworkNamespacePath=/run/netns/us_r')
    text=text.replace('[Unit]','[Unit]\nRequires=uplinkstead-fixture.service uplinkstead-fixture-server.service\nAfter=uplinkstead-fixture.service uplinkstead-fixture-server.service')
    require(guest['installed_unit_sha256']==hashlib.sha256(text.encode()).hexdigest())
    worker=(ROOT/'deploy/uplinkstead-policy.service').read_text().replace('[Service]','[Service]\nWorkingDirectory=/opt/uplinkstead/source')
    require(guest['policy_unit_sha256']==hashlib.sha256(worker.encode()).hexdigest())
    restart=v['reboot']
    require(re.fullmatch(r'VmRSS:\s+[1-9][0-9]* kB',restart['after']['rss_snapshot']) is not None)
    require(restart['after']['first_tick']['boot']==restart['after']['boot'])
    require(v['cleanup']['root_before_sha256'] == v['cleanup']['root_after_sha256'])
    recovery = d['link_down_owned_route_reconstruction']
    require(recovery['actual_route_loss_reconciled'] is True and recovery['probe_after_link_up'][0] == 3)
    require(recovery['backup_request']['ok'] is True and recovery['selection_remains_B'] is True)
    return True

def controls(v, source, ids):
    mutations = [('failed_stage', lambda x: x['stages'][0].update(exit_code=1)), ('timeout', lambda x: x['stages'][0].update(timed_out=True)), ('missing_case', lambda x: x['guest']['cases'].pop()), ('missing_test', lambda x: x['linux_unit']['tests'].pop()), ('source_mismatch', lambda x: x['guest'].update(source_sha256='bad')), ('fake_reboot', lambda x: x['reboot']['after'].update(boot=x['reboot']['before']['before_boot'])), ('shutdown_rollback', lambda x: x['reboot']['pre_agent_journal'].update(pending=None)), ('cleanup_failed', lambda x: x['cleanup'].update(root_network_unchanged=False)), ('vm_running', lambda x: x.update(vm_final='Running')), ('power_loss_claim', lambda x: x['reboot'].update(power_loss_tested=True))]
    def details(x,name):return next(r['details'] for r in x['guest']['cases'] if r['name']==name)
    mutations += [
      ('false_healthy_probes',lambda x:details(x,'pinned_healthy_probes').update(A=[0,[]])),
      ('internal_route_escape',lambda x:details(x,'lan_scope_new_tls_and_internal_exclusion')['internal_route'][0].update(gateway='192.0.2.5')),
      ('duplicate_borrow_link',lambda x:details(x,'probe_blackhole_missing_route_link_down')[1].update(link='A')),
      ('local_service_escape',lambda x:details(x,'lan_scope_new_tls_and_internal_exclusion')['local_after'].update(ok=False)),
      ('inverted_rule_accepted',lambda x:details(x,'inverted_rpdb_rules_rejected')[0].update(rejected=False)),
      ('expired_health_mutated',lambda x:details(x,'expired_health_before_mutation').update(selected='B')),
      ('malformed_target_crash',lambda x:details(x,'malformed_target_quorum').update(agent_survived=False)),
      ('fabricated_probe_time',lambda x:details(x,'real_probe_failover_flapping_and_budget')['rounds'][0]['probes']['A'].update(started=0,finished=0)),
      ('fake_budget_transition',lambda x:details(x,'real_probe_failover_flapping_and_budget')['rounds'][0].update(target='B')),
      ('unbounded_restart',lambda x:details(x,'mvp_bounded_restart').update(limit_message_observed=False)),
      ('worker_has_netadmin',lambda x:details(x,'mvp_privilege_boundary')['worker'].update(cap_eff='00001000')),
      ('unsafe_resume',lambda x:details(x,'mvp_safe_lifecycle_and_resume').update(premature_resume_denied=False)),
      ('unbounded_events',lambda x:details(x,'mvp_storage_bounds').update(events=1000)),
      ('hidden_request_failure',lambda x:details(x,'mvp_identical_schedule_benchmark')['modes'][0]['rows'].pop()),
      ('changed_arrival_schedule',lambda x:details(x,'mvp_identical_schedule_benchmark')['modes'][1]['rows'][3].update(scheduled=0)),
      ('false_storage_recovery',lambda x:details(x,'mvp_lifecycle_failure_recovery').update(sqlite_write_failure_no_mutation=False)),
      ('reboot_service_dead',lambda x:x['reboot']['after'].update(unit='MainPID=0\nActiveState=failed\nInvocationID=\n')),
      ('pre_agent_receipt_changed',lambda x:x['reboot']['pre_agent_journal'].update(selected='B')),
      ('latch_not_preserved',lambda x:x['reboot']['before'].update(latched_before=False)),
      ('fixed_baseline_wrong_path',lambda x:details(x,'mvp_identical_schedule_benchmark')['modes'][0]['rows'][0].update(peer='10.99.2.1')),
      ('automatic_before_fault_wrong_path',lambda x:details(x,'mvp_identical_schedule_benchmark')['modes'][1]['rows'][0].update(peer='10.99.2.1')),
      ('rss_from_replacement_process',lambda x:details(x,'mvp_identical_schedule_benchmark')['modes'][0]['processes_after']['writer'].update(pid=1)),
      ('fault_after_request',lambda x:details(x,'mvp_identical_schedule_benchmark')['modes'][0]['fault_window'].update(finished=9)),
      ('large_peer_blocks_quorum',lambda x:details(x,'mvp_oversized_peer_quorum')['quorum_event']['probes']['B'].update(successes=0)),
      ('expired_same_target_enabled',lambda x:details(x,'mvp_delayed_same_selected_resume').update(durable_mode='ENABLED')),
      ('wrong_installed_unit',lambda x:x['guest'].update(installed_unit_sha256='bad'))]
    rejected = []
    for (name, change) in mutations:
        trial = copy.deepcopy(v)
        change(trial)
        try:
            verify(trial, source, ids)
        except (AssertionError, KeyError, TypeError, ValueError):
            rejected.append(name)
        else:
            raise AssertionError('Report accepted corruption: ' + name)
    return rejected

def benchmark_html(v):
    cases=v.get('guest',{}).get('cases',[])
    data=next((r['details'] for r in cases if r['name']=='mvp_identical_schedule_benchmark'),None)
    if not data:return ''
    import math
    rows=''
    for m in data['modes']:
        lat=sorted(r['end_to_end'] for r in m['rows'])
        p95=lat[max(0,math.ceil(len(lat)*.95)-1)]
        rows+='<tr><td>'+html.escape(m['mode'])+'</td><td>'+str(m['successes'])+'/'+str(len(lat))+'</td><td>'+format(m['throughput'],'.3f')+'</td><td>'+format(p95*1000,'.1f')+'</td><td>'+str(m['rss_kib']['writer'])+' / '+str(m['rss_kib']['worker'])+'</td><td>'+str(m['journal_bytes'])+'</td></tr>'
    return '<h2>Controlled VM trial</h2><p>All-attempt end-to-end p95 includes failed requests and client-process overhead. One fixed-order trial; no speedup or SLA inference.</p><table><tr><th>Mode</th><th>Successful / attempted</th><th>Useful requests/s</th><th>All-attempt p95 ms</th><th>Writer / worker RSS KiB</th><th>Main DB bytes</th></tr>'+rows+'</table>'


def render(v):
    try:
        verify(v)
        passed = True
    except (AssertionError, KeyError, TypeError, ValueError):
        passed = False
    rows = ''.join(('<tr><td>' + html.escape(x['name']) + '</td><td>' + ('PASS' if x.get('passed') else 'FAIL') + '</td><td>' + format(x['seconds'], '.3f') + '</td></tr>' for x in v.get('guest', {}).get('cases', [])))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Uplinkstead MVP evidence</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 20px;color:#182536}table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f7;padding:16px}h1{color:#224d62}</style><h1>Uplinkstead MVP validation</h1><p><b>' + ('PASS' if passed else 'INCOMPLETE / FAIL') + '</b> · ' + html.escape(v.get('run_id', '')) + '</p><p>Isolated Linux ARM64 VM. Scenario seconds include orchestration and validation; they are not failover latency. RSS is a process snapshot, not peak or whole-VM memory. Orderly stop/start only; sudden power loss, boot-zero-gap and physical uplinks are untested.</p><table><thead><tr><th>Scenario</th><th>Result</th><th>Orchestration seconds</th></tr></thead><tbody>' + rows + '</tbody></table>' + benchmark_html(v) + '<h2>Measurement scope</h2><p>MVP benchmark uses identical open-loop arrival offsets and a fixed fault index. All scheduled attempts, failures and scheduling lateness are retained below. Latency includes the fixture client process and TLS request. Process RSS snapshots exclude whole-VM memory; a single controlled run does not establish a speedup or SLA.</p><h2>Complete retained evidence</h2><pre>' + html.escape(json.dumps(v, indent=2, allow_nan=False)) + '</pre></html>\n'

def main():
    p = argparse.ArgumentParser()
    p.add_argument('directory', type=Path)
    a = p.parse_args()
    v = json.loads((a.directory / 'evidence.json').read_text())
    verify(v, manifest(), test_ids())
    require((a.directory / 'report.html').read_text() == render(v))
    print(json.dumps(dict(passed=True, run_id=v['run_id'], report_controls=len(controls(v, manifest(), test_ids())))))
if __name__ == '__main__':
    main()
