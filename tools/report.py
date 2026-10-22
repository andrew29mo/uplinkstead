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
CASES = {'pinned_healthy_probes', 'probe_blackhole_missing_route_link_down', 'binding_error_unknown', 'lan_scope_new_tls_and_internal_exclusion', 'external_rpdb_conflict_and_preservation', 'output_success_does_not_prove_forwarding', 'strict_rp_filter_contract', 'routed_without_nat_and_provisioned_return_path', 'delayed_old_operation_rejected', 'live_old_writer_blocks_takeover', 'inherited_mutation_helper_lock', 'sigkill_intent_route_and_receipt_boundaries', 'real_probe_failover_flapping_and_budget', 'single_real_target_failure', 'link_down_owned_route_reconstruction','inverted_rpdb_rules_rejected','missing_local_lookup_rejected','expired_health_before_mutation','malformed_target_quorum'}

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
    restart = v['reboot']
    require(restart['passed'] is True and restart['orderly_vm_restart'] is True and (restart['power_loss_tested'] is False))
    require(restart['before']['before_boot'] != restart['after']['boot'] == restart['pre_agent_journal']['boot'])
    require(restart['before']['pending'] == restart['pre_agent_journal']['pending'])
    require(restart['pre_agent_journal']['pending']['target'] == 'B')
    require(restart['after']['selected'] == 'B' and restart['after']['pending'] is None and (restart['after']['latched'] is True))
    require(restart['after']['request']['ok'] is True and restart['after']['request']['result']['peer'] == '10.99.2.1')
    require(restart['after']['first_tick']['health'] == {'A': 'RECOVERING', 'B': 'RECOVERING'})
    require(all((v['cleanup'][k] is True for k in ('passed', 'root_network_unchanged', 'namespaces_removed', 'units_removed'))))
    require(guest['service_source_sha256'] == v['source']['deploy/uplinkstead.service'])
    text=(ROOT/'deploy/uplinkstead.service').read_text().replace('/etc/uplinkstead/config.json','/opt/uplinkstead/config.json').replace('/var/lib/uplinkstead','/opt/uplinkstead/state')
    text=text.replace('[Service]','[Service]\nWorkingDirectory=/opt/uplinkstead/source\nNetworkNamespacePath=/run/netns/us_r')
    text=text.replace('[Unit]','[Unit]\nRequires=uplinkstead-fixture.service uplinkstead-fixture-server.service\nAfter=uplinkstead-fixture.service uplinkstead-fixture-server.service')
    require(guest['installed_unit_sha256']==hashlib.sha256(text.encode()).hexdigest())
    require(re.fullmatch(r'VmRSS:\s+[1-9][0-9]* kB',restart['after']['rss_snapshot']) is not None)
    require(restart['after']['first_tick']['boot']==restart['after']['boot'])
    require(v['cleanup']['root_before_sha256'] == v['cleanup']['root_after_sha256'])
    restart_props = lambda text: dict((x.split('=', 1) for x in text.splitlines() if '=' in x))
    old = restart_props(restart['before']['process_restart_before'])
    new = restart_props(restart['before']['process_restart_after'])
    require(old['InvocationID'] != new['InvocationID'] and int(old['MainPID']) > 0 and (int(new['MainPID']) > 0))
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

def render(v):
    try:
        verify(v)
        passed = True
    except (AssertionError, KeyError, TypeError, ValueError):
        passed = False
    rows = ''.join(('<tr><td>' + html.escape(x['name']) + '</td><td>' + ('PASS' if x.get('passed') else 'FAIL') + '</td><td>' + format(x['seconds'], '.3f') + '</td></tr>' for x in v.get('guest', {}).get('cases', [])))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Uplinkstead exploration evidence</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 20px;color:#182536}table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f7;padding:16px}h1{color:#224d62}</style><h1>Uplinkstead technical explorations</h1><p><b>' + ('PASS' if passed else 'INCOMPLETE / FAIL') + '</b> · ' + html.escape(v.get('run_id', '')) + '</p><p>Isolated Linux ARM64 VM. Scenario seconds include orchestration and validation; they are not failover latency. RSS is a process snapshot, not peak or whole-VM memory. Orderly stop/start only; sudden power loss, boot-zero-gap and physical uplinks are untested.</p><table><thead><tr><th>Scenario</th><th>Result</th><th>Orchestration seconds</th></tr></thead><tbody>' + rows + '</tbody></table><h2>Complete retained evidence</h2><pre>' + html.escape(json.dumps(v, indent=2, allow_nan=False)) + '</pre></html>\n'

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
