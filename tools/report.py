"""Fail-closed evidence verifier and deterministic, escaped HTML renderer."""
import argparse
import copy
import html
import json
from pathlib import Path
import unittest
from .evidence import manifest,fingerprint

CASES={'pinned_healthy_probes','probe_blackhole_missing_route_link_down','binding_error_unknown',
       'lan_scope_new_tls_and_internal_exclusion','external_rpdb_conflict_and_preservation',
       'output_success_does_not_prove_forwarding','strict_rp_filter_contract',
       'routed_without_nat_and_provisioned_return_path','delayed_old_operation_rejected',
       'live_old_writer_blocks_takeover','inherited_mutation_helper_lock',
       'sigkill_intent_route_and_receipt_boundaries','real_probe_failover_flapping_and_budget',
       'single_real_target_failure','link_down_owned_route_reconstruction'}


def test_ids():
    def walk(t):
        if isinstance(t,unittest.TestSuite):return [i for x in t for i in walk(x)]
        return [t.id()]
    return sorted(walk(unittest.defaultTestLoader.discover('tests')))


def verify(v,source=None,ids=None):
    expected=fingerprint(source) if source is not None else v['source_sha256']
    assert v['passed'] is True and v['source_changed'] is False
    assert fingerprint(v['source'])==v['source_sha256']==expected
    assert v['vm_initial']=='Stopped' and v['vm_final']=='Stopped' and v['snapshot_removed'] is True
    required={'native-unit','vm-start','upload','setup','linux-unit','cases','prepare','vm-orderly-stop','vm-restart','after','cleanup','remove','vm-stop'}
    stages=v['stages'];assert len({x['name'] for x in stages})==len(stages)
    assert required <= {x['name'] for x in stages}
    assert all(x['exit_code']==0 and x['timed_out'] is False and x['seconds']>=0 for x in stages)
    native,linux=v['native_unit'],v['linux_unit']
    assert native['platform']=='Darwin' and linux['platform']=='Linux'
    assert native['tests']==linux['tests'] and len(native['tests'])==len(set(native['tests']))
    if ids is not None:assert sorted(native['tests'])==sorted(ids)
    for r in (native,linux):
        assert r['passed'] is True and r['count']==len(r['tests']) and r['count']>0
        assert r['failures']==r['errors']==r['skipped']==0 and r['source_sha256']==expected
    guest=v['guest'];assert guest['passed'] is True and guest['source_sha256']==expected
    rows=guest['cases'];assert {r['name'] for r in rows}==CASES and len(rows)==len(CASES)
    assert all(r['passed'] is True and r['seconds']>=0 for r in rows)
    d={r['name']:r['details'] for r in rows}
    for r in d['probe_blackhole_missing_route_link_down']:
        assert r['wrong_egress_packets']==0 and r['terminal_lookup_rejected'] is True
        assert r['blackhole'][0]==r['missing_route'][0]==r['link_down'][0]==0 and r['other'][0]==3
    assert len(d['probe_blackhole_missing_route_link_down'])==2
    assert d['binding_error_unknown'][0] is None
    for r in d['binding_error_unknown'][1]:assert r['infrastructure'] is True and r['ok'] is False
    scope=d['lan_scope_new_tls_and_internal_exclusion']
    for k,peer in [('lan_A','10.99.1.1'),('lan_B','10.99.2.1'),('host_before','10.99.1.1'),('host_after','10.99.1.1'),('other_before','10.99.1.1'),('other_after','10.99.1.1')]:
        assert scope[k]['ok'] and scope[k]['result']['peer']==peer
    assert scope['main_unchanged'] is True
    assert all(d['external_rpdb_conflict_and_preservation'].values())
    assert d['output_success_does_not_prove_forwarding']['exit_probe_successes']==3
    assert d['output_success_does_not_prove_forwarding']['lan_request']['ok'] is False
    assert d['single_real_target_failure'][0]==2
    assert d['delayed_old_operation_rejected']['rejected_exit']!=0
    assert d['live_old_writer_blocks_takeover']['successor_blocked_while_owner_alive'] is True
    assert all(d['inherited_mutation_helper_lock'].values())
    crash=d['sigkill_intent_route_and_receipt_boundaries'];assert len(crash)==3
    assert {r['boundary']:r['recovered_selected'] for r in crash}=={'before-route':'A','after-route':'B','before-complete':'B'}
    flap=d['real_probe_failover_flapping_and_budget'];assert flap['latched'] is True and len(flap['transitions'])==3
    assert any(r['state']=='DEGRADED_LATCHED' for r in flap['rounds'])
    restart=v['reboot'];assert restart['passed'] is True and restart['orderly_vm_restart'] is True and restart['power_loss_tested'] is False
    assert restart['before']['before_boot']!=restart['after']['boot']==restart['pre_agent_journal']['boot']
    assert restart['before']['pending']==restart['pre_agent_journal']['pending']
    assert restart['pre_agent_journal']['pending']['target']=='B'
    assert restart['after']['selected']=='B' and restart['after']['pending'] is None and restart['after']['latched'] is True
    assert restart['after']['request']['ok'] is True and restart['after']['request']['result']['peer']=='10.99.2.1'
    assert restart['after']['first_tick']['health']=={'A':'RECOVERING','B':'RECOVERING'}
    assert all(v['cleanup'][k] is True for k in ('passed','root_network_unchanged','namespaces_removed','units_removed'))
    assert guest['service_source_sha256']==v['source']['deploy/uplinkstead.service']
    assert v['cleanup']['root_before_sha256']==v['cleanup']['root_after_sha256']
    restart_props=lambda text:dict(x.split('=',1) for x in text.splitlines() if '=' in x)
    old=restart_props(restart['before']['process_restart_before'])
    new=restart_props(restart['before']['process_restart_after'])
    assert old['InvocationID']!=new['InvocationID'] and int(old['MainPID'])>0 and int(new['MainPID'])>0
    recovery=d['link_down_owned_route_reconstruction']
    assert recovery['actual_route_loss_reconciled'] is True and recovery['probe_after_link_up'][0]==3
    assert recovery['backup_request']['ok'] is True and recovery['selection_remains_B'] is True
    return True


def controls(v,source,ids):
    mutations=[('failed_stage',lambda x:x['stages'][0].update(exit_code=1)),
               ('timeout',lambda x:x['stages'][0].update(timed_out=True)),
               ('missing_case',lambda x:x['guest']['cases'].pop()),
               ('missing_test',lambda x:x['linux_unit']['tests'].pop()),
               ('source_mismatch',lambda x:x['guest'].update(source_sha256='bad')),
               ('fake_reboot',lambda x:x['reboot']['after'].update(boot=x['reboot']['before']['before_boot'])),
               ('shutdown_rollback',lambda x:x['reboot']['pre_agent_journal'].update(pending=None)),
               ('cleanup_failed',lambda x:x['cleanup'].update(root_network_unchanged=False)),
               ('vm_running',lambda x:x.update(vm_final='Running')),
               ('power_loss_claim',lambda x:x['reboot'].update(power_loss_tested=True))]
    rejected=[]
    for name,change in mutations:
        trial=copy.deepcopy(v);change(trial)
        try:verify(trial,source,ids)
        except (AssertionError,KeyError,TypeError,ValueError):rejected.append(name)
        else:raise AssertionError('Report accepted corruption: '+name)
    return rejected


def render(v):
    try:verify(v);passed=True
    except (AssertionError,KeyError,TypeError,ValueError):passed=False
    rows=''.join('<tr><td>'+html.escape(x['name'])+'</td><td>'+('PASS' if x.get('passed') else 'FAIL')+'</td><td>'+format(x['seconds'],'.3f')+'</td></tr>' for x in v.get('guest',{}).get('cases',[]))
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Uplinkstead exploration evidence</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:0 20px;color:#182536}table{border-collapse:collapse;width:100%}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f7;padding:16px}h1{color:#224d62}</style><h1>Uplinkstead technical explorations</h1><p><b>'+('PASS' if passed else 'INCOMPLETE / FAIL')+'</b> · '+html.escape(v.get('run_id',''))+'</p><p>Isolated Linux ARM64 VM. Scenario seconds include orchestration and validation; they are not failover latency. RSS is a process snapshot, not peak or whole-VM memory. Orderly stop/start only; sudden power loss, boot-zero-gap and physical uplinks are untested.</p><table><thead><tr><th>Scenario</th><th>Result</th><th>Orchestration seconds</th></tr></thead><tbody>'+rows+'</tbody></table><h2>Complete retained evidence</h2><pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre></html>\n'


def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args()
    v=json.loads((a.directory/'evidence.json').read_text());verify(v,manifest(),test_ids())
    assert (a.directory/'report.html').read_text()==render(v)
    print(json.dumps(dict(passed=True,run_id=v['run_id'],report_controls=len(controls(v,manifest(),test_ids())))))
if __name__=='__main__':main()
