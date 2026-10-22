"""Fail-closed verifier and escaped HTML for the DHCP lifecycle evidence."""
import argparse
import copy
import html
import json
from pathlib import Path
from .evidence import fingerprint, manifest
from .report import test_ids

CASES = ['wire_bound_and_pinned_tls', 'wire_renew', 'wire_gateway_change', 'wire_address_change',
         'service_sigkill_restart_and_old_session_fenced', 'blackhole_no_false_health_or_backup_borrow',
         'lease_deadline_with_stalled_client', 'formal_backend_partial_write_recovery']


def require(value, message):
    if not value:raise ValueError(message)


def verify(v):
    require(v['passed'] is True and v['source_changed'] is False, 'run failed/source changed')
    require(v['source_sha256'] == fingerprint(v['source']), 'source fingerprint')
    require(v['stages'] and all(s['exit_code'] == 0 and s['timed_out'] is False for s in v['stages']), 'failed stage')
    require({s['name'] for s in v['stages']} >= {'native', 'start', 'upload', 'linux', 'cases', 'cleanup', 'remove', 'stop'}, 'missing stage')
    a,b=v['native_unit'],v['linux_unit']
    for u in (a,b):
        require(u['passed'] is True and u['count']==len(u['tests']) and len(set(u['tests']))==u['count'] and
                u['count'] >= 91 and u['failures']==u['errors']==u['skipped']==0 and
                u['source_sha256']==v['source_sha256'], 'unit evidence')
    require(a['tests']==b['tests'] and sorted(a['tests'])==test_ids() and a['platform']=='Darwin' and b['platform']=='Linux', 'platform/test correspondence')
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'], 'guest source')
    require([c['name'] for c in g['cases']]==CASES and all(c['passed'] is True and c['seconds']>=0 for c in g['cases']), 'cases')
    c={x['name']:x['details'] for x in g['cases']}
    bound=c[CASES[0]];require(bound['state']['healthy'] and bound['state']['current']['ip']=='192.0.2.2' and
                            bound['request']['ok'] and bound['request']['response']['peer']=='10.99.1.1', 'bound path')
    require(not c[CASES[1]]['state']['healthy'] and c[CASES[1]]['after_healthy']['healthy'], 'renew health invalidation')
    require(c[CASES[2]]['state']['current']['gateway']=='192.0.2.5' and not c[CASES[2]]['state']['healthy'], 'gateway invalidation')
    require(c[CASES[3]]['before']['current']['ip']=='192.0.2.2' and c[CASES[3]]['current']['current']['ip']=='192.0.2.3' and
            not c[CASES[3]]['current']['healthy'], 'address invalidation')
    require(c[CASES[4]]['old_session_rejected'] and c[CASES[4]]['new_session'] and c[CASES[4]]['state']['healthy'] and
            c[CASES[4]]['state']['current']['ip']=='192.0.2.3', 'restart/stale event')
    require(not c[CASES[5]]['request']['ok'] and c[CASES[5]]['backup_packets_before']==c[CASES[5]]['backup_packets_after']==0, 'borrowed blackhole')
    require(c[CASES[6]]['current']['current'] is None and not c[CASES[6]]['current']['healthy'] and
            not c[CASES[6]]['request']['ok'] and c[CASES[6]]['backup_packets']==0 and
            c[CASES[6]]['client_stalled'] is True and c[CASES[6]]['observed']>=c[CASES[6]]['deadline'], 'expiry borrowed/healthy')
    require(all(c[CASES[7]].get(k) is True for k in ('fault_after_actual_write','intent_retained','recovered_unverified','owned_addresses_removed','owned_tables_empty')), 'backend recovery')
    require(g['service_source_sha256']==v['source']['deploy/uplinkstead-dhcp.service'], 'service source')
    require(g['power_loss_tested'] is False and g['orderly_vm_restart_tested'] is False, 'untested restart claim')
    require(all(v['cleanup'].get(k) is True for k in ('passed','root_network_unchanged','namespaces_removed','unit_removed')) and
            v['snapshot_removed'] is True and v['vm_final']=='Stopped', 'cleanup')


def controls(v):
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),
             lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),
             lambda x:x['linux_unit'].update(source_sha256='wrong'),lambda x:x['guest']['cases'].pop(),
             lambda x:x['guest']['cases'][1]['details']['state'].update(healthy=True),
             lambda x:x['guest']['cases'][5]['details'].update(backup_packets_after=1),
             lambda x:x['guest']['cases'][6]['details']['current'].update(healthy=True),
             lambda x:x['guest'].update(power_loss_tested=True),lambda x:x.update(vm_final='Running'),
             lambda x:x['cleanup'].update(root_network_unchanged=False)]
    for change in changes:
        bad=copy.deepcopy(v);change(bad)
        try:verify(bad)
        except (ValueError,KeyError,TypeError):continue
        raise ValueError('Verifier accepted corrupted evidence')
    return len(changes)


def render(v):
    return ('<!doctype html><meta charset="utf-8"><title>Uplinkstead DHCP lifecycle evidence</title>'
            '<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
            '<h1>Single DHCP uplink lifecycle</h1><p>Controlled Linux VM; real DHCP and installed service. '
            'Case times include fixture waits and DHCP protocol timers; not failover SLOs. RSS is a process snapshot, '
            'not peak or whole-VM memory. No VM reboot, power-loss or physical ISP claim.</p>'
            '<pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre>')


def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args()
    v=json.loads((a.directory/'evidence.json').read_text());verify(v);n=controls(v)
    require(v['source']==manifest(), 'Evidence is historical; current source differs')
    require((a.directory/'report.html').read_text()==render(v),'HTML differs from JSON')
    print(json.dumps(dict(passed=True,run_id=v['run_id'],controls=n)))


if __name__=='__main__':main()
