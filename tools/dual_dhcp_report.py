"""Fail-closed receipt checks and HTML generated from the identical JSON tree."""
import copy
import hashlib
import html
import json
import math

from .evidence import fingerprint


def require(condition, message):
    if not condition: raise ValueError(message)


def verify(v):
    require(v.get('passed') is True, 'Run did not pass')
    require(v.get('source_changed') is False, 'Source changed during validation')
    require(fingerprint(v['source']) == v.get('source_sha256'), 'Source identity mismatch')
    stages = v['stages']
    names = [s['name'] for s in stages]
    required = {'native','initial','start','preflight','upload','linux','linux-read','cases',
                'reboot-prepare','reboot-stop','reboot-between','reboot-start','reboot-after','cleanup','remove','stop','final'}
    require(len(names) == len(set(names)) and set(names) == required, 'Incomplete/duplicate stages')
    for s in stages:
        require(s['exit_code'] == 0 and s['timed_out'] is False and
                type(s['seconds']) in (int,float) and math.isfinite(s['seconds']) and s['seconds'] >= 0,
                'Failed/timed out/nonfinite stage')
    native, linux = v['native_unit'], v['linux_unit']
    for r, platform in ((native,'Darwin'),(linux,'Linux')):
        require(r['passed'] is True and r['platform'] == platform and r['count'] > 113 and
                len(r['tests']) == r['count'] == len(set(r['tests'])) and
                r['failures'] == r['errors'] == r['skipped'] == 0 and
                r['source_sha256'] == v['source_sha256'], 'Portable test mismatch')
    require(native['tests'] == linux['tests'], 'Different portable test IDs')
    guest = v['guest']
    require(guest['passed'] is True, 'Guest did not pass')
    require(guest['source_sha256'] == v['source_sha256'], 'Guest source mismatch')
    names = [c['name'] for c in guest['cases']]
    required_cases = {'two_real_wire_leases_and_A_data_path', 'inactive_B_real_renewal_isolation',
                      'B_client_restart_isolation', 'A_blackhole_no_borrow_and_explicit_safe_B_selection',
                      'B_blackhole_no_borrow_and_explicit_safe_A_selection',
                      'missing_A_probe_table_terminal_guard_no_B_borrow',
                      'synthetic_cross_link_conflict_withdraws_only_proposer',
                      'real_wire_cross_link_conflict_withdraws_only_proposer',
                      'natural_T1_both_clients_unicast_no_wrong_WAN',
                      'real_wire_option121_detected_and_B_withdrawn',
                      'writer_SIGKILL_quarantine_both_and_reject_old_sessions',
                      'real_backend_partial_address_write_recovery'}
    require(len(names) == len(set(names)) and required_cases <= set(names), 'Missing core VM case')
    for c in guest['cases']:
        require(c['passed'] is True and type(c['seconds']) in (int,float) and
                math.isfinite(c['seconds']) and c['seconds'] >= 0 and bool(c['details']), 'Invalid VM case')
    cleanup = guest['cleanup']
    require(all(cleanup.get(k) is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')), 'Guest cleanup incomplete')
    require(v.get('snapshot_removed') is True and v.get('vm_final') == 'Stopped', 'VM/source cleanup incomplete')
    require(all(v['cleanup'].get(k) is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')), 'Final cleanup incomplete')
    require(v['reboot_before']['passed'] is True and v['reboot']['passed'] is True, 'Reboot failed')
    require(v['reboot_before']['boot'] != v['reboot']['boot'], 'No actual boot change')
    before, after = v['reboot_before'], v['reboot']
    require(after['pre_core_evidence']['unchanged_since_before_VM_stop'] is True and
            after['pre_core_evidence']['journal_sha256'] == before['journal_sha256'], 'Journal changed before recovery')
    challenges = after['authority_challenges']
    require({(c['link'],c['field']) for c in challenges} == {('A','session'),('B','session'),('A','boot'),('B','boot')} and len(challenges) == 4,
            'Missing isolated reboot authority challenge')
    for c in challenges:
        require(c['origin'] == 'synthetic_isolated_authority_challenge' and
                all(c[k] is True for k in ('rejected','snapshot_unchanged','network_unchanged')), 'Stale challenge changed state')
    for r in (before, after):
        require(r['state']['active']['link'] == 'A' and all(r['state']['links'][k]['current'] is not None for k in ('A','B')),
                'Both live pre-restart leases not established')
        require(r['initial']['active'] is None and all(r['initial']['links'][k]['current'] is None for k in ('A','B')),
                'Old allocation reused at startup')
        require(r['client']['ok'] is True and r['client']['response']['peer'] == '10.99.1.1', 'Reboot data path wrong')
        require(all(r['cleanup'].get(k) is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')), 'Reboot cleanup incomplete')
    cases = {c['name']:c['details'] for c in guest['cases']}
    d = cases['two_real_wire_leases_and_A_data_path']
    require(d['client']['ok'] is True and d['client']['response']['peer'] == '10.99.1.1' and
            all(d['state']['links'][k]['current'] is not None for k in ('A','B')), 'Initial data path/leases missing')
    d = cases['missing_A_probe_table_terminal_guard_no_B_borrow']
    require(d['probe']['votes'] == 0 and d['before']['B']['target'] == d['after']['B']['target'] and
            d['viable_main_fallback']['ok'] is True and d['viable_main_fallback']['response']['peer'] == '10.99.2.1', 'Missing-route fallback evidence contradicted')
    natural = cases['natural_T1_both_clients_unicast_no_wrong_WAN']
    require({e['link'] for e in natural['events'] if e['reason'] == 'renew' and e['origin'] == 'real_busybox_hook'} == {'A','B'}, 'Missing natural wire renewal')
    for k in ('A','B'):
        require(natural['after'][k]['own_dhcp'] > natural['before'][k]['own_dhcp'] and
                natural['after'][k]['wrong_dhcp'] == natural['before'][k]['wrong_dhcp'], 'DHCP borrowed wrong WAN')
    for failed, other in (('A','B'),('B','A')):
        d = cases[failed+'_blackhole_no_borrow_and_explicit_safe_'+other+'_selection']
        require(d['blocked']['ok'] is False and d['after'][other]['target'] == d['before'][other]['target'] and
                d['client']['ok'] is True and d['client']['response']['peer'] == ('10.99.1.1' if other=='A' else '10.99.2.1'), 'Blackhole result contradicted')
    d = cases['real_wire_option121_detected_and_B_withdrawn']
    require('staticroutes' in d['event']['options'] and d['event']['origin'] == 'real_busybox_hook' and
            d['result']['state']['links']['B']['current'] is None and d['client']['ok'] is True, 'Wire option evidence missing')
    d = cases['real_wire_cross_link_conflict_withdraws_only_proposer']
    require(d['event']['origin'] == 'real_busybox_hook' and d['event']['lease']['ip'] == '198.51.100.3' and
            d['result']['state']['links']['A']['current'] is None and
            d['result']['state']['links']['B']['current']['ip'] == '198.51.100.2' and
            d['client']['ok'] is True and d['client']['response']['peer'] == '10.99.2.1', 'Wire conflict evidence contradicted')
    for k in ('driver_pid','driver_rss_kib','sqlite_main_bytes'):
        require(type(guest['measurements'][k]) is int and guest['measurements'][k] > 0, 'Invalid measurement')
    return True


def controls(v):
    mutations = [lambda x:x.update(source_changed=True), lambda x:x.update(source_sha256='0'*64),
                 lambda x:x['linux_unit'].update(source_sha256='0'*64),
                 lambda x:x['linux_unit'].update(skipped=1), lambda x:x['native_unit'].update(passed=False),
                 lambda x:x['stages'][0].update(exit_code=1), lambda x:x['stages'][0].update(timed_out=True),
                 lambda x:x['stages'][0].update(seconds=float('nan')), lambda x:x['stages'].pop(),
                 lambda x:x['guest']['cases'].pop(0), lambda x:x['guest']['cases'][0].update(passed=False),
                 lambda x:x['guest']['cleanup'].update(root_network_unchanged=False),
                 lambda x:x.update(snapshot_removed=False), lambda x:x.update(vm_final='Running'),
                 lambda x:x['reboot'].update(passed=False),
                 lambda x:x['reboot'].update(boot=x['reboot_before']['boot'])]
    mutations += [lambda x:x['reboot']['pre_core_evidence'].update(journal_sha256='0'*64),
                  lambda x:x['reboot']['initial'].update(active=x['reboot']['state']['active']),
                  lambda x:x['guest']['cases'][0]['details']['client'].update(ok=False),
                  lambda x:x['guest'].update(source_sha256='0'*64),
                  lambda x:x['cleanup'].update(root_network_unchanged=False),
                  lambda x:x['reboot']['authority_challenges'].pop(),
                  lambda x:x['reboot']['authority_challenges'][0].update(network_unchanged=False)]
    for mutate in mutations:
        broken = copy.deepcopy(v); mutate(broken)
        try: verify(broken)
        except (ValueError,KeyError,TypeError): pass
        else: raise ValueError('Corruption control accepted')
    return dict(passed=True, rejected=len(mutations))


def render(v):
    raw = json.dumps(v, sort_keys=True, indent=2, allow_nan=False)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    guest = v.get('guest', {})
    rows = ''.join('<tr><td>'+html.escape(c['name'])+'</td><td>'+str(c['passed'])+'</td><td>'+format(c['seconds'],'.3f')+'</td></tr>'
                   for c in guest.get('cases', []))
    measurements = html.escape(json.dumps(guest.get('measurements', {}), indent=2))
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Dual DHCP explorations</title>'
            '<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
            '<h1>Uplinkstead dual DHCP explorations</h1><p>Passed: '+str(v.get('passed') is True)+
            '</p><p>Linux VM observations are separate from native portable tests. No production, power-loss or zero-gap guarantee.</p>'
            '<p>This is a formal core/backend exploration, not an installed dual service or automatic failover qualification.</p>'
            '<h2>Linux VM scenarios</h2><table><tr><th>Scenario</th><th>Passed</th><th>Elapsed seconds</th></tr>'+rows+'</table>'
            '<h2>VM measurement scope</h2><pre>'+measurements+'</pre>'
            '<p>Stage duration includes fixture work and is not outage or recovery SLO. Reboot results are manually invoked core recovery.</p>'
            '<h2>Complete evidence</h2><p>Canonical JSON SHA-256: '+digest+'</p><pre>'+html.escape(raw)+'</pre></html>')
