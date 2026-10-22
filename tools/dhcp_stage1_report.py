"""Evidence correspondence for the formal stage-one service, not old exploration."""
import copy
import html
import json
import math
from .evidence import fingerprint


CASES = {'formal_service_two_real_leases_and_A_data', 'B_SIGKILL_supervised_replacement_preserves_A',
         'slow_B_probe_real_renewal_event_intake', 'real_backlogged_wire_renew_keeps_REQUEST_deadline',
         'retired_client_event_cannot_extend_lease', 'current_authority_without_wire_ACK_revokes_only_B',
         'concurrent_retired_event_flood_cannot_refresh_lease', 'bounded_live_loss_queue_overflow_retires_only_B',
         'wire_deadline_expires_without_client_cleanup'}


def require(value, message):
    if not value: raise ValueError(message)


def identity(row):
    return {k:row[k] for k in ('session','generation','current','expires')}


def proof(record):
    times = [record[k] for k in ('request_at','observed_at','hook_at','processed_at')]
    require(all(type(t) in (int,float) and math.isfinite(t) and t>=0 for t in times), 'Invalid wire clock')
    require(times == sorted(times), 'Wire clock order wrong')
    require(record['expires'] == record['request_at']+120, 'Lease rebased onto delivery/processing time')


def verify(v):
    require(v.get('passed') is True and v.get('source_changed') is False, 'Failed/changed-source run')
    require(v['source_sha256'] == fingerprint(v['source']), 'Source fingerprint mismatch')
    required={'native','initial','start','preflight','upload','linux','linux-read','cases','cleanup','remove','stop','final'}
    stages=v['stages'];names=[s['name'] for s in stages]
    require(set(names)==required and len(names)==len(required), 'Missing/duplicate stages')
    for s in stages:
        require(s['exit_code']==0 and s['timed_out'] is False and type(s['seconds']) in (int,float) and math.isfinite(s['seconds']) and s['seconds']>=0, 'Stage failed/timed out')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key]
        require(r['passed'] is True and r['source_sha256']==v['source_sha256'] and r['platform']==platform and r['count']>=193 and
                r['count']==len(r['tests'])==len(set(r['tests'])) and r['errors']==r['failures']==r['skipped']==0, 'Portable validation mismatch')
    require(v['native_unit']['tests']==v['linux_unit']['tests'], 'Different tests per platform')
    require({'test_dual_dhcp_service.RuntimeTests.test_older_queued_ACK_cannot_restore_after_newer_ACK_observed',
             'test_dual_dhcp_service.CaptureTests.test_claim_keeps_matching_ACK_version_instead_of_latest_global_version'} <= set(v['native_unit']['tests']), 'Missing ACK race regression')
    guest=v['guest'];require(guest['passed'] is True and guest['source_sha256']==v['source_sha256'], 'Guest failed/source mismatch')
    names=[c['name'] for c in guest['cases']]
    require(set(names)==CASES and len(names)==len(CASES), 'Missing/duplicate service scenario')
    for c in guest['cases']:
        require(c['passed'] is True and type(c['seconds']) in (int,float) and math.isfinite(c['seconds']) and c['seconds']>=0, 'Scenario failed')
    for c in (guest['cleanup'],v['cleanup']):
        require(all(c.get(k) is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')), 'Cleanup failed')
    require(v['snapshot_removed'] is True and v['vm_final']=='Stopped', 'VM/source cleanup failed')
    cases={c['name']:c['details'] for c in guest['cases']}
    d=cases['formal_service_two_real_leases_and_A_data'];s=d['observation']['state']
    require(s['active']['link']=='A' and all(s['links'][k]['current'] for k in ('A','B')) and
            d['client']['ok'] is True and d['client']['response']['peer']=='10.99.1.1','Initial real service path missing')
    for k in ('A','B'):
        records=[r for r in d['observation']['runtime']['recent'] if r['link']==k and r['reason'] in ('bound','renew') and r['expires']>0]
        require(bool(records),'Missing wire origin');proof(records[-1])
    d=cases['B_SIGKILL_supervised_replacement_preserves_A']
    require(d['before']['runtime']['children']['B']!=d['after']['runtime']['children']['B'] and
            d['before']['state']['links']['B']['session']!=d['after']['state']['links']['B']['session'] and
            identity(d['before']['state']['links']['A'])==identity(d['after']['state']['links']['A']) and
            d['before']['state']['active']==d['after']['state']['active'] and d['client']['ok'] is True, 'B replacement disrupted A')
    d=cases['slow_B_probe_real_renewal_event_intake']
    records=[r for r in d['after']['runtime']['recent'] if r['link']=='B' and r['reason']=='renew' and r['probe_inflight']['B']]
    require(bool(records),'No actual event/probe overlap');proof(records[-1])
    d=cases['real_backlogged_wire_renew_keeps_REQUEST_deadline'];r=d['wire_record'];proof(r)
    require(r['processed_at']>=d['service_resumed_at'] and r['expires']<=d['service_resumed_at']+120, 'Backlog extended lease')
    d=cases['retired_client_event_cannot_extend_lease']
    require(d['response']['ok'] is False and d['unchanged_expiry'] is True and
            identity(d['before']['state']['links']['B'])==identity(d['after']['state']['links']['B']), 'Retired event changed allocation')
    d=cases['current_authority_without_wire_ACK_revokes_only_B']
    require(d['response']['ok'] is False and d['before']['state']['links']['B']['session']!=d['after']['state']['links']['B']['session'] and
            identity(d['before']['state']['links']['A'])==identity(d['after']['state']['links']['A']) and d['client']['ok'] is True, 'Unproven lease retained/disrupted A')
    d=cases['concurrent_retired_event_flood_cannot_refresh_lease']
    require(d['requests']==48 and d['accepted']==0 and d['server_rejected']+d['transport_rejected']==48 and
            all(identity(d['before']['state']['links'][k])==identity(d['after']['state']['links'][k]) for k in ('A','B')), 'Stale flood mutated leases/unaccounted attempts')
    d=cases['bounded_live_loss_queue_overflow_retires_only_B'];q=d['after']['runtime']['queue']
    require(d['requests']==d['queued']+d['server_rejected']+d['transport_rejected']==48 and
            q['peak']<=q['capacity']==4 and q['overflow']['B']>d['before']['runtime']['queue']['overflow']['B'] and d['server_rejected']>0 and
            identity(d['before']['state']['links']['A'])==identity(d['after']['state']['links']['A']), 'Queue overflow not safely observed')
    d=cases['wire_deadline_expires_without_client_cleanup']
    require(d['stopped_clients_remained_same'] is True and d['observed_at']>=max(d['original_deadlines'].values()) and
            all(d['after']['state']['links'][k]['current'] is None for k in ('A','B')) and
            d['after']['state']['active'] is None and d['client']['ok'] is False, 'Live expiry not established')
    return True


def controls(v):
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),lambda x:x.update(source_sha256='0'*64),
             lambda x:x['native_unit'].update(skipped=1),lambda x:x['linux_unit'].update(source_sha256='0'*64),
             lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),
             lambda x:x['stages'].pop(),lambda x:x['guest']['cases'].pop(),lambda x:x['guest'].update(passed=False),
             lambda x:x['guest']['cases'][0].update(passed=False),lambda x:x['cleanup'].update(root_network_unchanged=False),
             lambda x:x.update(vm_final='Running'),lambda x:x.update(snapshot_removed=False),
             lambda x:x['guest']['cases'][0]['details']['client'].update(ok=False)]
    def alter(name,fn):
        return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==name))
    changes += [alter('real_backlogged_wire_renew_keeps_REQUEST_deadline',lambda d:d['wire_record'].update(expires=d['wire_record']['processed_at']+120)),
                alter('retired_client_event_cannot_extend_lease',lambda d:d.update(unchanged_expiry=False)),
                alter('wire_deadline_expires_without_client_cleanup',lambda d:d['client'].update(ok=True)),
                alter('bounded_live_loss_queue_overflow_retires_only_B',lambda d:d['after']['runtime']['queue'].update(peak=99))]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupted report accepted')
    return dict(passed=True,rejected=len(changes))


def render(v):
    raw=json.dumps(v,sort_keys=True,indent=2,allow_nan=False)
    rows=''.join('<tr><td>'+html.escape(c['name'])+'</td><td>'+str(c['passed'])+'</td><td>'+format(c['seconds'],'.3f')+'</td></tr>' for c in v.get('guest',{}).get('cases',[]))
    return ('<!doctype html><html lang="en"><meta charset="utf-8"><title>Uplinkstead DHCP stage 1</title>'
            '<style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
            '<h1>Formal dual-DHCP stage-one service</h1><p>Passed: '+str(v.get('passed') is True)+'</p>'
            '<p>Linux VM foreground service; native macOS portable tests are separate. No systemd, VM reboot, power-loss, zero-gap or automatic failover claim.</p>'
            '<p>Lease origin is a conservative REQUEST receive-queue-empty lower bound, not hook or processing time. Stage durations are not outage guarantees.</p>'
            '<table><tr><th>Scenario</th><th>Passed</th><th>Seconds</th></tr>'+rows+'</table><h2>Complete JSON evidence</h2><pre>'+html.escape(raw)+'</pre></html>')
