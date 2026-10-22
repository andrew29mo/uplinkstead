"""Fail-closed verifier and escaped HTML for the DHCP lifecycle evidence."""
import argparse
import copy
import html
import hashlib
import json
import math
import re
from pathlib import Path
from .evidence import ROOT, fingerprint, manifest
from .report import test_ids
from .dhcp_fixture import unit as fixture_unit, monitor_expressions
from uplinkstead.dhcp import Backend, config

CASES = ['wire_bound_and_pinned_tls', 'wire_renew', 'wire_gateway_change', 'wire_address_change',
         'service_sigkill_restart_and_old_session_fenced', 'unsupported_current_renew_withdraws_old_lease',
         'blackhole_no_false_health_or_backup_borrow',
         'lease_deadline_with_stalled_client', 'formal_backend_partial_write_recovery']
STAGES = ['native', 'initial', 'start', 'preflight', 'upload', 'linux', 'linux-read',
          'cases', 'reboot-prepare', 'reboot-stop', 'reboot-between', 'reboot-start',
          'reboot-after', 'reboot-cleanup', 'cleanup', 'remove', 'stop', 'final']


def require(value, message):
    if not value:raise ValueError(message)


def service(value):
    require(value['ActiveState']=='active' and int(value['MainPID'])>0 and
            re.fullmatch('[0-9a-f]{32}',value['InvocationID']) and
            value['FragmentPath']=='/etc/systemd/system/uplinkstead-dhcp.service' and not value['DropInPaths'] and
            set(value['CapabilityBoundingSet'].split())=={'cap_net_admin','cap_net_raw','cap_net_bind_service'}, 'service identity')


def installed(source_hash, installed_hash):
    original=(ROOT/'deploy/uplinkstead-dhcp.service').read_bytes()
    require(hashlib.sha256(original).hexdigest()==source_hash, 'service source')
    require(hashlib.sha256(fixture_unit(original.decode()).encode()).hexdigest()==installed_hash, 'installed service differs')


BUILTINS = [dict(priority=0,src='all',table='local'),dict(priority=32766,src='all',table='main'),
            dict(priority=32767,src='all',table='default')]


def strict_rules(network):
    expected=Backend(config(ROOT/'deploy/dhcp.example.json')).expected()+BUILTINS
    rules=[Backend.normalized(r) for r in network['rules']]
    require(len(rules)==len(expected) and all(rules.count(r)==1 for r in expected),
            'missing/foreign/duplicate policy rule')


def no_forwarding(network):
    require(not network['data_routes'] and not network['probe_routes'] and
            not any(r['addr_info'] for r in network['addresses']), 'allocation still present')
    strict_rules(network)


def startup(receipt, instance, before, pre, fresh):
    message=receipt['message'];s=message['state']
    require(receipt['_PID']==instance['MainPID'] and receipt['_SYSTEMD_INVOCATION_ID']==instance['InvocationID'] and
            receipt['_BOOT_ID']==fresh['boot'].replace('-','') and int(receipt['__MONOTONIC_TIMESTAMP'])>0,
            'startup journal identity')
    require(message['event']=='dhcp_startup_ready' and message['backend_empty_verified'] is True and
            s['boot']==fresh['boot'] and s['session']==fresh['session'] and s['current'] is None and
            s['expires']==0 and s['healthy'] is False and s['revision']==before['journal']['revision']+1 and
            pre['captured_boottime']<=message['boottime']<fresh['expires']-fresh['current']['seconds'], 'startup before client did not quarantine')


def restart(d, initial_session, initial_invocation):
    old,new=d['before'],d['state']
    service(d['old_service']);service(d['new_service'])
    require(old['healthy'] is True and new['healthy'] is True and old['session']==initial_session and
            old['session']!=new['session'] and old['boot']==new['boot'] and
            d['old_service']['InvocationID']==initial_invocation and
            d['old_service']['MainPID']!=d['new_service']['MainPID'] and
            d['old_service']['InvocationID']!=d['new_service']['InvocationID'], 'restart identity')
    q=d['event']
    require(q['session']==old['session'] and q['boot']==new['boot'] and q['revision']==new['revision'] and
            q['reason']=='deconfig' and q['lease'] is None and q['at']>0 and
            d['rejection']==dict(rejected=True,error='RetiredSession') and
            d['before_network']==d['after_network'], 'stale rejection/readback')
    require(new['current']['ip']=='192.0.2.3' and new['revision']>old['revision'], 'new lease after restart')


def deadline(d):
    require(d['before']['healthy'] is True and d['before']['current'] is not None and
            d['before']['expires']==d['deadline'] and d['before_request']['ok'] is True and
            d['before_request']['response']['peer']=='10.99.1.1', 'expiry did not start healthy')
    v=d['before']['current']
    require(any(r.get('dst')=='default' and r.get('gateway')==v['gateway'] and r.get('dev')=='wan0'
                for r in d['before_network']['data_routes']), 'expiry had no active forwarding')
    require(d['current']['current'] is None and d['current']['healthy'] is False and
            d['request']['ok'] is False and d['backup_packets']==0 and d['client_stalled'] is True and
            d['observed']>=d['deadline'], 'expiry borrowed/healthy')
    no_forwarding(d['after_network'])


def monitor(d):
    c=d['backup_control']
    require(c['local_address']=='198.51.100.2' and c['peer_address']=='203.0.113.2' and c['peer_port']==8443,
            'backup control tuple')
    rules=[x['rule'] for x in d['backup_monitor']['nftables'] if 'rule' in x]
    chains=[x['chain'] for x in d['backup_monitor']['nftables'] if 'chain' in x]
    require(len(chains)==1 and chains[0]['family']=='ip' and chains[0]['table']=='observe' and
            chains[0]['name']=='f' and chains[0]['type']=='filter' and chains[0]['hook']=='forward' and
            chains[0]['prio']==-100 and chains[0]['policy']=='accept', 'backup monitor hook')
    require(len(rules)==2 and all(r['family']=='ip' and r['table']=='observe' and r['chain']=='f' for r in rules) and
            [r['expr'] for r in rules]==monitor_expressions(c['local_port']), 'backup monitor exemption/scope')


def reboot(d, before, source):
    require(d['passed'] is True and d['orderly_vm_restart_tested'] is True and
            d['power_loss_tested'] is False and d['before']==before, 'reboot scope/receipt')
    pre=d['prestart'];old=before['state'];new=d['fresh'];service(before['service']);service(d['service'])
    require(before['boot']==old['boot'] and d['boot']==pre['boot']==new['boot'] and d['boot']!=before['boot'] and
            old['healthy'] is True and before['service_frozen'] is True and before['request']['ok'] is True and
            before['request']['response']['peer']=='10.99.1.1', 'reboot identity/before health')
    require(any(r.get('dst')=='default' for r in before['network']['data_routes']), 'reboot started without active route')
    require(before['shutdown_fault']==dict(KillSignal='9',DropInPaths='/run/systemd/system/uplinkstead-dhcp.service.d/reboot-fault.conf'), 'shutdown fault not observed')
    j=before['journal']
    require(pre['journal']==j and j['current']==old['current'] and j['current'] is not None and j['intent'] is None and
            j['boot']==before['boot'] and j['session']==old['session'] and j['revision']==old['revision'] and
            j['expires']==old['expires'] and j['expires']>0, 'journal cleared before boot')
    require(before['source_sha256']==pre['source_sha256']==d['source_sha256']==source and
            d['service']['InvocationID']!=before['service']['InvocationID'] and
            new['session']!=old['session'] and new['revision']>old['revision'], 'new boot authority/source')
    require(not pre['network']['data_routes'] and not pre['network']['probe_routes'] and
            not any(r['addr_info'] for r in pre['network']['addresses']), 'fixture replayed lease')
    from .dhcp_reboot import fixture
    require(before['fixture_sha256']==d['fixture_sha256']==hashlib.sha256(fixture().encode()).hexdigest(), 'boot fixture mismatch')
    monitor(d)
    require(d['dhcp_server_absent_while_waiting'] is True and d['backup_warmup_packets']>0 and d['backup_packets']==0 and len(d['waiting'])>=3, 'backup not tested')
    for observation in d['waiting']:
        w=observation['state']
        require(w['boot']==d['boot'] and w['session']==new['session'] and w['current'] is None and
                w['expires']==0 and w['healthy'] is False and observation['request']['ok'] is False and
                observation['backup_packets']==0, 'old lease/health or borrowing before reacquisition')
        no_forwarding(observation['network'])
    u=d['unverified'];uv=u['state']
    require(uv['current']['ip']=='192.0.2.4' and uv['current']['gateway']=='192.0.2.5' and
            uv['healthy'] is False and not u['network']['data_routes'] and u['request']['ok'] is False and
            new['current']==uv['current'] and new['healthy'] is True and uv['session']==new['session'] and
            d['request']['ok'] is True and d['request']['response']['peer']=='10.99.1.1', 'new wire lease/fresh health')
    startup(d['startup'],d['service'],before,pre,new)
    require(d['rss_identity_before']==d['rss_identity_after']==d['service'], 'RSS process changed')
    strict_rules(before['network']);strict_rules(u['network'])
    stale=d['stale'];q0=stale['state_before']
    strict_rules(stale['network_before']);strict_rules(stale['network_after'])
    require(q0==stale['state_after']==new and stale['network_before']==stale['network_after'] and
            len(stale['events'])==3, 'stale changed configuration')
    require(abs(stale['prior_event']-(new['expires']-new['current']['seconds']))<1e-6, 'stale baseline event time')
    from uplinkstead.dhcp import lease
    cfg=config(ROOT/'deploy/dhcp.example.json')
    for i,entry in enumerate(stale['events']):
        q=entry['event'];error=('RetiredSession','Blocked','Blocked')[i]
        clocks=[q['at'],entry['sent'],entry['completed'],stale['prior_event']]
        require(all(type(t) in (int,float) and math.isfinite(t) for t in clocks) and
                stale['prior_event']<q['at']<=entry['sent']<=entry['completed'] and entry['completed']-q['at']<=3 and entry['completed']<new['expires'],
                'stale challenge also had invalid time')
        require(set(q)=={'session','boot','revision','at','reason','lease'} and
                lease(cfg,q['lease'])['ip']=='192.0.2.2', 'invalid stale allocation')
        require(entry['rejection']==dict(rejected=True,error=error) and q['reason']=='renew' and
                q['lease']['ip']=='192.0.2.2' and q['at']>0 and
                q['session']==(old['session'] if i==0 else new['session']) and
                q['boot']==(before['boot'] if i==1 else new['boot']) and
                q['revision']==(old['revision'] if i==2 else new['revision']) and
                old['boot']!=new['boot'] and old['revision']!=new['revision'], 'stale authority not isolated')
    require(re.fullmatch(r'VmRSS:\s+[1-9][0-9]* kB',d['rss_snapshot']) and d['seconds']>=0, 'reboot measurement')


def verify(v):
    require(v['passed'] is True and v['source_changed'] is False, 'run failed/source changed')
    require(v['source_sha256'] == fingerprint(v['source']), 'source fingerprint')
    require(v['stages'] and all(s['exit_code'] == 0 and s['timed_out'] is False for s in v['stages']), 'failed stage')
    require([s['name'] for s in v['stages']]==STAGES, 'missing/reordered stage')
    a,b=v['native_unit'],v['linux_unit']
    for u in (a,b):
        require(u['passed'] is True and u['count']==len(u['tests']) and len(set(u['tests']))==u['count'] and
                u['count'] > 0 and u['failures']==u['errors']==u['skipped']==0 and
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
    restart(c[CASES[4]],bound['state']['session'],bound['invocation'])
    bad=c[CASES[5]]
    require(bad['before']['healthy'] is True and bad['reply']['lease_rejected'] is True and
            bad['reply']['healthy'] is False and bad['reply']['current'] is None and
            bad['reply']['revision']>bad['before']['revision'] and
            bad['service_before']==bad['service_after'], 'unsupported renew kept old lease')
    require(any(r.get('dst')=='default' for r in bad['before_network']['data_routes']), 'unsupported renew was already withdrawn')
    no_forwarding(bad['after_network']);service(bad['service_after'])
    late=bad['late'];q=late['event'];prior=late['before']
    require(prior['healthy'] is True and prior['expires']<=bad['before']['expires'] and
            prior['session']==bad['before']['session'] and
            any(r.get('dst')=='default' for r in late['before_network']['data_routes']) and
            q['session']==prior['session'] and q['boot']==prior['boot'] and q['revision']==prior['revision'] and
            q['at']>late['restore_event']['at'] and late['observed']-q['at']>3 and
            late['reply']['event_expired'] is True and late['reply']['healthy'] is False and
            late['reply']['current'] is None and late['reply']['revision']>prior['revision'], 'latest delayed callback kept old lease')
    no_forwarding(late['after_network'])
    hole=c[CASES[6]]
    require(hole['state']['healthy'] is False and hole['request']['ok'] is False and
            hole['backup_warmup_packets']>0 and hole['backup_packets_before']==hole['backup_packets_after']==0, 'borrowed blackhole')
    service(hole['service']);deadline(c[CASES[7]])
    require(all(c[CASES[8]].get(k) is True for k in ('fault_after_actual_write','intent_retained','recovered_unverified','owned_addresses_removed','owned_tables_empty')), 'backend recovery')
    require(g['service_source_sha256']==v['source']['deploy/uplinkstead-dhcp.service'], 'service source')
    installed(g['service_source_sha256'],g['installed_unit_sha256'])
    service(g['rss_service']);require(g['rss_service']==hole['service'], 'RSS replacement process')
    require(re.fullmatch(r'VmRSS:\s+[1-9][0-9]* kB',g['rss_snapshot']) and
            type(g['db_bytes']) is int and 0<g['db_bytes']<=8*1024*1024, 'memory/disk observation')
    require(g['power_loss_tested'] is False and g['vm_restart_in_this_phase'] is False, 'pre-reboot phase claim')
    reboot(v['reboot'],v['reboot_before'],v['source_sha256'])
    installed(g['service_source_sha256'],v['reboot']['installed_unit_sha256'])
    require(v['reboot_cleanup']==dict(passed=True,fixture_removed=True),'boot fixture cleanup')
    require(all(v['cleanup'].get(k) is True for k in ('passed','root_network_unchanged','namespaces_removed','unit_removed')) and
            v['snapshot_removed'] is True and v['vm_final']=='Stopped', 'cleanup')


def controls(v):
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),
             lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),
             lambda x:x['linux_unit'].update(source_sha256='wrong'),lambda x:x['guest']['cases'].pop(),
             lambda x:x['guest']['cases'][1]['details']['state'].update(healthy=True),
             lambda x:x['guest']['cases'][6]['details'].update(backup_packets_after=1),
             lambda x:x['guest']['cases'][7]['details']['current'].update(healthy=True),
             lambda x:x['guest'].update(power_loss_tested=True),lambda x:x.update(vm_final='Running'),
             lambda x:x['cleanup'].update(root_network_unchanged=False),
             lambda x:x['guest'].update(installed_unit_sha256='0'*64),
             lambda x:x['guest']['cases'][4]['details']['state'].update(session=x['guest']['cases'][0]['details']['state']['session']),
             lambda x:x['guest']['cases'][4]['details']['rejection'].update(error='TimeoutError'),
             lambda x:x['guest']['cases'][4]['details']['rejection'].update(error='Blocked'),
             lambda x:x['guest']['cases'][4]['details']['after_network'].update(data_routes=[]),
             lambda x:x['guest']['cases'][7]['details']['before'].update(healthy=False),
             lambda x:x['guest']['cases'][7]['details']['before_network'].update(data_routes=[]),
             lambda x:x['guest']['cases'][5]['details']['reply'].update(healthy=True),
             lambda x:x['guest']['cases'][5]['details']['late']['reply'].update(healthy=True),
             lambda x:x['guest']['rss_service'].update(MainPID='999999'),
             lambda x:x['stages'].pop(1),
             lambda x:x['reboot'].update(boot=x['reboot_before']['boot']),
             lambda x:x['reboot']['prestart']['journal'].update(current=None),
             lambda x:x['reboot']['waiting'][0]['state'].update(healthy=True),
             lambda x:x['reboot']['waiting'][0]['state'].update(current={'ip':'192.0.2.3'}),
             lambda x:x['reboot']['waiting'][0].update(backup_packets=1),
             lambda x:x['reboot']['waiting'][0]['network'].update(rules=[r for r in x['reboot']['waiting'][0]['network']['rules'] if r['priority']!=10213]),
             lambda x:x['reboot']['unverified']['state'].update(healthy=True),
             lambda x:x['reboot']['stale']['state_after'].update(current=None),
             lambda x:x['reboot']['stale']['events'][0]['rejection'].update(error='Blocked'),
             lambda x:x['reboot'].update(power_loss_tested=True),
             lambda x:x['reboot_cleanup'].update(fixture_removed=False),
             lambda x:x['reboot'].update(installed_unit_sha256='0'*64),
             lambda x:x['reboot'].update(fixture_sha256='0'*64),
             lambda x:x['reboot_before']['shutdown_fault'].update(KillSignal='15'),
             lambda x:x['reboot'].update(dhcp_server_absent_while_waiting=False),
             lambda x:x['reboot']['waiting'][0]['network']['rules'].append(dict(priority=1,src='10.77.0.0/24',iif='lan0',dst='203.0.113.99/32',table='main')),
             lambda x:x['reboot']['stale']['events'][1]['event'].update(at=1),
             lambda x:x['reboot']['stale']['events'][2]['event'].update(at=10**12),
             lambda x:x['reboot']['startup']['message']['state'].update(current={'ip':'192.0.2.3'}),
             lambda x:x['reboot']['startup'].update(_SYSTEMD_INVOCATION_ID='0'*32),
             lambda x:x['reboot']['startup']['message'].update(backend_empty_verified=False),
             lambda x:x['reboot']['rss_identity_after'].update(MainPID='999999'),
             lambda x:x['reboot']['backup_control'].update(local_address='10.77.0.2'),
             lambda x:x['reboot']['backup_monitor']['nftables'].append({'rule':dict(family='ip',table='observe',chain='f',expr=[{'return':None}])})]
    for index,change in enumerate(changes):
        bad=copy.deepcopy(v);change(bad)
        try:verify(bad)
        except (ValueError,KeyError,TypeError):continue
        raise ValueError('Verifier accepted corrupted evidence at index '+str(index))
    return len(changes)


def render(v):
    g=v.get('guest',{})
    rows=''.join('<tr><td>'+html.escape(c['name'])+'</td><td>'+str(c['passed'])+'</td><td>'+
                 format(c['seconds'],'.3f')+'</td></tr>' for c in g.get('cases',[]))
    return ('<!doctype html><meta charset="utf-8"><title>Uplinkstead DHCP lifecycle evidence</title>'
            '<style>body{font:16px system-ui;max-width:1000px;margin:40px auto;padding:20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left}</style>'
            '<h1>Single DHCP uplink lifecycle</h1><p>Controlled Linux VM; real DHCP and installed service. '
            'Case times include fixture waits and DHCP protocol timers; not failover SLOs. RSS is a process snapshot, '
            'not peak or whole-VM memory. Includes orderly VM stop/start with a frozen service and explicit shutdown-only SIGKILL override; '
            'no sudden power-loss or physical ISP claim.</p>'
            '<p>Run: '+html.escape(v['run_id'])+'; overall passed: '+str(v['passed'])+'</p>'
            '<p>Writer RSS snapshot: '+html.escape(g.get('rss_snapshot','not collected'))+
            '; SQLite main file bytes: '+str(g.get('db_bytes','not collected'))+'</p>'
            '<p>DHCP orderly VM restart: '+str(v.get('reboot',{}).get('passed','not collected'))+
            '; post-boot service RSS snapshot: '+html.escape(v.get('reboot',{}).get('rss_snapshot','not collected'))+'</p>'+
            '<table><tr><th>Scenario</th><th>Passed</th><th>Elapsed seconds</th></tr>'+rows+'</table>'
            '<details><summary>Full JSON evidence</summary><pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre></details>')


def main():
    p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args()
    v=json.loads((a.directory/'evidence.json').read_text());verify(v);n=controls(v)
    require(v['source']==manifest(), 'Evidence is historical; current source differs')
    require((a.directory/'report.html').read_text()==render(v),'HTML differs from JSON')
    print(json.dumps(dict(passed=True,run_id=v['run_id'],controls=n)))


if __name__=='__main__':main()
