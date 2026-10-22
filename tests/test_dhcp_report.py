"""Synthetic contradictions test the verifier, not networking performance."""
import copy
import hashlib
from pathlib import Path
import unittest

from tools.dhcp_report import installed, restart, deadline, BUILTINS, no_forwarding
from tools.dhcp_fixture import unit, monitor_expressions
from uplinkstead.dhcp import Backend, config


class DHCPReportTests(unittest.TestCase):
    def test_installed_service_must_match_declared_fixture_transform(self):
        source=(Path(__file__).resolve().parents[1]/'deploy/uplinkstead-dhcp.service').read_bytes()
        original=hashlib.sha256(source).hexdigest()
        expected=unit(source.decode())
        installed(original, hashlib.sha256(expected.encode()).hexdigest())
        for changed in ('0'*64, hashlib.sha256(expected.replace('Restart=on-failure','Restart=no').encode()).hexdigest()):
            with self.assertRaises(ValueError):installed(original, changed)

    def test_restart_rejects_environment_error_reused_session_and_changed_routes(self):
        def service(pid, invocation):
            return dict(MainPID=str(pid), InvocationID=invocation*32, ActiveState='active',
                        FragmentPath='/etc/systemd/system/uplinkstead-dhcp.service', DropInPaths='',
                        CapabilityBoundingSet='cap_net_bind_service cap_net_admin cap_net_raw')
        before=dict(healthy=True, session='a'*48, boot='boot', revision=1)
        after=dict(healthy=True, session='b'*48, boot='boot', revision=2,current=dict(ip='192.0.2.3'))
        d=dict(before=before,state=after,old_service=service(1,'a'),new_service=service(2,'b'),
               event=dict(session='a'*48,boot='boot',revision=2,reason='deconfig',lease=None,at=1),
               rejection=dict(rejected=True,error='RetiredSession'),before_network=dict(data_routes=['actual']),
               after_network=dict(data_routes=['actual']))
        restart(d,'a'*48,'a'*32)
        changes=[lambda x:x['state'].update(session='a'*48),
                 lambda x:x['new_service'].update(InvocationID='a'*32),
                 lambda x:x['rejection'].update(error='TimeoutError'),
                 lambda x:x['rejection'].update(error='Blocked'),
                 lambda x:x['after_network'].update(data_routes=[])]
        for change in changes:
            v=copy.deepcopy(d);change(v)
            with self.assertRaises(ValueError):restart(v,'a'*48,'a'*32)

    def test_expiry_requires_previously_active_flow_and_allocation_removal(self):
        c=config(Path(__file__).resolve().parents[1]/'deploy/dhcp.example.json')
        d=dict(before=dict(healthy=True,current=dict(gateway='192.0.2.1'),expires=2),deadline=2,observed=2.1,
               before_request=dict(ok=True,response=dict(peer='10.99.1.1')),
               before_network=dict(data_routes=[dict(dst='default',gateway='192.0.2.1',dev='wan0')]),
               current=dict(current=None,healthy=False),request=dict(ok=False),backup_packets=0,client_stalled=True,
               after_network=dict(data_routes=[],probe_routes=[],addresses=[],rules=Backend(c).expected()+BUILTINS))
        deadline(d)
        changes=[lambda x:x['before'].update(healthy=False),lambda x:x['before_network'].update(data_routes=[]),
                 lambda x:x['after_network']['rules'].pop(),lambda x:x.update(observed=1.9),
                 lambda x:x['after_network'].update(addresses=[dict(addr_info=[dict(local='192.0.2.2')])])]
        for change in changes:
            v=copy.deepcopy(d);change(v)
            with self.assertRaises(ValueError):deadline(v)

    def test_reboot_verifier_requires_live_prestart_journal_no_borrow_and_distinct_authorities(self):
        from tools.dhcp_report import reboot
        from tools.dhcp_reboot import fixture
        c=config(Path(__file__).resolve().parents[1]/'deploy/dhcp.example.json')
        def svc(invocation):
            return dict(MainPID='123',InvocationID=invocation*32,ActiveState='active',
                        FragmentPath='/etc/systemd/system/uplinkstead-dhcp.service',DropInPaths='',
                        CapabilityBoundingSet='cap_net_admin cap_net_raw cap_net_bind_service')
        old=dict(boot='old',session='a'*48,revision=1,current=dict(ip='192.0.2.3'),expires=100,healthy=True)
        journal=dict(boot='old',session=old['session'],revision=1,current=old['current'],expires=100,intent=None)
        source='source';sha=hashlib.sha256(fixture().encode()).hexdigest()
        before=dict(boot='old',state=old,journal=journal,service=svc('a'),service_frozen=True,
                    request=dict(ok=True,response=dict(peer='10.99.1.1')),source_sha256=source,fixture_sha256=sha,
                    network=dict(data_routes=[dict(dst='default')],rules=Backend(c).expected()+BUILTINS),
                    shutdown_fault=dict(KillSignal='9',DropInPaths='/run/systemd/system/uplinkstead-dhcp.service.d/reboot-fault.conf'))
        fresh=dict(boot='new',session='b'*48,revision=3,current=dict(ip='192.0.2.4',gateway='192.0.2.5',seconds=60),expires=62,healthy=True)
        waiting=dict(fresh,current=None,expires=0,healthy=False)
        net=dict(data_routes=[],probe_routes=[],addresses=[],rules=Backend(c).expected()+BUILTINS)
        events=[]
        for i in range(3):
            q=dict(session=old['session'] if i==0 else fresh['session'],boot='old' if i==1 else 'new',
                   revision=1 if i==2 else 3,reason='renew',lease=dict(ip='192.0.2.2',router='192.0.2.1',subnet='255.255.255.0',lease='60'),at=3)
            events.append(dict(event=q,rejection=dict(rejected=True,error='RetiredSession' if i==0 else 'Blocked'),sent=3.01,completed=3.1))
        d=dict(passed=True,orderly_vm_restart_tested=True,power_loss_tested=False,before=copy.deepcopy(before),boot='new',
               prestart=dict(boot='new',journal=copy.deepcopy(journal),network=copy.deepcopy(net),source_sha256=source,captured_boottime=.1),
               service=svc('b'),startup=dict(message=dict(event='dhcp_startup_ready',
               state=dict(fresh,current=None,expires=0,healthy=False,revision=2),backend_empty_verified=True,boottime=1),
               _PID='123',_SYSTEMD_INVOCATION_ID='b'*32,_BOOT_ID='new',__MONOTONIC_TIMESTAMP='1000000'),
               rss_identity_before=svc('b'),rss_identity_after=svc('b'),source_sha256=source,fixture_sha256=sha,backup_warmup_packets=1,backup_packets=0,dhcp_server_absent_while_waiting=True,
               waiting=[dict(state=copy.deepcopy(waiting),network=copy.deepcopy(net),request=dict(ok=False),backup_packets=0) for _ in range(3)],
               unverified=dict(state=dict(fresh,healthy=False),network=copy.deepcopy(net),request=dict(ok=False)),
               fresh=fresh,request=dict(ok=True,response=dict(peer='10.99.1.1')),
               stale=dict(state_before=copy.deepcopy(fresh),state_after=copy.deepcopy(fresh),
                          network_before=copy.deepcopy(net),network_after=copy.deepcopy(net),events=events,prior_event=2),
               rss_snapshot='VmRSS: 12345 kB',seconds=1)
        d['backup_control']=dict(local_address='198.51.100.2',local_port=40000,peer_address='203.0.113.2',peer_port=8443)
        d['backup_monitor']=dict(nftables=[dict(chain=dict(family='ip',table='observe',name='f',type='filter',hook='forward',prio=-100,policy='accept'))]+
            [dict(rule=dict(family='ip',table='observe',chain='f',expr=expr)) for expr in monitor_expressions(40000)])
        reboot(d,before,source)
        changes=[lambda x:x.update(boot='old'),lambda x:x['prestart']['journal'].update(current=None),
                 lambda x:x['waiting'][0]['state'].update(healthy=True),
                 lambda x:x['waiting'][0]['network']['rules'].pop(),
                 lambda x:x['waiting'][0].update(backup_packets=1),
                 lambda x:x['stale']['events'][0]['rejection'].update(error='Blocked'),
                 lambda x:x['stale']['state_after'].update(current=None),
                 lambda x:x.update(power_loss_tested=True),lambda x:x.update(fixture_sha256='bad'),
                 lambda x:x['stale']['events'][1]['event'].update(at=1),
                 lambda x:x['stale']['events'][2]['event'].update(at=10**12),
                 lambda x:x['startup']['message'].update(backend_empty_verified=False),
                 lambda x:x['rss_identity_after'].update(MainPID='456')]
        for change in changes:
            bad=copy.deepcopy(d);change(bad)
            with self.assertRaises(ValueError):reboot(bad,before,source)

    def test_unknown_priority_rule_cannot_bypass_guards_for_an_unprobed_destination(self):
        c=config(Path(__file__).resolve().parents[1]/'deploy/dhcp.example.json')
        network=dict(data_routes=[],probe_routes=[],addresses=[],rules=Backend(c).expected()+BUILTINS)
        no_forwarding(network)
        network['rules'].append(dict(priority=1,src='10.77.0.0/24',iif='lan0',dst='203.0.113.99/32',table='main'))
        with self.assertRaises(ValueError):no_forwarding(network)
