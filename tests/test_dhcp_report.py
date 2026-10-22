"""Synthetic contradictions test the verifier, not networking performance."""
import copy
import hashlib
from pathlib import Path
import unittest

from tools.dhcp_report import installed, restart, deadline
from tools.dhcp_fixture import unit
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
               after_network=dict(data_routes=[],probe_routes=[],addresses=[],rules=Backend(c).expected()))
        deadline(d)
        changes=[lambda x:x['before'].update(healthy=False),lambda x:x['before_network'].update(data_routes=[]),
                 lambda x:x['after_network']['rules'].pop(),lambda x:x.update(observed=1.9),
                 lambda x:x['after_network'].update(addresses=[dict(addr_info=[dict(local='192.0.2.2')])])]
        for change in changes:
            v=copy.deepcopy(d);change(v)
            with self.assertRaises(ValueError):deadline(v)
