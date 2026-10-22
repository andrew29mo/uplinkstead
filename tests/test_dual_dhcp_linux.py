"""Backend scope checks. Real syscall behavior is separately VM-qualified."""
import copy
import unittest
from unittest.mock import patch

from uplinkstead.dual_dhcp_linux import Backend, TABLE
from uplinkstead.dhcp import lease
from uplinkstead.linux import Blocked


class DualBackendTests(unittest.TestCase):
    def setUp(self):
        self.c = dict(links={'A': {'interface': 'wanA'}, 'B': {'interface': 'wanB'}},
                      lan=dict(interface='lan0', prefix='10.77.0.0/24'), targets=[])
        self.values = {k: lease(self.c, dict(ip=ip, subnet='24', router=gw, lease='120'))
                       for k, ip, gw in [('A', '192.0.2.2', '192.0.2.1'),
                                         ('B', '198.51.100.2', '198.51.100.1')]}
        self.b = Backend(self.c)

    def test_dhcp_and_marked_probe_lookups_have_terminal_guards(self):
        rows = self.b.expected()
        for r in rows:
            if r.get('table') in (TABLE['A'], TABLE['B']):
                guard = dict(r, priority=r['priority']+1, action='prohibit')
                del guard['table']
                self.assertIn(guard, rows)
        self.assertEqual({r['oif'] for r in rows if 'oif' in r}, {'wanA', 'wanB'})
        for r in rows:
            if 'oif' in r:
                cmd = self.b.rule_command(r)
                self.assertIn('oif', cmd)
                self.assertNotIn('iif', cmd)

    def test_inactive_update_cannot_flush_active_data_table(self):
        allowed = {k: [v] for k, v in self.values.items()}
        active = dict(link='A', generation=1, value=self.values['A'])
        with patch.object(self.b, 'check') as check, patch.object(self.b, '_allocation') as allocation, patch.object(self.b, '_active') as route:
            self.b.link('B', allowed, self.values['B'], active)
            route.assert_not_called()
            allocation.assert_called_once_with('B', allowed['B'], self.values['B'])
            self.assertEqual(check.call_count, 2)

    def test_unknown_route_properties_and_foreign_gateway_reject(self):
        row = dict(dst='default', dev='wanA', gateway='192.0.2.1', metric=100)
        for changes in ({'gateway': '192.0.2.99'}, {'nhid': 1}, {'type': 'blackhole'}, {'encap': {}}):
            with self.subTest(changes=changes), patch.object(self.b, 'routes', return_value=[dict(row, **changes)]):
                with self.assertRaises(Blocked):
                    self.b._routes_allowed(TABLE['A'], [('wanA', self.values['A'])])

    def test_selection_unknown_allocation_rejects_before_network_write(self):
        allowed = {k: [v] for k, v in self.values.items()}
        bad = copy.deepcopy(self.values['A']); bad['ip'] = '192.0.2.3'
        with patch.object(self.b, 'check'), patch.object(self.b, '_active') as mutation:
            with self.assertRaises(Blocked):
                self.b.select(allowed, dict(link='A', generation=1, value=bad), 100)
            mutation.assert_not_called()

    def test_missing_expected_route_is_not_a_successful_readback(self):
        v = self.values['A']
        connected = dict(dst=v['prefix'], dev='wanA', scope='link')
        default = dict(dst='default', dev='wanA', gateway=v['gateway'], metric=100)
        for rows in ([], [connected], [default], [connected, default, default]):
            with self.subTest(rows=rows), patch.object(self.b, 'routes', return_value=rows):
                with self.assertRaises(Blocked): self.b._verify_table(TABLE['A'], 'wanA', v)
        with patch.object(self.b, 'routes', return_value=[connected, default]):
            self.b._verify_table(TABLE['A'], 'wanA', v)


if __name__ == '__main__': unittest.main()
