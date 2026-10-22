"""Readback failure semantics needed before a fresh boot has created any table."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from tools.dhcp_guest import network


class DHCPFixtureTests(unittest.TestCase):
    def test_known_absent_table_handles_truncated_ip_json(self):
        with patch('tools.dhcp_guest.cmd', return_value=SimpleNamespace(returncode=2,stdout='[',
                   stderr='Error: ipv4: FIB table does not exist.\nDump terminated\n')), \
             patch('tools.dhcp_guest.ip', return_value=SimpleNamespace(stdout='[]')):
            value=network()
            self.assertEqual(value['data_routes'],[])
            self.assertEqual(value['probe_routes'],[])

    def test_unknown_command_failure_or_corrupt_success_is_not_empty_table(self):
        for result,error in ((SimpleNamespace(returncode=1,stdout='',stderr='Operation not permitted'),RuntimeError),
                             (SimpleNamespace(returncode=0,stdout='[',stderr=''),json.JSONDecodeError)):
            with self.subTest(result=result),patch('tools.dhcp_guest.cmd',return_value=result), \
                 self.assertRaises(error):network()
