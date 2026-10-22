import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import MagicMock,patch
from uplinkstead.linux import Linux,Blocked
from uplinkstead.probe import one,round as probe_round
from tests.test_core import config


class PreflightTests(unittest.TestCase):
    def exercise(self,mutate):
        c=config();b=Linux(c)
        builtins=[dict(priority=0,src='all',table='local'),dict(priority=32766,src='all',table='main'),dict(priority=32767,src='all',table='default')]
        rules=builtins+b.expected();mutate(rules)
        b.rules=lambda:rules;b.routes=lambda table:[]
        b.run=lambda argv,**kw:json.dumps([{'addr_info':[{'local':v['source']} for v in c['links'].values()]}])
        read=lambda name,*a,**kw:io.StringIO('1' if str(name).endswith('ip_forward') else '2')
        with patch('builtins.open',side_effect=read):b.preflight()
    def test_inverted_disjoint_lookup_rejected(self):
        with self.assertRaises(Blocked):self.exercise(lambda rows:rows.append(dict(priority=9990,src='all',iif='other0',table='main',**{'not':None})))
    def test_inverted_disjoint_prohibit_rejected(self):
        with self.assertRaises(Blocked):self.exercise(lambda rows:rows.append(dict(priority=9990,src='all',iif='other0',action='prohibit',**{'not':None})))
    def test_unknown_disjoint_selector_rejected(self):
        with self.assertRaises(Blocked):self.exercise(lambda rows:rows.append(dict(priority=9990,src='all',iif='other0',table='main',goto=10000)))
    def test_missing_local_rejected(self):
        with self.assertRaises(Blocked):self.exercise(lambda rows:rows.pop(0))
    def test_duplicate_builtin_rejected(self):
        with self.assertRaises(Blocked):self.exercise(lambda rows:rows.append(copy.deepcopy(rows[0])))
    def test_plain_disjoint_lookup_still_accepted(self):
        self.exercise(lambda rows:rows.append(dict(priority=9990,src='all',iif='other0',table='main')))


class ProbeBodyTests(unittest.TestCase):
    def response(self,value,encoded=False):
        raw=MagicMock();raw.__enter__.return_value=raw
        tls=MagicMock();tls.__enter__.return_value=tls
        tls.recv.side_effect=[b'HTTP/1.0 200 OK\r\n\r\n'+(value if encoded else json.dumps(value).encode()),b'']
        ctx=MagicMock();ctx.wrap_socket.return_value=tls
        with patch('uplinkstead.probe.socket.socket',return_value=raw),patch('uplinkstead.probe.socket.SO_BINDTODEVICE',25,create=True),patch('uplinkstead.probe.socket.SO_MARK',36,create=True),patch('uplinkstead.probe.ssl.create_default_context',return_value=ctx),patch('uplinkstead.probe.secrets.token_hex',return_value='nonce'):
            return one(config(),'A',config()['targets'][0])
    def test_valid_json_nonobjects_are_target_failures(self):
        for body in (None,[],[1],'text',3,True):
            with self.subTest(body=body):
                result=self.response(body);self.assertFalse(result['ok']);self.assertFalse(result['infrastructure'])
    def test_nonfinite_and_invalid_peer_are_target_failures(self):
        for peer in (float('nan'),float('inf'),{},[],3):
            result=self.response(dict(nonce='nonce',ok=True,peer=peer))
            self.assertFalse(result['ok']);self.assertFalse(result['infrastructure'])
    def test_deeply_nested_json_is_target_failure(self):
        result=self.response(b'['*1200+b'0'+b']'*1200,encoded=True)
        self.assertFalse(result['ok']);self.assertFalse(result['infrastructure'])
    def test_peer_limit_is_utf8_bytes_not_json_wire_or_character_count(self):
        for peer in ('x'*65,'中'*22,'中'*4000):
            result=self.response(dict(nonce='nonce',ok=True,peer=peer))
            self.assertFalse(result['ok']);self.assertFalse(result['infrastructure'])
        self.assertTrue(self.response(dict(nonce='nonce',ok=True,peer='x'*64))['ok'])
        self.assertTrue(self.response(dict(nonce='nonce',ok=True,peer='中'*21))['ok'])
    def test_valid_object_still_successful(self):
        self.assertTrue(self.response(dict(nonce='nonce',ok=True,peer='fixture'))['ok'])
    def test_two_healthy_targets_retain_quorum(self):
        bad=self.response(None);good=self.response(dict(nonce='nonce',ok=True))
        with patch('uplinkstead.probe.one',side_effect=lambda c,k,t:bad if t['port']==8443 else good):
            count,rows=probe_round(config(),'A')
        self.assertEqual(count,2);self.assertEqual(len(rows),3)


class OptimizedValidationTests(unittest.TestCase):
    def test_report_rejects_failure_under_optimization(self):
        code="""from tools.report import verify,render
from tools.evidence import fingerprint
v=dict(passed=False,source={},source_sha256=fingerprint({}))
try:verify(v)
except AssertionError:pass
else:raise RuntimeError('false evidence accepted')
if '<b>PASS</b>' in render(v):raise RuntimeError('failure rendered PASS')
"""
        p=subprocess.run([sys.executable,'-O','-c',code],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
    def test_unit_runner_refuses_optimized_validation(self):
        p=subprocess.run([sys.executable,'-O','-m','tools.unit','--output','/should-not-exist/uplinkstead.json'],capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0);self.assertIn('Optimized execution',p.stderr)
