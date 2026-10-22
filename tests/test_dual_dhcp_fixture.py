"""Timeout cleanup never adopts foreign resources or hides a failed run."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from tools import dual_dhcp_fixture as fixture
from tools.dual_dhcp_guest import finalize


def network():
    return dict(rules=[dict(priority=0,src='all',table='local')],
                routes=[dict(dst='default',gateway='192.0.2.1',dev='eth0')],
                nft=json.dumps(dict(nftables=[dict(rule=dict(family='ip',table='filter',chain='input',
                    handle=1,expr=[dict(counter=dict(packets=1,bytes=80)),dict(accept=None)]))])),
                iptables='# Generated at old time\n*filter\n:INPUT ACCEPT [1:80]\nCOMMIT\n# Completed old\n',
                ip6tables='')


class CleanupTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.names=self.root/'netns';self.names.mkdir()
        p=patch.object(fixture,'NETNS_ROOT',self.names);p.start();self.addCleanup(p.stop)
        self.before=network();self.calls=[]

    def ledger(self,entries):
        (self.root/'ownership.json').write_text(json.dumps(dict(root_before=self.before,namespaces=entries)))

    def command(self,args):
        self.calls.append(args)
        if args[:3]==['ip','netns','del']:(self.names/args[3]).unlink()
        return SimpleNamespace(stdout='')

    def test_counter_timestamp_changes_accepted_and_raw_evidence_retained(self):
        p=self.names/'dd_r';p.touch();self.ledger({'dd_r':p.stat().st_ino})
        after=copy.deepcopy(self.before);after['iptables']=after['iptables'].replace('old','new').replace('[1:80]','[55:4400]')
        data=json.loads(after['nft']);data['nftables'][0]['rule']['handle']=12
        data['nftables'][0]['rule']['expr'][0]['counter']['packets']=55;after['nft']=json.dumps(data)
        with patch.object(fixture,'cmd',side_effect=self.command),patch.object(fixture,'root_snapshot',return_value=after):
            self.assertTrue(fixture.cleanup_owned(self.root)['root_network_unchanged'])
        self.assertFalse(p.exists());self.assertFalse((self.root/'ownership.json').exists())
        diff=json.loads((self.root/'cleanup-network-diff.json').read_text())
        self.assertTrue(diff['raw_changed']);self.assertEqual(diff['semantic_changed'],[])
        self.assertEqual(json.loads((self.root/'cleanup-after-raw.json').read_text()),after)

    def test_route_change_fails_and_preserves_ledger_and_raw_difference(self):
        self.ledger({});after=copy.deepcopy(self.before);after['routes'][0]['gateway']='192.0.2.99'
        with patch.object(fixture,'root_snapshot',return_value=after),self.assertRaises(RuntimeError):fixture.cleanup_owned(self.root)
        self.assertTrue((self.root/'ownership.json').exists())
        self.assertEqual(json.loads((self.root/'cleanup-network-diff.json').read_text())['semantic_changed'],['routes'])

    def test_rule_priority_or_nft_verdict_changes_are_not_ignored(self):
        for kind in ('rpdb','nft'):
            with self.subTest(kind=kind):
                self.ledger({});after=copy.deepcopy(self.before)
                if kind=='rpdb':after['rules'][0]['priority']=99
                else:
                    rules=json.loads(after['nft']);rules['nftables'][0]['rule']['expr'][-1]={'drop':None}
                    after['nft']=json.dumps(rules)
                with patch.object(fixture,'root_snapshot',return_value=after),self.assertRaises(RuntimeError):fixture.cleanup_owned(self.root)
                self.assertTrue((self.root/'ownership.json').exists())

    def test_replaced_namespace_inode_is_never_killed_or_deleted(self):
        p=self.names/'dd_r';p.touch();self.ledger({'dd_r':p.stat().st_ino+1})
        with patch.object(fixture,'cmd') as command,patch.object(fixture.os,'kill') as kill,self.assertRaises(RuntimeError):fixture.cleanup_owned(self.root)
        command.assert_not_called();kill.assert_not_called();self.assertTrue(p.exists())

    def test_partial_cleanup_missing_owned_namespace_is_idempotent(self):
        p=self.names/'dd_b';p.touch();foreign=self.names/'other';foreign.touch()
        self.ledger({'dd_r':123,'dd_b':p.stat().st_ino})
        with patch.object(fixture,'cmd',side_effect=self.command),patch.object(fixture,'root_snapshot',return_value=self.before):
            self.assertTrue(fixture.cleanup_owned(self.root)['namespaces_removed'])
            self.assertTrue(fixture.cleanup_owned(self.root)['idempotent'])
        self.assertTrue(foreign.exists());self.assertFalse(p.exists())
        self.assertEqual([v for v in self.calls if v[:3]==['ip','netns','del']],[['ip','netns','del','dd_b']])

    def test_new_phase_drains_old_hook_records_without_changing_raw_timestamps(self):
        path=self.root/'events-A.jsonl';old=dict(session='retired',boot='old',at=10,reason='bound')
        original=json.dumps(old)+'\n';path.write_text(original)
        fresh=fixture.Fixture(self.root,self.root)
        fresh.discard_previous_phase_events()
        self.assertEqual(fresh.events('A'),[])
        new=dict(session='new',boot='new',at=11,reason='bound')
        with path.open('a') as f:f.write(json.dumps(new)+'\n')
        self.assertEqual(fresh.events('A'),[new]);self.assertTrue(path.read_text().startswith(original))

    def test_replacement_client_drains_retired_client_events_before_spawn(self):
        path=self.root/'events-B.jsonl';path.write_text(json.dumps(dict(session='old',at=10))+'\n')
        fresh=fixture.Fixture(self.root,self.root);fresh.hook=self.root/'hook.py'
        child=SimpleNamespace()
        with patch.object(fresh,'spawn',return_value=child) as spawn:
            fresh.start_client('B','new-session','new-boot')
        self.assertEqual(fresh.events('B'),[])
        env=spawn.call_args.args[-1]
        self.assertEqual(env['DUAL_SESSION'],'new-session');self.assertEqual(env['DUAL_BOOT'],'new-boot')

    def test_cleanup_failure_overrides_passed_true_in_persisted_result(self):
        result=dict(passed=True,cases=[dict(passed=True)])
        broken=SimpleNamespace(cleanup=lambda:(_ for _ in ()).throw(RuntimeError('injected cleanup failure')))
        with self.assertRaises(RuntimeError):finalize(self.root,result,broken,None,'guest.json')
        recorded=json.loads((self.root/'guest.json').read_text())
        self.assertFalse(recorded['passed']);self.assertEqual(recorded['cleanup_failure']['type'],'RuntimeError')
