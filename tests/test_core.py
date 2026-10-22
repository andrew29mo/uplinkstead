import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uplinkstead.config import load
from uplinkstead.linux import Linux,Blocked
from uplinkstead.writer import Writer


def config():
    return dict(lan=dict(interface='lan0',prefix='10.77.0.0/24',exclude=['198.18.0.0/24']),
                links={'A':dict(interface='wanA',source='192.0.2.2',gateway='192.0.2.1',prefix='192.0.2.0/30'),
                       'B':dict(interface='wanB',source='192.0.2.6',gateway='192.0.2.5',prefix='192.0.2.4/30')},
                targets=[dict(ip='203.0.113.2',port=p) for p in (8443,8444,8445)],
                ca='/opt/uplinkstead/ca.crt',server_name='probe.test',policy={})


class ConfigTests(unittest.TestCase):
    def read(self,c):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'c';p.write_text(json.dumps(c));return load(p)

    def test_hash_stable(self):self.assertEqual(self.read(config())['_hash'],self.read(config())['_hash'])
    def test_overlapping_interfaces_rejected(self):
        c=config();c['links']['B']['interface']='wanA'
        with self.assertRaises(ValueError):self.read(c)
    def test_invalid_source_rejected(self):
        c=config();c['links']['A']['source']='192.0.2.99'
        with self.assertRaises(ValueError):self.read(c)
    def test_duplicate_target_rejected(self):
        c=config();c['targets'][1]=c['targets'][0]
        with self.assertRaises(ValueError):self.read(c)
    def test_unknown_key_rejected(self):
        c=config();c['arbitrary_command']='false'
        with self.assertRaises(ValueError):self.read(c)
    def test_exclusions_bounded(self):
        c=config();c['lan']['exclude']=['0.0.0.0/0']
        with self.assertRaises(ValueError):self.read(c)


class RoutingShapeTests(unittest.TestCase):
    def setUp(self):self.b=Linux(config())
    def test_every_lookup_has_matching_terminal_guard(self):
        rows=self.b.expected()
        for r in rows:
            if 'table' in r:
                guard=next(x for x in rows if x['priority']==r['priority']+1)
                self.assertEqual(guard['action'],'prohibit')
                for k in ('iif','src','dst','fwmark'):
                    self.assertEqual(r.get(k),guard.get(k))
    def test_real_iproute2_rule_output_normalization(self):
        rows=json.loads((Path(__file__).parent/'fixtures/ip-rules-linux68.json').read_text())
        expected=self.b.expected()
        observed=[self.b.normalized(r) for r in rows if 10000 < r['priority'] < 11000]
        self.assertEqual(observed,expected)

    def test_forward_selector_not_host_source_alone(self):
        r=next(x for x in self.b.expected() if x['priority']==10100)
        self.assertEqual(r['iif'],'lan0');self.assertEqual(r['src'],'10.77.0.0/24')
    def test_probe_is_local_and_marked(self):
        rows=[r for r in self.b.expected() if r['priority'] in (10010,10012)]
        self.assertEqual([r['iif'] for r in rows],['lo','lo'])
        self.assertEqual(len({r['fwmark'] for r in rows}),2)
    def test_internal_lookup_suppresses_main_default(self):
        rows=[r for r in self.b.expected() if 'dst' in r and 'table' in r]
        self.assertEqual(len(rows),4)
        self.assertTrue(all(r['suppress_prefixlength']==0 for r in rows))


class FakeLinux:
    route=None
    def __init__(self,*a):pass
    def preflight(self,**kw):pass
    def layout(self):pass
    def refresh_probes(self):pass
    def selected(self):return type(self).route
    def select(self,target,guard=None,deadline=None):
        if guard:guard()
        type(self).route=target


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory();self.addCleanup(self.d.cleanup)
        self.c=config();self.c['_hash']='cfg';FakeLinux.route=None
        self.patches=[patch('uplinkstead.writer.Linux',FakeLinux),patch('uplinkstead.writer.boot_id',return_value='boot'),patch('uplinkstead.writer.now',return_value=1)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def proof(self,w):
        return dict(config_hash='cfg',boot='boot',target='B',round=3,observed_at=1,expires_at=3)
    def test_automatic_admission_requires_proof(self):
        with Writer(self.c,self.d.name) as w:
            with self.assertRaises(Blocked):w.switch(w.s['epoch'],'B',dict(boot='boot',at=1))
            self.assertIsNone(FakeLinux.route)
    def test_health_expired_during_preflight_cannot_write(self):
        with Writer(self.c,self.d.name) as w:
            w.switch(w.s['epoch'],'A')
            with patch('uplinkstead.writer.now',return_value=1) as clock:
                def delayed(**kw):clock.return_value=4
                w.backend.preflight=delayed
                with self.assertRaises(Blocked):w.switch(w.s['epoch'],'B',dict(boot='boot',at=1),self.proof(w))
            self.assertEqual(FakeLinux.route,'A');self.assertIsNone(w.s['pending'])
    def test_health_expired_after_intent_cannot_dispatch(self):
        with Writer(self.c,self.d.name) as w:
            w.switch(w.s['epoch'],'A');actual=w.save
            with patch('uplinkstead.writer.now',return_value=1) as clock:
                def slow_save():actual();clock.return_value=4
                w.save=slow_save
                with self.assertRaises(Blocked):w.switch(w.s['epoch'],'B',dict(boot='boot',at=1),self.proof(w))
            self.assertEqual(FakeLinux.route,'A');self.assertEqual(w.s['pending']['target'],'B')
        with Writer(self.c,self.d.name) as w:self.assertEqual(w.s['selected'],'A');self.assertIsNone(w.s['pending'])
    def test_wrong_boot_config_and_round_proof_rejected(self):
        with Writer(self.c,self.d.name) as w:
            for change in ({'boot':'old'},{'config_hash':'old'},{'round':-1},{'expires_at':float('nan')}):
                proof=self.proof(w);proof.update(change)
                with self.assertRaises(Blocked):w.switch(w.s['epoch'],'B',dict(boot='boot',at=1),proof)
            self.assertIsNone(FakeLinux.route)
    def test_generation_rejects_stale_after_reopen(self):
        with Writer(self.c,self.d.name) as w:old=w.s['epoch'];w.switch(old,'A')
        with Writer(self.c,self.d.name) as w:
            w.switch(w.s['epoch'],'B')
            with self.assertRaises(Blocked):w.switch(old,'A')
            self.assertEqual(FakeLinux.route,'B')
    def test_actual_old_route_reconciles_pending_without_replay(self):
        with Writer(self.c,self.d.name) as w:
            w.switch(w.s['epoch'],'A');w.s['pending']=dict(token='t',target='B',before='A');w.save()
        with Writer(self.c,self.d.name) as w:self.assertEqual(w.s['selected'],'A');self.assertIsNone(w.s['pending'])
    def test_actual_new_route_reconciles_incomplete_receipt(self):
        with Writer(self.c,self.d.name) as w:
            w.switch(w.s['epoch'],'A');w.s['pending']=dict(token='t',target='B',before='A');w.save();FakeLinux.route='B'
        with Writer(self.c,self.d.name) as w:self.assertEqual(w.s['selected'],'B');self.assertIsNone(w.s['pending'])
    def test_unexpected_route_blocks(self):
        with Writer(self.c,self.d.name) as w:w.switch(w.s['epoch'],'A')
        FakeLinux.route='B'
        with self.assertRaises(Blocked):
            with Writer(self.c,self.d.name):pass
    def test_lock_contention_blocks(self):
        with Writer(self.c,self.d.name):
            with self.assertRaises(BlockingIOError):
                with Writer(self.c,self.d.name):pass
    def test_symlink_lock_rejected(self):
        p=Path(self.d.name);(p/'target').touch();(p/'writer.lock').symlink_to(p/'target')
        with self.assertRaises(OSError):
            with Writer(self.c,p):pass
    def test_invalid_journal_rejected(self):
        with Writer(self.c,self.d.name) as w:w.s['selected']='C';w.save()
        with self.assertRaises(Blocked):
            with Writer(self.c,self.d.name):pass
