import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from uplinkstead.dhcp import Lifecycle, Backend, lease, config, PROBE_TABLE, DATA_TABLE
from uplinkstead.linux import Blocked


class FakeBackend:
    def __init__(self, *args):
        self.current = None
        self.active = False
        self.calls = []

    def reconcile_many(self, allowed, new):
        self.calls.append(('recover', copy.deepcopy(allowed)))
        self.current, self.active = new, False

    def reconcile(self, old, new):
        self.calls.append(('reconcile', copy.deepcopy(new)))
        self.current, self.active = new, False

    def activate(self, value, deadline):
        self.active = True

    def withdraw(self, value):
        self.active = False


class DHCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.c = config(Path(__file__).resolve().parents[1]/'deploy/dhcp.example.json')
        self.clock = 100.
        self.addCleanup(patch.stopall)
        patch('uplinkstead.dhcp.Backend', FakeBackend).start()
        patch('uplinkstead.dhcp.boot_id', return_value='boot1').start()
        patch('uplinkstead.dhcp.now', side_effect=lambda: self.clock).start()
        self.probes = patch('uplinkstead.dhcp.probe_round', return_value=(3, [])).start()

    def value(self, ip='192.0.2.2', router='192.0.2.1', seconds='60'):
        return dict(ip=ip, subnet='255.255.255.0', router=router, lease=seconds)

    def event(self, w, reason='bound', value=None):
        self.clock += .1
        return dict(session=w.s['session'], boot='boot1', revision=w.s['revision'],
                    at=self.clock, reason=reason, lease=value or self.value())

    def open(self):
        return Lifecycle(self.c, Path(self.tmp.name)/'state')

    def test_actual_journal_renew_invalidates_health_and_old_events(self):
        with self.open() as w:
            q = self.event(w);w.event(q)
            w.tick();self.assertFalse(w.healthy)
            w.tick();self.assertTrue(w.healthy)
            w.event(self.event(w, 'renew'))
            self.assertFalse(w.healthy);self.assertFalse(w.backend.active)
            with self.assertRaises(Blocked):w.event(q)
            self.assertFalse(w.healthy)

    def test_address_and_gateway_change_require_new_quorum(self):
        with self.open() as w:
            w.event(self.event(w));w.tick();w.tick()
            w.event(self.event(w, 'renew', self.value('192.0.3.2', '192.0.3.1')))
            self.assertFalse(w.healthy)
            self.assertEqual(w.s['current']['gateway'], '192.0.3.1')
            w.tick();self.assertFalse(w.healthy)
            w.tick();self.assertTrue(w.healthy)
            self.assertEqual(self.probes.call_args.args[0]['links']['A']['source'], '192.0.3.2')

    def test_expiry_and_expiry_during_probe_never_activate(self):
        with self.open() as w:
            w.event(self.event(w, value=self.value(seconds='2')))
            w.tick()
            def delayed(*args):
                self.clock += 3
                return 3, []
            self.probes.side_effect = delayed
            w.tick()
            self.assertIsNone(w.s['current']);self.assertFalse(w.healthy)
            self.assertFalse(w.backend.active)

    def test_deconfig_withdraws_and_replay_is_rejected(self):
        with self.open() as w:
            w.event(self.event(w));w.tick();w.tick()
            q=self.event(w, 'deconfig');q['lease']=None
            w.event(q)
            self.assertIsNone(w.s['current']);self.assertFalse(w.backend.active)
            with self.assertRaises(Blocked):w.event(q)

    def test_restart_fences_session_and_does_not_trust_saved_lease(self):
        with self.open() as w:
            w.event(self.event(w));w.tick();w.tick()
            old=self.event(w, 'renew')
        with self.open() as w:
            self.assertIsNone(w.s['current']);self.assertFalse(w.healthy)
            with self.assertRaises(Blocked):w.event(old)
            self.assertTrue(any(v is not None for v in w.backend.calls[0][1]))

    def test_failed_backend_recovers_intent_without_replaying_lease(self):
        with self.open() as w:
            w.event(self.event(w))
            with patch.object(w.backend, 'reconcile', side_effect=OSError('injected write')):
                with self.assertRaises(OSError):
                    w.event(self.event(w, 'renew', self.value('192.0.3.2', '192.0.3.1')))
        with self.open() as w:
            known = w.backend.calls[0][1]
            self.assertEqual({v['ip'] for v in known if v}, {'192.0.2.2', '192.0.3.2'})
            self.assertIsNone(w.s['intent']);self.assertIsNone(w.s['current'])

    def test_changed_boot_quarantines_lease_before_new_authority(self):
        with self.open() as w:
            w.event(self.event(w));w.tick();w.tick()
            old=self.event(w, 'renew')
        with patch('uplinkstead.dhcp.boot_id', return_value='boot2'):
            self.clock=1
            with self.open() as w:
                self.assertIsNone(w.s['current']);self.assertFalse(w.healthy)
                self.assertEqual(w.s['boot'], 'boot2')
                with self.assertRaises(Blocked):w.event(old)

    def test_actual_sqlite_save_failure_cannot_mutate_backend(self):
        import sqlite3
        with self.open() as w:
            before=copy.deepcopy(w.backend.calls)
            w.db.execute('PRAGMA query_only=ON')
            with self.assertRaises(sqlite3.OperationalError):w.event(self.event(w))
            self.assertEqual(w.backend.calls,before)
        with self.open() as w:
            self.assertIsNone(w.s['current'])

    def test_unknown_infrastructure_or_failed_quorum_withdraws(self):
        with self.open() as w:
            w.event(self.event(w));w.tick();w.tick()
            for votes in (None, 1, 0):
                self.probes.return_value=(votes, [])
                self.assertFalse(w.tick()['healthy']);self.assertFalse(w.backend.active)

    def test_stale_future_wrong_boot_session_and_duplicate_are_readonly(self):
        with self.open() as w:
            for change in ({'at': 0}, {'at': 999}, {'boot':'old'}, {'session':'old'}, {'revision':-1}, {'at':float('nan')}):
                q=self.event(w);q.update(change)
                before=copy.deepcopy(w.s);calls=copy.deepcopy(w.backend.calls)
                with self.assertRaises(Blocked):w.event(q)
                self.assertEqual(w.s,before);self.assertEqual(w.backend.calls,calls)

    def test_invalid_lease_cannot_reach_backend(self):
        with self.open() as w:
            for data in (self.value(router='198.51.100.1'),self.value(router='192.0.2.1 192.0.2.3'),
                         self.value(ip='10.77.0.2',router='10.77.0.1'),self.value(seconds='0'),
                         self.value(seconds='999999'),self.value(ip='192.0.2.0')):
                calls=len(w.backend.calls)
                with self.assertRaises(ValueError):w.event(self.event(w,value=data))
                self.assertEqual(len(w.backend.calls),calls)

    def test_lock_excludes_second_writer_and_corrupt_journal_refuses(self):
        with self.open() as w:
            with self.assertRaises(BlockingIOError):
                with self.open():pass
            w.db.execute("UPDATE state SET value='{}'")
        with self.assertRaises(Blocked):
            with self.open():pass


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.c=config(Path(__file__).resolve().parents[1]/'deploy/dhcp.example.json')
        self.b=Backend(self.c)
        self.commands=[]
        def run(args, **kwargs):
            self.commands.append(args)
            return '[]' if '-j' in args else ''
        self.b.run=run
        self.b.rules=lambda:[dict(priority=0,src='all',table='local'),dict(priority=32766,src='all',table='main'),dict(priority=32767,src='all',table='default')]
        self.b.routes=lambda table:[]

    def test_formal_backend_accepts_empty_ipv4_and_installs_guards_first(self):
        self.b.reconcile_many([None],None)
        mutations=[c for c in self.commands if c[0] in ('rule','route')]
        self.assertTrue(all(c[-1]=='prohibit' for c in mutations[:3]))
        self.assertTrue(all(c[0]=='rule' for c in mutations[:6]))
        self.assertEqual(mutations[-2:],[['route','flush','table',DATA_TABLE],['route','flush','table',PROBE_TABLE]])

    def test_formal_backend_rejects_foreign_rule_before_mutation(self):
        self.b.rules=lambda:[dict(priority=1,src='all',table='main')]
        with self.assertRaises(Blocked):self.b.reconcile_many([None],None)
        self.assertFalse(any(c[0] in ('rule','route','addr') for c in self.commands))

    def test_formal_backend_rejects_foreign_route_before_flush(self):
        self.b.routes=lambda table:[dict(dst='default',gateway='198.51.100.1',dev='backup0',metric=100)]
        with self.assertRaises(Blocked):self.b.reconcile_many([None],None)
        self.assertFalse(any(c[0]=='route' for c in self.commands))
