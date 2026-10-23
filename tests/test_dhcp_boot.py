"""Formal core across changed boot IDs; whole VM boot is a separate Linux gate."""
import copy,contextlib,io,sqlite3,unittest
from unittest.mock import patch
from tests import test_dual_dhcp as core
from uplinkstead.dual_dhcp import DualLifecycle,StorageUnavailable

class BootTests(unittest.TestCase):
    setUp=core.DualDHCPTests.setUp
    bind=core.DualDHCPTests.bind
    healthy=core.DualDHCPTests.healthy
    event=core.DualDHCPTests.event
    choose=core.DualDHCPTests.choose
    open=core.DualDHCPTests.open
    def live(self):
        for k in ('A','B'):self.bind(k);self.healthy(k)
        self.choose('A');return copy.deepcopy(self.w.s)
    def reboot(self):
        self.w.__exit__();self.boot='boot2';self.time=1.;self.w=self.open()
    def test_changed_boot_retires_old_authority_and_requires_new_evidence(self):
        old=self.live();self.reboot()
        self.assertEqual(self.w.s['history'],old['history']);self.assertGreater(self.w.s['epoch'],old['epoch']);self.assertIsNone(self.w.s['active'])
        for k in ('A','B'):
            self.assertIsNone(self.w.s['links'][k]['current']);self.assertNotEqual(self.w.s['links'][k]['session'],old['links'][k]['session']);self.assertEqual(self.w.health[k],dict(state='WAITING',good=0,bad=0,round=-1,until=0.))
        self.bind('A')
        with self.assertRaises(RuntimeError):self.choose('A')
        self.healthy('A');self.choose('A');before=copy.deepcopy(self.w.s)
        for op in ('pause','resume','reset-budget'):
            q=dict(op=op,epoch=old['epoch'],revision=old['revision'],id='b'*32)
            if op=='reset-budget':q['ack']='reset-switch-budget'
            with self.assertRaises(RuntimeError):self.w.operator(q)
        with self.assertRaises(RuntimeError):self.w.choose('B',old['epoch'],old['revision'])
        self.assertEqual(self.w.s,before)
    def test_old_boot_budget_cannot_age_out_or_unlock_on_reboot(self):
        self.live();self.w.s['history']=[dict(boot=self.boot,at=self.time) for _ in range(self.w.budget)];self.w.save();self.reboot()
        self.bind('A');self.healthy('A')
        with self.assertRaises(RuntimeError):self.choose('A')
        self.assertTrue(self.w.s['latched']);self.w.pause();prior=copy.deepcopy(self.w.s)
        self.w.__exit__();self.boot='boot3';self.w=self.open();self.assertTrue(self.w.s['paused']);self.assertTrue(self.w.s['latched']);self.assertEqual(self.w.s['history'],prior['history'])
        self.bind('A');self.healthy('A')
        with self.assertRaises(RuntimeError):self.choose('A')
        self.assertIsNone(self.w.s['active'])
    def test_storage_failure_on_new_boot_never_becomes_ready_then_repairs(self):
        old=self.live();self.w.__exit__();self.boot='boot2';self.time=1.
        from uplinkstead.writer import Writer
        created=[]
        def backend(c,fd):b=core.ScopedBackend(c,fd);created.append(b);return b
        with patch.object(Writer,'save',side_effect=sqlite3.OperationalError('injected failed persistence')),contextlib.redirect_stderr(io.StringIO()):
            failed=DualLifecycle(self.c,self.tmp.name,backend,clock=lambda:self.time,boot=lambda:self.boot)
            with self.assertRaises(StorageUnavailable):failed.__enter__()
            self.assertNotEqual(failed.s['phase'],'READY');self.assertTrue(failed.storage_fault['quarantined']);self.assertFalse(failed.storage_fault['durable'])
            self.assertIsNone(created[0].active)
        self.w=self.open();self.assertEqual(self.w.s['history'],old['history']);self.assertIsNone(self.w.s['active'])
        self.assertTrue(all(v['current'] is None for v in self.w.s['links'].values()))
