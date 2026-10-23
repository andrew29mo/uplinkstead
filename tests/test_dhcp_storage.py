"""Formal SQLite/core storage retirement; actual filesystems are a Linux VM gate."""
import contextlib,copy,io,json,secrets,sqlite3,unittest
from unittest.mock import patch,Mock
from tests import test_dual_dhcp as core
from uplinkstead.dual_dhcp import DualLifecycle,StorageUnavailable

class StorageTests(unittest.TestCase):
    setUp=core.DualDHCPTests.setUp
    bind=core.DualDHCPTests.bind
    healthy=core.DualDHCPTests.healthy
    event=core.DualDHCPTests.event
    choose=core.DualDHCPTests.choose
    open=core.DualDHCPTests.open
    def live(self):
        for k in ('A','B'):self.bind(k);self.healthy(k)
        self.choose('A')
    def pause(self):
        return self.w.operator(dict(op='pause',epoch=self.w.s['epoch'],revision=self.w.s['revision'],id=secrets.token_hex(16)))
    def test_real_sqlite_readonly_retires_and_quarantines_without_commit(self):
        self.live();old=copy.deepcopy(self.w.s);self.w.db.execute('PRAGMA query_only=ON')
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(StorageUnavailable):self.pause()
        self.assertEqual(self.w.storage_fault['kind'],'sqlite_readonly');self.assertTrue(self.w.storage_fault['quarantined']);self.assertFalse(self.w.storage_fault['durable'])
        self.assertIsNone(self.w.backend.active);self.assertEqual(self.w.backend.allocations,dict(A=None,B=None));self.assertEqual(self.w.s['phase'],'RECOVERY_REQUIRED')
        stored=json.loads(self.w.db.execute('select value from state').fetchone()[0]);self.assertEqual(stored,old)
        with self.assertRaises(RuntimeError):self.choose('B')
        self.w.__exit__();self.w=self.open();self.assertEqual(self.w.s['history'],old['history']);self.assertIsNone(self.w.s['active'])
        with self.assertRaises(RuntimeError):self.w.choose('B',old['epoch'],old['revision'])
    def test_real_sqlite_full_and_restart_only_capacity_repair(self):
        self.live();self.w.db.execute('PRAGMA max_page_count='+str(self.w.db.execute('pragma page_count').fetchone()[0]))
        with contextlib.redirect_stderr(io.StringIO()):
            for _ in range(40):
                try:self.pause()
                except StorageUnavailable:break
            else:self.fail('SQLite capacity error not observed')
        self.assertEqual(self.w.storage_fault['kind'],'sqlite_full');self.assertEqual(self.w.storage_fault['sqlite_code']&255,13);self.assertTrue(self.w.storage_fault['quarantined'])
        before=json.loads(self.w.db.execute('select value from state').fetchone()[0]);self.w.__exit__()
        c=dict(self.c,storage=dict(max_pages=2048));self.w=DualLifecycle(c,self.tmp.name,core.ScopedBackend,clock=lambda:self.time,boot=lambda:self.boot).__enter__()
        self.assertEqual(self.w.s['history'],before['history']);self.assertEqual(self.w.s['operations'],before['operations']);self.assertTrue(self.w.s['paused']);self.assertGreater(self.w.s['epoch'],before['epoch'])
    def test_storage_resource_size_does_not_change_route_authority(self):
        for pages in (2,2048):self.assertEqual(DualLifecycle(dict(self.c,storage=dict(max_pages=pages)),self.tmp.name,core.ScopedBackend).c,self.w.c)
        for value in (0,1,2049,True):
            with self.assertRaises(ValueError):DualLifecycle(dict(self.c,storage=dict(max_pages=value)),self.tmp.name,core.ScopedBackend)
    def test_competing_readonly_lock_cannot_reach_backend(self):
        factory=Mock()
        with self.assertRaises(BlockingIOError):DualLifecycle(self.c,self.tmp.name,factory,clock=lambda:self.time,boot=lambda:self.boot).__enter__()
        factory.assert_not_called()
    def test_partial_actual_write_uses_both_durable_and_memory_authority(self):
        self.live();original=self.w.save
        def failing():
            if self.w.s['pending'] is None and self.w.s['active'] and self.w.s['active']['link']=='B':
                self.w.storage_failed(sqlite3.OperationalError('injected final receipt failure'))
            return original()
        with patch.object(self.w,'save',side_effect=failing),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(StorageUnavailable):self.choose('B')
        self.assertIsNone(self.w.backend.active);self.assertTrue(self.w.storage_fault['quarantined']);self.assertIsNone(self.w.s['active'])
    def test_fresh_storage_failure_cannot_invent_durable_ownership(self):
        import tempfile
        from uplinkstead.writer import Writer
        created=[]
        def factory(c,fd):
            b=core.ScopedBackend(c,fd);created.append(b);return b
        with tempfile.TemporaryDirectory() as path,patch.object(Writer,'save',side_effect=OSError('fresh storage unavailable')),contextlib.redirect_stderr(io.StringIO()):
            w=DualLifecycle(self.c,path,factory,clock=lambda:self.time,boot=lambda:self.boot)
            with self.assertRaises(StorageUnavailable):w.__enter__()
            self.assertFalse(w.storage_fault['quarantined']);self.assertEqual(created[0].calls,[])

    def test_scope_failure_is_not_reported_as_success(self):
        self.live();self.w.db.execute('PRAGMA query_only=ON')
        with patch.object(self.w.backend,'reconcile',side_effect=RuntimeError('foreign scope')),contextlib.redirect_stderr(io.StringIO()),self.assertRaises(StorageUnavailable):self.pause()
        self.assertFalse(self.w.storage_fault['quarantined']);self.assertIn('foreign scope',self.w.storage_fault['quarantine_error'])
        with self.assertRaises(RuntimeError):self.choose('B')
