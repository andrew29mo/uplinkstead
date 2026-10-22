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


class RebootOwnershipTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        from tools import dhcp_reboot as r
        self.r=r
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        base=Path(tmp.name);root=base/'root';system=base/'etc';fault=base/'run/u.service.d/reboot-fault.conf'
        root.mkdir();system.mkdir();fault.parent.parent.mkdir()
        (root/'owner').write_text('this-test')
        (system/'multi-user.target.wants').mkdir()
        for name,value in (('ROOT',root),('SYSTEM',system),('FAULT',fault)):
            patcher=patch.object(r,name,value);patcher.start();self.addCleanup(patcher.stop)
        for name in ('command','cmd'):
            patcher=patch.object(r.g,name);patcher.start();self.addCleanup(patcher.stop)

    def test_preexisting_same_content_unit_or_link_is_never_owned_or_removed(self):
        r=self.r;unit=r.SYSTEM/r.TOPO
        unit.write_text(r.fixture())
        with self.assertRaises(FileExistsError):r.install()
        r.cleanup();self.assertEqual(unit.read_text(),r.fixture());unit.unlink()
        link=r.SYSTEM/'multi-user.target.wants'/r.g.UNIT;link.symlink_to('../'+r.g.UNIT)
        with self.assertRaises(FileExistsError):r.install()
        r.cleanup();self.assertTrue(link.is_symlink())
        self.assertFalse((r.ROOT/'reboot-owned.json').exists())

    def test_partial_install_ledger_owns_only_successful_creations(self):
        from pathlib import Path
        r=self.r;original=Path.symlink_to
        foreign=r.SYSTEM/'multi-user.target.wants'/r.g.UNIT
        def collide(path,target,*args,**kwargs):
            if path==foreign:
                original(path,target,*args,**kwargs)  # Another creator won this path.
                raise FileExistsError('injected collision')
            return original(path,target,*args,**kwargs)
        with patch.object(Path,'symlink_to',collide),self.assertRaises(FileExistsError):r.install()
        ledger=json.loads((r.ROOT/'reboot-owned.json').read_text())
        self.assertNotIn(str(foreign),ledger['links'])
        self.assertTrue(r.cleanup()['fixture_removed'])
        self.assertTrue(foreign.is_symlink())
        self.assertFalse((r.SYSTEM/r.TOPO).exists());self.assertFalse(r.FAULT.exists())

    def test_exclusive_create_then_partial_write_is_owned_and_cleaned(self):
        from pathlib import Path
        r=self.r;original=Path.open;unit=r.SYSTEM/r.TOPO
        class Partial:
            def __init__(self,f):self.f=f
            def __enter__(self):return self
            def __exit__(self,*args):self.f.close()
            def write(self,text):
                self.f.write(text[:17]);self.f.flush()
                raise OSError('injected fixture write failure')
        def open_file(path,*args,**kwargs):
            f=original(path,*args,**kwargs)
            return Partial(f) if path==unit and args and args[0]=='x' else f
        with patch.object(Path,'open',open_file),self.assertRaises(OSError):r.install()
        ledger=json.loads((r.ROOT/'reboot-owned.json').read_text())
        self.assertFalse(ledger['files'][str(unit)]['complete'])
        self.assertTrue(unit.exists())
        self.assertTrue(r.cleanup()['fixture_removed'])
        self.assertFalse(unit.exists());self.assertFalse(r.FAULT.parent.exists())
