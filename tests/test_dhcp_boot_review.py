"""Review regressions: actual core snapshots and owned fixture-file operations."""
import copy,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tools import dhcp_boot_guest as guest
from tools.dhcp_boot_checks import authority,charged
from tests import test_dual_dhcp as core

class EvidenceTests(unittest.TestCase):
    bind=core.DualDHCPTests.bind
    healthy=core.DualDHCPTests.healthy
    choose=core.DualDHCPTests.choose
    event=core.DualDHCPTests.event
    open=core.DualDHCPTests.open
    def setUp(self):
        core.DualDHCPTests.setUp(self)
        for k in ('A','B'):self.bind(k);self.healthy(k)
        self.choose('A');self.old=dict(state=self.w.snapshot());self.w.__exit__();self.boot='boot2';self.time=1.;self.w=self.open()
        self.waiting=dict(state=self.w.snapshot());self.ready_at=self.time
        for k in ('A','B'):self.bind(k);self.healthy(k)
        self.fresh=dict(state=self.w.snapshot());self.fresh_at=self.time
        self.choose('A');self.final=dict(state=self.w.snapshot());self.final_at=self.time
    def test_formal_core_observations_bind_new_authority(self):
        self.assertTrue(authority(self.fresh,self.waiting,self.old,self.boot,self.fresh_at,True))
        self.assertTrue(authority(self.final,self.waiting,self.old,self.boot,self.final_at))
        self.assertTrue(charged(self.final,self.old['state'],self.boot,self.ready_at,self.final_at))
    def test_retired_snapshot_expired_health_and_wrong_allocation_reject(self):
        mutations=[lambda s:s['state'].update(boot='boot1'),lambda s:s['state'].update(epoch=self.old['state']['epoch']),lambda s:s['state']['links']['A'].update(until=0),lambda s:s['state']['links']['A'].update(last_event=-1),lambda s:s['state']['links']['A'].update(round=-1),lambda s:s['state']['links']['A'].update(session=self.old['state']['links']['A']['session']),lambda s:s['state']['active']['value'].update(gateway='192.0.2.99')]
        for mutate in mutations:
            s=copy.deepcopy(self.final);mutate(s)
            with self.subTest(snapshot=s),self.assertRaises(ValueError):authority(s,self.waiting,self.old,self.boot,self.final_at)
        s=copy.deepcopy(self.final);s['state']=copy.deepcopy(self.old['state']);s['state']['history']=self.final['state']['history'];s['state']['active']=self.final['state']['active']
        with self.assertRaises(ValueError):authority(s,self.waiting,self.old,self.boot,self.final_at)
    def test_charge_uses_this_boot_and_observation_clock(self):
        for updates in (dict(boot='boot1'),dict(at=-1),dict(at=self.final_at+100)):
            s=copy.deepcopy(self.final);s['state']['history'][-1].update(updates)
            with self.subTest(updates=updates),self.assertRaises(ValueError):charged(s,self.old['state'],self.boot,self.ready_at,self.final_at)

class OwnershipTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name);self.fault=self.root/'runtime'/'fault.conf';self.fault.parent.mkdir()
        guest.save(self.root/'installation.json',dict(files=[]));self.boot='boot1'
        p=patch.object(guest,'FAULT',self.fault);p.start();self.addCleanup(p.stop)
        p=patch.object(guest,'boot_id',lambda:self.boot);p.start();self.addCleanup(p.stop)
    def test_foreign_files_symlinks_and_parent_are_preserved(self):
        for kind in ('file','dangling','parent'):
            with self.subTest(kind=kind):
                target=self.root/'foreign-target'
                if kind=='file':self.fault.write_text('foreign')
                elif kind=='dangling':self.fault.symlink_to(target)
                else:self.fault.parent.rmdir();target.mkdir();self.fault.parent.symlink_to(target,target_is_directory=True)
                with self.assertRaises((RuntimeError,FileExistsError)):guest.install(self.root)
                with patch.object(guest,'system') as system:
                    with self.assertRaises(RuntimeError):guest.cleanup(self.root)
                    system.assert_not_called()
                if kind=='file':self.assertEqual(self.fault.read_text(),'foreign');self.fault.unlink()
                elif kind=='dangling':self.assertTrue(self.fault.is_symlink());self.assertFalse(target.exists());self.fault.unlink()
                else:self.assertTrue(self.fault.parent.is_symlink());self.assertEqual(list(target.iterdir()),[]);self.fault.parent.unlink();target.rmdir();self.fault.parent.mkdir()
    def test_exclusive_creation_collision_does_not_overwrite(self):
        original=guest.fault_absent
        def race():original();self.fault.write_text('created concurrently')
        with patch.object(guest,'fault_absent',side_effect=race),self.assertRaises(FileExistsError):guest.install_fault(self.root)
        self.assertEqual(self.fault.read_text(),'created concurrently');self.assertNotIn('runtime_fault',guest.read(self.root/'installation.json'))
    def test_owned_creation_cleanup_and_missing_after_boot(self):
        guest.install_fault(self.root);self.assertEqual(self.fault.read_text(),guest.FAULT_TEXT);guest.remove_fault(self.root);self.assertFalse(self.fault.exists())
        guest.install_fault(self.root);self.fault.unlink();self.boot='boot2';guest.remove_fault(self.root);self.assertNotIn('runtime_fault',guest.read(self.root/'installation.json'))
        guest.install_fault(self.root);guest.remove_fault(self.root)
    def test_changed_ownership_content_or_boot_refuses_deletion(self):
        for field in ('path','inode','device','uid','boot','sha256','content'):
            guest.install_fault(self.root);owned=guest.read(self.root/'installation.json')
            if field=='content':self.fault.write_text('user edit')
            else:
                owned['runtime_fault'][field]=owned['runtime_fault'][field]+1 if type(owned['runtime_fault'][field]) is int else 'changed'
                guest.save(self.root/'installation.json',owned)
            with self.subTest(field=field),self.assertRaises(RuntimeError):guest.remove_fault(self.root)
            self.assertTrue(self.fault.exists());self.fault.unlink();guest.save(self.root/'installation.json',dict(files=[]))
    def test_prepare_error_after_creation_can_clean_owned_only(self):
        neighbor=self.fault.parent/'other.conf';neighbor.write_text('leave intact')
        with self.assertRaisesRegex(RuntimeError,'prepare stopped'):
            try:guest.install_fault(self.root);raise RuntimeError('prepare stopped')
            finally:guest.remove_fault(self.root)
        self.assertFalse(self.fault.exists());self.assertEqual(neighbor.read_text(),'leave intact')
