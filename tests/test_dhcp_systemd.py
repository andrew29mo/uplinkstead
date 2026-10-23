"""Portable production recovery/notify tests; systemd enforcement is a VM gate."""
import copy,json,os,socket,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from tests import test_dual_dhcp as core
from tests import test_dual_dhcp_service as runtime
from uplinkstead import dual_dhcp_stop as stop
from uplinkstead.dual_dhcp_service import notify_ready

class DeploymentTests(unittest.TestCase):
    def test_named_client_uses_busybox_dispatch_without_changing_executable(self):
        t=runtime.RuntimeTests();t.setUp()
        try:
            from unittest.mock import Mock
            t.r.captures['A']=Mock();t.r.executable='/usr/libexec/uplinkstead-busybox'
            with patch('uplinkstead.dual_dhcp_service.subprocess.Popen') as spawn:t.r.spawn('A')
            self.assertEqual(spawn.call_args.args[0][:2],['busybox','udhcpc'])
            self.assertEqual(spawn.call_args.kwargs['executable'],t.r.executable)
        finally:t.doCleanups()
    def test_readiness_uses_real_datagram_and_no_socket_is_foreground(self):
        with tempfile.TemporaryDirectory() as tmp,socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as receiver:
            path=str(Path(tmp)/'notify');receiver.bind(path);receiver.settimeout(1)
            with patch.dict(os.environ,{'NOTIFY_SOCKET':path}):notify_ready()
            self.assertIn(b'READY=1',receiver.recv(4096))
        with patch.dict(os.environ,{},clear=True):notify_ready()
    def test_notify_failure_is_not_silent_readiness(self):
        with patch.dict(os.environ,{'NOTIFY_SOCKET':'/not-present/uplinkstead-notify'}):
            with self.assertRaises(OSError):notify_ready()
    def exercise(self,fail=False):
        t=core.DualDHCPTests();t.setUp()
        try:
            for k in ('A','B'):t.bind(k);t.healthy(k)
            t.choose('A');t.w.pause();t.w.s['latched']=True;t.w.save()
            before=copy.deepcopy(t.w.s);t.w.__exit__()
            class Clocked(core.DualLifecycle):
                def __init__(self,c,d,b):super().__init__(c,d,b,clock=lambda:110.,boot=lambda:'boot1')
            class Failed(core.ScopedBackend):
                def reconcile(self,*a):raise OSError('recovery kernel failure')
            with patch.object(stop,'DualLifecycle',Clocked):
                if fail:
                    with self.assertRaises(OSError):stop.quarantine(t.c,t.tmp.name,Failed)
                    return
                answer=stop.quarantine(t.c,t.tmp.name,core.ScopedBackend)
            with Clocked(t.c,t.tmp.name,core.ScopedBackend) as w:
                self.assertTrue(answer['quarantined']);self.assertGreater(w.s['epoch'],before['epoch'])
                self.assertTrue(w.s['paused']);self.assertTrue(w.s['latched']);self.assertEqual(w.s['history'],before['history'])
                for k in ('A','B'):
                    self.assertIsNone(w.s['links'][k]['current']);self.assertEqual(w.health[k]['state'],'WAITING')
                    self.assertNotEqual(w.s['links'][k]['session'],before['links'][k]['session'])
                self.assertIsNone(w.s['active'])
                q=dict(op='pause',epoch=before['epoch'],revision=before['revision'],id='f'*32)
                with self.assertRaises(RuntimeError):w.operator(q)
        finally:t.doCleanups()
    def test_poststop_uses_formal_recovery_preserves_limits_retires_authority(self):self.exercise()
    def test_failed_poststop_cannot_report_quarantine_success(self):self.exercise(True)
