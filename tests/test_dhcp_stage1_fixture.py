"""Stage 1 receipt helpers fail closed without a Linux VM dependency."""
import json
import errno
import socket
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from tools import dhcp_stage1_guest as guest


class Stage1FixtureTests(unittest.TestCase):
    def test_wait_never_treats_timeout_as_success(self):
        with patch.object(guest.time,'monotonic',side_effect=[0,0,0,2]),patch.object(guest.time,'sleep'):
            with self.assertRaises(TimeoutError):guest.wait(lambda:False,timeout=1)

    def test_wait_predicate_failure_is_not_swallowed(self):
        with self.assertRaisesRegex(RuntimeError,'dead service'):
            guest.wait(lambda:(_ for _ in ()).throw(RuntimeError('dead service')))

    def test_wait_returns_observed_payload(self):
        observed={'state':'READY'}
        self.assertIs(guest.wait(lambda:observed),observed)

    def test_cleanup_failure_invalidates_receipt_even_after_cases_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            result=dict(passed=True,cases=[dict(passed=True)])
            fixture=SimpleNamespace(cleanup=lambda:(_ for _ in ()).throw(RuntimeError('network changed')))
            with self.assertRaisesRegex(RuntimeError,'network changed'):
                guest.finalize(Path(directory),result,fixture,None)
            receipt=json.loads((Path(directory)/'stage1-guest.json').read_text())
            self.assertFalse(receipt['passed']);self.assertEqual(receipt['cleanup_failure']['type'],'RuntimeError')

    def test_service_stop_failure_still_runs_network_cleanup_and_fails_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            observed=[];result=dict(passed=True)
            service=SimpleNamespace(stop=lambda:(_ for _ in ()).throw(RuntimeError('stop failed')))
            fixture=SimpleNamespace(cleanup=lambda:observed.append('cleanup') or dict(namespaces_removed=True))
            with self.assertRaisesRegex(RuntimeError,'stop failed'):
                guest.finalize(Path(directory),result,fixture,service)
            self.assertEqual(observed,['cleanup']);self.assertFalse(result['passed'])

    def test_immutable_link_projection_excludes_changing_probe_rounds(self):
        row=dict(session='s',generation=2,current={'ip':'192.0.2.2'},expires=100,round=3,state='HEALTHY')
        projection=guest.immutable_link(row);row['current']['ip']='changed';row['round']=4
        self.assertEqual(projection['current']['ip'],'192.0.2.2');self.assertNotIn('round',projection)

    def test_service_call_propagates_rejection(self):
        service=object.__new__(guest.Service)
        service.raw=lambda q:dict(ok=False,error='Stale event')
        with self.assertRaisesRegex(RuntimeError,'Stale event'):service.call('event')

    def test_service_call_retains_raw_top_level_state_and_runtime(self):
        service=object.__new__(guest.Service);observed=dict(ok=True,state={},runtime={})
        service.raw=lambda q:observed
        self.assertIs(service.call('status'),observed)

    def test_connect_backlog_before_send_is_separate_transport_rejection(self):
        peer=MagicMock();peer.connect.side_effect=BlockingIOError(errno.EAGAIN,'Backlog full')
        context=MagicMock();context.__enter__.return_value=peer
        with patch.object(guest.socket,'socket',return_value=context):
            result=guest.exchange(Path('/tmp/unused'),{'op':'event'},allow_connect_backpressure=True)
        self.assertEqual(result,dict(ok=False,transport_rejected=True,error='ConnectBacklogFull'))
        peer.sendall.assert_not_called();peer.recv.assert_not_called()

    def test_backlog_classification_is_opt_in_and_timeout_is_never_passed(self):
        for error in (BlockingIOError(errno.EAGAIN,'Backlog full'),socket.timeout('late'),PermissionError(errno.EACCES,'denied')):
            with self.subTest(error=type(error).__name__):
                peer=MagicMock();peer.connect.side_effect=error
                context=MagicMock();context.__enter__.return_value=peer
                with patch.object(guest.socket,'socket',return_value=context),self.assertRaises(type(error)):
                    guest.exchange(Path('/tmp/unused'),{'op':'event'})
                peer.sendall.assert_not_called()

    def test_timeout_after_connect_is_not_classified_as_transport_rejection(self):
        peer=MagicMock();peer.recv.side_effect=socket.timeout('Reply missing')
        context=MagicMock();context.__enter__.return_value=peer
        with patch.object(guest.socket,'socket',return_value=context),self.assertRaises(socket.timeout):
            guest.exchange(Path('/tmp/unused'),{'op':'event'},allow_connect_backpressure=True)
        peer.sendall.assert_called_once()
