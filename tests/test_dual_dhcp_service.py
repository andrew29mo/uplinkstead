"""Stage-one production inbox/runtime challenged without Linux routing mocks as proof."""
import copy
from collections import deque
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from uplinkstead.dual_dhcp import DualLifecycle
from uplinkstead.dual_dhcp_service import Inbox, Runtime, Capture
from uplinkstead.dhcp_wire import DHCPTracker
from tests.test_dual_dhcp import ScopedBackend
from tests.test_dhcp_wire import MAC,LEASE,packet


def now():
    # Portable clock injection; actual CLOCK_BOOTTIME is separately VM-qualified.
    return 1000+time.monotonic()


def event(link='B', identity='one', session='s', boot='b'):
    instant = now()
    return dict(link=link,session=session,boot=boot,id=identity,at=instant,reason='bound',
                lease=dict(ip='192.0.2.2' if link=='A' else '198.51.100.2',subnet='24',
                           router='192.0.2.1' if link=='A' else '198.51.100.1',lease='120'),
                options=[],request_at=instant-1,observed_at=instant-.1)


class InboxTests(unittest.TestCase):
    def test_event_is_deep_copied_with_original_time_and_sequence(self):
        box=Inbox(4);box.replace('B','s','b');e=event();at=e['at']
        self.assertEqual(box.put(e),1);e['at']+=500;e['lease']['lease']='999'
        received=box.get();self.assertEqual(received['at'],at)
        self.assertEqual(received['lease']['lease'],'120');self.assertEqual(received['sequence'],1)

    def test_B_cannot_consume_A_reserved_capacity(self):
        box=Inbox(4)
        for k in ('A','B'):box.replace(k,'s','b')
        box.put(event(identity='1'));box.put(event(identity='2'))
        with self.assertRaises(OverflowError):box.put(event(identity='3'))
        self.assertEqual(box.put(event('A')),1)
        self.assertEqual(box.stats()['revoked'],['B']);self.assertEqual(box.stats()['depth'],3)
        self.assertLessEqual(box.stats()['peak'],4)

    def test_duplicate_and_retired_event_are_readonly(self):
        box=Inbox(4);box.replace('B','s','b');e=event();box.put(e)
        before=box.stats()
        with self.assertRaises(ValueError):box.put(e)
        self.assertEqual(box.stats(),before)
        box.replace('B','new','b');before=box.stats()
        with self.assertRaises(ValueError):box.put(e)
        self.assertEqual(box.stats(),before)

    def test_revocation_drops_unclaimed_events_without_rebasing(self):
        box=Inbox(4);box.replace('B','s','b')
        box.put(event(identity='1'));box.put(event(identity='2'))
        with self.assertRaises(OverflowError):box.put(event(identity='3'))
        self.assertIsNone(box.get());self.assertEqual(box.stats()['depth'],0)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.c=dict(links={'A':{'interface':'wanA'},'B':{'interface':'wanB'}},
                    lan=dict(interface='lan0',prefix='10.77.0.0/24'),freshness=10,
                    targets=[dict(ip='203.0.113.2',port=p) for p in (8443,8444,8445)])
        clock_patch=patch('uplinkstead.dual_dhcp_service.now',side_effect=now)
        clock_patch.start();self.addCleanup(clock_patch.stop)
        self.w=DualLifecycle(self.c,self.tmp.name,ScopedBackend,clock=now,boot=lambda:'portable-test-boot').__enter__();self.addCleanup(self.w.__exit__)
        self.release=threading.Event();self.started=threading.Event()
        def slow_probe(*_):self.started.set();self.release.wait(timeout=2);return 3,[]
        self.r=Runtime(self.w,Path(self.tmp.name)/'run/events.sock',Path('unused'),probe=slow_probe)
        def finish():self.release.set();self.r.pool.shutdown(wait=True,cancel_futures=True)
        self.addCleanup(finish)
        for k in ('A','B'):
            self.r.captures[k]=SimpleNamespace(error=None,take_dirty=lambda:False,stats=lambda:{},acknowledge=lambda _:None,is_current=lambda _:True)
            self.r.inbox.replace(k,self.w.s['links'][k]['session'],self.w.s['boot'])

    def submit(self,k='B',**changes):
        e=event(k,session=self.w.s['links'][k]['session'],boot=self.w.s['boot'])
        if 'identity' in changes: changes['id']=changes.pop('identity')
        e.update(changes);self.r.inbox.put(e);return e

    def test_runtime_restores_selected_only_with_new_lease_and_health(self):
        self.r.restore_selected=True;self.submit();self.r.step()
        row=self.w.s['links']['B'];self.w.observation('B',row['generation'],10,now(),3);self.w.observation('B',row['generation'],11,now(),3)
        self.w.choose('B',self.w.s['epoch'],self.w.s['revision']);self.r.restore_target='B'
        before=copy.deepcopy(self.w.s['history']);self.submit(identity='next',reason='renew');self.r.step()
        self.assertIsNone(self.w.s['active']);row=self.w.s['links']['B']
        self.w.observation('B',row['generation'],12,now(),3);self.w.observation('B',row['generation'],13,now(),3)
        self.r.converge();self.assertEqual(self.w.s['active']['link'],'B');self.assertEqual(before,self.w.s['history'])
    def test_restoration_rate_limit_does_not_spend_global_budget(self):
        self.r.restore_selected=True;self.submit();self.r.step();row=self.w.s['links']['B']
        self.w.observation('B',row['generation'],10,now(),3);self.w.observation('B',row['generation'],11,now(),3)
        self.w.choose('B',self.w.s['epoch'],self.w.s['revision']);self.r.restore_target='B'
        self.submit(identity='next',reason='renew');self.r.step();row=self.w.s['links']['B']
        self.w.observation('B',row['generation'],12,now(),3);self.w.observation('B',row['generation'],13,now(),3)
        self.r.restorations.extend([now()]*16);history=copy.deepcopy(self.w.s['history']);self.r.converge()
        self.assertEqual(self.r.restore_status,'RATE_LIMITED');self.assertIsNone(self.w.s['active']);self.assertEqual(history,self.w.s['history'])
    def test_pending_wire_allocation_blocks_restore(self):
        self.r.restore_selected=True;self.submit();self.r.step();row=self.w.s['links']['B']
        self.w.observation('B',row['generation'],10,now(),3);self.w.observation('B',row['generation'],11,now(),3)
        self.w.choose('B',self.w.s['epoch'],self.w.s['revision']);self.r.restore_target='B'
        self.submit(identity='next',reason='renew');self.r.step();row=self.w.s['links']['B']
        self.w.observation('B',row['generation'],12,now(),3);self.w.observation('B',row['generation'],13,now(),3)
        self.r.captures['B'].stats=lambda:dict(pending=True);self.r.converge();self.assertIsNone(self.w.s['active'])

    def test_slow_probe_does_not_block_formal_lease_application(self):
        self.submit();self.r.step();self.assertTrue(self.started.wait(timeout=1))
        before=self.w.s['links']['B']['generation']
        e=self.submit(identity='renewal',reason='renew');self.r.step()
        self.assertEqual(self.w.s['links']['B']['generation'],before+1)
        self.assertEqual(self.w.s['links']['B']['expires'],e['request_at']+120)
        self.assertTrue(self.r.recent[-1]['probe_inflight']['B'])
        self.assertFalse(self.r.futures['B'][0].done())

    def test_expired_backlog_never_starts_a_new_full_lifetime(self):
        instant=now()
        self.submit(at=instant-121,request_at=instant-122,observed_at=instant-121)
        # at must be newer than a client's last event (zero after startup).
        self.r.step();self.assertIsNone(self.w.s['links']['B']['current'])
        self.assertEqual(self.w.s['links']['B']['expires'],0)

    def test_expired_same_xid_renewal_retires_only_its_client(self):
        self.submit('A');self.r.step()
        before=copy.deepcopy(self.w.s['links']['A']);session=self.w.s['links']['B']['session']
        instant=now()
        self.submit(reason='renew',at=instant,request_at=instant-121,observed_at=instant-.1)
        self.r.step()
        self.assertNotEqual(self.w.s['links']['B']['session'],session)
        self.assertIsNone(self.w.s['links']['B']['current'])
        self.assertEqual(self.r.metrics['client_restarts']['B'],1)
        self.assertEqual(self.w.s['links']['A'],before)

    def test_overflow_retires_only_affected_client_authority(self):
        for k in ('A','B'):self.submit(k,identity=k);self.r.step()
        before=copy.deepcopy(self.w.s['links']['A'])
        self.r.inbox=Inbox(4)
        for k in ('A','B'):self.r.inbox.replace(k,self.w.s['links'][k]['session'],self.w.s['boot'])
        self.submit(identity='1');self.submit(identity='2')
        with self.assertRaises(OverflowError):self.submit(identity='3')
        self.r.step()
        self.assertEqual(self.w.s['links']['A'],before)
        self.assertIsNone(self.w.s['links']['B']['current'])
        self.assertEqual(self.r.metrics['client_restarts']['B'],1)

    def test_missing_proof_revokes_only_matching_current_authority(self):
        self.r.captures['B']=SimpleNamespace(claim=lambda *_:(_ for _ in ()).throw(ValueError('no proof')))
        q=event(session=self.w.s['links']['B']['session'],boot=self.w.s['boot'])
        for key in ('request_at','observed_at'):q.pop(key)
        q['op']='event'
        with self.assertRaises(ValueError):self.r.intake(q)
        self.assertEqual(self.r.inbox.stats()['revoked'],['B'])
        self.assertIsNotNone(self.r.inbox.sessions['A'])

    def test_client_origin_can_only_shorten_wire_deadline(self):
        for offset in (-.01,.01):
            q=event(session=self.w.s['links']['B']['session'],boot=self.w.s['boot'])
            origin=q.pop('request_at');q.pop('observed_at');q.update(op='event',id=str(offset),client_origin_ns=int((origin+offset)*1e9),client_xid=42)
            self.r.captures['B']=SimpleNamespace(claim=lambda *_:dict(request_at=origin,observed_at=origin+.1,options=[],xid=42))
            self.r.intake(q);e=self.r.inbox.get()
            self.assertEqual(e['request_at'],min(origin,q['client_origin_ns']/1e9))
            self.assertEqual(e['wire_request_at'],origin)

    def test_client_origin_wrong_xid_revokes_only_B(self):
        q=event(session=self.w.s['links']['B']['session'],boot=self.w.s['boot']);origin=q.pop('request_at');q.pop('observed_at')
        q.update(op='event',client_origin_ns=int(origin*1e9),client_xid=43)
        self.r.captures['B']=SimpleNamespace(claim=lambda *_:dict(request_at=origin,observed_at=origin+.1,options=[],xid=42))
        with self.assertRaises(ValueError):self.r.intake(q)
        self.assertEqual(self.r.inbox.stats()['revoked'],['B'])

    def test_retired_hook_cannot_consume_new_capture_proof(self):
        capture=SimpleNamespace(claim=unittest.mock.Mock())
        self.r.captures['B']=capture
        q=event(session='old',boot=self.w.s['boot'])
        for key in ('request_at','observed_at'):q.pop(key)
        q['op']='event'
        with self.assertRaises(ValueError):self.r.intake(q)
        capture.claim.assert_not_called()

    def test_unclaimed_new_ACK_invalidates_only_affected_old_allocation(self):
        for k in ('A','B'):self.submit(k,identity=k);self.r.step()
        before=copy.deepcopy(self.w.s['links']['A'])
        self.r.captures['B'].take_dirty=unittest.mock.Mock(return_value=True)
        self.r.step()
        self.assertIsNone(self.w.s['links']['B']['current'])
        self.assertEqual(self.w.s['links']['A'],before)

    def test_older_queued_ACK_cannot_restore_after_newer_ACK_observed(self):
        self.submit(capture_version=1)
        self.r.captures['B'].take_dirty=lambda:True
        self.r.captures['B'].is_current=lambda version:version==2
        self.r.step()
        self.assertIsNone(self.w.s['links']['B']['current'])
        self.assertEqual(self.r.metrics['rejected'],1)
        self.assertEqual(self.w.s['links']['B']['event_sequence'],0)


class CaptureTests(unittest.TestCase):
    def test_unanswered_old_ACK_cannot_dirty_or_ambiguate_current_proof(self):
        capture=Capture.__new__(Capture)
        capture.stop=threading.Event();capture.lock=threading.RLock();capture.empty_at=10;capture.error=None;capture.observations=deque(maxlen=32)
        capture.session='current';capture.counts=dict(frames=0,requests=0,acks=0,unsupported=0)
        capture.version=0;capture.versions={};capture.dirty=False;capture.tracker=DHCPTracker(MAC)
        frames=iter([packet(3,xid=10),packet(5,xid=10),packet(3,xid=11),packet(3,xid=12),packet(5,xid=12),packet(5,xid=11)]+[packet(5,xid=11)]*40)
        def receive(_):
            try:return next(frames)
            except StopIteration:capture.stop.set();raise BlockingIOError()
        capture.socket=SimpleNamespace(recv=receive)
        with patch('uplinkstead.dual_dhcp_service.now',return_value=100.):
            capture.run();proof=capture.claim(LEASE,'current')
        self.assertEqual(proof['xid'],12);self.assertEqual(capture.version,2)
        capture.acknowledge(proof['capture_version']);self.assertFalse(capture.take_dirty())
        self.assertEqual(len(capture.observations),32)

    def test_contradictory_ACK_invalidates_already_claimed_queued_proof(self):
        capture=Capture.__new__(Capture)
        capture.stop=threading.Event();capture.lock=threading.RLock();capture.empty_at=10;capture.error=None;capture.observations=deque(maxlen=32)
        capture.session='current';capture.counts=dict(frames=0,requests=0,acks=0,unsupported=0)
        capture.version=0;capture.versions={};capture.dirty=False;capture.tracker=DHCPTracker(MAC)
        def drain(frames):
            frames=iter(frames);capture.stop.clear()
            def receive(_):
                try:return next(frames)
                except StopIteration:capture.stop.set();raise BlockingIOError()
            capture.socket=SimpleNamespace(recv=receive)
            with patch('uplinkstead.dual_dhcp_service.now',return_value=100.):capture.run()
        drain([packet(3),packet(5)])
        with patch('uplinkstead.dual_dhcp_service.now',return_value=100.):proof=capture.claim(LEASE,'current')
        capture.acknowledge(proof['capture_version']);self.assertFalse(capture.take_dirty())
        changed=packet(5).replace(b'\x03\x04\xc0\x00\x02\x01',b'\x03\x04\xc0\x00\x02\x03')
        drain([changed])
        self.assertTrue(capture.take_dirty());self.assertFalse(capture.is_current(proof['capture_version']))
        self.assertFalse(capture.tracker.acks)

    def test_backlogged_frames_use_previous_empty_queue_time(self):
        capture=Capture.__new__(Capture)
        capture.stop=threading.Event();capture.lock=threading.RLock();capture.empty_at=10;capture.error=None;capture.observations=deque(maxlen=32)
        capture.counts=dict(frames=0,requests=0,acks=0,unsupported=0);capture.version=0;capture.versions={};capture.dirty=False
        capture.tracker=DHCPTracker(MAC)
        frames=iter([packet(3),packet(5)])
        def receive(_):
            try:return next(frames)
            except StopIteration:capture.stop.set();raise BlockingIOError()
        capture.socket=SimpleNamespace(recv=receive)
        with patch('uplinkstead.dual_dhcp_service.now',side_effect=[100.,101.,102.]):capture.run()
        proof=capture.tracker.claim(LEASE,103.)
        self.assertEqual(proof['request_at'],10.)
        self.assertEqual(proof['request_at']+60,70.)  # Already expired, never 160.

    def test_claim_keeps_matching_ACK_version_instead_of_latest_global_version(self):
        capture=Capture.__new__(Capture)
        capture.stop=threading.Event();capture.lock=threading.RLock();capture.empty_at=10;capture.error=None;capture.observations=deque(maxlen=32)
        capture.session='current';capture.counts=dict(frames=0,requests=0,acks=0,unsupported=0)
        capture.version=0;capture.versions={};capture.dirty=False;capture.tracker=DHCPTracker(MAC)
        second=packet(5,xid=2).replace(b'\x33\x04\x00\x00\x00\x3c',b'\x33\x04\x00\x00\x00\x3d')
        frames=iter([packet(3),packet(5),packet(3,xid=2),second])
        def receive(_):
            try:return next(frames)
            except StopIteration:capture.stop.set();raise BlockingIOError()
        capture.socket=SimpleNamespace(recv=receive)
        with patch('uplinkstead.dual_dhcp_service.now',return_value=100.):
            capture.run()
            with self.assertRaises(ValueError):capture.tracker.claim(LEASE,100.)
            proof=capture.claim(dict(LEASE,lease='61'),'current')
        self.assertEqual(proof['capture_version'],2)
        self.assertEqual(capture.version,2)
        self.assertTrue(capture.is_current(proof['capture_version']))
        self.assertTrue(capture.take_dirty());self.assertTrue(capture.take_dirty())

    def test_old_claim_cannot_clear_a_newer_allocation_notice(self):
        capture=Capture.__new__(Capture);capture.lock=threading.RLock();capture.version=2;capture.dirty=True
        capture.acknowledge(1);self.assertTrue(capture.dirty)
        capture.acknowledge(2);self.assertFalse(capture.dirty)

    def test_non_DHCP_frame_does_not_kill_observer(self):
        capture=Capture.__new__(Capture)
        capture.stop=threading.Event();capture.lock=threading.RLock();capture.empty_at=1;capture.error=None;capture.observations=deque(maxlen=32)
        capture.counts=dict(frames=0,requests=0,acks=0,unsupported=0)
        tracker=SimpleNamespace(feed=unittest.mock.Mock(side_effect=ValueError('ordinary IPv4')),acks={})
        capture.tracker=tracker
        def receive(_):
            if tracker.feed.call_count: capture.stop.set();raise BlockingIOError()
            return b'ordinary non-DHCP frame'
        capture.socket=SimpleNamespace(recv=receive)
        with patch('uplinkstead.dual_dhcp_service.now',side_effect=now):capture.run()
        self.assertIsNone(capture.error);tracker.feed.assert_called_once()


if __name__=='__main__':unittest.main()
