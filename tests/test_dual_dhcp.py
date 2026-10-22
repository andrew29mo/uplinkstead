"""Portable contract tests invoke the formal SQLite-backed dual lifecycle."""
import copy
import json
import select
import subprocess
import sys
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from uplinkstead.dual_dhcp import DualLifecycle
from uplinkstead.linux import Blocked


class ScopedBackend:
    def __init__(self, config, fd):
        self.allocations = dict(A=None,B=None)
        self.active = None
        self.calls = []
        self.fail = False
        self.fd = fd

    def reconcile(self, allowed, new, active):
        self.calls.append(('recover',copy.deepcopy(allowed)))
        self.allocations = copy.deepcopy(new)
        self.active = copy.deepcopy(active)

    def link(self, link, allowed, new, active):
        self.calls.append(('link',link,copy.deepcopy(allowed)))
        self.allocations[link] = copy.deepcopy(new)
        self.active = copy.deepcopy(active)
        if self.fail:
            raise OSError('after partial kernel mutation')

    def select(self, allowed, active, deadline):
        self.calls.append(('select',copy.deepcopy(active)))
        self.active = copy.deepcopy(active)
        if self.fail:
            raise OSError('unknown selection outcome')


class DualDHCPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.time = 100.
        self.boot = 'boot1'
        self.c = dict(links=dict(A=dict(interface='wanA'),B=dict(interface='wanB')),
                      lan=dict(interface='lan0',prefix='10.30.0.0/24'),
                      targets=[dict(ip='203.0.113.'+str(n),port=443) for n in (1,2,3)])
        self.w = self.open()
        self.addCleanup(lambda:self.w.__exit__())

    def open(self):
        return DualLifecycle(self.c,self.tmp.name,ScopedBackend,clock=lambda:self.time,boot=lambda:self.boot).__enter__()

    def event(self,k,**changes):
        self.time += .01
        row = self.w.snapshot()['links'][k]
        data = dict(link=k,session=row['session'],boot=self.boot,revision=row['revision'],at=self.time,reason='bound',lease=dict(ip='192.0.2.2' if k=='A' else '198.51.100.2',subnet='24',router='192.0.2.1' if k=='A' else '198.51.100.1',lease='60'))
        data.update(changes)
        return data

    def bind(self,k,**changes):
        return self.w.callback(**self.event(k,**changes))

    def healthy(self,k):
        for n in range(2):
            self.time += .01
            self.w.observation(k,self.w.s['links'][k]['generation'],n,self.time,3)

    def choose(self,k):
        return self.w.choose(k,self.w.s['epoch'],self.w.s['revision'])

    def wire_event(self, k, sequence=1, **changes):
        row = self.w.s['links'][k]
        data = dict(link=k,session=row['session'],boot=self.boot,sequence=sequence,
                    at=self.time,reason='bound',request_at=self.time-5,
                    observed_at=self.time-1,
                    lease=dict(ip='192.0.2.2' if k=='A' else '198.51.100.2',
                               subnet='24',router='192.0.2.1' if k=='A' else '198.51.100.1',lease='60'))
        data.update(changes)
        return data

    def test_wire_origin_not_hook_or_processing_time_determines_deadline(self):
        event = self.wire_event('A')
        self.time += 20
        result = self.w.wire_callback(**event)
        self.assertEqual(result['links']['A']['expires'],155.)
        self.assertEqual(result['links']['A']['event_sequence'],1)
        self.time = 155.; self.w.tick()
        self.assertIsNone(self.w.s['links']['A']['current'])

    def test_wire_backlog_expired_current_event_withdraws_only_its_link(self):
        self.bind('A'); self.healthy('A'); self.choose('A'); self.bind('B')
        a = self.w.snapshot()['links']['A']
        result = self.w.wire_callback(**self.wire_event('B',request_at=self.time-61))
        self.assertTrue(result['lease_rejected'])
        self.assertIsNone(result['links']['B']['current'])
        self.assertEqual(result['links']['A'],a)
        self.assertEqual(result['active']['link'],'A')

    def test_wire_stale_sequence_session_and_boot_are_readonly(self):
        event = self.wire_event('B'); self.w.wire_callback(**event)
        for changes in ({},{'sequence':0},{'sequence':2,'session':'retired'},{'sequence':2,'boot':'old'}):
            before = self.w.snapshot(); calls = copy.deepcopy(self.w.backend.calls)
            with self.assertRaises(Blocked): self.w.wire_callback(**dict(event,**changes))
            self.assertEqual(before,self.w.snapshot()); self.assertEqual(calls,self.w.backend.calls)

    def test_wire_missing_proof_and_unsupported_options_withdraw_current(self):
        for changes in ({'request_at':None},{'observed_at':self.time+1},{'options':['121']}):
            self.bind('B')
            event = self.wire_event('B',sequence=self.w.s['links']['B']['event_sequence']+1,**changes)
            result = self.w.wire_callback(**event)
            self.assertTrue(result['lease_rejected'])
            self.assertIsNone(result['links']['B']['current'])

    def test_wire_sequence_is_durable_and_client_restart_rotates_authority(self):
        event = self.wire_event('B',sequence=7); self.w.wire_callback(**event)
        with sqlite3.connect(Path(self.tmp.name)/'journal.sqlite') as db:
            saved = json.loads(db.execute('SELECT value FROM state').fetchone()[0])
        self.assertEqual(saved['links']['B']['event_sequence'],7)
        self.w.restart_client('B')
        self.assertEqual(self.w.s['links']['B']['event_sequence'],0)
        before = self.w.snapshot()
        with self.assertRaises(Blocked): self.w.wire_callback(**dict(event,sequence=8))
        self.assertEqual(before,self.w.snapshot())

    def test_historical_journal_migration_is_explicit_and_validated(self):
        self.bind('A'); self.w.__exit__()
        with sqlite3.connect(Path(self.tmp.name)/'journal.sqlite') as db:
            state = json.loads(db.execute('SELECT value FROM state').fetchone()[0])
            for row in state['links'].values(): del row['event_sequence']
            db.execute('UPDATE state SET value=?',(json.dumps(state),))
        self.w = self.open()
        self.assertTrue(all(row['event_sequence']==0 for row in self.w.s['links'].values()))
        self.w.__exit__()
        with sqlite3.connect(Path(self.tmp.name)/'journal.sqlite') as db:
            state = json.loads(db.execute('SELECT value FROM state').fetchone()[0])
            state['links']['A']['event_sequence'] = True
            db.execute('UPDATE state SET value=?',(json.dumps(state),))
        with self.assertRaises(Blocked): self.open()
        # Keep cleanup idempotent after deliberately invalid on-disk journal.

    def test_inactive_renew_preserves_active_identity_and_proof(self):
        self.bind('A'); self.healthy('A'); self.choose('A'); self.bind('B')
        before = self.w.snapshot()
        self.bind('B',reason='renew')
        after = self.w.snapshot()
        self.assertEqual(before['links']['A'],after['links']['A'])
        self.assertEqual(before['active'],after['active'])
        self.assertEqual(self.w.backend.allocations['A'],before['links']['A']['current'])
        self.assertEqual(after['links']['B']['state'],'UNVERIFIED')

    def test_client_restart_is_local_and_retires_callback(self):
        self.bind('A'); self.healthy('A'); self.choose('A'); self.bind('B')
        stale = self.event('B')
        a = self.w.snapshot()['links']['A']
        self.w.restart_client('B')
        before = self.w.snapshot()
        with self.assertRaises(Blocked): self.w.callback(**stale)
        self.assertEqual(before,self.w.snapshot())
        self.assertEqual(a,self.w.snapshot()['links']['A'])
        self.assertEqual(self.w.s['active']['link'],'A')

    def test_current_conflict_withdraws_only_proposer(self):
        self.bind('A'); self.healthy('A'); self.choose('A'); self.bind('B')
        a = self.w.snapshot()['links']['A']
        result = self.bind('B',lease=dict(ip='192.0.2.3',router='192.0.2.1',subnet='24',lease='60'))
        self.assertTrue(result['lease_rejected'])
        self.assertIsNone(result['links']['B']['current'])
        self.assertEqual(result['links']['A'],a)
        self.assertEqual(result['active']['link'],'A')

    def test_route_options_and_delayed_current_event_invalidate_old(self):
        for field in ('options','at'):
            self.bind('B')
            e = self.event('B')
            if field == 'options': e['options'] = ['121']
            else: self.time += 4
            r = self.w.callback(**e)
            self.assertTrue(r['lease_rejected'])
            self.assertIsNone(r['links']['B']['current'])

    def test_stale_callback_is_readonly_even_if_payload_conflicts(self):
        e = self.event('B'); self.bind('B')
        before = self.w.snapshot(); calls = copy.deepcopy(self.w.backend.calls)
        with self.assertRaises(Blocked): self.w.callback(**e)
        self.assertEqual(before,self.w.snapshot()); self.assertEqual(calls,self.w.backend.calls)

    def test_stale_probe_generation_and_selection_rejected(self):
        self.bind('A'); old = self.w.s['links']['A']['generation']
        self.bind('A',reason='renew'); before = self.w.snapshot()
        with self.assertRaises(Blocked): self.w.observation('A',old,0,self.time,3)
        self.healthy('A')
        with self.assertRaises(Blocked): self.w.choose('A',self.w.s['epoch']-1,self.w.s['revision'])
        self.assertIsNone(self.w.s['active'])
        self.assertEqual(before['links']['A']['generation'],self.w.s['links']['A']['generation'])

    def test_unknown_immediately_withdraws_and_failure_debounce_expires(self):
        self.bind('A'); self.healthy('A'); self.choose('A')
        self.w.observation('A',self.w.s['links']['A']['generation'],2,self.time,0)
        self.assertIsNotNone(self.w.s['active'])
        self.time += 2.1; self.w.tick(); self.assertIsNone(self.w.s['active'])
        self.bind('A'); self.healthy('A'); self.choose('A')
        self.w.observation('A',self.w.s['links']['A']['generation'],2,self.time,None)
        self.assertIsNone(self.w.s['active'])

    def test_pause_and_latch_never_block_expiry_cleanup(self):
        self.bind('A'); self.healthy('A'); self.choose('A')
        self.w.pause(); self.w.s['latched'] = True; self.w.save()
        history = copy.deepcopy(self.w.s['history'])
        self.time += 61; self.w.tick()
        self.assertIsNone(self.w.s['active']); self.assertIsNone(self.w.s['links']['A']['current'])
        self.assertEqual(history,self.w.s['history'])
        self.bind('B'); self.healthy('B')
        with self.assertRaises(Blocked): self.choose('B')

    def test_partial_write_persists_intent_and_recovery_quarantines_both(self):
        self.bind('A'); self.bind('B'); oldA = copy.deepcopy(self.w.s['links']['A']['current'])
        self.w.backend.fail = True
        with self.assertRaises(OSError): self.bind('A',lease=dict(ip='192.0.2.3',router='192.0.2.1',subnet='24',lease='60'))
        self.assertEqual(self.w.s['phase'],'RECOVERY_REQUIRED')
        with self.assertRaises(Blocked): self.bind('B')
        with sqlite3.connect(Path(self.tmp.name)/'journal.sqlite') as db:
            saved = json.loads(db.execute('SELECT value FROM state').fetchone()[0])
        self.assertEqual(saved['pending']['old'],oldA)
        self.assertEqual(saved['pending']['new']['ip'],'192.0.2.3')
        old_session = self.w.s['links']['B']['session']
        self.w.__exit__(); self.boot = 'boot2'; self.w = self.open()
        allowed = self.w.backend.calls[0][1]
        self.assertIn(oldA,allowed['A']); self.assertTrue(any(v and v['ip']=='192.0.2.3' for v in allowed['A']))
        self.assertIsNone(self.w.s['active'])
        self.assertTrue(all(v['current'] is None for v in self.w.s['links'].values()))
        self.assertNotEqual(old_session,self.w.s['links']['B']['session'])

    def test_budget_survives_new_boot_and_same_ip_reactivation_counts(self):
        self.w.budget = 1
        self.bind('A'); self.healthy('A'); self.choose('A')
        self.w.restart_client('A'); self.bind('A'); self.healthy('A')
        with self.assertRaises(Blocked): self.choose('A')
        self.assertTrue(self.w.s['latched'])
        self.w.__exit__(); self.boot='boot2'; self.w=self.open()
        self.assertTrue(self.w.s['latched']); self.assertEqual(len(self.w.s['history']),1)

    def test_failed_selection_is_durable_and_retires_writer(self):
        self.bind('A'); self.healthy('A'); self.w.backend.fail = True
        with self.assertRaises(OSError): self.choose('A')
        self.assertEqual(self.w.s['pending']['after']['link'],'A')
        self.assertEqual(len(self.w.s['history']),1)
        with self.assertRaises(Blocked): self.w.tick()

    def test_snapshot_does_not_grant_mutable_authority(self):
        self.bind('A'); s = self.w.snapshot(); s['links']['A']['current']['ip']='1.2.3.4'
        self.assertEqual(self.w.s['links']['A']['current']['ip'],'192.0.2.2')


    def test_intent_save_failure_retires_before_any_network_mutation(self):
        self.bind('A')
        calls = copy.deepcopy(self.w.backend.calls)
        with patch.object(self.w, 'save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): self.bind('A',reason='renew')
        self.assertEqual(calls,self.w.backend.calls)
        self.assertEqual(self.w.s['phase'],'RECOVERY_REQUIRED')
        with self.assertRaises(Blocked): self.w.tick()

    def test_choose_rechecks_revision_after_expiry_cleanup(self):
        self.bind('B',lease=dict(ip='198.51.100.2',router='198.51.100.1',subnet='24',lease='1'))
        self.bind('A'); self.healthy('A')
        epoch,revision=self.w.s['epoch'],self.w.s['revision']
        self.time += 1.1
        with self.assertRaises(Blocked): self.w.choose('A',epoch,revision)
        self.assertIsNone(self.w.s['active'])
        self.assertIsNone(self.w.s['links']['B']['current'])

    def test_slow_selection_does_not_leave_expired_lease_active(self):
        self.bind('A',lease=dict(ip='192.0.2.2',router='192.0.2.1',subnet='24',lease='1'))
        self.healthy('A')
        original = self.w.backend.select
        def slow(allowed,active,deadline):
            original(allowed,active,deadline)
            if active: self.time += 2
        with patch.object(self.w.backend,'select',side_effect=slow):
            self.choose('A')
        self.assertIsNone(self.w.s['active'])
        self.assertIsNone(self.w.s['links']['A']['current'])

    def test_restart_quarantines_both_valid_leases_and_health(self):
        self.bind('A'); self.bind('B'); self.healthy('A'); self.healthy('B'); self.choose('A')
        old = self.w.snapshot()
        self.w.__exit__(); self.boot='boot2'; self.w=self.open()
        for k in ('A','B'):
            self.assertIn(old['links'][k]['current'],self.w.backend.calls[0][1][k])
            self.assertIsNone(self.w.s['links'][k]['current'])
            self.assertEqual(self.w.snapshot()['links'][k]['state'],'WAITING')
            self.assertNotEqual(self.w.s['links'][k]['session'],old['links'][k]['session'])
        self.assertIsNone(self.w.s['active'])

    def test_same_link_update_retires_old_health_but_not_other_authority(self):
        self.bind('A'); self.bind('B'); self.healthy('A'); self.choose('A')
        callbackB = self.event('B',reason='renew')
        self.bind('A',reason='renew')
        self.assertIsNone(self.w.s['active'])
        self.assertEqual(self.w.snapshot()['links']['A']['state'],'UNVERIFIED')
        self.w.callback(**callbackB)
        self.assertIsNotNone(self.w.s['links']['B']['current'])

    def test_pause_resume_retires_queued_selection(self):
        self.bind('A'); self.healthy('A')
        epoch,revision = self.w.s['epoch'],self.w.s['revision']
        self.w.pause(); self.w.pause(False)
        with self.assertRaises(Blocked): self.w.choose('A',epoch,revision)
        self.assertIsNone(self.w.s['active'])

    def test_inherited_helper_lock_blocks_successor_until_retirement(self):
        self.bind('A'); self.bind('B')
        old = copy.deepcopy(self.w.s['links']['A']['current'])
        old_epoch = self.w.s['epoch']
        self.w.backend.fail = True
        with self.assertRaises(OSError):
            self.bind('A',lease=dict(ip='192.0.2.3',router='192.0.2.1',subnet='24',lease='60'))
        pending_new = copy.deepcopy(self.w.s['pending']['new'])
        # This real child inherits the formal writer's actual lock fd. The
        # stopping handshake ensures it is still alive after writer closure.
        code = "import os,signal; print('inherited', flush=True); os.kill(os.getpid(),signal.SIGSTOP)"
        helper = subprocess.Popen([sys.executable,'-c',code],pass_fds=(self.w.fd,),
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            readable,_,_ = select.select([helper.stdout],[],[],5)
            self.assertTrue(readable,'helper readiness timed out')
            self.assertEqual(helper.stdout.readline().strip(),'inherited')
            self.assertIsNone(helper.poll())
            self.w.__exit__()
            with self.assertRaises(BlockingIOError): self.open()
            helper.kill()
            helper.communicate(timeout=5)
            self.assertIsNotNone(helper.returncode)
            self.w = self.open()
            recovered = self.w.backend.calls[0][1]
            self.assertIn(old,recovered['A'])
            self.assertIn(pending_new,recovered['A'])
            self.assertIsNone(self.w.s['active'])
            self.assertTrue(all(v['current'] is None for v in self.w.s['links'].values()))
            self.bind('A'); self.healthy('A')
            before = self.w.snapshot()
            calls = copy.deepcopy(self.w.backend.calls)
            persisted = self.w.db.execute('SELECT value FROM state').fetchone()[0]
            with self.assertRaises(Blocked):
                self.w.choose('A',old_epoch,self.w.s['revision'])
            self.assertEqual(before,self.w.snapshot())
            self.assertEqual(calls,self.w.backend.calls)
            self.assertEqual(persisted,self.w.db.execute('SELECT value FROM state').fetchone()[0])
        finally:
            if helper.poll() is None:
                helper.kill()
            helper.communicate(timeout=5)

    def test_internal_selection_refuses_retired_writer(self):
        self.bind('A'); self.healthy('A')
        self.w.s['phase'] = 'RECOVERY_REQUIRED'
        calls = copy.deepcopy(self.w.backend.calls)
        with self.assertRaises(Blocked): self.w._select(None)
        self.assertEqual(calls,self.w.backend.calls)

    def test_valid_inactive_callback_cannot_preserve_expired_active_lease(self):
        self.bind('A',lease=dict(ip='192.0.2.2',router='192.0.2.1',subnet='24',lease='1'))
        self.healthy('A'); self.choose('A'); self.bind('B')
        history = copy.deepcopy(self.w.s['history'])
        self.time += 1.1
        result = self.bind('B',reason='renew')
        self.assertIsNone(result['active'])
        self.assertIsNone(result['links']['A']['current'])
        self.assertIsNone(self.w.backend.allocations['A'])
        self.assertIsNotNone(result['links']['B']['current'])
        self.assertEqual(history,self.w.s['history'])

    def test_slow_callback_also_cleans_other_expired_health(self):
        self.bind('A'); self.healthy('A'); self.choose('A'); self.bind('B')
        original = self.w.backend.link
        def slow(link,allowed,new,active):
            original(link,allowed,new,active)
            if link == 'B': self.time += 3
        with patch.object(self.w.backend,'link',side_effect=slow):
            result = self.bind('B',reason='renew')
        self.assertIsNone(result['active'])
        self.assertEqual(result['links']['A']['state'],'UNKNOWN')
        self.assertIsNotNone(result['links']['A']['current'])

    def test_slow_withdrawal_precheck_has_no_health_deadline(self):
        self.bind('A'); self.healthy('A'); self.choose('A')
        original = self.w.backend.select
        observed_deadlines = []
        def slow(allowed,active,deadline):
            observed_deadlines.append(deadline)
            self.time += 3  # Simulate ownership readback before route flush.
            if deadline is not None and deadline <= self.time:
                raise Blocked('Health evidence expired before dispatch')
            original(allowed,active,deadline)
        with patch.object(self.w.backend,'select',side_effect=slow):
            self.w.observation('A',self.w.s['links']['A']['generation'],2,self.time,None)
        self.assertEqual(observed_deadlines,[None])
        self.assertIsNone(self.w.s['active'])
        self.assertIsNone(self.w.backend.active)
        self.assertEqual(self.w.s['phase'],'READY')

    def test_exclusive_writer_lock(self):
        with self.assertRaises(BlockingIOError): self.open()

    def test_corrupt_journal_rejected_before_backend_mutation(self):
        self.w.__exit__()
        with sqlite3.connect(Path(self.tmp.name)/'journal.sqlite') as db:
            state = json.loads(db.execute('SELECT value FROM state').fetchone()[0]); state['links']['A']['current']={'ip':'garbage'}
            db.execute('UPDATE state SET value=?',(json.dumps(state),))
        with self.assertRaises(Blocked): self.open()

class LeaseRestorationTests(unittest.TestCase):
    setUp=DualDHCPTests.setUp
    open=DualDHCPTests.open
    event=DualDHCPTests.event
    bind=DualDHCPTests.bind
    healthy=DualDHCPTests.healthy
    choose=DualDHCPTests.choose
    def test_same_WAN_new_generation_restores_without_spending_budget(self):
        self.w.budget=1;self.bind('A');self.healthy('A');self.choose('A')
        history=copy.deepcopy(self.w.s['history'])
        for _ in range(4):
            self.bind('A',reason='renew')
            with self.assertRaises(Blocked):self.w.restore('A',self.w.s['epoch'],self.w.s['revision'])
            self.healthy('A');self.w.restore('A',self.w.s['epoch'],self.w.s['revision'])
            self.assertEqual(self.w.s['active']['link'],'A');self.assertEqual(self.w.s['history'],history)
            self.assertFalse(self.w.s['latched'])
    def test_health_flapping_does_not_reuse_same_generation_restoration(self):
        self.bind('A');self.healthy('A');self.choose('A');self.bind('A',reason='renew');self.healthy('A')
        self.w.restore('A',self.w.s['epoch'],self.w.s['revision'])
        self.w._select(None)
        with self.assertRaises(Blocked):self.w.restore('A',self.w.s['epoch'],self.w.s['revision'])
    def test_restore_cannot_cross_WAN_after_withdrawal(self):
        self.w.budget=1;self.bind('A');self.bind('B');self.healthy('A');self.healthy('B');self.choose('A')
        self.w.transition('A',None,0)
        with self.assertRaises(Blocked):self.w.restore('B',self.w.s['epoch'],self.w.s['revision'])
        with self.assertRaises(Blocked):self.choose('B')
        self.assertTrue(self.w.s['latched']);self.assertIsNone(self.w.s['active'])
    def test_old_restoration_token_and_old_health_cannot_select_new_lease(self):
        self.bind('A');self.healthy('A');self.choose('A');old=copy.deepcopy(self.w.s)
        self.bind('A',reason='renew')
        with self.assertRaises(Blocked):self.w.restore('A',old['epoch'],old['revision'])
        with self.assertRaises(Blocked):self.w.observation('A',old['links']['A']['generation'],99,self.time,3)
        self.assertIsNone(self.w.s['active'])
    def test_writer_reopen_disarms_restoration_without_resetting_budget(self):
        self.bind('A');self.healthy('A');self.choose('A');history=copy.deepcopy(self.w.s['history'])
        self.w.__exit__();self.w=self.open()
        self.assertIsNone(self.w.s['selection']);self.assertEqual(self.w.s['history'],history)
    def test_restore_is_blocked_by_pause_and_latch(self):
        self.bind('A');self.healthy('A');self.choose('A');self.bind('A',reason='renew');self.healthy('A')
        for key in ('paused','latched'):
            self.w.s[key]=True
            with self.assertRaises(Blocked):self.w.restore('A',self.w.s['epoch'],self.w.s['revision'])
            self.w.s[key]=False
    def test_historical_journal_additive_migration_preserves_budget(self):
        self.bind('A');self.healthy('A');self.choose('A');history=copy.deepcopy(self.w.s['history'])
        self.w.s.pop('selection');self.w.save();self.w.__exit__();self.w=self.open()
        self.assertIsNone(self.w.s['selection']);self.assertEqual(self.w.s['history'],history)
    def test_invalid_future_selection_anchor_rejected(self):
        self.w.s['selection']=dict(link='A',generation=999);self.w.save();self.w.__exit__()
        with self.assertRaises(Blocked):self.open()
