"""Production automatic runtime/core with deterministic time and injected IO races.

ScopedBackend is a portable mutation double; actual Linux writes are a separate VM gate.
"""
import copy
from concurrent.futures import Future
import threading
from unittest.mock import patch
import unittest
from tests import test_dual_dhcp_service as runtime_tests
now=runtime_tests.now
event=runtime_tests.event
from uplinkstead.dual_dhcp_service import Runtime

class AutomaticTests(unittest.TestCase):
    setUp=runtime_tests.RuntimeTests.setUp
    def start(self):
        self.t=now()+10
        p=patch('uplinkstead.dual_dhcp_service.now',side_effect=lambda:self.t);p.start();self.addCleanup(p.stop)
        self.w.clock=lambda:self.t
        self.r.automatic_selection=True;self.r.restore_selected=True
        self.r.selection_hold=.2;self.r.failover_delay=.5
    def bind(self,k):
        self.t+=.01;r=self.w.s['links'][k]
        self.w.wire_callback(k,r['session'],self.w.s['boot'],r['event_sequence']+1,self.t,'bound',dict(ip='192.0.2.2' if k=='A' else '198.51.100.2',subnet='24',router='192.0.2.1' if k=='A' else '198.51.100.1',lease='120'),self.t-.005,self.t-.001,[])
        self.r.inbox.sequence[k]=r['event_sequence']
    def health(self,k,votes=3,rounds=2):
        for _ in range(rounds):
            h=self.w.health[k];self.w.observation(k,self.w.s['links'][k]['generation'],h['round']+1,self.t,votes)
    def cycle(self,advance=0):
        self.t+=advance;self.w.tick();self.r.converge();self.r.automatic()
    def initial(self):
        self.start()
        for k in ('A','B'):self.bind(k);self.health(k)
        self.cycle();self.cycle(.21)
        self.assertEqual(self.w.s['active']['link'],'A')
    def test_hold_initial_preference_sticky_failover_no_preemption(self):
        self.start()
        for k in ('A','B'):self.bind(k);self.health(k)
        self.cycle();self.assertIsNone(self.w.s['active']);self.cycle(.21)
        self.assertEqual(self.w.s['active']['link'],'A')
        self.health('A',0,3);self.cycle();self.assertIsNone(self.w.s['active']);self.cycle(.49);self.assertIsNone(self.w.s['active'])
        self.cycle(.02);self.assertEqual(self.w.s['active']['link'],'B');self.assertEqual(len(self.w.s['history']),2)
        self.health('A');self.cycle(1);self.assertEqual(self.w.s['active']['link'],'B');self.assertEqual(len(self.w.s['history']),2)
    def test_renewal_requires_new_health_does_not_spend_budget(self):
        self.initial();history=copy.deepcopy(self.w.s['history']);self.bind('A');self.cycle()
        self.assertIsNone(self.w.s['active']);self.health('A');self.cycle()
        self.assertEqual(self.w.s['active']['link'],'A');self.assertEqual(history,self.w.s['history'])
    def test_expiry_and_both_unhealthy_withdraw_without_main_fallback(self):
        self.initial();self.health('B',0,3);self.t=self.w.s['links']['A']['expires'];self.cycle();self.cycle(1)
        self.assertIsNone(self.w.s['active']);self.assertIsNone(self.w.backend.active)
    def test_latch_and_pause_never_bypassed(self):
        self.initial();self.w.budget=1;history=copy.deepcopy(self.w.s['history'])
        self.w.pause(True);self.bind('A');self.health('A');self.cycle(1);self.assertIsNone(self.w.s['active'])
        self.w.pause(False);self.health('A',0,3);self.cycle();self.cycle(1)
        self.assertTrue(self.w.s['latched']);self.assertIsNone(self.w.s['active'])
        self.bind('B');self.health('B');self.cycle(1);self.assertIsNone(self.w.s['active']);self.assertEqual(history,self.w.s['history'])
    def test_restore_rate_limit_cannot_fall_through_to_charged_same_WAN_choose(self):
        self.initial();history=copy.deepcopy(self.w.s['history']);self.bind('A');self.health('A')
        self.r.restorations.extend([self.t]*16);self.cycle(1);self.cycle(1)
        self.assertEqual(self.r.auto_status,'LEASE_RESTORE_BLOCKED');self.assertIsNone(self.w.s['active']);self.assertEqual(history,self.w.s['history'])
    def test_new_ACK_during_real_runtime_selection_invalidates_before_publish(self):
        self.start();self.bind('A');self.health('A');self.cycle();old=self.w.s['links']['A']['generation']
        original=self.w.backend.select
        def raced(*args):
            original(*args);self.r.captures['A'].stats=lambda:dict(version=1,pending=True)
        with patch.object(self.w.backend,'select',side_effect=raced):self.cycle(.21)
        self.assertIsNone(self.w.s['active']);self.assertIsNone(self.w.s['links']['A']['current']);self.assertEqual(self.r.metrics['selection_invalidations'],1)
        with self.assertRaises(RuntimeError):self.w.observation('A',old,99,self.t,3)
        self.r.captures['A'].stats=lambda:dict(version=1,pending=False)
        self.bind('A');self.health('A');self.cycle();self.assertEqual(self.w.s['active']['link'],'A');self.assertEqual(len(self.w.s['history']),1)
    def test_lease_loss_enqueued_during_selection_invalidates(self):
        self.start();self.bind('A');self.health('A');self.cycle();original=self.w.backend.select
        def raced(*args):
            original(*args);r=self.w.s['links']['A'];q=event('A',session=r['session'],boot=self.w.s['boot']);q.update(id='loss',at=self.t,reason='deconfig',lease=None);self.r.inbox.put(q)
        with patch.object(self.w.backend,'select',side_effect=raced):self.cycle(.21)
        self.assertIsNone(self.w.s['active']);self.assertIsNone(self.w.backend.active);self.assertEqual(self.r.metrics['selection_invalidations'],1)
    def test_delayed_operator_and_old_probe_cannot_override_new_generation(self):
        self.initial();q=dict(link='A',epoch=self.w.s['epoch'],revision=self.w.s['revision'])
        oldgen=self.w.s['links']['A']['generation'];self.bind('A');self.health('A');self.cycle()
        history=copy.deepcopy(self.w.s['history']);f=Future();f.set_result((3,[]));self.r.futures['A']=(f,oldgen,self.t-1,999)
        done=threading.Event();answer={};self.r.operator.append((q,done,answer));self.r.step()
        self.assertTrue(done.is_set());self.assertFalse(answer['ok']);self.assertEqual(history,self.w.s['history']);self.assertEqual(self.r.metrics['stale_probe_results'],1)
    def test_disabled_by_default_and_invalid_config_rejected(self):
        self.assertFalse(self.r.automatic_selection)
        for cfg in ({'automatic_selection':1},{'automatic_selection':True,'restore_selected':False},{'selection_hold':float('nan')},{'failover_delay':0}):
            self.w.cfg['runtime']=cfg
            with self.assertRaises(ValueError):Runtime(self.w,self.r.path,self.r.hook)
    def test_pending_intake_breaks_continuous_candidate_hold(self):
        self.start();self.bind('A');self.health('A');self.cycle()
        self.r.captures['A'].stats=lambda:dict(pending=True);self.cycle(.19)
        self.r.captures['A'].stats=lambda:dict(pending=False);self.cycle(.1)
        self.assertIsNone(self.w.s['active']);self.cycle(.21);self.assertEqual(self.w.s['active']['link'],'A')
    def test_new_ACK_during_free_restore_withdraws_without_spending_budget(self):
        self.initial();history=copy.deepcopy(self.w.s['history']);self.bind('A');self.health('A');original=self.w.backend.select
        def raced(*args):
            original(*args);self.r.captures['A'].stats=lambda:dict(pending=True,version=99)
        with patch.object(self.w.backend,'select',side_effect=raced):self.r.converge()
        self.assertIsNone(self.w.s['active']);self.assertIsNone(self.w.backend.active);self.assertEqual(history,self.w.s['history']);self.assertEqual(self.r.metrics['selection_invalidations'],1)
    def test_one_failed_round_then_success_preserves_qualified_selected_route(self):
        self.initial();history=copy.deepcopy(self.w.s['history']);active=copy.deepcopy(self.w.s['active'])
        self.health('A',0,1);self.assertEqual(self.w.health['A']['state'],'SUSPECT');self.assertEqual(active,self.w.s['active'])
        self.health('A',3,1);self.assertEqual(active,self.w.s['active'])
        self.cycle(1);self.assertEqual(active,self.w.s['active']);self.assertEqual(history,self.w.s['history'])
    def test_suspect_recovery_exception_cannot_qualify_backup_or_new_lease(self):
        self.initial();history=copy.deepcopy(self.w.s['history'])
        self.health('B',0,1);self.health('B',3,1);self.assertEqual(self.w.health['B']['state'],'UNVERIFIED')
        self.bind('A');self.health('A',3,1);self.cycle(1)
        self.assertEqual(self.w.health['A']['state'],'UNVERIFIED');self.assertIsNone(self.w.s['active'])
        self.health('A',3,1);self.cycle();self.assertEqual(self.w.s['active']['link'],'A');self.assertEqual(history,self.w.s['history'])
