"""Formal runtime/core control contracts; kernel UID/capabilities tested in Linux VM."""
import copy,contextlib,io,json,secrets,threading
from unittest.mock import patch
import unittest
from tests import test_dhcp_automatic as auto
from uplinkstead import dual_dhcp_cli as cli
from uplinkstead import dual_dhcp_worker as worker
from uplinkstead.dual_dhcp import DualLifecycle
from tests.test_dual_dhcp import ScopedBackend

class ControlTests(unittest.TestCase):
    setUp=auto.AutomaticTests.setUp
    start=auto.AutomaticTests.start
    bind=auto.AutomaticTests.bind
    health=auto.AutomaticTests.health
    cycle=auto.AutomaticTests.cycle
    initial=auto.AutomaticTests.initial
    def mode(self):self.r.policy_uid=61001;self.r.policy_gid=61001
    def proposal(self,k='A'):
        return dict(op='propose',target=k,epoch=self.w.s['epoch'],revision=self.w.s['revision'],generation=self.w.s['links'][k]['generation'])
    def op(self,kind,**kw):
        q=dict(op=kind,epoch=self.w.s['epoch'],revision=self.w.s['revision'],id=secrets.token_hex(16));q.update(kw);return q
    def root(self,kind,**kw):return self.r.process_control(self.op(kind,**kw),0)
    def test_worker_required_and_writer_owns_hold_initial_and_sticky_decision(self):
        self.start();self.mode()
        for k in ('A','B'):self.bind(k);self.health(k)
        with self.assertRaises(RuntimeError):self.r.process_control(self.proposal(),61001)
        self.cycle(.21);self.assertIsNone(self.w.s['active'])
        self.assertTrue(self.r.process_control(self.proposal(),61001)['ok']);self.assertEqual(self.w.s['active']['link'],'A')
        before=copy.deepcopy(self.w.s)
        with self.assertRaises(RuntimeError):self.r.process_control(self.proposal('B'),61001)
        self.assertEqual(before,self.w.s)
    def test_only_exact_uid_can_propose_no_operator_or_proof_injection(self):
        self.initial();self.mode();before=copy.deepcopy(self.w.s)
        for uid in (0,61002):
            with self.assertRaises(PermissionError):self.r.validate_control(self.proposal(),uid)
        for kind in ('pause','resume','reset-budget'):
            q=self.op(kind,**({'ack':'reset-switch-budget'} if kind=='reset-budget' else {}))
            with self.assertRaises(PermissionError):self.r.process_control(q,61001)
        for extra in ({'health':{'A':'HEALTHY'}},{'command':'ip route'},{'uid':0}):
            q=self.proposal();q.update(extra)
            with self.assertRaises(ValueError):self.r.validate_control(q,61001)
        self.assertEqual(before,self.w.s)
    def test_stale_epoch_revision_and_generation_cannot_authorize(self):
        self.start();self.mode();self.bind('A');self.health('A');self.cycle();self.cycle(.21)
        for field in ('epoch','revision','generation'):
            q=self.proposal();q[field]-=1
            with self.assertRaises(RuntimeError):self.r.process_control(q,61001)
        self.assertIsNone(self.w.s['active']);self.assertEqual(self.w.s['history'],[])
    def test_pause_reset_resume_are_separate_and_old_operations_reject(self):
        self.initial();self.mode();old=self.op('resume');self.root('pause');self.w.s['latched']=True;self.w.save()
        history=copy.deepcopy(self.w.s['history']);active=copy.deepcopy(self.w.s['active'])
        with self.assertRaises(RuntimeError):self.root('resume')
        with self.assertRaises(RuntimeError):self.r.process_control(old,0)
        self.assertEqual(history,self.w.s['history'])
        self.root('reset-budget',ack='reset-switch-budget')
        self.assertTrue(self.w.s['paused']);self.assertFalse(self.w.s['latched']);self.assertEqual(active,self.w.s['active']);self.assertEqual(self.w.s['history'],[])
        self.assertTrue(self.root('resume')['ok']);self.assertFalse(self.w.s['paused']);self.assertEqual(self.w.s['history'],[])
        self.assertEqual([e['kind'] for e in self.w.s['operations']],['pause','reset-budget','resume'])
    def test_reset_requires_pause_and_ack_does_not_reset_other_limits(self):
        self.initial();self.mode()
        with self.assertRaises(RuntimeError):self.root('reset-budget',ack='reset-switch-budget')
        self.root('pause');self.r.restorations.extend([self.t]*16)
        with self.assertRaises(ValueError):self.root('reset-budget',ack='yes')
        self.root('reset-budget',ack='reset-switch-budget');self.assertEqual(len(self.r.restorations),16)
    def test_pause_does_not_block_lease_expiry_or_allow_stale_health_resume(self):
        self.initial();self.mode();self.root('pause');self.t=self.w.s['links']['A']['expires'];self.w.tick()
        self.assertIsNone(self.w.s['active'])
        with self.assertRaises(RuntimeError):self.root('resume')
        self.assertTrue(self.w.s['paused'])
    def test_ACK_during_resume_persistence_repauses_and_quarantines(self):
        self.initial();self.mode();self.root('pause');original=self.w.save
        def save():
            original()
            if not self.w.s['paused']:self.r.captures['A'].stats=lambda:dict(pending=True,version=1)
        with patch.object(self.w,'save',side_effect=save):answer=self.root('resume')
        self.assertFalse(answer['ok']);self.assertTrue(self.w.s['paused']);self.assertIsNone(self.w.s['active']);self.assertIsNone(self.w.s['links']['A']['current']);self.assertEqual(self.w.s['operations'][-1]['outcome'],'REPAUSED')
    def test_resume_expiring_during_save_cannot_report_success(self):
        self.initial();self.mode();self.root('pause');original=self.w.save
        def save():
            original()
            if not self.w.s['paused']:self.t+=self.w.freshness+1
        with patch.object(self.w,'save',side_effect=save):
            with self.assertRaises(RuntimeError):self.root('resume')
        self.assertTrue(self.w.s['paused']);self.assertIsNone(self.w.s['active']);self.assertEqual(self.w.s['operations'][-1]['outcome'],'REPAUSED')
    def test_storage_failure_retires_writer_never_reports_success(self):
        self.initial();self.mode()
        with patch.object(self.w,'save',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):self.root('pause')
        self.assertEqual(self.w.s['phase'],'RECOVERY_REQUIRED')
        with self.assertRaises(RuntimeError):self.root('resume')
    def test_operation_receipts_bounded_durable_and_replay_rejected(self):
        self.initial();self.mode();q=self.op('pause');self.r.process_control(q,0)
        q.update(epoch=self.w.s['epoch'],revision=self.w.s['revision'])
        with self.assertRaises(RuntimeError):self.r.process_control(q,0)
        for _ in range(36):self.root('pause')
        self.assertEqual(len(self.w.s['operations']),32);ops=copy.deepcopy(self.w.s['operations']);history=copy.deepcopy(self.w.s['history'])
        self.w.__exit__()
        with DualLifecycle(self.c,self.tmp.name,ScopedBackend,clock=lambda:self.t,boot=lambda:'portable-test-boot') as reopened:
            self.assertEqual(ops,reopened.s['operations']);self.assertTrue(reopened.s['paused']);self.assertEqual(history,reopened.s['history'])
    def test_unknown_operation_journal_fields_reject(self):
        self.initial();self.root('pause');self.w.s['operations'][-1]['uid']=1
        with self.assertRaises(RuntimeError):self.w.validate()
    def test_root_queue_precedes_proposal_and_stales_old_advice(self):
        self.start();self.mode();self.bind('A');self.health('A');self.cycle();self.cycle(.21)
        old=self.proposal();done=threading.Event();answer={};self.r.proposals.append(({'_control':old,'_uid':61001},done,answer))
        root_done=threading.Event();root_answer={};self.r.operator.append(({'_control':self.op('pause'),'_uid':0},root_done,root_answer))
        self.r.step();self.r.step();self.assertTrue(root_answer['ok']);self.assertFalse(answer['ok']);self.assertIsNone(self.w.s['active'])
    def test_proposal_capacity_does_not_consume_root_slots(self):
        self.initial();self.mode();q=self.proposal()
        with patch.object(threading.Event,'wait',return_value=False):
            self.assertEqual(self.r.submit_control(q,61001)['error'],'OutcomeUnknownInspectStatus')
            with self.assertRaises(OverflowError):self.r.submit_control(q,61001)
            self.r.submit_control(self.op('pause'),0)
        self.assertEqual(len(self.r.operator),1);self.assertEqual(len(self.r.proposals),1)
    def test_no_session_authority_or_caller_proof_in_policy_status(self):
        self.initial();self.mode();s=self.r.control_status();raw=json.dumps(s)
        self.assertNotIn('session',raw);self.assertNotIn('config_hash',s);self.assertNotIn('ca',s)
    def test_worker_only_sends_status_and_fenced_proposal(self):
        s=dict(epoch=2,revision=4,candidate=dict(target='B',generation=8))
        with patch.object(worker,'request',side_effect=[dict(ok=True,status=s),dict(ok=True)]) as request:
            self.assertTrue(worker.step('socket')['ok'])
            self.assertEqual(request.call_args_list[1].args[1],dict(op='propose',epoch=2,revision=4,target='B',generation=8))
    def test_cli_does_not_refresh_explicit_stale_token_or_retry(self):
        s=dict(epoch=9,revision=20)
        with patch.object(cli,'request',side_effect=[dict(ok=True,status=s),dict(ok=False,error='Stale')]) as request,patch('sys.argv',['cli','--socket','x','pause','--epoch','1','--revision','2','--id','f'*32]),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(),1);self.assertEqual(request.call_count,2);self.assertEqual(request.call_args.args[1]['revision'],2)
    def test_cli_reset_without_ack_never_dispatches(self):
        with patch.object(cli,'request') as request,patch('sys.argv',['cli','--socket','x','reset-budget']),contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):cli.main()
            request.assert_not_called()
    def test_budget_latch_advances_revision_and_invalidates_old_operator(self):
        self.initial();self.mode();old=self.op('pause');self.w.budget=1
        self.health('A',0,3);self.cycle();self.cycle(1)
        q=self.proposal('B')
        answer=self.r.process_control(q,61001)
        self.assertFalse(answer['ok']);self.assertTrue(self.w.s['latched']);self.assertGreater(self.w.s['revision'],old['revision'])
        with self.assertRaises(RuntimeError):self.r.process_control(old,0)
