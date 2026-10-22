import copy
import json
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tests.test_core import config,FakeLinux
from uplinkstead.control import Controller,decode,MAX_REQUEST,dispatch
from uplinkstead.linux import Blocked,UncertainCommand
from uplinkstead.writer import Writer


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.d=tempfile.TemporaryDirectory();self.addCleanup(self.d.cleanup)
        self.c=config();self.c['_hash']='cfg';FakeLinux.route=None
        self.clock=10
        for module in ('writer','control'):
            p=patch('uplinkstead.'+module+'.boot_id',return_value='boot');p.start();self.addCleanup(p.stop)
            p=patch('uplinkstead.'+module+'.now',side_effect=lambda:self.clock);p.start();self.addCleanup(p.stop)
        p=patch('uplinkstead.writer.Linux',FakeLinux);p.start();self.addCleanup(p.stop)
        p=patch.object(FakeLinux,'detach',lambda obj:setattr(FakeLinux,'route',None),create=True);p.start();self.addCleanup(p.stop)
        p=patch('uplinkstead.control.probe_round',return_value=(3,[dict(ok=True,infrastructure=False,seconds=.01)]*3));p.start();self.addCleanup(p.stop)
        self.w=Writer(self.c,self.d.name,initial_mode='DISABLED').__enter__();self.addCleanup(self.w.__exit__)
        self.ctl=Controller(self.w,1234)
    def op(self,op,uid=0,**fields):
        q=dict(op=op,**fields)
        if op not in ('status','sample'):q.update(epoch=self.w.s['epoch'],revision=self.w.s['revision'])
        return self.ctl.handle(q,uid)
    def enable(self):return self.op('enable',ack='attach-owned-routing')
    def healthy(self):
        for _ in range(3):self.clock+=1;self.op('sample',uid=1234)
    def test_first_start_detached_then_enable_paused(self):
        self.assertEqual(self.op('status')['mode'],'DISABLED');self.assertIsNone(FakeLinux.route)
        self.assertEqual(self.enable()['mode'],'PAUSED');self.assertIsNone(FakeLinux.route)
    def test_untrusted_peer_and_worker_operator_denied(self):
        for op in ('status','sample'):
            with self.assertRaises(PermissionError):self.op(op,uid=4321)
        for op in ('enable','pause','disable','resume','select'):
            fields={'ack':'x'} if op in ('enable','disable') else {'ack':'x','target':'A'} if op=='resume' else {'target':'A'} if op=='select' else {}
            with self.assertRaises(PermissionError):self.op(op,uid=1234,**fields)
    def test_no_arbitrary_commands_or_caller_health_proofs(self):
        for q in (dict(op='exec',command='ip route flush table main'),dict(op='status',path='/etc/shadow'),dict(op='automatic',epoch=0,revision=0,round=0,target='A',proof={})):
            with self.assertRaises(ValueError):self.ctl.handle(q,0)
    def test_resume_needs_fresh_writer_health_and_ack(self):
        self.enable()
        with self.assertRaises(ValueError):self.op('resume',target='A',ack='reset-budget')
        self.healthy()
        with self.assertRaises(Blocked):self.op('resume',target='A',ack='wrong')
        self.assertEqual(self.op('resume',target='A',ack='reset-budget')['selected'],'A')
        self.op('pause');self.clock+=3
        with self.assertRaises(ValueError):self.op('resume',target='A',ack='reset-budget')
        self.assertEqual(FakeLinux.route,'A');self.assertEqual(self.w.s['mode'],'PAUSED')
    def test_old_revision_rejected_after_pause_and_same_process_resume(self):
        self.enable();self.healthy();old=dict(op='pause',epoch=self.w.s['epoch'],revision=self.w.s['revision'])
        self.op('resume',target='A',ack='reset-budget')
        with self.assertRaises(Blocked):self.ctl.handle(old,0)
        self.assertEqual(self.w.s['mode'],'ENABLED')
    def test_disabled_pause_does_not_switch_and_restart_retains_mode(self):
        self.enable();self.healthy();self.op('resume',target='A',ack='reset-budget');self.op('pause')
        with self.assertRaises(Blocked):self.op('automatic',uid=1234,round=self.ctl.rid,target='B')
        self.w.__exit__()
        self.w=Writer(self.c,self.d.name).__enter__();self.addCleanup(self.w.__exit__)
        self.assertEqual(self.w.s['mode'],'PAUSED');self.assertEqual(FakeLinux.route,'A')
    def test_disable_explicit_handoff_and_reenable_has_no_stale_health(self):
        self.enable();self.healthy();self.op('resume',target='A',ack='reset-budget')
        with self.assertRaises(Blocked):self.op('disable',ack='wrong')
        self.assertEqual(self.op('disable',ack='restore-main-routing')['mode'],'DISABLED');self.assertIsNone(FakeLinux.route)
        self.enable()
        with self.assertRaises(ValueError):self.op('resume',target='B',ack='reset-budget')
    def test_forged_automatic_target_and_old_round_rejected(self):
        self.enable();self.healthy();self.op('resume',target='A',ack='reset-budget')
        for round_id in (self.ctl.rid-1,self.ctl.rid):
            with self.assertRaises(Blocked):self.op('automatic',uid=1234,round=round_id,target='B')
        self.assertEqual(FakeLinux.route,'A')
    def test_probe_rate_bounded(self):
        self.enable();self.op('sample',uid=1234)
        with self.assertRaises(Blocked):self.op('sample',uid=1234)
    def test_event_retention_and_database_capacity(self):
        for i in range(350):self.w.event('fixture',index=i)
        self.assertEqual(self.w.db.execute('SELECT count(*) FROM events').fetchone()[0],128)
        self.assertEqual(self.w.db.execute('PRAGMA max_page_count').fetchone()[0],2048)
        with self.assertRaises(Blocked):self.w.event('oversize',data='x'*33000)
    def test_actual_sqlite_capacity_error_is_not_success(self):
        pages=self.w.db.execute('PRAGMA page_count').fetchone()[0]
        self.w.db.execute('PRAGMA max_page_count='+str(pages+1))
        with self.assertRaises(sqlite3.OperationalError) as error:self.w.event('full',data='x'*32000)
        self.assertIn('full',str(error.exception));self.assertFalse(self.w.db.in_transaction)
        self.w.event('still_usable')
        self.assertIsNone(FakeLinux.route)
    def test_uncertain_command_does_not_keep_serving_even_without_pending(self):
        with patch.object(self.ctl,'snapshot',side_effect=UncertainCommand('timeout')):
            with self.assertRaises(UncertainCommand):dispatch(self.ctl,dict(op='status'),0)
    def test_clean_rejection_keeps_serving_but_partial_state_retires_owner(self):
        self.assertFalse(dispatch(self.ctl,dict(op='unknown'),0)['ok'])
        self.enable();self.healthy()
        q=dict(op='resume',epoch=self.w.s['epoch'],revision=self.w.s['revision'],target='A',ack='reset-budget')
        with patch.object(self.w,'save',side_effect=Blocked('low space')):
            with self.assertRaises(Blocked):dispatch(self.ctl,q,0)
    def test_detached_corrupt_attached_intent_rejected(self):
        self.w.s['selected']='B';self.w.save();self.w.__exit__()
        with self.assertRaises(Blocked):
            with Writer(self.c,self.d.name):pass
        self.assertIsNone(FakeLinux.route)
    def test_low_disk_blocks_before_route_write(self):
        self.enable();self.healthy()
        with patch('uplinkstead.writer.shutil.disk_usage',return_value=shutil._ntuple_diskusage(100,99,1)):
            with self.assertRaises(Blocked):self.op('resume',target='A',ack='reset-budget')
        self.assertIsNone(FakeLinux.route)
    def test_failed_enable_is_durable_and_restarts_to_paused(self):
        with patch.object(self.w.backend,'layout',side_effect=Blocked('injected backend failure')):
            with self.assertRaises(Blocked):self.enable()
        with sqlite3.connect(Path(self.d.name)/'journal.sqlite') as db:
            self.assertEqual(json.loads(db.execute('SELECT value FROM state').fetchone()[0])['lifecycle'],'enable')
        self.w.__exit__();self.w=Writer(self.c,self.d.name).__enter__();self.addCleanup(self.w.__exit__)
        self.assertIsNone(self.w.s['lifecycle']);self.assertEqual(self.w.s['mode'],'PAUSED')
    def test_failed_disable_is_durable_and_restarts_to_disabled(self):
        self.enable()
        with patch.object(self.w.backend,'detach',side_effect=Blocked('injected backend failure')):
            with self.assertRaises(Blocked):self.op('disable',ack='restore-main-routing')
        self.w.__exit__();self.w=Writer(self.c,self.d.name).__enter__();self.addCleanup(self.w.__exit__)
        self.assertEqual(self.w.s['mode'],'DISABLED');self.assertIsNone(self.w.s['lifecycle'])
    def test_state_write_failure_precedes_lifecycle_mutation(self):
        with patch.object(self.w,'save',side_effect=sqlite3.OperationalError('injected disk full')),patch.object(self.w.backend,'layout') as layout:
            with self.assertRaises(sqlite3.OperationalError):self.enable()
            layout.assert_not_called()
    def test_parser_rejects_oversize_duplicate_and_nonobject(self):
        for body in (b'x'*(MAX_REQUEST+1),b'[]',b'{"op":"status","op":"disable"}',b'['*1200+b'0'+b']'*1200):
            with self.assertRaises(ValueError):decode(body)
