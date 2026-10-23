"""Actual runtime probe scheduling; fake target I/O is not routing/TLS proof."""
from pathlib import Path
from types import SimpleNamespace
import threading,unittest
from unittest.mock import patch
from uplinkstead.dual_dhcp_service import Runtime
from uplinkstead import probe

class ProbeExecutorTests(unittest.TestCase):
    def config(self):return dict(targets=[dict(ip='203.0.113.2',port=p) for p in (8443,8444,8445)])
    def test_runtime_reuses_six_target_threads_across_both_links_and_joins(self):
        r=Runtime(SimpleNamespace(cfg={}),Path('unused'),Path('unused'));seen=[];barrier=threading.Barrier(6)
        def target(c,k,t):
            seen.append((threading.get_ident(),k,t['port']));barrier.wait(timeout=3)
            return dict(ok=True,infrastructure=False)
        try:
            with patch.object(probe,'one',side_effect=target):
                identities=None
                for _ in range(4):
                    futures=[r.pool.submit(r.probe,self.config(),k) for k in ('A','B')]
                    self.assertEqual([f.result(timeout=5)[0] for f in futures],[3,3])
                    current={row[0] for row in seen[-6:]};self.assertEqual(len(current),6)
                    if identities is None:identities=current
                    else:self.assertEqual(current,identities)
            self.assertEqual(len(seen),24);threads=list(r.target_pool._threads)
        finally:r.pool.shutdown(wait=True,cancel_futures=True);r.target_pool.shutdown(wait=True,cancel_futures=True)
        self.assertTrue(all(not t.is_alive() for t in threads))
        with self.assertRaises(RuntimeError):r.probe(self.config(),'A')
    def test_injected_probe_keeps_original_call_contract(self):
        def injected(c,k):return 2,[k]
        r=Runtime(SimpleNamespace(cfg={}),Path('unused'),Path('unused'),probe=injected)
        try:self.assertIsNone(r.target_pool);self.assertEqual(r.probe({},'B'),(2,['B']))
        finally:r.pool.shutdown(wait=True,cancel_futures=True)
    def test_standalone_probe_round_preserves_infrastructure_failure(self):
        def target(c,k,t):return dict(ok=True,infrastructure=t['port']==8445)
        with patch.object(probe,'one',side_effect=target):
            votes,rows=probe.round(self.config(),'A')
        self.assertIsNone(votes);self.assertEqual(len(rows),3)
