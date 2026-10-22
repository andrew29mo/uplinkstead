"""Synthetic helper fixtures challenge each specific correspondence check."""
import copy
import unittest
from tools.report import verify_restart,verify_benchmark


def restart():
    pending=dict(before='A',target='B',token='fixture-token')
    unit=lambda pid,invocation,active=True:f'MainPID={pid}\nInvocationID={invocation*32}\n'+('ActiveState=active\n' if active else '')
    return dict(passed=True,orderly_vm_restart=True,power_loss_tested=False,
        before=dict(before_boot='old-boot',pending=pending,selected_receipt='A',latched_before=True,mode_before='ENABLED',epoch_before=10,
                    actual_route=[dict(dst='default',gateway='192.0.2.5',dev='wanB',metric=100)],
                    process_restart_before=unit(1,'a',False),process_restart_after=unit(2,'b')),
        pre_agent_journal=dict(boot='new-boot',pending=copy.deepcopy(pending),selected='A',latched=True,mode='ENABLED',epoch=10),
        after=dict(boot='new-boot',selected='B',pending=None,latched=True,mode='ENABLED',epoch=11,unit=unit(3,'c'),
                   request=dict(ok=True,result=dict(peer='10.99.2.1')),first_tick=dict(boot='new-boot',health=dict(A='RECOVERING',B='RECOVERING'))))


def benchmark():
    modes=[]
    for name in ('fixed_primary','automatic'):
        rows=[]
        for i in range(20):
            scheduled=i*.5;started=scheduled+.01;finished=started+.1
            ok=i<4 or (name=='automatic' and i>=10)
            rows.append(dict(index=i,scheduled=scheduled,started=started,finished=finished,latency=finished-started,
                             end_to_end=finished-scheduled,late=False,ok=ok,peer=('10.99.1.1' if i<4 else '10.99.2.1') if ok else None))
        processes=dict(writer=dict(pid=1,invocation='a'*32,rss_kib=100),worker=dict(pid=2,invocation='b'*32,rss_kib=50))
        successes=sum(r['ok'] for r in rows)
        modes.append(dict(mode=name,rows=rows,elapsed=10,successes=successes,failures=20-successes,throughput=successes/10,
                          rss_kib=dict(writer=100,worker=50),processes_before=processes,processes_after=copy.deepcopy(processes),
                          fault_window=dict(started=2,finished=2.005),journal_bytes_before=4096,journal_bytes=4096,
                          final_selected='B' if name=='automatic' else 'A'))
    return dict(vm_only=True,repeated_trials=False,schedule=dict(requests=20,interval=.5,blackhole_from_index=4),modes=modes)


class ReportReviewTests(unittest.TestCase):
    def test_reboot_correspondence_rejects_independent_counterexamples(self):
        verify_restart(restart())
        changes=[lambda r:r['after'].update(unit='MainPID=0\nActiveState=failed\nInvocationID=\n'),
                 lambda r:r['pre_agent_journal'].update(selected='B'),lambda r:r['before'].update(latched_before=False),
                 lambda r:r['pre_agent_journal'].update(mode='PAUSED'),lambda r:r['after'].update(epoch=10)]
        for change in changes:
            with self.subTest(change=change):
                r=restart();change(r)
                with self.assertRaises(AssertionError):verify_restart(r)
    def test_benchmark_path_fault_and_process_identity_are_required(self):
        verify_benchmark(benchmark())
        changes=[lambda b:b['modes'][0]['rows'][0].update(peer='10.99.2.1'),
                 lambda b:b['modes'][1]['rows'][0].update(peer='10.99.2.1'),
                 lambda b:b['modes'][0]['processes_after']['writer'].update(pid=42),
                 lambda b:b['modes'][0]['fault_window'].update(finished=9)]
        for change in changes:
            with self.subTest(change=change):
                b=benchmark();change(b)
                with self.assertRaises(AssertionError):verify_benchmark(b)
