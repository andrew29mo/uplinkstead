"""Reporter-only adversarial resource series; no simulated service qualification."""
import copy,unittest,tempfile
from pathlib import Path
from tools.dhcp_closure_guest import group_process_count
from tools.dhcp_closure_report import resource_summary

class ResourceTests(unittest.TestCase):
    def rows(self):
        return [dict(at=i*2.5,phase='tail',processes={k:dict(pid=j+1,start_ticks='fixed',rss_kib=24000 if j==0 else 12000,fd=12 if j==0 else 5,threads=7 if j==0 else 1) for j,k in enumerate(('writer','worker','clientA','clientB'))},db_bytes=16384,disk_bytes=16384,queue=dict(depth=0,capacity=8,peak=1),recent_count=16,selection_count=6,errors=[],cgroup_processes=4) for i in range(300)]
    def test_bounded_series_and_exact_delta(self):
        r=self.rows();r[-1]['processes']['writer']['rss_kib']+=100
        s=resource_summary(r);self.assertEqual(s['samples'],300);self.assertEqual(s['writer_rss_kib']['max'],24100);self.assertEqual(s['writer_rss_kib']['delta'],0)
    def test_growth_restart_and_resource_overflow_reject(self):
        for kind in ('growth','restart','queue','disk','errors','fd','threads','tail-growth'):
            r=self.rows()
            if kind=='growth':
                for row in r[-50:]:row['processes']['writer']['rss_kib']+=5000
            elif kind=='restart':r[-1]['processes']['worker']['start_ticks']='new'
            elif kind=='queue':r[-1]['queue']['depth']=9
            elif kind=='disk':r[-1]['db_bytes']=8388609
            elif kind=='tail-growth':
                for row in r[-100:]:row['processes']['worker']['rss_kib']+=128
            elif kind=='fd':r[-1]['processes']['writer']['fd']=25
            elif kind=='threads':r[-1]['processes']['writer']['threads']=14
            else:r[-1]['errors']=['failure']
            with self.subTest(kind=kind),self.assertRaises(ValueError):resource_summary(r)
    def test_short_missing_or_invalid_clock_reject(self):
        for kind in ('short','missing','clock'):
            r=self.rows()
            if kind=='short':r=r[:80]
            elif kind=='missing':
                for row in r:row['phase']='fault'
            else:r[-1]['at']=float('nan')
            with self.subTest(kind=kind),self.assertRaises(ValueError):resource_summary(r)

class CgroupTests(unittest.TestCase):
    def test_membership_does_not_inspect_ephemeral_proc_or_double_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'cgroup.procs').write_text('2147483646\n2147483645\n');child=root/'child';child.mkdir();(child/'cgroup.procs').write_text('2147483645\n')
            self.assertEqual(group_process_count(root),2)
            (child/'cgroup.procs').unlink();self.assertEqual(group_process_count(root),2)
            (root/'cgroup.procs').write_text('');self.assertEqual(group_process_count(root),0)
    def test_missing_group_and_invalid_members_never_mean_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with self.assertRaises(RuntimeError):group_process_count(root/'missing')
            for value in ('not-a-pid','0','-1'):
                (root/'cgroup.procs').write_text(value)
                with self.assertRaises(ValueError):group_process_count(root)
