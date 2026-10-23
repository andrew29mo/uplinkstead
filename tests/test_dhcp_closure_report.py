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

class EvidenceGateTests(unittest.TestCase):
    """Synthetic mutations of a recorded receipt test the reporter, not a VM."""
    def receipt(self):
        import json
        v=json.loads((Path(__file__).parent/'fixtures/closure_report.json').read_text())
        v['guest']['samples']=ResourceTests().rows();v['resources']=resource_summary(v['guest']['samples'])
        h=v['guest']['handoff'];before=copy.deepcopy(h['new']);s=before['state']
        h['traffic']=dict(ok=True,response=dict(peer='10.99.1.1' if s['active']['link']=='A' else '10.99.2.1'))
        replies=[]
        for dimension in ('epoch','revision'):
            request=dict(epoch=h['old']['state']['epoch'] if dimension=='epoch' else s['epoch'],revision=s['revision'] if dimension=='epoch' else h['old']['state']['revision'])
            reply=dict(operation='pause',arguments={'--epoch':request['epoch'],'--revision':request['revision']},exit_code=1,answer=dict(ok=False,detail='Stale operation token',status=dict(epoch=s['epoch'],revision=s['revision'])))
            h['stale_'+dimension]=dict(request=request,before=copy.deepcopy(before),after=copy.deepcopy(before),reply=reply);replies.append(reply)
        v['guest']['operations']=v['guest']['operations'][:5]+replies
        return v
    def test_recorded_observations_with_synthetic_stale_receipts_and_all_controls(self):
        from tools.dhcp_closure_report import verify,controls
        v=self.receipt();self.assertTrue(verify(v));self.assertEqual(controls(v),dict(passed=True,rejected=30))
    def test_initial_charge_and_fresh_restart_authority_are_required(self):
        from tools.dhcp_closure_report import verify
        for kind in ('initial','lease','generation','until','quorum','pending','traffic'):
            v=self.receipt();h=v['guest']['handoff'];s=h['new']['state'];k=s['active']['link'];r=s['links'][k]
            if kind=='initial':v['guest']['initial']['state']['history']=[]
            elif kind=='lease':r['current']=None
            elif kind=='generation':s['active']['generation']+=1
            elif kind=='until':r['until']=0
            elif kind=='quorum':r['good']=1
            elif kind=='pending':h['new']['runtime']['capture'][k]['pending']=True
            else:h['traffic']['response']['peer']='198.18.0.1'
            with self.subTest(kind=kind),self.assertRaises(ValueError):verify(v)
    def test_stale_dimensions_and_no_side_effect_are_independent(self):
        from tools.dhcp_closure_report import verify
        for kind in ('epoch-race','revision-epoch','side-effect','accepted'):
            v=self.receipt();h=v['guest']['handoff']
            if kind=='epoch-race':h['stale_epoch']['reply']['answer']['status']['revision']+=1
            elif kind=='revision-epoch':h['stale_revision']['request']['epoch']-=1
            elif kind=='side-effect':h['stale_epoch']['after']['state']['paused']=True
            else:h['stale_epoch']['reply']['answer']['ok']=True
            with self.subTest(kind=kind),self.assertRaises(ValueError):verify(v)
