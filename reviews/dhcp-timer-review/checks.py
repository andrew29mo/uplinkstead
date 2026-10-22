"""Post-run offline review controls; separate from the 215 portable unit tests.

Run with ordinary Python and -O. Mutate a valid retained artifact, never a live
service. Require the exact semantic check, not an unrelated provenance failure.
"""
import copy,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from tools.dhcp_timer_report import verify


def main():
    path=Path(__file__).with_name('evidence.json');v=json.loads(path.read_text());verify(v)
    def case(x,name):return next(c['details'] for c in x['guest']['cases'] if c['name']==name)
    broken=copy.deepcopy(v);d=case(broken,'no_early_loss_expiry_withdrawal_and_reacquisition')
    early=d['baseline']['status']['state']['links']['B']['expires']-30
    samples=[s for s in d['retention_samples'] if s['observed_at']<early]
    final=copy.deepcopy(samples[-1]);final.update(observed_at=early,as_of=early,present=False,expires=0)
    d['retention_samples']=samples+[final];d['expired']['runtime']['as_of']=early
    changes=[('coupled_early_writer_with_later_client_expiry',broken,'Expiry publication detached from writer deadline')]
    broken=copy.deepcopy(v);d=case(broken,'ACK_received_after_address_quarantine')
    match=next(e['match'] for row in d['udp_drop']['nftables'] if 'rule' in row for e in row['rule']['expr'] if 'match' in e and e['match']['right']=='wanB')
    match['right']='wanA';changes.append(('positive_drop_counter_wrong_interface',broken,'Wrong ACK UDP drop scope/hook'))
    rejected=[]
    for name,broken,reason in changes:
        try:verify(broken)
        except ValueError as exc:
            if str(exc)!=reason:raise RuntimeError('Rejected for the wrong reason: '+str(exc))
            rejected.append(dict(name=name,reason=reason))
        else:raise RuntimeError('Corrupted artifact passed: '+name)
    print(json.dumps(dict(passed=True,optimized=not __debug__,run_id=v['run_id'],source_sha256=v['source_sha256'],verifier_sha256=hashlib.sha256((ROOT/'tools/dhcp_timer_report.py').read_bytes()).hexdigest(),rejected=rejected),indent=2))

if __name__=='__main__':main()
