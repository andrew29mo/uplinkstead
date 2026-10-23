"""Root operator interface. Lost replies require status inspection, never retry."""
import argparse,json,secrets,sys
from .dual_dhcp_worker import request

def main():
    p=argparse.ArgumentParser();p.add_argument('--socket',required=True)
    p.add_argument('operation',choices=('status','pause','resume','reset-budget'))
    p.add_argument('--epoch',type=int);p.add_argument('--revision',type=int)
    p.add_argument('--id',default=None);p.add_argument('--ack-reset-budget',action='store_true');a=p.parse_args()
    if (a.epoch is None)!=(a.revision is None):p.error('Epoch and revision must be supplied together')
    if a.operation=='reset-budget' and not a.ack_reset_budget:p.error('Explicit --ack-reset-budget required')
    q=dict(op=a.operation)
    try:
        if a.operation!='status':
            initial=request(a.socket,dict(op='status'))
            if not initial['ok']:print(json.dumps(initial));return 1
            s=initial['status'];q.update(epoch=s['epoch'] if a.epoch is None else a.epoch,revision=s['revision'] if a.revision is None else a.revision,id=a.id or secrets.token_hex(16))
            if a.operation=='reset-budget':q['ack']='reset-switch-budget'
        answer=request(a.socket,q)
    except (OSError,ValueError,KeyError) as exc:
        answer=dict(ok=False,error='OutcomeUnknownInspectStatus',id=q.get('id'),detail=type(exc).__name__)
    print(json.dumps(answer,allow_nan=False));return 0 if answer['ok'] else 1
if __name__=='__main__':sys.exit(main())
