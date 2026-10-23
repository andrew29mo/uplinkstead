"""Capability-free DHCP policy client: proposals only, never supplied health/IO.

This standalone stdlib module can be installed read-only outside private state.
Writer computes and independently rechecks its candidate at proposal admission.
"""
import argparse,json,os,signal,socket,threading,time

def request(path,q):
    raw=json.dumps(q,allow_nan=False).encode()
    if len(raw)>4096:raise ValueError('Oversized request')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(3);s.connect(str(path));s.sendall(raw)
        data,_,flags,_=s.recvmsg(65536)
        if flags&socket.MSG_TRUNC or not data:raise ValueError('Invalid control reply')
        return json.loads(data)

def step(path):
    answer=request(path,dict(op='status'))
    if not answer['ok']:return answer
    status=answer['status'];candidate=status['candidate']
    if candidate:
        return request(path,dict(op='propose',epoch=status['epoch'],revision=status['revision'],target=candidate['target'],generation=candidate['generation']))
    return dict(ok=True,idle=True)

def privilege():
    if os.geteuid()==0:raise PermissionError('Worker must be unprivileged')
    with open('/proc/self/status') as f:rows=dict(line.split(':',1) for line in f if ':' in line)
    if any(int(rows[k].strip(),16)!=0 for k in ('CapEff','CapPrm','CapInh','CapAmb')) or rows['NoNewPrivs'].strip()!='1':raise PermissionError('Zero capabilities and NoNewPrivs required')

def main():
    p=argparse.ArgumentParser();p.add_argument('--socket',required=True);p.add_argument('--interval',type=float,default=.2);p.add_argument('--once',action='store_true');a=p.parse_args()
    if not .05<=a.interval<=5:p.error('Interval outside .05..5 seconds')
    privilege();stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    while not stop.is_set():
        began=time.monotonic()
        try:answer=step(a.socket)
        except (OSError,ValueError,KeyError) as exc:answer=dict(ok=False,error=type(exc).__name__)
        if not answer.get('idle'):print(json.dumps(answer,allow_nan=False),flush=True)
        if a.once:return
        stop.wait(max(.01,a.interval-(time.monotonic()-began)))
if __name__=='__main__':main()
