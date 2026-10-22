"""Narrow local writer boundary. No caller-supplied command, route or health proof."""
import json
import copy
import os
from pathlib import Path
import socket
import struct
import time
from .linux import Blocked,UncertainCommand
from .policy import Policy, Settings
from .probe import round as probe_round
from .writer import boot_id, now

MAX_REQUEST=4096
MAX_REPLY=32768


def decode(data):
    if len(data)>MAX_REQUEST:raise ValueError('Request exceeds capacity')
    def pairs(rows):
        value={}
        for k,v in rows:
            if k in value:raise ValueError('Duplicate request key')
            value[k]=v
        return value
    try:v=json.loads(data,object_pairs_hook=pairs)
    except RecursionError as exc:raise ValueError('Request nesting exceeds capacity') from exc
    if not isinstance(v,dict):raise ValueError('Object request required')
    return v


class Controller:
    def __init__(self, writer, agent_uid):
        self.w=writer;self.agent_uid=agent_uid;self.rid=-1;self.last_sample=None
        self.policy=Policy(Settings(**writer.c['policy']),writer.c['_hash'],boot_id(),writer.s['history'],writer.s['latched'])

    def snapshot(self):
        w=self.w
        if w.s['mode']=='DISABLED':w.backend.preflight(fresh=True)
        else:w.backend.preflight();actual=w.backend.selected()
        if w.s['mode']!='DISABLED' and actual!=w.s['selected']:raise Blocked('Readback drift')
        return dict(epoch=w.s['epoch'],revision=w.s['revision'],mode=w.s['mode'],selected=w.s['selected'],
                    pending=w.s['pending'],lifecycle=w.s['lifecycle'],latched=w.s['latched'],
                    health={k:self.policy.fresh(k,now()) for k in ('A','B')},
                    history=list(w.s['history']),boot=boot_id(),config_hash=w.c['_hash'],
                    policy=w.c['policy'],round=self.rid,
                    storage=dict(events=w.db.execute('SELECT count(*) FROM events').fetchone()[0],
                                 pages=w.db.execute('PRAGMA page_count').fetchone()[0],
                                 page_size=w.db.execute('PRAGMA page_size').fetchone()[0],
                                 max_pages=w.db.execute('PRAGMA max_page_count').fetchone()[0]))

    def sample(self):
        w=self.w
        if w.s['mode']=='DISABLED':raise Blocked('Enable routing before collecting health')
        if self.last_sample is not None and now()-self.last_sample<0.8:raise Blocked('Probe rate limited')
        self.last_sample=now();self.rid+=1;w.reconcile();probes={}
        for k in ('A','B'):
            started=now();successes,results=probe_round(w.c,k);finished=now()
            self.policy.observe(k,self.rid,started,finished,finished,successes,w.c['_hash'],boot_id())
            probes[k]=dict(started=started,finished=finished,successes=successes,results=results)
        proposal,state=self.policy.candidate(w.s['selected'],now())
        if self.policy.latched and not w.s['latched']:
            w.s['latched']=True;w.s['revision']+=1;w.save()
        result=dict(status=self.snapshot(),probes=probes,proposal=proposal,state=state)
        w.event('service_sample',round=self.rid,probes=probes,proposal=proposal,state=state)
        w.event('tick',round=self.rid,health=result['status']['health'],selected=w.s['selected'])
        return result

    def token(self,q):
        if type(q['epoch']) is not int or type(q['revision']) is not int or (q['epoch'],q['revision'])!=(self.w.s['epoch'],self.w.s['revision']):
            raise Blocked('Stale operation token')
        if self.w.s['pending'] or self.w.s['lifecycle']:raise Blocked('Recovery required')

    def select(self,target):
        w=self.w;proof=self.policy.proof(target,now())
        admission=self.policy.admit(now());w.s['history']=self.policy.history[:-1]
        w.switch(w.s['epoch'],target,admission,proof)
        w.event('service_selected',target=target,round=self.rid)

    def handle(self,q,uid):
        if not isinstance(q,dict) or not isinstance(q.get('op'),str):raise ValueError('Invalid operation')
        op=q['op'];schema={
            'status':set(),'sample':set(),
            'automatic':{'epoch','revision','round','target'},'pause':{'epoch','revision'},
            'enable':{'epoch','revision','ack'},'disable':{'epoch','revision','ack'},
            'resume':{'epoch','revision','target','ack'},'select':{'epoch','revision','target'}}
        if op not in schema or set(q)!={'op'}|schema[op]:raise ValueError('Unknown operation or fields')
        if uid not in (0,self.agent_uid):raise PermissionError('Untrusted local peer')
        if op not in ('status','sample','automatic') and uid!=0:raise PermissionError('Root operator required')
        if op=='status':return self.snapshot()
        if op=='sample':return self.sample()
        self.token(q);w=self.w
        if 'target' in q and q['target'] not in ('A','B'):raise ValueError('Invalid target')
        if op=='automatic':
            if w.s['mode']!='ENABLED' or type(q['round']) is not int or q['round']!=self.rid:raise Blocked('Automation paused or old round')
            target,_=self.policy.candidate(w.s['selected'],now())
            if target is None or target!=q['target']:raise Blocked('Proposal not admitted by writer health/budget')
            self.select(target)
        elif op=='pause':
            if w.s['mode']!='ENABLED':raise Blocked('Not enabled')
            w.s.update(mode='PAUSED',revision=w.s['revision']+1);w.save();w.event('operator_pause',uid=uid)
        elif op in ('enable','disable'):
            expected='attach-owned-routing' if op=='enable' else 'restore-main-routing'
            if q['ack']!=expected:raise Blocked('Explicit routing handoff acknowledgement required')
            w.lifecycle(op)
            self.policy=Policy(Settings(**w.c['policy']),w.c['_hash'],boot_id(),w.s['history'],w.s['latched'])
            self.last_sample=None
        elif op in ('resume','select'):
            if w.s['mode']!='PAUSED':raise Blocked('Pause before operator selection/resume')
            self.policy.proof(q['target'],now())  # New observations, never a caller proof.
            if op=='resume':
                if q['ack']!='reset-budget':raise Blocked('Explicit budget reset required')
                self.policy.history=[];self.policy.latched=False
                w.s.update(history=[],latched=False,revision=w.s['revision']+1);w.save()
                w.event('operator_budget_reset',uid=uid,target=q['target'])
            elif self.policy.latched or len(self.policy.history)>=self.policy.s.budget:
                raise Blocked('Budget latched; use guarded resume')
            if w.s['selected']!=q['target']:self.select(q['target'])
            if op=='resume':w.s['mode']='ENABLED'
            w.s['revision']+=1;w.save();w.event('operator_'+op,uid=uid,target=q['target'])
        return self.snapshot()


def dispatch(ctl,q,uid):
    """Only clean rejections keep serving; partial state/unknown IO retires owner."""
    before=copy.deepcopy(ctl.w.s)
    try:return dict(ok=True,result=ctl.handle(q,uid))
    except (ValueError,PermissionError,Blocked) as exc:
        if isinstance(exc,UncertainCommand) or ctl.w.s!=before or ctl.w.s['pending'] or ctl.w.s['lifecycle']:
            raise
        return dict(ok=False,error=str(exc))


def request(path,q):
    data=json.dumps(q,allow_nan=False).encode()
    if len(data)>MAX_REQUEST:raise ValueError('Request exceeds capacity')
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(15);s.connect(str(path));s.sendall(data)
        data,_,flags,_=s.recvmsg(MAX_REPLY)
        if flags & socket.MSG_TRUNC:raise ValueError('Truncated reply')
        v=json.loads(data)
        if not v['ok']:raise Blocked(v['error'])
        return v['result']


def serve(writer,path,agent_uid,stopped):
    path=Path(path);parent=path.parent
    st=parent.lstat()
    if not parent.is_dir() or parent.is_symlink() or st.st_uid!=0 or st.st_mode&0o022:
        raise Blocked('Socket directory must be root-owned and not writable by peers')
    if path.exists() or path.is_symlink():
        # Only remove a prior socket in the verified root-owned directory.
        import stat
        if not stat.S_ISSOCK(path.lstat().st_mode) or path.lstat().st_uid!=0:raise Blocked('Foreign socket path')
        path.unlink()
    ctl=Controller(writer,agent_uid)
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
        server.bind(str(path));os.chmod(path,0o660);server.listen(16);server.settimeout(.5)
        try:
            while not stopped.is_set():
                try:conn,_=server.accept()
                except TimeoutError:continue
                with conn:
                    conn.settimeout(2)
                    uid=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                    before=copy.deepcopy(writer.s)
                    try:
                        try:data,_,flags,_=conn.recvmsg(MAX_REQUEST)
                        except (TimeoutError,ConnectionResetError):continue
                        before=copy.deepcopy(writer.s)
                        if flags & socket.MSG_TRUNC:raise ValueError('Request exceeds capacity')
                        reply=dispatch(ctl,decode(data),uid)
                    except (ValueError,PermissionError,Blocked) as exc:
                        if isinstance(exc,UncertainCommand) or writer.s['pending'] or writer.s['lifecycle'] or writer.s!=before:raise
                        reply=dict(ok=False,error=str(exc))
                    encoded=json.dumps(reply,allow_nan=False).encode()
                    if len(encoded)>MAX_REPLY:raise Blocked('Reply exceeds capacity')
                    try:conn.sendall(encoded)
                    except (BrokenPipeError,ConnectionResetError,TimeoutError):pass  # Lost reply is not rollback.
                # SQLite/storage errors or uncertain operations terminate service;
                # only a successor holding the same lock can reconcile.
        finally:path.unlink(missing_ok=True)
