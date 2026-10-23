"""Stage-one dual DHCP runtime: one writer, bounded intake, independent clients.

Automatic selection is opt-in; manual mode remains the default. Packet
capture supplies conservative REQUEST-time lower bounds, never hook-time leases.
"""
import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
import re
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time

from .control import decode
from .dual_dhcp import DualLifecycle, LINKS
from .dual_dhcp_linux import Backend
from .dhcp_wire import DHCPTracker,dhcp_envelope
from .probe import round as probe_round
from .writer import now


def request(path, q, timeout=3):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as peer:
        peer.settimeout(timeout); peer.connect(str(path))
        peer.sendall(json.dumps(q, allow_nan=False).encode())
        raw = peer.recv(65537)
        if len(raw) > 65536: raise ValueError('Oversized response')
        return json.loads(raw)


class Inbox:
    """Immutable intake authority; overflow revokes a link instead of hiding loss."""
    def __init__(self, capacity):
        if type(capacity) is not int or not 2 <= capacity <= 64:
            raise ValueError('Queue capacity must be 2..64')
        self.capacity = capacity
        self.per_link_limit = capacity//2
        self.queue, self.revoked = deque(), set()
        self.sessions = {k: None for k in LINKS}
        self.sequence = {k: 0 for k in LINKS}
        self.seen = {k: deque(maxlen=64) for k in LINKS}
        self.overflow = {k: 0 for k in LINKS}
        self.peak = 0
        self.lock = threading.RLock()

    def replace(self, link, session, boot):
        with self.lock:
            self.sessions[link] = (session, boot)
            self.sequence[link] = 0
            self.seen[link].clear()
            self.queue = deque(e for e in self.queue if e['link'] != link)
            self.revoked.discard(link)

    def put(self, event):
        with self.lock:
            k = event['link']
            if k not in LINKS or self.sessions[k] != (event['session'], event['boot']) or k in self.revoked:
                raise ValueError('Retired client authority')
            if event['id'] in self.seen[k]: raise ValueError('Duplicate event')
            if sum(e['link'] == k for e in self.queue) >= self.per_link_limit:
                self.overflow[k] += 1
                self.revoked.add(k)
                self.sessions[k] = None
                raise OverflowError('Queue full; affected client revoked')
            self.sequence[k] += 1
            value = copy.deepcopy(event)
            value['sequence'] = self.sequence[k]
            self.seen[k].append(value['id'])
            self.queue.append(value)
            self.peak = max(self.peak, len(self.queue))
            return value['sequence']

    def get(self):
        with self.lock:
            while self.queue:
                event = self.queue.popleft()
                k = event['link']
                if k not in self.revoked and self.sessions[k] == (event['session'],event['boot']):
                    # Dequeue is the linearization point. A bounded writer
                    # operation already claimed here may finish before a later
                    # revocation; unread queued events never gain that right.
                    return event
            return None

    def stats(self):
        with self.lock:
            return dict(depth=len(self.queue), capacity=self.capacity, peak=self.peak,
                        per_link_limit=self.per_link_limit,
                        per_link_depth={k:sum(e['link']==k for e in self.queue) for k in LINKS},
                        overflow=dict(self.overflow), revoked=sorted(self.revoked))


class Capture:
    """One dedicated-interface AF_PACKET queue; timestamp lower bounds survive lag.

    A time sampled BEFORE a recv that returns EAGAIN is earlier than any packet
    subsequently queued. Until the next proven-empty queue, every REQUEST uses
    that old lower bound, not its potentially delayed userspace receive time.
    Thus queue delay may shorten a lease, never grant extra lifetime.
    """
    def __init__(self, interface):
        self.mac = bytes.fromhex(Path('/sys/class/net', interface, 'address').read_text().strip().replace(':', ''))
        self.lock, self.stop = threading.RLock(), threading.Event()
        self.tracker = DHCPTracker(self.mac)
        self.empty_at = now()
        self.error = None
        self.session = None
        self.counts = dict(frames=0,requests=0,acks=0,unsupported=0)
        self.last_unsupported = None
        self.dirty = False
        self.version = 0
        self.versions = {}
        self.observations = deque(maxlen=32)
        # ETH_P_ALL taps outgoing REQUESTs as well as incoming ACKs. A socket
        # subscribed only to ETH_P_IP is insufficient for the transmit tap.
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        self.socket.bind((interface, 0)); self.socket.setblocking(False)
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def reset(self, session):
        with self.lock:
            self.tracker = DHCPTracker(self.mac)
            self.session = session
            self.dirty = False
            self.version = 0
            self.versions = {}
            self.observations.clear()

    def proof_keys(self):
        return {(k,v['request_at'],v['at']) for k,v in self.tracker.acks.items()}

    def run(self):
        try:
            while not self.stop.is_set():
                for _ in range(128):
                    before = now()
                    try: frame = self.socket.recv(4096)
                    except BlockingIOError:
                        with self.lock: self.empty_at = before
                        break
                    # Normal IPv4 traffic is not DHCP; malformed/unsupported
                    # frames provide no proof, rather than killing observation.
                    with self.lock:
                        self.counts['frames'] += 1
                        before_ack = self.proof_keys()
                        invalidations = getattr(self.tracker, 'invalidations', 0)
                        try:
                            kind = self.tracker.feed(frame, self.empty_at)
                            if kind == 3: self.counts['requests'] += 1
                            if kind == 5: self.counts['acks'] += 1
                            after_ack = self.proof_keys()
                            for key in after_ack-before_ack:
                                # New allocation invalidates old health even
                                # if hook/IPC delivery later fails.
                                self.dirty = True
                                self.version += 1
                                self.versions[key] = self.version
                            self.versions = {k:v for k,v in self.versions.items() if k in after_ack}
                        except ValueError as exc:
                            self.counts['unsupported'] += 1
                            self.last_unsupported = str(exc)
                        finally:
                            if dhcp_envelope(frame):
                                self.observations.append(dict(frame_sha256=hashlib.sha256(frame).hexdigest(),frame_index=self.counts['frames']))
                            if getattr(self.tracker, 'invalidations', 0) != invalidations:
                                # Contradictions can remove a proof (including
                                # one already queued), not merely add a new ACK.
                                self.dirty = True
                                self.version += 1
                                self.versions = {k:v for k,v in self.versions.items() if k in self.proof_keys()}
                self.stop.wait(.005)
        except OSError:
            if not self.stop.is_set(): self.error = 'Packet observation failed'

    def claim(self, value, session):
        until = now()+.2
        while now() < until:
            with self.lock:
                if session != self.session: raise ValueError('Retired capture authority')
                try:
                    before = self.proof_keys()
                    proof = self.tracker.claim(value, now())
                    consumed = before-self.proof_keys()
                    if len(consumed) != 1: raise ValueError('Ambiguous consumed ACK identity')
                    version = self.versions.pop(next(iter(consumed)), None)
                    if version is None: raise ValueError('ACK has no captured version')
                    return dict(proof,capture_version=version)
                except (ValueError, LookupError): pass
            if self.error: break
            self.stop.wait(.005)
        raise ValueError('No matching unconsumed DHCP REQUEST/ACK proof')

    def close(self):
        self.stop.set(); self.thread.join(timeout=1); self.socket.close()

    def take_dirty(self):
        with self.lock:
            # Sticky until the matching newest proof is actually applied.
            return self.dirty

    def is_current(self, version):
        with self.lock: return version == self.version

    def acknowledge(self, version):
        with self.lock:
            if version == self.version: self.dirty = False

    def stats(self):
        with self.lock:
            return dict(self.counts,unclaimed_acks=len(self.tracker.acks),requests_tracked=len(self.tracker.requests),
                        empty_at=self.empty_at,version=self.version,pending=self.dirty,seen_frames=list(self.observations),
                        last_unsupported=self.last_unsupported,alive=self.thread.is_alive())


class Runtime:
    def __init__(self, writer, path, hook, executable='/usr/bin/busybox', probe=probe_round, policy_uid=None, policy_gid=None, control_path=None):
        self.w, self.path, self.hook, self.executable, self.probe = writer, Path(path), Path(hook), executable, probe
        if any(v is not None for v in (policy_uid,policy_gid,control_path)) and not (type(policy_uid) is int and policy_uid>0 and type(policy_gid) is int and policy_gid>0 and control_path is not None):raise ValueError('Explicit non-root policy UID/GID and control path required')
        self.policy_uid,self.policy_gid=policy_uid,policy_gid
        self.control_path=Path(control_path) if control_path is not None else None
        if self.control_path==self.path:raise ValueError('Separate event and control sockets required')
        self.candidate_link=None
        self.control_cache={}
        cfg = writer.cfg.get('runtime', {})
        if set(cfg)-{'queue_capacity','probe_interval','restart_delay','client_diagnostics','restore_selected','automatic_selection','selection_hold','failover_delay'}: raise ValueError('Unknown runtime config')
        self.automatic_selection=cfg.get('automatic_selection',False)
        if type(self.automatic_selection) is not bool:raise ValueError('automatic_selection must be boolean')
        self.selection_hold=cfg.get('selection_hold',1.)
        self.failover_delay=cfg.get('failover_delay',2.)
        for v in (self.selection_hold,self.failover_delay):
            if type(v) not in (int,float) or not .05<=v<=30:raise ValueError('Selection delay outside .05..30 seconds')
        self.stable={k:None for k in LINKS}
        self.withdrawn_at=None
        self.auto_status='DISABLED'
        self.restore_selected=cfg.get('restore_selected',self.automatic_selection)
        if type(self.restore_selected) is not bool:raise ValueError('restore_selected must be boolean')
        if self.automatic_selection and not self.restore_selected:raise ValueError('Automatic selection requires lease restoration')
        self.restore_target=None
        self.restorations=deque(maxlen=16)
        self.restore_status='DISARMED'
        self.client_diagnostics = cfg.get('client_diagnostics',False)
        if type(self.client_diagnostics) is not bool:raise ValueError('client_diagnostics must be boolean')
        self.inbox = Inbox(cfg.get('queue_capacity', 8))
        self.interval = cfg.get('probe_interval', .2)
        self.restart_delay = cfg.get('restart_delay', .2)
        if any(type(v) not in (int,float) or not .05 <= v <= 5 for v in (self.interval,self.restart_delay)):
            raise ValueError('Runtime interval outside .05..5 seconds')
        self.stop = threading.Event()
        self.children, self.captures, self.futures = {}, {}, {}
        self.rounds = {k: 0 for k in LINKS}
        self.next_probe = {k: 0 for k in LINKS}
        self.restart_at = {k: 0 for k in LINKS}
        self.restarts = {k: deque(maxlen=3) for k in LINKS}
        self.metrics = dict(queued=0,processed=0,rejected=0,probe_results=0,stale_probe_results=0,
                            client_restarts={k:0 for k in LINKS},lease_restore_attempts=0,lease_restores=0,
                            automatic_choices=0,selection_invalidations=0)
        self.recent = deque(maxlen=16)
        self.selection_events = deque(maxlen=16)
        self.errors = deque(maxlen=16)
        self.cache = {}
        self.cache_lock = threading.RLock()
        self.operator = deque(maxlen=4)
        self.proposals = deque(maxlen=1)
        self.pool = ThreadPoolExecutor(max_workers=2)

    def increment(self, key):
        with self.cache_lock: self.metrics[key] += 1

    def publish(self):
        with self.cache_lock:
            self.cache = dict(ok=True, state=self.w.snapshot(), runtime=dict(
                children={k:self.children[k].pid if k in self.children and self.children[k].poll() is None else None for k in LINKS},
                restoration=dict(enabled=self.restore_selected,target=self.restore_target,status=self.restore_status,recent=len(self.restorations),limit=16,window_seconds=60),
                automatic=dict(enabled=self.automatic_selection,status=self.auto_status,selection_hold=self.selection_hold,failover_delay=self.failover_delay,withdrawn_at=self.withdrawn_at),
                inflight={k:k in self.futures for k in LINKS}, queue=self.inbox.stats(),
                metrics=copy.deepcopy(self.metrics), recent=list(self.recent), as_of=now(),
                selection_events=list(self.selection_events),
                capture={k:c.stats() for k,c in self.captures.items()},
                last_errors=list(self.errors),
                lease_clock='CLOCK_BOOTTIME; earlier of fixed client REQUEST origin and previous empty AF_PACKET queue bound'))
            self.control_cache=self.control_status()

    def spawn(self, k):
        s = self.w.s
        self.captures[k].reset(s['links'][k]['session'])
        self.inbox.replace(k, s['links'][k]['session'], s['boot'])
        env = dict(os.environ, UPLINKSTEAD_SOCKET=str(self.path), UPLINKSTEAD_LINK=k,
                   UPLINKSTEAD_SESSION=s['links'][k]['session'], UPLINKSTEAD_BOOT=s['boot'])
        self.children[k] = subprocess.Popen([self.executable,'udhcpc','-f','-i',self.w.cfg['links'][k]['interface'],
            '-s',str(self.hook),'-t','3','-T','1','-A','1','-O','lease','-O','33','-O','121','-O','249','-O','58','-O','59'],
            env=env, stdout=None if self.client_diagnostics else subprocess.DEVNULL,
            stderr=subprocess.STDOUT if self.client_diagnostics else subprocess.DEVNULL)

    @staticmethod
    def kill(child):
        if child.poll() is None:
            child.terminate()
            try: child.wait(timeout=.3)
            except subprocess.TimeoutExpired: child.kill(); child.wait(timeout=2)

    def retire(self, k):
        if k in self.children: self.kill(self.children[k])
        self.w.restart_client(k)
        with self.inbox.lock:
            self.inbox.sessions[k] = None
            self.inbox.revoked.discard(k)
            self.inbox.queue = deque(e for e in self.inbox.queue if e['link'] != k)
        self.metrics['client_restarts'][k] += 1
        instant = now()
        self.restarts[k] = deque((t for t in self.restarts[k] if instant-t < 60), maxlen=3)
        if len(self.restarts[k]) >= 3:
            self.restart_at[k] = float('inf')
        else:
            self.restarts[k].append(instant)
            self.restart_at[k] = instant+self.restart_delay

    def intake(self, q):
        base={'op','link','session','boot','id','at','reason','lease','options'}
        if set(q) not in (base,base|{'client_origin_ns','client_xid'}):
            raise ValueError('Invalid hook envelope')
        k = q['link']
        if k not in LINKS or not isinstance(q['id'],str) or not 1 <= len(q['id']) <= 64 or not self.w.number(q['at']) or not q['at'] <= now():
            raise ValueError('Invalid event identity/time')
        with self.inbox.lock:
            if self.inbox.sessions[k] != (q['session'],q['boot']) or k in self.inbox.revoked:
                raise ValueError('Retired client authority')
            if q['id'] in self.inbox.seen[k]: raise ValueError('Duplicate event')
        event = {a:b for a,b in q.items() if a != 'op'}
        if q['reason'] in ('bound','renew'):
            try:
                proof = self.captures[k].claim(q['lease'], q['session'])
                proof['wire_request_at']=proof['request_at']
                if 'client_origin_ns' in q:
                    origin=q['client_origin_ns']
                    if type(origin) is not int or not 0<=origin<=int(q['at']*1_000_000_000) or type(q['client_xid']) is not int or q['client_xid']!=proof['xid']:
                        raise ValueError('Invalid client request origin/transaction')
                    proof['request_at']=min(proof['request_at'],origin/1_000_000_000)
            except ValueError:
                # The current client reported an allocation we cannot verify.
                # Retire only that authority, never a replacement client.
                with self.inbox.lock:
                    if self.inbox.sessions[k] == (q['session'],q['boot']):
                        self.inbox.sessions[k] = None
                        self.inbox.revoked.add(k)
                raise
            event.update(proof)
            event['options'] = sorted(set(event['options'])|set(proof['options']))
        elif q['reason'] not in ('deconfig','nak','leasefail') or q['lease'] is not None:
            raise ValueError('Invalid loss event')
        else: event.update(request_at=None,observed_at=None)
        seq = self.inbox.put(event)
        self.increment('queued')
        return dict(ok=True, queued=True, sequence=seq, at=q['at'])

    def listen(self, listener):
        while not self.stop.is_set():
            try: peer,_ = listener.accept()
            except socket.timeout: continue
            except OSError: break
            with peer:
                peer.settimeout(.1)
                try:
                    uid = struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                    if uid != 0: raise PermissionError('Root-only adapter and operator')
                    q = decode(peer.recv(4097))
                    if q == {'op':'status'}:
                        with self.cache_lock: answer = copy.deepcopy(self.cache)
                        answer['runtime']['queue'] = self.inbox.stats()
                    elif q.get('op') == 'event': answer = self.intake(q)
                    elif q.get('op') == 'choose' and set(q) == {'op','link','epoch','revision'}:
                        item = (copy.deepcopy(q),threading.Event(),{})
                        with self.cache_lock:
                            if len(self.operator) >= 4: raise OverflowError('Operator queue full')
                            self.operator.append(item)
                        if item[1].wait(.5): answer = item[2]
                        else: answer = dict(ok=False,error='OutcomeUnknownInspectStatus')
                    else: raise ValueError('Unsupported operation')
                except (ValueError,TypeError,KeyError,OSError,OverflowError) as exc:
                    self.increment('rejected')
                    with self.cache_lock: self.errors.append(type(exc).__name__+': '+str(exc)[:160])
                    answer = dict(ok=False,error=type(exc).__name__)
                try: peer.sendall(json.dumps(answer,allow_nan=False).encode())
                except OSError: pass

    def step(self):
        self.w.tick()
        for k in LINKS:
            if self.captures[k].take_dirty() and self.w.s['links'][k]['current']:
                self.w.transition(k,None,0)
            with self.inbox.lock: revoked = k in self.inbox.revoked
            child = self.children.get(k)
            if revoked or (child is not None and child.poll() is not None and self.restart_at[k] == 0):
                self.retire(k)
            if self.captures[k].error:
                raise RuntimeError('Capture failed; stop rather than admit unobserved leases')
            if self.restart_at[k] and now() >= self.restart_at[k]:
                self.spawn(k); self.restart_at[k] = 0
        event = self.inbox.get()
        if event:
            try:
                if 'capture_version' in event and not self.captures[event['link']].is_current(event['capture_version']):
                    raise RuntimeError('Stale captured allocation')
                outcome = self.w.wire_callback(**{k:event[k] for k in ('link','session','boot','sequence','at','reason','lease','request_at','observed_at','options')})
                if 'capture_version' in event: self.captures[event['link']].acknowledge(event['capture_version'])
                self.increment('processed')
                self.recent.append(dict(link=event['link'],sequence=event['sequence'],reason=event['reason'],
                    xid=event.get('xid'),
                    client_origin_ns=event.get('client_origin_ns'),wire_request_at=event.get('wire_request_at'),
                    request_at=event['request_at'],observed_at=event['observed_at'],hook_at=event['at'],processed_at=now(),
                    expires=self.w.s['links'][event['link']]['expires'],
                    probe_inflight={k:k in self.futures and not self.futures[k][0].done() for k in LINKS}))
                if outcome.get('lease_rejected'):
                    # A real same-xid renewal may outlive its conservative
                    # deadline. Reacquire under fresh authority instead of
                    # remaining permanently stuck on that expired proof.
                    self.retire(event['link'])
            except RuntimeError as exc:
                if self.w.s['phase'] != 'READY': raise
                self.increment('rejected')
                self.errors.append(type(exc).__name__+': '+str(exc)[:160])
            with self.inbox.lock: revoked = event['link'] in self.inbox.revoked
            if revoked: self.retire(event['link'])
        for k in LINKS:
            if k in self.futures and self.futures[k][0].done():
                f,gen,started,rid = self.futures.pop(k)
                votes,_ = f.result()
                try: self.w.observation(k,gen,rid,started,votes); self.metrics['probe_results'] += 1
                except RuntimeError: self.metrics['stale_probe_results'] += 1
            row = self.w.s['links'][k]
            if row['current'] and k not in self.futures and now() >= self.next_probe[k]:
                self.rounds[k] += 1
                c = copy.deepcopy(self.w.cfg); c['links'][k]['source'] = row['current']['ip']
                started = now()
                self.futures[k] = (self.pool.submit(self.probe,c,k),row['generation'],started,self.rounds[k])
                self.next_probe[k] = started+self.interval
        with self.cache_lock: item = self.operator.popleft() if self.operator else (self.proposals.popleft() if self.proposals else None)
        if item:
            q,done,result = item
            try:
                if '_control' in q:result.update(self.process_control(q['_control'],q['_uid']))
                else:
                    valid=self.select_guarded(q['link'],lambda:self.w.choose(q['link'],q['epoch'],q['revision']))
                    if valid and self.restore_selected:self.restore_target=q['link']
                    result.update(ok=valid,state=self.w.snapshot())
                    if not valid:result['error']='SelectionInvalidated'
            except RuntimeError as exc:
                if self.w.s['phase'] != 'READY': raise
                result.update(ok=False,error=type(exc).__name__)
                if '_control' in q:result.update(detail=str(exc)[:160],status=self.control_status())
            done.set()
        self.converge()
        self.automatic()
        self.publish()

    def selection_stamp(self,k):
        c=self.captures[k].stats();q=self.inbox.stats()
        return (c.get('version',0),q['per_link_depth'][k],self.inbox.sequence[k],k in q['revoked']),bool(c.get('pending',False) or q['per_link_depth'][k] or k in q['revoked'])

    def control_status(self):
        s=self.w.s;k=self.candidate_link
        return dict(epoch=s['epoch'],revision=s['revision'],phase=s['phase'],paused=s['paused'],latched=s['latched'],
            active={n:s['active'][n] for n in ('link','generation')} if s['active'] else None,
            links={k:dict(generation=r['generation'],has_lease=r['current'] is not None,health=self.w.health[k]['state'],expires=r['expires']) for k,r in s['links'].items()},
            history_count=len(s['history']),budget=self.w.budget,
            candidate=dict(target=k,generation=s['links'][k]['generation']) if k and s['active'] is None and not s['paused'] and not s['latched'] else None,
            worker_required=self.policy_uid is not None,operations=copy.deepcopy(s['operations']),as_of=now())

    def validate_control(self,q,uid):
        if uid not in (0,self.policy_uid):raise PermissionError('Untrusted local peer')
        op=q.get('op');schemas={'status':{'op'},'propose':{'op','epoch','revision','target','generation'},
            'pause':{'op','epoch','revision','id'},'resume':{'op','epoch','revision','id'},'reset-budget':{'op','epoch','revision','id','ack'}}
        if not isinstance(op,str) or op not in schemas or set(q)!=schemas[op]:raise ValueError('Unknown control operation/fields')
        if op not in ('status','propose') and uid!=0:raise PermissionError('Root operator required')
        if op=='propose' and (self.policy_uid is None or uid!=self.policy_uid):raise PermissionError('Dedicated policy peer required')
        if op!='status' and any(type(q[n]) is not int or q[n]<0 for n in ('epoch','revision')):raise ValueError('Invalid operation token')
        if op=='propose' and (not isinstance(q['target'],str) or q['target'] not in LINKS or type(q['generation']) is not int or q['generation']<0):raise ValueError('Invalid proposal')
        if op in ('pause','resume','reset-budget') and (not isinstance(q['id'],str) or not re.fullmatch('[0-9a-f]{32}',q['id'])):raise ValueError('Invalid operation ID')
        if op=='reset-budget' and q['ack']!='reset-switch-budget':raise ValueError('Explicit budget acknowledgement required')

    def process_control(self,q,uid):
        self.validate_control(q,uid);op=q['op']
        self.w.token(q);self.w.tick();self.w.token(q)
        if op=='propose':
            k=q['target']
            if k not in LINKS or type(q['generation']) is not int or q['generation']!=self.w.s['links'][k]['generation'] or self.candidate()!=k:
                raise RuntimeError('Proposal not admitted by writer')
            valid=self.admit_candidate(k)
            return dict(ok=valid,status=self.control_status(),**({} if valid else dict(error='ProposalInvalidated')))
        k=None;stamp=None
        if op=='resume':
            links=sorted(LINKS,key=lambda link: not (self.w.s['active'] and self.w.s['active']['link']==link))
            for link in links:
                value,pending=self.selection_stamp(link)
                if self.w.healthy(link) and not pending:k,stamp=link,value;break
            if k is None:raise RuntimeError('No fresh admitted lease/health')
        self.w.operator(q,k)
        if op=='resume':
            after,pending=self.selection_stamp(k)
            if pending or after!=stamp or not self.w.healthy(k):
                self.w.transition(k,None,0.)
                self.w.repause();return dict(ok=False,error='ResumeEvidenceChanged',status=self.control_status())
        return dict(ok=True,status=self.control_status())

    def submit_control(self,q,uid):
        self.validate_control(q,uid)
        if q['op']=='status':
            with self.cache_lock:return dict(ok=True,status=copy.deepcopy(self.control_cache))
        item=({'_control':copy.deepcopy(q),'_uid':uid},threading.Event(),{})
        with self.cache_lock:
            queue=self.proposals if q['op']=='propose' else self.operator
            if len(queue)>=queue.maxlen:raise OverflowError('Control queue full')
            queue.append(item)
        if item[1].wait(.5):return item[2]
        return dict(ok=False,error='OutcomeUnknownInspectStatus',id=q.get('id'))

    def open_control(self):
        parent=self.control_path.parent
        if not parent.exists():
            parent.mkdir(mode=0o750);os.chown(parent,0,self.policy_gid)
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or parent.is_symlink() or st.st_uid!=0 or st.st_gid!=self.policy_gid or st.st_mode&0o027 or st.st_mode&0o050!=0o050:
            raise PermissionError('Root-owned non-writable policy directory required')
        if self.control_path.exists() or self.control_path.is_symlink():
            st=self.control_path.lstat()
            if not stat.S_ISSOCK(st.st_mode) or st.st_uid!=0:raise RuntimeError('Foreign control socket')
            self.control_path.unlink()
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        try:
            listener.bind(str(self.control_path));os.chown(self.control_path,0,self.policy_gid);self.control_path.chmod(0o660)
            listener.listen(4);listener.settimeout(.1);return listener
        except BaseException:listener.close();raise

    def listen_control(self,listener):
        while not self.stop.is_set():
            try:peer,_=listener.accept()
            except socket.timeout:continue
            except OSError:break
            with peer:
                peer.settimeout(.1)
                try:
                    uid=struct.unpack('3i',peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]
                    raw,_,flags,_=peer.recvmsg(4096)
                    if flags&socket.MSG_TRUNC:raise ValueError('Control request too large')
                    answer=self.submit_control(decode(raw),uid)
                except (ValueError,TypeError,KeyError,PermissionError,OSError,OverflowError) as exc:
                    self.increment('rejected');answer=dict(ok=False,error=type(exc).__name__)
                try:peer.sendall(json.dumps(answer,allow_nan=False).encode())
                except OSError:pass

    def select_guarded(self,k,action):
        """Recheck intake after a real write; never publish that stale choice.

        This is not an atomic ACK/kernel transaction. A later packet is handled
        by the next step; an observed concurrent change withdraws and resets health.
        """
        if k not in LINKS:raise RuntimeError('Unknown selection link')
        before,blocked=self.selection_stamp(k)
        if blocked:raise RuntimeError('Pending lease evidence')
        action()
        after,blocked=self.selection_stamp(k)
        if blocked or after!=before:
            self.w.transition(k,None,0.)
            self.increment('selection_invalidations')
            self.selection_events.append(dict(at=now(),link=k,outcome='INVALIDATED',before=list(before),after=list(after),pending=blocked,
                generation=self.w.s['links'][k]['generation'],current=copy.deepcopy(self.w.s['links'][k]['current']),active=copy.deepcopy(self.w.s['active'])))
            return False
        return self.w.s['active'] is not None and self.w.s['active']['link']==k

    def candidate(self):
        if not self.automatic_selection:return
        instant=now();s=self.w.s
        for k in LINKS:
            row=s['links'][k];_,pending=self.selection_stamp(k)
            if row['current'] is None or self.w.health[k]['state']!='HEALTHY' or pending:
                self.stable[k]=None
            elif self.stable[k] is None or self.stable[k][0]!=row['generation']:
                self.stable[k]=(row['generation'],instant)
        if s['paused'] or s['latched']:
            self.auto_status='OPERATOR_BLOCKED';return
        if s['active'] is not None:
            self.withdrawn_at=None;self.auto_status='SELECTED';return
        if self.withdrawn_at is None:self.withdrawn_at=instant
        anchor=s['selection']
        if anchor is not None:
            k=anchor['link'];row=s['links'][k]
            if row['generation']>anchor['generation'] and row['current'] and self.w.health[k]['state']=='HEALTHY':
                self.auto_status='LEASE_RESTORE_BLOCKED';return
        if anchor is not None and instant-self.withdrawn_at<self.failover_delay:
            self.auto_status='WITHDRAWAL_GRACE';return
        candidates=[k for k in LINKS if self.stable[k] is not None and instant-self.stable[k][1]>=self.selection_hold]
        # Sticky, no automatic preemption/failback. Prefer the last WAN if both
        # are usable after withdrawal; initial acquisition prefers A when ready.
        preferred=anchor['link'] if anchor else 'A'
        candidates.sort(key=lambda k:k!=preferred)
        if not candidates:self.auto_status='NO_STABLE_UPLINK';return
        return candidates[0]

    def automatic(self):
        self.candidate_link=self.candidate()
        if self.candidate_link is not None and self.policy_uid is None:self.admit_candidate(self.candidate_link)

    def admit_candidate(self,k):
        s=self.w.s
        try:
            valid=self.select_guarded(k,lambda:self.w.choose(k,s['epoch'],s['revision']))
        except RuntimeError:
            if s['phase']!='READY':raise
            self.auto_status='OPERATOR_BLOCKED' if s['latched'] else 'EVIDENCE_CHANGED';return False
        self.restore_target=k
        if valid:
            self.withdrawn_at=None
            self.increment('automatic_choices');self.auto_status='SELECTED'
        else:self.auto_status='EVIDENCE_CHANGED'
        return valid

    def converge(self):
        if not self.restore_selected or self.restore_target is None:
            self.restore_status='DISARMED';return
        k=self.restore_target;s=self.w.s;row=s['links'][k];anchor=s['selection']
        if s['paused'] or s['latched']:
            self.restore_status='OPERATOR_BLOCKED';return
        if s['active'] is not None:
            self.restore_status='SELECTED';return
        if anchor is None or anchor['link']!=k or row['generation']<=anchor['generation']:
            self.restore_status='NO_NEW_LEASE';return
        if row['current'] is None or self.w.health[k]['state']!='HEALTHY' or self.captures[k].stats().get('pending',False):
            self.restore_status='AWAITING_FRESH_LEASE_HEALTH';return
        instant=now()
        while self.restorations and instant-self.restorations[0]>=60:self.restorations.popleft()
        if len(self.restorations)>=16:
            self.restore_status='RATE_LIMITED';return
        self.restorations.append(instant);self.increment('lease_restore_attempts')
        try:valid=self.select_guarded(k,lambda:self.w.restore(k,s['epoch'],s['revision']))
        except RuntimeError:
            if s['phase']!='READY':raise
            self.restore_status='EVIDENCE_CHANGED';return
        if valid and s['active'] is not None:self.increment('lease_restores')
        self.restore_status='SELECTED' if s['active'] is not None else 'WITHDRAWN_DURING_RESTORE'

    def run(self):
        if os.geteuid() != 0: raise PermissionError('Root Linux runtime required')
        self.path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        st = self.path.parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
            raise PermissionError('Private root-owned socket directory required')
        if self.path.exists():
            if not stat.S_ISSOCK(self.path.lstat().st_mode): raise RuntimeError('Refusing foreign socket path')
            self.path.unlink()
        thread = None;control_thread=None;control_listener=None
        try:
            for k in LINKS: self.captures[k] = Capture(self.w.cfg['links'][k]['interface'])
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as listener:
                listener.bind(str(self.path)); self.path.chmod(0o600); listener.listen(4); listener.settimeout(.1)
                self.publish()
                if self.control_path is not None:
                    control_listener=self.open_control()
                    control_thread=threading.Thread(target=self.listen_control,args=(control_listener,),daemon=True);control_thread.start()
                thread = threading.Thread(target=self.listen,args=(listener,),daemon=True); thread.start()
                for k in LINKS: self.spawn(k)
                while not self.stop.is_set(): self.step(); self.stop.wait(.01)
        finally:
            self.stop.set()
            if thread: thread.join(timeout=1)
            if control_listener:control_listener.close()
            if control_thread:control_thread.join(timeout=1)
            if control_listener and self.control_path:self.control_path.unlink(missing_ok=True)
            for p in self.children.values(): self.kill(p)
            self.pool.shutdown(wait=True,cancel_futures=True)
            for capture in self.captures.values(): capture.close()
            if self.w.s['phase'] == 'READY':
                for k in LINKS: self.w.restart_client(k)
            self.path.unlink(missing_ok=True)


def hook():
    import secrets
    import sys
    reason = sys.argv[1]
    if reason not in ('bound','renew','deconfig','nak','leasefail'): return
    q = dict(op='event',link=os.environ['UPLINKSTEAD_LINK'],session=os.environ['UPLINKSTEAD_SESSION'],
             boot=os.environ['UPLINKSTEAD_BOOT'],id=secrets.token_hex(16),at=now(),reason=reason,
             lease={k:os.environ.get(k,'') for k in ('ip','subnet','router','lease')} if reason in ('bound','renew') else None,
             options=[k for k in ('routes','staticroutes','msstaticroutes') if os.environ.get(k)])
    if reason in ('bound','renew') and 'UPLINKSTEAD_CLIENT_ORIGIN_NS' in os.environ:
        q.update(client_origin_ns=int(os.environ['UPLINKSTEAD_CLIENT_ORIGIN_NS']),client_xid=int(os.environ['UPLINKSTEAD_CLIENT_XID']))
    answer = request(Path(os.environ['UPLINKSTEAD_SOCKET']),q)
    if not answer['ok']: raise RuntimeError('DHCP event not queued; inspect service status')


def main():
    p = argparse.ArgumentParser(); p.add_argument('--config',type=Path,required=True)
    p.add_argument('--journal',type=Path,required=True); p.add_argument('--socket',type=Path,required=True)
    p.add_argument('--hook',type=Path,default=Path('/usr/libexec/uplinkstead-dual-hook.py'))
    p.add_argument('--client',default='/usr/bin/busybox')
    p.add_argument('--policy-uid',type=int);p.add_argument('--policy-gid',type=int);p.add_argument('--control-socket',type=Path)
    a = p.parse_args()
    c = json.loads(a.config.read_text())
    with DualLifecycle(c,a.journal,Backend) as writer:
        runtime = Runtime(writer,a.socket,a.hook,a.client,policy_uid=a.policy_uid,policy_gid=a.policy_gid,control_path=a.control_socket)
        def stop(*_): runtime.stop.set()
        signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
        runtime.run()


if __name__ == '__main__': main()
