"""Bounded dual-DHCP exploration core; no daemon or DHCP wire adapter.

Callers serialize entry points. Backend helpers inherit fd to retain the writer
lock after a writer crash. Health is deliberately volatile across recovery.
"""
import copy
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
from pathlib import Path
import secrets
import sqlite3
import stat
import sys

from .dhcp import lease as parse_lease
from .linux import Blocked
from .writer import Writer, boot_id, now

LINKS = ('A', 'B')


class StorageUnavailable(Blocked):
    """Writer retired; a non-durable quarantine receipt is not API success."""


class DualLifecycle(Writer):
    def __init__(self, config, directory, backend_factory, clock=now, boot=boot_id):
        self.cfg, self.factory, self.clock, self.boot = config, backend_factory, clock, boot
        if set(config['links']) != set(LINKS):
            raise ValueError('Exactly two dedicated links required')
        names = [config['links'][k]['interface'] for k in LINKS]+[config['lan']['interface']]
        if len(set(names)) != 3 or any(not isinstance(n,str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}',n) or n == 'lo' for n in names):
            raise ValueError('Distinct dedicated interfaces required')
        lan = ipaddress.IPv4Network(config['lan']['prefix'])
        if lan.prefixlen == 0 or len(config['targets']) != 3:
            raise ValueError('Bounded LAN and three targets required')
        endpoints = set()
        for t in config['targets']:
            a = ipaddress.IPv4Address(t['ip'])
            if set(t) != {'ip','port'} or type(t['port']) is not int or not 1 <= t['port'] <= 65535 or a in lan or a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local:
                raise ValueError('Invalid unicast TLS target')
            endpoints.add((str(a),t['port']))
        if len(endpoints) != 3 or len(json.dumps(config)) > 16384:
            raise ValueError('Three distinct targets and bounded config required')
        storage=config.get('storage',{})
        if not isinstance(storage,dict) or set(storage)-{'max_pages'} or type(storage.get('max_pages',2048)) is not int or not 2<=storage.get('max_pages',2048)<=2048:
            raise ValueError('storage.max_pages must be 2..2048')
        self.max_pages=storage.get('max_pages',2048)
        # Storage size is a restart-only resource limit, not lease/route authority.
        authority={k:v for k,v in config.items() if k!='storage'}
        super().__init__({'_hash': hashlib.sha256(json.dumps(authority, sort_keys=True).encode()).hexdigest()}, directory)
        self._owns_lock=False;self._last_durable=None;self.storage_fault=None
        self.successes = config.get('success_rounds', 2)
        self.failures = config.get('failure_rounds', 3)
        self.freshness = config.get('freshness', 2.)
        self.budget = config.get('budget', 3)
        self.window = config.get('window', 60.)
        if any(type(n) is not int or not 1 <= n <= 64 for n in (self.successes, self.failures, self.budget)) or any(type(n) not in (int, float) or not math.isfinite(n) or n <= 0 for n in (self.freshness, self.window)):
            raise ValueError('Invalid policy limits')

    @staticmethod
    def empty():
        return dict(current=None, generation=0, revision=0, session=secrets.token_hex(24), event_sequence=0, last_event=0., expires=0.)

    def __enter__(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = self.directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Blocked('Private owned state directory required')
        try:
            lock=self.directory/'writer.lock'
            self.fd = os.open(lock, (os.O_RDONLY if lock.exists() else os.O_CREAT|os.O_RDWR) | os.O_NOFOLLOW, 0o600)
            st = os.fstat(self.fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid!=os.geteuid():
                raise Blocked('Unsafe writer lock')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB);self._owns_lock=True
            path = self.directory/'journal.sqlite'
            if path.is_symlink():raise Blocked('Unsafe journal')
            row=None
            uninitialized=False
            if path.exists():
                st=path.lstat()
                uninitialized=(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and st.st_nlink==1 and st.st_size==0 and
                               not any(Path(str(path)+suffix).exists() or Path(str(path)+suffix).is_symlink() for suffix in ('-journal','-wal','-shm')))
            # A failed first CREATE can leave an owned empty SQLite file. It
            # carries no durable authority; never generalize this to missing
            # schemas, hot journals or corrupt/nonempty snapshots.
            if path.exists() and not uninitialized:
                reader=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,isolation_level=None)
                try:row=reader.execute('SELECT value FROM state WHERE id=1').fetchone()
                finally:reader.close()
            had_snapshot=row is not None
            self.s = json.loads(row[0]) if row else dict(config_hash=self.c['_hash'], boot=self.boot(), epoch=0, revision=0, history=[], latched=False, paused=False, phase='RECOVERING', links={k:self.empty() for k in LINKS}, active=None, pending=None, selection=None,operations=[])
            # Explicit additive migration of the historical exploration schema.
            # Existing unknown fields are still rejected by validate().
            for row in self.s.get('links', {}).values():
                if isinstance(row, dict) and set(row) == {'current','generation','revision','session','last_event','expires'}:
                    row['event_sequence'] = 0
            base={'config_hash','boot','epoch','revision','history','latched','paused','phase','links','active','pending'}
            if base<=set(self.s)<=base|{'selection','operations'}:
                self.s.setdefault('selection',None);self.s.setdefault('operations',[])
            self.validate()
            if had_snapshot:self._last_durable=copy.deepcopy(self.s)
            self.backend = self.factory(self.cfg, self.fd)
            self.health = {k:dict(state='WAITING', good=0, bad=0, round=-1, until=0.) for k in LINKS}
            try:
                self.db = sqlite3.connect(path, isolation_level=None)
                self.db.execute('PRAGMA synchronous=FULL')
                self.db.execute('PRAGMA journal_mode=DELETE')
                if self.db.execute('PRAGMA page_size').fetchone()[0] != 4096 or self.db.execute('PRAGMA max_page_count='+str(self.max_pages)).fetchone()[0] != self.max_pages:
                    raise Blocked('Journal capacity/layout unsupported')
                self.db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)')
            except (sqlite3.Error,OSError,Blocked) as exc:self.storage_failed(exc)
            self.s.update(epoch=self.s['epoch']+1, phase='RECOVERING')
            self.save()
            self.backend.reconcile(self.allowed(), {k:None for k in LINKS}, None)
            for k in LINKS:
                old = self.s['links'][k]
                self.s['links'][k] = dict(self.empty(), generation=old['generation']+1, revision=old['revision']+1)
            self.s.update(boot=self.boot(), active=None, pending=None, selection=None, phase='READY', revision=self.s['revision']+1)
            self.save()
            return self
        except BaseException:
            self.__exit__()
            raise

    def __exit__(self,*args):
        try:super().__exit__(*args)
        finally:self._owns_lock=False

    def storage_failed(self,exc):
        if self.storage_fault is not None:raise StorageUnavailable('Storage unavailable; writer retired') from exc
        code=getattr(exc,'sqlite_errorcode',None)
        kind='sqlite_full' if code is not None and code&255==sqlite3.SQLITE_FULL else 'sqlite_readonly' if code is not None and code&255==sqlite3.SQLITE_READONLY else ('reserve' if str(exc).startswith('State volume reserve') else 'layout') if isinstance(exc,Blocked) else 'sqlite_error' if isinstance(exc,sqlite3.Error) else 'os_error'
        receipt=dict(event='storage_failure',kind=kind,sqlite_code=code,sqlite_name=getattr(exc,'sqlite_errorname',None),errno=getattr(exc,'errno',None),quarantined=False,durable=False,lock_held=self._owns_lock)
        self.storage_fault=receipt;self.s['phase']='RECOVERY_REQUIRED'
        try:
            if not self._owns_lock or self.fd is None or self._last_durable is None:raise Blocked('No exclusive validated durable authority')
            self.validate()
            allowed=self.allowed();prior=self.allowed(self._last_durable)
            for k in LINKS:
                for v in prior[k]:
                    if v not in allowed[k]:allowed[k].append(v)
            # Only quarantine. No successful journal write, new route, lease,
            # budget reset or client authority is permitted by this path.
            self.backend.reconcile(allowed,{k:None for k in LINKS},None)
            receipt['quarantined']=True
            self.s.update(active=None,pending=None,selection=None)
            for k in LINKS:
                self.s['links'][k].update(current=None,expires=0.)
                self.health[k]=dict(state='WAITING',good=0,bad=0,round=-1,until=0.)
        except Exception as failure:receipt['quarantine_error']=type(failure).__name__+': '+str(failure)[:160]
        print(json.dumps(receipt,allow_nan=False),file=sys.stderr,flush=True)
        raise StorageUnavailable('Storage unavailable; quarantine='+str(receipt['quarantined'])+'; writer retired') from exc

    def save(self):
        if self.storage_fault is not None:raise StorageUnavailable('Storage unavailable; writer retired')
        try:super().save()
        except (sqlite3.Error,OSError,Blocked) as exc:self.storage_failed(exc)
        self._last_durable=copy.deepcopy(self.s)

    def validate(self):
        s = self.s
        if set(s) != {'config_hash','boot','epoch','revision','history','latched','paused','phase','links','active','pending','selection','operations'} or s['config_hash'] != self.c['_hash'] or set(s['links']) != set(LINKS):
            raise Blocked('Invalid dual DHCP journal')
        if not isinstance(s['boot'],str) or not s['boot'] or any(type(s[n]) is not int or s[n] < 0 for n in ('epoch','revision')) or type(s['paused']) is not bool or type(s['latched']) is not bool or s['phase'] not in ('RECOVERING','READY','RECOVERY_REQUIRED'):
            raise Blocked('Invalid journal authority')
        if not isinstance(s['history'], list) or len(s['history']) > 64 or any(set(h) != {'boot','at'} or not isinstance(h['boot'],str) or not self.number(h['at']) for h in s['history']):
            raise Blocked('Invalid budget history')
        if not isinstance(s['operations'],list) or len(s['operations'])>32:raise Blocked('Invalid operation history')
        ids=set()
        for op in s['operations']:
            if not isinstance(op,dict) or set(op)!={'id','kind','uid','at','boot','epoch','revision','outcome'} or not isinstance(op['id'],str) or not re.fullmatch('[0-9a-f]{32}',op['id']) or op['id'] in ids or op['kind'] not in ('pause','resume','reset-budget') or type(op['uid']) is not int or op['uid']!=0 or not self.number(op['at']) or not isinstance(op['boot'],str) or not op['boot'] or any(type(op[n]) is not int or not 0<=op[n]<=s[n] for n in ('epoch','revision')) or op['outcome'] not in ('APPLIED','REPAUSED'):
                raise Blocked('Invalid operation receipt')
            ids.add(op['id'])
        for k, row in s['links'].items():
            if set(row) != {'current','generation','revision','session','event_sequence','last_event','expires'} or any(type(row[n]) is not int or row[n] < 0 for n in ('generation','revision','event_sequence')) or not isinstance(row['session'],str) or not re.fullmatch('[0-9a-f]{48}',row['session']) or any(not self.number(row[n]) for n in ('last_event','expires')):
                raise Blocked('Invalid link journal')
            self.validate_value(row['current'])
        anchor=s['selection']
        if anchor is not None and (not isinstance(anchor,dict) or set(anchor)!={'link','generation'} or anchor['link'] not in LINKS or type(anchor['generation']) is not int or not 0<=anchor['generation']<=s['links'][anchor['link']]['generation']):
            raise Blocked('Invalid lease restoration anchor')
        self.validate_active(s['active'])
        if s['active']:
            a = s['active']; row = s['links'][a['link']]
            if a['generation'] != row['generation'] or a['value'] != row['current']:
                raise Blocked('Active identity differs from current allocation')
        if s['pending'] is not None:
            p = s['pending']
            if not isinstance(p,dict) or set(p) != {'kind','link','old','new','before','after'} or p['kind'] not in ('link','select') or p['link'] not in (*LINKS,None):
                raise Blocked('Invalid pending intent')
            self.validate_active(p['before']); self.validate_active(p['after'])
            if (p['kind'] == 'link' and (p['link'] not in LINKS or p['old'] != s['links'][p['link']]['current'])) or (p['kind'] == 'select' and (p['link'] is not None or p['old'] is not None or p['new'] is not None)) or p['before'] != s['active']:
                raise Blocked('Pending intent identity mismatch')
            if p['kind'] == 'link':
                expected = None if p['before'] and p['before']['link'] == p['link'] else p['before']
                if p['after'] != expected:
                    raise Blocked('Invalid link transition target')
            elif p['after']:
                a = p['after']; row = s['links'][a['link']]
                if a['generation'] != row['generation'] or a['value'] != row['current']:
                    raise Blocked('Invalid selection generation')
            self.validate_value(p['old']); self.validate_value(p['new'])
            self.validate_active(p['before']); self.validate_active(p['after'])

    @staticmethod
    def number(v):
        return type(v) in (int,float) and math.isfinite(v) and 0 <= v < 1e12

    def validate_value(self, v):
        if v is not None:
            try:
                parsed = parse_lease(self.cfg, dict(ip=v['ip'],subnet=v['prefix'].split('/')[1],router=v['gateway'],lease=v['seconds']))
                if parsed != v:
                    raise ValueError()
            except (KeyError,TypeError,ValueError,IndexError):
                raise Blocked('Invalid stored allocation') from None

    def validate_active(self, a):
        if a is not None:
            if not isinstance(a,dict) or set(a) != {'link','generation','value'} or a['link'] not in LINKS or type(a['generation']) is not int or a['generation'] < 0 or a['value'] is None:
                raise Blocked('Invalid active identity')
            self.validate_value(a['value'])

    def allowed(self,state=None):
        state=self.s if state is None else state
        values = {k:[state['links'][k]['current']] for k in LINKS}
        p = state['pending']
        if p:
            if p['link']:
                values[p['link']] += [p['old'],p['new']]
            for a in (p['before'],p['after']):
                if a:
                    values[a['link']].append(a['value'])
        return values

    def ready(self):
        if self.s['phase'] != 'READY':
            raise Blocked('Recovery required; writer retired')

    def snapshot(self):
        result = copy.deepcopy(self.s)
        for k in LINKS:
            result['links'][k].update(copy.deepcopy(self.health[k]))
        return result

    def mutate(self, pending, action, finish):
        self.s['pending'] = pending
        try:
            self.save()
            action()
            finish()
            self.s['pending'] = None
            self.s['revision'] += 1
            self.save()
        except BaseException:
            self.s['phase'] = 'RECOVERY_REQUIRED'
            try:
                self.save()
            except Exception:
                pass  # Disk may remain unavailable; this object is retired.
            raise

    def transition(self, k, value, expires):
        self.ready()
        row = self.s['links'][k]
        before = copy.deepcopy(self.s['active'])
        after = None if before and before['link'] == k else before
        self.health[k] = dict(state='UNVERIFIED' if value else 'WAITING',good=0,bad=0,round=-1,until=0.)
        p = dict(kind='link',link=k,old=row['current'],new=value,before=before,after=after)
        def finish():
            row.update(current=value,expires=expires,generation=row['generation']+1,revision=row['revision']+1)
            self.s['active'] = after
        self.mutate(p, lambda:self.backend.link(k,self.allowed(),value,after),finish)

    def wire_callback(self, link, session, boot, sequence, at, reason, lease=None,
                      request_at=None, observed_at=None, options=None):
        """Runtime entry: immutable intake authority and conservative wire origin.

        Unlike the historical exploration callback, processing never looks up a
        newer revision or starts a lease at hook time. Missing current-session
        wire evidence withdraws only that link; stale authority is read-only.
        """
        self.ready()
        if link not in LINKS:
            raise Blocked('Unknown link')
        row = self.s['links'][link]
        if session != row['session'] or boot != self.s['boot'] or type(sequence) is not int or sequence <= row['event_sequence'] or not self.number(at) or not row['last_event'] <= at <= self.clock():
            raise Blocked('Stale DHCP wire event')
        if reason not in ('bound','renew','deconfig','nak','leasefail') or (reason not in ('bound','renew') and lease is not None):
            raise Blocked('Invalid DHCP reason/payload')
        value, expires, rejected = None, 0., False
        if reason in ('bound','renew'):
            try:
                if options or not self.number(request_at) or not self.number(observed_at) or not request_at <= observed_at <= at:
                    raise ValueError('Missing or unsupported wire proof')
                value = parse_lease(self.cfg, lease)
                expires = request_at + value['seconds']
                if expires <= self.clock():
                    raise ValueError('Wire lease already expired')
                other = 'B' if link == 'A' else 'A'
                if any(v and ipaddress.IPv4Network(value['prefix']).overlaps(ipaddress.IPv4Network(v['prefix'])) for v in self.allowed()[other]):
                    raise ValueError('Cross-link lease conflict')
            except (ValueError,TypeError,KeyError,OverflowError):
                value, expires, rejected = None, 0., True
        row.update(event_sequence=sequence, last_event=at)
        self.transition(link, value, expires)
        self.tick()
        return dict(self.snapshot(), lease_rejected=rejected)

    def callback(self, link, session, boot, revision, at, reason, lease=None, options=None):
        """Historical exploration adapter; hook-time approximation, not runtime."""
        self.ready()
        if link not in LINKS:
            raise Blocked('Unknown link')
        row = self.s['links'][link]
        if session != row['session'] or boot != self.s['boot'] or type(revision) is not int or revision != row['revision'] or not self.number(at) or not row['last_event'] < at <= self.clock():
            raise Blocked('Stale DHCP event')
        if reason not in ('bound','renew','deconfig','nak','leasefail') or (reason not in ('bound','renew') and lease is not None):
            raise Blocked('Invalid DHCP reason/payload')
        value, expires, rejected = None, 0., False
        if reason in ('bound','renew'):
            try:
                if options:
                    raise ValueError('Unsupported supplied route options')
                value = parse_lease(self.cfg, lease)
                expires = at + value['seconds']
                if expires <= self.clock() or self.clock()-at > 3:
                    raise ValueError('Expired observation')
                other = 'B' if link == 'A' else 'A'
                if any(v and ipaddress.IPv4Network(value['prefix']).overlaps(ipaddress.IPv4Network(v['prefix'])) for v in self.allowed()[other]):
                    raise ValueError('Cross-link lease conflict')
            except (ValueError,TypeError,KeyError,OverflowError):
                value,expires,rejected = None,0.,True
        row['last_event'] = at
        self.transition(link,value,expires)
        # A valid mutation may consume enough time for another lease/proof to
        # expire. Process safety cleanup before admitting another callback.
        # Stale callbacks return above without any mutation or cleanup.
        self.tick()
        return dict(self.snapshot(),lease_rejected=rejected)

    def observation(self, link, generation, round_id, at, votes):
        self.ready()
        if link not in LINKS:
            raise Blocked('Unknown link')
        row,h = self.s['links'][link],self.health[link]
        if type(generation) is not int or generation != row['generation'] or type(round_id) is not int or round_id <= h['round'] or not self.number(at) or not at <= self.clock() < at+self.freshness or row['current'] is None or at < row['last_event'] or self.clock() >= row['expires']:
            raise Blocked('Stale health proof')
        if votes is not None and (type(votes) is not int or not 0 <= votes <= 3):
            raise Blocked('Invalid votes')
        h['round'] = round_id
        if votes is None:
            h.update(state='UNKNOWN',good=0,bad=0,until=0.)
        elif votes >= 2:
            active=self.s['active']
            # A fresh successful round repairs a SUSPECT selected path without
            # treating its already-qualified generation as a new acquisition.
            # Unselected/new/expired generations still need the full quorum.
            continuing=active is not None and active['link']==link and active['generation']==generation and h['state'] in ('HEALTHY','SUSPECT') and self.clock()<h['until']
            h.update(good=h['good']+1,bad=0,until=min(at+self.freshness,row['expires']))
            h['state'] = 'HEALTHY' if continuing or h['good'] >= self.successes else 'UNVERIFIED'
        else:
            h.update(good=0,bad=h['bad']+1)
            h['state'] = 'DOWN' if h['bad'] >= self.failures else 'SUSPECT'
        self.tick()
        return self.snapshot()

    def _select(self, active):
        self.ready()
        self.validate_active(active)
        if active:
            row = self.s['links'][active['link']]
            if active['generation'] != row['generation'] or active['value'] != row['current']:
                raise Blocked('Selection allocation is no longer current')
        before = copy.deepcopy(self.s['active'])
        p = dict(kind='select',link=None,old=None,new=None,before=before,after=active)
        # Withdrawal has no health-evidence deadline: slow ownership readback
        # must not turn already-expired evidence into permission to keep it.
        # Each underlying helper still has its bounded execution timeout.
        deadline = None
        if active:
            row = self.s['links'][active['link']]
            deadline = min(self.clock()+self.freshness,row['expires'],self.health[active['link']]['until'])
        def finish():
            self.s['active']=active
            if active:self.s['selection']=dict(link=active['link'],generation=active['generation'])
        self.mutate(p,lambda:self.backend.select(self.allowed(),active,deadline),finish)

    def tick(self):
        self.ready()
        for k in LINKS:
            row,h = self.s['links'][k],self.health[k]
            if row['current'] is not None and self.clock() >= row['expires']:
                self.transition(k,None,0.)
            elif h['until'] and self.clock() >= h['until']:
                h.update(state='UNKNOWN',good=0,bad=0,until=0.)
        a = self.s['active']
        if a:
            row,h = self.s['links'][a['link']],self.health[a['link']]
            if row['generation'] != a['generation'] or h['state'] not in ('HEALTHY','SUSPECT') or self.clock() >= h['until']:
                self._select(None)
        return self.snapshot()

    def choose(self, link, epoch, revision):
        self.ready()
        if type(epoch) is not int or type(revision) is not int or epoch != self.s['epoch'] or revision != self.s['revision']:
            raise Blocked('Stale selection')
        self.tick()
        if type(epoch) is not int or type(revision) is not int or epoch != self.s['epoch'] or revision != self.s['revision']:
            raise Blocked('Selection invalidated by safety cleanup')
        if self.s['paused'] or self.s['latched'] or link not in LINKS or self.health[link]['state'] != 'HEALTHY':
            raise Blocked('Selection not permitted')
        row = self.s['links'][link]
        active = dict(link=link,generation=row['generation'],value=copy.deepcopy(row['current']))
        if active == self.s['active']:
            return self.snapshot()
        # Across a different boot, conservatively retain history: monotonic
        # timestamps cannot safely be aged using this boot's clock.
        self.s['history'] = [h for h in self.s['history'] if h['boot'] != self.s['boot'] or self.clock()-h['at'] < self.window]
        if len(self.s['history']) >= self.budget:
            self.s['latched'] = True
            self.s['revision'] += 1
            self.save()
            raise Blocked('Switch budget exhausted')
        self.s['history'].append(dict(boot=self.s['boot'],at=self.clock()))
        self._select(active)
        # A delayed backend return cannot certify a now-expired allocation.
        self.tick()
        return self.snapshot()

    def restore(self, link, epoch, revision):
        """One new lease generation on the previously chosen WAN, never failover."""
        self.ready()
        if type(epoch) is not int or type(revision) is not int or epoch!=self.s['epoch'] or revision!=self.s['revision']:
            raise Blocked('Stale restoration')
        self.tick()
        if epoch!=self.s['epoch'] or revision!=self.s['revision']:
            raise Blocked('Restoration invalidated by cleanup')
        a=self.s['selection']
        if self.s['paused'] or self.s['latched'] or self.s['active'] is not None or a is None or link!=a['link']:
            raise Blocked('Restoration not armed for this WAN')
        row=self.s['links'][link]
        if row['generation']<=a['generation'] or row['current'] is None or self.health[link]['state']!='HEALTHY':
            raise Blocked('Fresh lease and health required')
        self._select(dict(link=link,generation=row['generation'],value=copy.deepcopy(row['current'])))
        self.tick()
        return self.snapshot()

    def restart_client(self, link):
        self.ready()
        if link not in LINKS:
            raise Blocked('Unknown link')
        self.transition(link,None,0.)
        self.s['links'][link].update(session=secrets.token_hex(24),event_sequence=0,last_event=0.)
        self.save()
        return self.snapshot()

    def pause(self, paused=True):
        self.ready()
        if type(paused) is not bool:
            raise ValueError('Boolean required')
        self.s['paused'] = paused
        self.s['revision'] += 1
        self.save()
        return self.tick()

    def token(self,q):
        self.ready()
        if any(type(q[n]) is not int or q[n]!=self.s[n] for n in ('epoch','revision')):
            raise Blocked('Stale operation token')

    def healthy(self,k):
        if k not in LINKS:return False
        r,h=self.s['links'][k],self.health[k]
        return r['current'] is not None and h['state']=='HEALTHY' and self.clock()<min(r['expires'],h['until'])

    def control_save(self):
        try:self.save()
        except BaseException:
            self.s['phase']='RECOVERY_REQUIRED'
            raise

    def repause(self):
        self.s['paused']=True;self.s['revision']+=1
        self.s['operations'][-1].update(outcome='REPAUSED',revision=self.s['revision'])
        self.control_save()

    def operator(self,q,link=None):
        op=q['op'];fields={'op','epoch','revision','id'}|({'ack'} if op=='reset-budget' else set())
        if op not in ('pause','resume','reset-budget') or set(q)!=fields or not isinstance(q['id'],str) or not re.fullmatch('[0-9a-f]{32}',q['id']):raise ValueError('Invalid operator envelope')
        self.token(q);self.tick();self.token(q)
        if any(v['id']==q['id'] for v in self.s['operations']):raise Blocked('Operation already recorded; inspect status')
        if op=='reset-budget':
            if not self.s['paused'] or q['ack']!='reset-switch-budget':raise Blocked('Pause and explicit budget acknowledgement required')
            self.s.update(history=[],latched=False)
        elif op=='resume':
            if not self.s['paused'] or self.s['latched'] or not self.healthy(link):raise Blocked('Paused, unlatched fresh lease/health required')
            self.s['paused']=False
        else:self.s['paused']=True
        self.s['revision']+=1
        self.s['operations']=(self.s['operations']+[dict(id=q['id'],kind=op,uid=0,at=self.clock(),boot=self.boot(),epoch=self.s['epoch'],revision=self.s['revision'],outcome='APPLIED')])[-32:]
        self.control_save();self.tick()
        if op=='resume' and not self.healthy(link):
            self.repause();raise Blocked('Resume evidence expired; remains paused')
        return self.snapshot()
