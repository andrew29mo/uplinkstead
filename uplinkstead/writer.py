"""Durable intent + serialized actual mutation; not an atomic DB/kernel transaction."""
import fcntl
import json
import math
import os
from pathlib import Path
import sqlite3
import stat
import time
import uuid
from .linux import Linux, Blocked


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def now():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


class Writer:
    def __init__(self, config, directory):
        self.c, self.directory = config, Path(directory)
        self.fd = self.db = None

    def __enter__(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = self.directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Blocked('State directory must be private and owned')
        self.fd = os.open(self.directory/'writer.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(self.fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise Blocked('Unsafe lock inode')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.directory/'journal.sqlite'
            if path.is_symlink():
                raise Blocked('Unsafe journal')
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)')
            self.db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, value TEXT NOT NULL)')
            row = self.db.execute('SELECT value FROM state WHERE id=1').fetchone()
            self.backend = Linux(self.c, self.fd)
            if row is None:
                self.backend.preflight(fresh=True)
                self.s = dict(config_hash=self.c['_hash'], epoch=0, selected=None, pending=None,
                              boot=boot_id(), history=[], latched=False, provisioning=True)
                self.save()
            else:
                self.s = json.loads(row[0])
                self.validate()
            self.backend.preflight(partial=self.s['provisioning'] or self.s['boot'] != boot_id())
            self.s['epoch'] += 1
            self.save()
            self.reconcile()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def validate(self):
        keys = {'config_hash','epoch','selected','pending','boot','history','latched','provisioning'}
        s = self.s
        if set(s) != keys or s['config_hash'] != self.c['_hash'] or type(s['epoch']) is not int or s['epoch'] < 0:
            raise Blocked('Invalid journal/config')
        if s['selected'] not in (None, 'A', 'B') or type(s['latched']) is not bool or type(s['provisioning']) is not bool:
            raise Blocked('Invalid journal fields')
        if not isinstance(s['boot'],str) or not s['boot'] or not isinstance(s['history'],list):
            raise Blocked('Invalid history')
        for e in s['history']:
            if set(e) != {'boot','at'} or not isinstance(e['boot'],str) or type(e['at']) not in (int,float) or not 0 <= e['at'] < 1e12:
                raise Blocked('Invalid budget event')
        p = s['pending']
        if p is not None and (not isinstance(p,dict) or set(p) != {'token','target','before'} or
                              not isinstance(p['token'],str) or p['target'] not in ('A','B') or p['before'] not in (None,'A','B')):
            raise Blocked('Invalid pending operation')

    def save(self):
        self.db.execute('INSERT INTO state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value',
                        (json.dumps(self.s, sort_keys=True, allow_nan=False),))

    def event(self, name, **fields):
        self.db.execute('INSERT INTO events(value) VALUES(?)',
                        (json.dumps(dict(name=name, boot=boot_id(), at=now(), **fields), allow_nan=False),))

    def reconcile(self):
        changed_boot = self.s['boot'] != boot_id()
        if self.s['provisioning'] or changed_boot:
            self.backend.layout()
            target = self.s['pending']['target'] if self.s['pending'] else self.s['selected']
            if target is not None:
                self.backend.select(target)
            self.s['provisioning'] = False
        self.backend.preflight()
        actual = self.backend.selected()
        p = self.s['pending']
        if p:
            if actual == p['target']:
                self.s['selected'], self.s['pending'] = actual, None
            elif actual == p['before']:
                # Do not replay a stale health decision; keep the actual old route.
                self.s['selected'], self.s['pending'] = actual, None
            else:
                raise Blocked('Pending outcome differs from before and intended route')
        elif actual != self.s['selected']:
            if actual is None and self.s['selected'] is not None and not self.backend.link_up(self.s['selected']):
                self.event('link_removed_route', previous=self.s['selected'])
                self.s['selected'] = None
            else:
                raise Blocked('Unexpected route drift')
        self.backend.refresh_probes()
        self.s['boot'] = boot_id()
        self.save()
        self.event('reconciled', selected=actual, changed_boot=changed_boot)

    def check_proof(self, proof, target, epoch):
        if (not isinstance(proof,dict) or set(proof) != {'config_hash','boot','target','round','observed_at','expires_at'} or
                proof['config_hash'] != self.c['_hash'] or proof['boot'] != boot_id() or
                proof['target'] != target or epoch != self.s['epoch'] or
                type(proof['round']) is not int or proof['round'] < 0):
            raise Blocked('Invalid automatic health proof')
        for key in ('observed_at','expires_at'):
            if type(proof[key]) not in (float,int) or not math.isfinite(proof[key]):
                raise Blocked('Invalid proof timestamp')
        instant=now()
        if not 0 <= proof['observed_at'] <= instant <= proof['expires_at']:
            raise Blocked('Automatic health proof expired')

    def switch(self, epoch, target, admission=None, proof=None):
        if epoch != self.s['epoch'] or target not in ('A','B') or self.s['pending']:
            raise Blocked('Stale or concurrent operation')
        if admission is not None:
            self.check_proof(proof,target,epoch)
        self.backend.preflight()
        if self.backend.selected() != self.s['selected']:
            raise Blocked('Route drift before mutation')
        if admission is not None:
            self.check_proof(proof,target,epoch)
        p = dict(token=uuid.uuid4().hex, target=target, before=self.s['selected'])
        self.s['pending'] = p
        if admission:
            self.s['history'].append(admission)
        self.save()
        self.event('intent', target=target, token=p['token'])
        if admission is None:
            self.backend.select(target)
        else:
            self.backend.select(target,guard=lambda:self.check_proof(proof,target,epoch),deadline=proof['expires_at'])
        if self.backend.selected() != target:
            raise Blocked('Selection readback mismatch')
        self.s['selected'], self.s['pending'] = target, None
        self.save()
        self.event('completed', target=target, token=p['token'])

    def __exit__(self, *_):
        if self.db:
            self.db.close()
            self.db = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
