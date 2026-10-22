"""Single DHCP uplink lifecycle. Not part of the static dual-uplink controller.

One root writer, an inherited process lock, journal-before-network mutation and
session/boot/monotonic event fencing. DHCP options never become command strings.
"""
import copy
import ipaddress
import json
import math
import re
import secrets
from pathlib import Path

from .linux import Linux, Blocked
from .writer import Writer, boot_id, now
from .probe import round as probe_round

PROBE_TABLE = 41101
DATA_TABLE = 41103


def config(path):
    if Path(path).stat().st_size > 16384:
        raise ValueError('DHCP config too large')
    c = json.loads(Path(path).read_text())
    if set(c) != {'interface', 'lan', 'targets', 'ca', 'server_name'}:
        raise ValueError('Unexpected DHCP config keys')
    if set(c['lan']) != {'interface', 'prefix'}:
        raise ValueError('Unexpected LAN keys')
    names = [c['interface'], c['lan']['interface']]
    if names[0] == names[1] or any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', s) or s == 'lo' for s in names):
        raise ValueError('Distinct dedicated interfaces required')
    lan = ipaddress.IPv4Network(c['lan']['prefix'])
    if lan.prefixlen == 0:
        raise ValueError('LAN cannot claim every source')
    if len(c['targets']) != 3 or len({(t['ip'], t['port']) for t in c['targets']}) != 3:
        raise ValueError('Three distinct targets required')
    for t in c['targets']:
        if set(t) != {'ip', 'port'} or type(t['port']) is not int or not 1 <= t['port'] <= 65535:
            raise ValueError('Invalid target')
        a = ipaddress.IPv4Address(t['ip'])
        if a in lan or a.is_unspecified or a.is_loopback or a.is_multicast or a.is_link_local:
            raise ValueError('TLS targets must be unicast beyond LAN')
    return c


def lease(c, data):
    if set(data) != {'ip', 'subnet', 'router', 'lease'}:
        raise ValueError('Unexpected lease keys')
    seconds = int(data['lease'])
    if str(seconds) != str(data['lease']) or not 1 <= seconds <= 86400:
        raise ValueError('Lease lifetime must be 1..86400 seconds')
    # Reject multiple gateways, off-link gateways, host/network/broadcast values,
    # overlap with LAN and targets, and non-unicast allocations.
    address = ipaddress.IPv4Address(data['ip'])
    gateway = ipaddress.IPv4Address(data['router'])
    network = ipaddress.IPv4Network(str(address) + '/' + data['subnet'], strict=False)
    if (network.prefixlen > 30 or network.overlaps(ipaddress.IPv4Network(c['lan']['prefix'])) or
            address == gateway or any(a not in network or a in (network.network_address, network.broadcast_address)
            or a.is_multicast or a.is_unspecified or a.is_loopback or a.is_link_local for a in (address, gateway)) or
            any(ipaddress.IPv4Address(t['ip']) in network for t in c['targets'])):
        raise ValueError('Unsupported lease topology')
    return dict(ip=str(address), gateway=str(gateway), prefix=str(network),
                address=str(address) + '/' + str(network.prefixlen), seconds=seconds)


class Backend(Linux):
    """Owns only two reserved tables, four rules and its DHCP address."""
    def expected(self):
        return [dict(priority=10206, src=self.c['lan']['prefix'], iif=self.c['lan']['interface'], dst=self.c['lan']['prefix'], table='main', suppress_prefixlength=0),
                dict(priority=10207, src=self.c['lan']['prefix'], iif=self.c['lan']['interface'], dst=self.c['lan']['prefix'], action='prohibit'),
                dict(priority=10210, src='all', iif='lo', fwmark='0x5101', table=PROBE_TABLE),
                dict(priority=10211, src='all', iif='lo', fwmark='0x5101', action='prohibit'),
                dict(priority=10212, src=self.c['lan']['prefix'], iif=self.c['lan']['interface'], table=DATA_TABLE),
                dict(priority=10213, src=self.c['lan']['prefix'], iif=self.c['lan']['interface'], action='prohibit')]

    def check(self, allowed):
        expected = self.expected()
        builtins = [dict(priority=0, src='all', table='local'),
                    dict(priority=32766, src='all', table='main'),
                    dict(priority=32767, src='all', table='default')]
        rows = [self.normalized(r) for r in self.rules()]
        if any(r not in expected + builtins for r in rows) or any(rows.count(r) != 1 for r in builtins):
            raise Blocked('Unsupported RPDB rules; no coexistence claim')
        if any(rows.count(r) > 1 for r in expected):
            raise Blocked('Duplicate owned rules')
        addrs = json.loads(self.run(['-j', '-4', 'addr', 'show', 'dev', self.c['interface']]))
        allowed_addr = {v['address'] for v in allowed if v}
        if len(addrs) > 1 or any(str(a['local'])+'/'+str(a['prefixlen']) not in allowed_addr
                                 for row in addrs for a in row['addr_info']):
            raise Blocked('Dedicated interface contains foreign IPv4 address')
        for table in (PROBE_TABLE, DATA_TABLE):
            for r in self.routes(table):
                if (r.get('type', 'unicast') != 'unicast' or set(r) -
                        {'dst', 'gateway', 'dev', 'metric', 'scope', 'flags', 'protocol', 'prefsrc', 'type'} or
                        not any(r.get('dev') == self.c['interface'] and
                        ((r.get('dst') == v['prefix'] and r.get('scope') == 'link') or
                         (r.get('dst') == 'default' and r.get('gateway') == v['gateway'] and r.get('metric') == 100))
                        for v in allowed if v)):
                    raise Blocked('Foreign reserved-table route')

    def reconcile(self, old, new):
        self.reconcile_many([old, new], new)

    def reconcile_many(self, allowed, new):
        self.check(allowed)
        existing = [self.normalized(r) for r in self.rules()]
        # Terminal guards precede lookup rules and every destructive operation.
        for r in sorted(self.expected(), key=lambda r: 'table' in r):
            if r not in existing:
                self.run(self.rule_command(r))
        for table in (DATA_TABLE, PROBE_TABLE):
            self.run(['route', 'flush', 'table', table], absent=True)
        rows = json.loads(self.run(['-j', '-4', 'addr', 'show', 'dev', self.c['interface']]))
        present = {str(a['local'])+'/'+str(a['prefixlen']) for row in rows for a in row['addr_info']}
        for address in sorted({v['address'] for v in allowed if v} & present):
            self.run(['addr', 'del', address, 'dev', self.c['interface']])
        if new:
            self.run(['addr', 'replace', new['address'], 'dev', self.c['interface'], 'noprefixroute'])
            self.run(['route', 'replace', new['prefix'], 'dev', self.c['interface'], 'scope', 'link', 'table', PROBE_TABLE])
            self.run(['route', 'replace', 'default', 'via', new['gateway'], 'dev', self.c['interface'], 'table', PROBE_TABLE, 'metric', 100])

    def activate(self, value, deadline):
        self.check([value])
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
            raise Blocked('Forwarding must be provisioned')
        self.run(['route', 'replace', value['prefix'], 'dev', self.c['interface'], 'scope', 'link', 'table', DATA_TABLE], deadline=deadline)
        self.run(['route', 'replace', 'default', 'via', value['gateway'], 'dev', self.c['interface'], 'table', DATA_TABLE, 'metric', 100], deadline=deadline)

    def withdraw(self, value):
        self.check([value])
        self.run(['route', 'flush', 'table', DATA_TABLE], absent=True)


class Lifecycle(Writer):
    """Uses Writer's private SQLite storage, FULL sync and inherited exclusive lock."""
    def __init__(self, c, directory):
        import hashlib
        self.cfg = c
        super().__init__({'_hash': hashlib.sha256(json.dumps(c, sort_keys=True).encode()).hexdigest()}, directory)

    def __enter__(self):
        # Writer's storage helper is reused, not its static routing lifecycle.
        import os, stat, fcntl, sqlite3
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        st = self.directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Blocked('Private owned state directory required')
        try:
            self.fd = os.open(self.directory/'writer.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            st = os.fstat(self.fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise Blocked('Unsafe lock')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.directory/'journal.sqlite'
            if path.is_symlink():
                raise Blocked('Unsafe journal')
            self.db = sqlite3.connect(path, isolation_level=None)
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA journal_mode=DELETE')
            if self.db.execute('PRAGMA page_size').fetchone()[0] != 4096 or self.db.execute('PRAGMA max_page_count=2048').fetchone()[0] != 2048:
                raise Blocked('Journal capacity/layout unsupported')
            self.db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL)')
            row = self.db.execute('SELECT value FROM state WHERE id=1').fetchone()
            self.s = json.loads(row[0]) if row else dict(config_hash=self.c['_hash'], history=[], boot=boot_id(),
                session=None, revision=0, last_event=0, current=None, intent=None, expires=0)
            self.validate()
            self.backend = Backend(self.cfg, self.fd)
            # Recovery quarantines both sides of an incomplete intent. Never
            # briefly reapply a pre-restart lease or reuse persisted health.
            allowed = [self.s['current']]
            if self.s['intent']:
                allowed += list(self.s['intent'].values())
            self.backend.reconcile_many(allowed, None)
            self.s.update(current=None, intent=None, expires=0, revision=self.s['revision']+1)
            self.s.update(boot=boot_id(), session=secrets.token_hex(24), last_event=0)
            self.save()
            self.healthy = False
            self.streak = 0
            return self
        except BaseException:
            self.__exit__()
            raise

    def validate(self):
        s = self.s
        if (set(s) != {'config_hash', 'history', 'boot', 'session', 'revision', 'last_event', 'current', 'intent', 'expires'} or
                s['config_hash'] != self.c['_hash'] or s['history'] != [] or
                not isinstance(s['boot'], str) or type(s['revision']) is not int or s['revision'] < 0 or
                (s['session'] is not None and not re.fullmatch('[0-9a-f]{48}', s['session']))):
            raise Blocked('Invalid DHCP journal')
        for k in ('expires', 'last_event'):
            if type(s[k]) not in (int, float) or not math.isfinite(s[k]) or s[k] < 0:
                raise Blocked('Invalid journal time')
        values = [s['current']]
        if s['intent'] is not None:
            if not isinstance(s['intent'], dict) or set(s['intent']) != {'old', 'new'}:
                raise Blocked('Invalid lease intent')
            values += list(s['intent'].values())
        for v in values:
            if v is not None:
                parsed = lease(self.cfg, dict(ip=v['ip'], router=v['gateway'], subnet=v['prefix'].split('/')[1], lease=v['seconds']))
                if v != parsed:
                    raise Blocked('Invalid journal lease')

    def transition(self, new, expires):
        old = self.s['current']
        self.healthy = False
        self.streak = 0
        self.s.update(intent=dict(old=old, new=new), expires=expires, revision=self.s['revision']+1)
        self.save()  # Intent precedes all network changes; failures retire service.
        self.backend.reconcile(old, new)
        self.s.update(current=new, intent=None)
        self.save()

    def snapshot(self):
        return dict(session=self.s['session'], revision=self.s['revision'], boot=self.s['boot'],
                    current=copy.deepcopy(self.s['current']), expires=self.s['expires'], healthy=self.healthy)

    def event(self, q):
        if set(q) != {'session', 'boot', 'revision', 'at', 'reason', 'lease'}:
            raise Blocked('Unexpected DHCP event')
        instant = now()
        if (q['session'] != self.s['session'] or q['boot'] != boot_id() or
                type(q['revision']) is not int or q['revision'] != self.s['revision'] or
                type(q['at']) not in (int, float) or not math.isfinite(q['at']) or
                not self.s['last_event'] < q['at'] <= instant or instant-q['at'] > 3):
            raise Blocked('Stale DHCP event')
        if q['reason'] in ('bound', 'renew'):
            value = lease(self.cfg, q['lease'])
            expires = q['at']+value['seconds']
            if expires <= instant:
                raise Blocked('Lease already expired')
        elif q['reason'] in ('deconfig', 'nak', 'leasefail') and q['lease'] is None:
            value, expires = None, 0
        else:
            raise Blocked('Unsupported DHCP reason')
        self.s['last_event'] = q['at']
        self.transition(value, expires)
        return self.snapshot()

    def tick(self):
        value = self.s['current']
        if value is None:
            return dict(healthy=False, votes=None)
        if self.s['expires'] <= now():
            self.transition(None, 0)
            return dict(healthy=False, votes=None)
        c = dict(links={'A': dict(interface=self.cfg['interface'], source=value['ip'])},
                 targets=self.cfg['targets'], ca=self.cfg['ca'], server_name=self.cfg['server_name'])
        votes, rows = probe_round(c, 'A')
        if self.s['expires'] <= now():
            self.transition(None, 0)
        elif votes is not None and votes >= 2:
            self.streak += 1
            if self.streak >= 2:
                self.backend.activate(value, min(self.s['expires'], now()+1))
                if self.s['expires'] <= now():
                    self.transition(None, 0)
                else:
                    self.healthy = True
        else:
            self.streak = 0
            self.healthy = False
            self.backend.withdraw(value)
        return dict(healthy=self.healthy, votes=votes, results=rows)
