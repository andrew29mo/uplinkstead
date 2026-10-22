"""Scoped Linux backend for the dual-DHCP exploration core.

Dedicated namespaces/interfaces only. No main routes, sysctls, NAT, foreign
tables or DHCP-client configuration are rewritten. This is not a service unit.
"""
import json
from pathlib import Path

from .linux import Linux, Blocked
from .probe import MARK

TABLE = {'A': 41201, 'B': 41202, 'LAN': 41203}


class Backend(Linux):
    def expected(self):
        rows = []
        for i, link in enumerate(('A', 'B')):
            iface = self.c['links'][link]['interface']
            for offset, base in ((0, dict(src='all', iif='lo', fwmark=hex(MARK[link]))),
                                 (4, dict(src='all', oif=iface))):
                priority = 10300 + i*10 + offset
                rows += [dict(base, priority=priority, table=TABLE[link]),
                         dict(base, priority=priority+1, action='prohibit')]
        base = dict(src=self.c['lan']['prefix'], iif=self.c['lan']['interface'])
        rows += [dict(base, priority=10330, dst=self.c['lan']['prefix'], table='main', suppress_prefixlength=0),
                 dict(base, priority=10331, dst=self.c['lan']['prefix'], action='prohibit'),
                 dict(base, priority=10340, table=TABLE['LAN']),
                 dict(base, priority=10341, action='prohibit')]
        return rows

    def rule_command(self, r):
        if 'oif' not in r:
            return super().rule_command(r)
        cmd = ['rule', 'add', 'priority', r['priority'], 'from', r['src'], 'oif', r['oif']]
        return cmd + (['lookup', r['table']] if 'table' in r else [r['action']])

    def check(self, allowed, complete=True):
        expected = self.expected()
        builtins = [dict(priority=0, src='all', table='local'),
                    dict(priority=32766, src='all', table='main'),
                    dict(priority=32767, src='all', table='default')]
        rows = [self.normalized(r) for r in self.rules()]
        if (any(r not in expected+builtins for r in rows) or
                any(rows.count(r) != 1 for r in builtins) or
                any(rows.count(r) > 1 for r in expected) or
                (complete and any(r not in rows for r in expected))):
            raise Blocked('Unknown/missing/duplicate dual DHCP RPDB rule')
        for link in ('A', 'B'):
            iface = self.c['links'][link]['interface']
            values = [v for v in allowed[link] if v]
            addresses = json.loads(self.run(['-j', '-4', 'addr', 'show', 'dev', iface]))
            valid = {v['address'] for v in values}
            if any(str(a['local'])+'/'+str(a['prefixlen']) not in valid
                   for row in addresses for a in row['addr_info']):
                raise Blocked('Foreign IPv4 address on dedicated DHCP interface')
            self._routes_allowed(TABLE[link], [(iface, v) for v in values])
        self._routes_allowed(TABLE['LAN'], [(self.c['links'][k]['interface'], v)
                                             for k in ('A', 'B') for v in allowed[k] if v])
        if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
            raise Blocked('Forwarding must be provisioned')
        all_filter = int(Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text())
        for v in self.c['links'].values():
            if max(all_filter, int(Path('/proc/sys/net/ipv4/conf', v['interface'], 'rp_filter').read_text())) == 1:
                raise Blocked('Strict reverse-path filtering is unsupported')

    def _routes_allowed(self, table, values):
        for r in self.routes(table):
            if (r.get('type', 'unicast') != 'unicast' or set(r)-
                    {'dst', 'gateway', 'dev', 'metric', 'scope', 'flags', 'protocol', 'prefsrc', 'type'} or
                    not any(r.get('dev') == iface and
                            ((r.get('dst') == v['prefix'] and r.get('scope') == 'link') or
                             (r.get('dst') == 'default' and r.get('gateway') == v['gateway'] and r.get('metric') == 100))
                            for iface, v in values)):
                raise Blocked('Foreign dual DHCP table route')

    def _guards(self):
        existing = [self.normalized(r) for r in self.rules()]
        for r in sorted(self.expected(), key=lambda r: 'table' in r):
            if r not in existing:
                self.run(self.rule_command(r))

    def _allocation(self, link, allowed, new):
        iface = self.c['links'][link]['interface']
        self.run(['route', 'flush', 'table', TABLE[link]], absent=True)
        rows = json.loads(self.run(['-j', '-4', 'addr', 'show', 'dev', iface]))
        present = {str(a['local'])+'/'+str(a['prefixlen']) for row in rows for a in row['addr_info']}
        for address in sorted({v['address'] for v in allowed if v} & present):
            self.run(['addr', 'del', address, 'dev', iface])
        if new:
            self.run(['addr', 'replace', new['address'], 'dev', iface, 'noprefixroute'])
            self.run(['route', 'replace', new['prefix'], 'dev', iface, 'scope', 'link', 'table', TABLE[link]])
            self.run(['route', 'replace', 'default', 'via', new['gateway'], 'dev', iface,
                      'table', TABLE[link], 'metric', 100])
        rows = json.loads(self.run(['-j', '-4', 'addr', 'show', 'dev', iface]))
        actual = [str(a['local'])+'/'+str(a['prefixlen']) for row in rows for a in row['addr_info']]
        if sorted(actual) != ([] if new is None else [new['address']]):
            raise Blocked('Allocation address postcondition failed')
        self._verify_table(TABLE[link], iface, new)

    def _verify_table(self, table, iface, value):
        rows = self.routes(table)
        if value is None:
            if rows: raise Blocked('Withdrawn route table is not empty')
            return
        connected = [r for r in rows if r.get('dst') == value['prefix'] and r.get('dev') == iface and
                     r.get('scope') == 'link' and r.get('type', 'unicast') == 'unicast' and 'gateway' not in r]
        default = [r for r in rows if r.get('dst') == 'default' and r.get('dev') == iface and
                   r.get('gateway') == value['gateway'] and r.get('metric') == 100 and r.get('type', 'unicast') == 'unicast']
        if len(rows) != 2 or len(connected) != 1 or len(default) != 1:
            raise Blocked('Expected complete route table was not read back')

    def _active(self, active, deadline=None):
        self.run(['route', 'flush', 'table', TABLE['LAN']], absent=True, deadline=deadline)
        if active:
            iface = self.c['links'][active['link']]['interface']
            value = active['value']
            self.run(['route', 'replace', value['prefix'], 'dev', iface, 'scope', 'link',
                      'table', TABLE['LAN']], deadline=deadline)
            self.run(['route', 'replace', 'default', 'via', value['gateway'], 'dev', iface,
                      'table', TABLE['LAN'], 'metric', 100], deadline=deadline)
        self._verify_table(TABLE['LAN'], self.c['links'][active['link']]['interface'] if active else None,
                           active['value'] if active else None)

    def reconcile(self, allowed_by_link, new_by_link, active):
        self.check(allowed_by_link, complete=False)
        self._guards()
        self._active(None)
        for link in ('A', 'B'):
            self._allocation(link, allowed_by_link[link], new_by_link[link])
        self._active(active)
        self.check({k: [v] for k, v in new_by_link.items()})

    def link(self, link, allowed_by_link, new, active):
        self.check(allowed_by_link)
        # Updating inactive B must not flush/recreate the global A route.
        if active is None or active['link'] == link:
            self._active(None)
        self._allocation(link, allowed_by_link[link], new)
        if active is not None and active['link'] == link:
            self._active(active)
        after = dict(allowed_by_link, **{link: [new]})
        self.check(after)

    def select(self, allowed_by_link, active, deadline):
        self.check(allowed_by_link)
        if active and active['value'] not in allowed_by_link[active['link']]:
            raise Blocked('Selected allocation is not admitted')
        self._active(active, deadline)
        self.check(allowed_by_link)
