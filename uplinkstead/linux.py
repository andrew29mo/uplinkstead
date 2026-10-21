"""iproute2 backend. Mutation subprocesses inherit the writer's flock descriptor."""
import ipaddress
import json
import os
import subprocess
from .probe import MARK

TABLE = {'A': 41001, 'B': 41002, 'LAN': 41003}


class Blocked(RuntimeError):
    pass


class Linux:
    def __init__(self, config, lock_fd=None):
        self.c = config
        self.fd = lock_fd

    def run(self, args, absent=False):
        p = subprocess.Popen(['/usr/sbin/ip', *map(str, args)], text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             pass_fds=() if self.fd is None else (self.fd,))
        try:
            out, err = p.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()  # Never relinquish writer ownership with a live helper.
            raise Blocked('ip timeout; outcome requires readback')
        if p.returncode:
            if absent and 'FIB table does not exist' in err:
                return '[]'
            raise Blocked('ip command failed')
        return out

    def rules(self):
        return json.loads(self.run(['-j', 'rule', 'show']))

    def routes(self, table):
        return json.loads(self.run(['-j', 'route', 'show', 'table', table], absent=True))

    def expected(self):
        rows = []
        for i, link in enumerate(('A', 'B')):
            base = {'src': 'all', 'iif': 'lo', 'fwmark': hex(MARK[link])}
            rows.extend([dict(base, priority=10010+i*2, table=TABLE[link]),
                         dict(base, priority=10011+i*2, action='prohibit')])
        # Internal prefixes consult only non-default main routes; lookup miss is
        # terminal and cannot enter the active WAN table or main's default.
        excluded = sorted({self.c['lan']['prefix'], *(v['prefix'] for v in self.c['links'].values()),
                           *self.c['lan'].get('exclude', [])})
        for i, prefix in enumerate(excluded):
            base = {'src': self.c['lan']['prefix'], 'iif': self.c['lan']['interface'], 'dst': prefix}
            rows.extend([dict(base, priority=10030+2*i, table='main', suppress_prefixlength=0),
                         dict(base, priority=10031+2*i, action='prohibit')])
        base = {'src': self.c['lan']['prefix'], 'iif': self.c['lan']['interface']}
        rows.extend([dict(base, priority=10100, table=TABLE['LAN']), dict(base, priority=10101, action='prohibit')])
        return rows

    @staticmethod
    def normalized(r):
        value = {k: v for k, v in r.items() if k not in ('protocol',)}
        for key in ('src','dst'):
            length = value.pop(key+'len', None)
            if length is not None:
                value[key] = str(ipaddress.IPv4Network(str(value[key])+'/'+str(length),strict=True))
        if str(value.get('table','')).isdigit():
            value['table'] = int(value['table'])
        if 'suppress_prefixlen' in value:
            value['suppress_prefixlength'] = value.pop('suppress_prefixlen')
        return value

    def rule_command(self, r):
        cmd = ['rule', 'add', 'priority', r['priority'], 'from', r['src'], 'iif', r['iif']]
        if 'fwmark' in r:
            cmd += ['fwmark', r['fwmark']]
        if 'dst' in r:
            cmd += ['to', r['dst']]
        if 'table' in r:
            cmd += ['lookup', r['table']]
            if 'suppress_prefixlength' in r:
                cmd += ['suppress_prefixlength', r['suppress_prefixlength']]
        else:
            cmd += [r['action']]
        return cmd

    def preflight(self, fresh=False, partial=False):
        if self.c['lan']['interface'] == 'lo':
            raise Blocked('Loopback LAN unsupported')
        for v in self.c['links'].values():
            rows = json.loads(self.run(['-j', 'addr', 'show', 'dev', v['interface']]))
            if len(rows) != 1 or v['source'] not in [a.get('local') for a in rows[0]['addr_info']]:
                raise Blocked('Configured source absent')
        expected = {r['priority']: r for r in self.expected()}
        seen = set()
        builtins = [{'priority': 0, 'src': 'all', 'table': 'local'},
                    {'priority': 32766, 'src': 'all', 'table': 'main'},
                    {'priority': 32767, 'src': 'all', 'table': 'default'}]
        for raw in self.rules():
            r = self.normalized(raw)
            if r in builtins:
                continue
            if r.get('priority') in expected and r == expected[r['priority']]:
                if fresh or r['priority'] in seen:
                    raise Blocked('Preexisting/duplicate owned rule')
                seen.add(r['priority'])
                continue
            # Only a plainly disjoint ingress selector is admitted. Generic
            # source/fwmark/goto/VRF rules cannot be proven disjoint here.
            if r.get('iif') and r['iif'] not in ('lo', self.c['lan']['interface']) and r.get('priority', 0) > 0:
                continue
            raise Blocked('Unsupported/intersecting RPDB rule: '+repr(r))
        if not fresh and not partial and seen != set(expected):
            raise Blocked('Owned policy rule missing: '+repr(sorted(set(expected)-seen)))
        for key, table in TABLE.items():
            rows = self.routes(table)
            if fresh and rows:
                raise Blocked('Reserved table already occupied')
            for r in rows:
                dst = r.get('dst')
                if dst == 'default':
                    allowed = ('A', 'B') if key == 'LAN' else (key,)
                    if r.get('metric') != 100 or not any(
                            r.get('gateway') == self.c['links'][k]['gateway'] and
                            r.get('dev') == self.c['links'][k]['interface'] for k in allowed):
                        raise Blocked('Unrecognized default route')
                elif not any(dst == v['prefix'] and r.get('dev') == v['interface'] for v in self.c['links'].values()):
                    raise Blocked('Unrecognized owned-table route: '+repr(r))
                if r.get('type', 'unicast') != 'unicast' or any(k in r for k in ('nexthops', 'encap', 'nhid')):
                    raise Blocked('Unsupported route object')
        # Deployment contract: this backend reads but never rewrites sysctls/NAT.
        if open('/proc/sys/net/ipv4/ip_forward').read().strip() != '1':
            raise Blocked('Forwarding must be provisioned')
        all_filter = int(open('/proc/sys/net/ipv4/conf/all/rp_filter').read())
        for iface in [v['interface'] for v in self.c['links'].values()]:
            effective = max(all_filter, int(open('/proc/sys/net/ipv4/conf/'+iface+'/rp_filter').read()))
            if effective == 1:
                raise Blocked('Strict rp_filter unsupported in this MVP topology')

    def layout(self):
        # Record ownership intent before calling this method. All terminal guards
        # go in first, then routes, then lookup rules. Restart is idempotent.
        existing = {r['priority']: r for r in self.rules()}
        for r in self.expected():
            if r.get('action') == 'prohibit' and r['priority'] not in existing:
                self.run(self.rule_command(r))
        for key, table in TABLE.items():
            for v in self.c['links'].values():
                if key != 'LAN' and self.c['links'][key] != v:
                    continue
                self.run(['route', 'replace', v['prefix'], 'dev', v['interface'], 'scope', 'link', 'table', table])
            if key != 'LAN':
                v = self.c['links'][key]
                self.run(['route', 'replace', 'default', 'via', v['gateway'], 'dev', v['interface'],
                          'table', table, 'metric', 100])
        for r in self.expected():
            if 'table' in r and r['priority'] not in existing:
                self.run(self.rule_command(r))

    def link_up(self, link):
        rows = json.loads(self.run(['-j','link','show','dev',self.c['links'][link]['interface']]))
        return len(rows) == 1 and 'UP' in rows[0]['flags']

    def refresh_probes(self):
        # Linux removes interface routes on link-down. Restore only missing owned
        # probe routes after administrative link-up; never repair foreign rules.
        self.preflight()
        for key, v in self.c['links'].items():
            if not self.link_up(key):
                continue
            data_rows = self.routes(TABLE['LAN'])
            if not any(r.get('dst') == v['prefix'] for r in data_rows):
                self.run(['route','replace',v['prefix'],'dev',v['interface'],'scope','link','table',TABLE['LAN']])
            rows = self.routes(TABLE[key])
            if not any(r.get('dst') == v['prefix'] for r in rows):
                self.run(['route','replace',v['prefix'],'dev',v['interface'],'scope','link','table',TABLE[key]])
            if not any(r.get('dst') == 'default' for r in rows):
                self.run(['route','replace','default','via',v['gateway'],'dev',v['interface'],'table',TABLE[key],'metric',100])

    def selected(self):
        rows = [r for r in self.routes(TABLE['LAN']) if r.get('dst') == 'default']
        if not rows:
            return None
        if len(rows) != 1:
            raise Blocked('Ambiguous selection')
        for k, v in self.c['links'].items():
            if rows[0].get('gateway') == v['gateway'] and rows[0].get('dev') == v['interface'] and rows[0].get('metric') == 100:
                return k
        raise Blocked('Unknown selection')

    def select(self, target):
        v = self.c['links'][target]
        self.run(['route', 'replace', 'default', 'via', v['gateway'], 'dev', v['interface'],
                  'table', TABLE['LAN'], 'metric', 100])
