import hashlib
import ipaddress
import json
import re
from .policy import Settings


def load(path):
    c = json.loads(path.read_text())
    if set(c) != {'lan', 'links', 'targets', 'ca', 'server_name', 'policy'}:
        raise ValueError('Unexpected config keys')
    if set(c['links']) != {'A', 'B'} or len(c['targets']) != 3:
        raise ValueError('Exactly two links and three targets required')
    interfaces = [c['lan']['interface']] + [v['interface'] for v in c['links'].values()]
    if len(set(interfaces)) != 3 or any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', s) for s in interfaces):
        raise ValueError('Distinct simple interface names required')
    if set(c['lan']) != {'interface','prefix','exclude'} or not isinstance(c['lan']['exclude'],list) or len(c['lan']['exclude']) > 8:
        raise ValueError('Invalid LAN exclusions')
    for prefix in c['lan']['exclude']:
        if ipaddress.IPv4Network(prefix).prefixlen == 0:
            raise ValueError('Cannot exclude all traffic')
    lan = ipaddress.IPv4Network(c['lan']['prefix'])
    networks = [lan]
    for v in c['links'].values():
        if set(v) != {'interface', 'source', 'gateway', 'prefix'}:
            raise ValueError('Unexpected link keys')
        n = ipaddress.IPv4Network(v['prefix'])
        if ipaddress.IPv4Address(v['source']) not in n or ipaddress.IPv4Address(v['gateway']) not in n or v['source'] == v['gateway']:
            raise ValueError('Invalid static gateway/source')
        networks.append(n)
    if any(a.overlaps(b) for i, a in enumerate(networks) for b in networks[i+1:]):
        raise ValueError('Overlapping subnet unsupported')
    for t in c['targets']:
        if set(t) != {'ip', 'port'} or type(t['port']) is not int or not 1 <= t['port'] <= 65535:
            raise ValueError('Invalid target')
        address = ipaddress.IPv4Address(t['ip'])
        if any(address in n for n in networks):
            raise ValueError('Probe must be beyond the connected subnets')
    if len({(t['ip'], t['port']) for t in c['targets']}) != 3:
        raise ValueError('Targets must be distinct endpoints')
    Settings(**c['policy'])
    c['_hash'] = hashlib.sha256(json.dumps(c, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return c
