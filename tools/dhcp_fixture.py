"""Explicit fixture-only transformations of the shipped DHCP service unit."""
ROOT = '/opt/uplinkstead-dhcp'


def unit(source):
    value = source.replace('/etc/uplinkstead/dhcp.json', ROOT+'/config.json')
    value = value.replace('/var/lib/uplinkstead-dhcp', ROOT+'/state')
    value = value.replace('/run/uplinkstead-dhcp', ROOT+'/run')
    value = value.replace('--socket '+ROOT+'/run/events.sock',
                          '--socket '+ROOT+'/run/events.sock --hook '+ROOT+'/source/deploy/uplinkstead-udhcpc.py')
    for line in ('StateDirectory=uplinkstead-dhcp\n', 'StateDirectoryMode=0700\n',
                 'RuntimeDirectory=uplinkstead-dhcp\n', 'RuntimeDirectoryMode=0700\n'):
        value = value.replace(line, '')
    return value.replace('[Service]', '[Service]\nWorkingDirectory='+ROOT+'/source\nEnvironment=PYTHONPATH='+
                         ROOT+'/source\nNetworkNamespacePath=/run/netns/ud_r\nReadWritePaths='+ROOT)


def monitor_expressions(port):
    """Exclude only the identified root warmup TCP tuple, never LAN/probe flows."""
    if type(port) is not int or not 1 <= port <= 65535:raise ValueError('Invalid control port')
    def match(protocol,field,value):
        return dict(match=dict(op='==',left=dict(payload=dict(protocol=protocol,field=field)),right=value))
    return [[match('ip','saddr','198.51.100.2'),match('tcp','sport',port),
             match('tcp','dport',8443),match('ip','daddr','203.0.113.2'),{'return':None}],
            [match('ip','daddr','203.0.113.2'),dict(counter=dict(packets=0,bytes=0))]]


def monitor_script(port):
    monitor_expressions(port)  # Validate before interpolating a numeric port.
    return ('flush chain ip observe f\nadd rule ip observe f ip saddr 198.51.100.2 tcp sport '+str(port)+
            ' tcp dport 8443 ip daddr 203.0.113.2 return\n'
            'add rule ip observe f ip daddr 203.0.113.2 counter\n')
