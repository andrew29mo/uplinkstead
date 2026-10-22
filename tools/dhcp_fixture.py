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
