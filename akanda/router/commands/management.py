import re
import sys

from akanda.router.drivers import ifconfig


def configure_ssh():
    """
    """
    mgr = ifconfig.InterfaceManager()

    interfaces = mgr.get_interfaces(['em', 're'])
    interfaces.sort(key=lambda x: x.ifname)
    primary = interfaces[0]

    if not primary.is_up:
        mgr.up(primary)
        primary = mgr.get_interface(primary)

    for address in primary.addresses:
        if str(address.ip).startswith('fe80'):
            listen_ip = '%s%%%s' % (address.ip, primary.ifname)
    else:
        sys.stderr.write('Unable to bring up first interface (%s)!\n' %
                         primary.ifname)
        sys.exit(1)

    config = open('/etc/ssh/sshd_config', 'r').read()
    config = re.sub('(^|\n)(#)?(ListenAddress|AddressFamily) .*', '', config)
    config += '\n'.join(
        ['ListenAddress %s' % listen_ip, 'AddressFamily inet6'])
    open('/etc/ssh/sshd_config', 'w+').write(config)
    sys.stderr.write('sshd configured to listen on %s\n' % listen_ip)
