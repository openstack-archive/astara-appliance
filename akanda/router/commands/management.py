import re
import sys

from akanda.router.drivers import ifconfig


def configure_ssh():
    """
    """
    mgr = ifconfig.InterfaceManager()

    listen_ip = mgr.get_management_address(ensure_configuration=True)

    if not listen_ip:
        sys.stderr.write('Unable to bring up first interface (ge0)!\n')
        sys.exit(1)

    config = open('/etc/ssh/sshd_config', 'r').read()
    config = re.sub('(^|\n)(#)?(ListenAddress|AddressFamily) .*', '', config)
    config += '\n'.join(['AddressFamily inet6', 'ListenAddress ' + listen_ip])
    open('/etc/ssh/sshd_config', 'w+').write(config)
    sys.stderr.write('sshd configured to listen on %s\n' % listen_ip)
