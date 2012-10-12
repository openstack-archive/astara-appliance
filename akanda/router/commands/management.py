import re
import sys
import textwrap

from akanda.router import defaults
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
    try:
        open('/etc/ssh/sshd_config', 'w+').write(config)
        sys.stderr.write('sshd configured to listen on %s\n' % listen_ip)
    except:
        sys.stderr.write('Unable to write sshd configuration file.')


def configure_gunicorn():
    """
    """
    mgr = ifconfig.InterfaceManager()

    listen_ip = mgr.get_management_address(ensure_configuration=True)

    if not listen_ip:
        sys.stderr.write('Unable to bring up first interface (ge0)!\n')
        sys.exit(1)

    args = {'host': listen_ip,
            'port': defaults.API_SERVICE}

    config = """
    import multiprocessing

    bind = '[%(host)s]:%(port)d'
    workers = workers = multiprocessing.cpu_count() * 2 + 1
    backlog = 2048
    worker_class ="sync"
    debug = False
    daemon = True
    pidfile = "/tmp/gunicorn.pid"
    logfile = "/tmp/gunicorn.log"
    """
    config = textwrap.dedent(config % args).lstrip()

    try:
        open('/etc/akanda_gunicorn_config', 'w+').write(config)
        sys.stderr.write('http configured to listen on %s\n' % listen_ip)
    except:
        sys.stderr.write('Unable to write sshd configuration file.')
