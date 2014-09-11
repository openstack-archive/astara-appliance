# Copyright 2014 DreamHost, LLC
#
# Author: DreamHost, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


import re
import sys
import textwrap

from akanda.router import defaults
from akanda.router.drivers import ip


def configure_ssh():
    """
    """
    mgr = ip.IPManager()

    listen_ip = mgr.get_management_address(ensure_configuration=True)

    if not listen_ip:
        sys.stderr.write('Unable to bring up first interface (ge0)!\n')
        sys.exit(1)

    config = open('/etc/ssh/sshd_config', 'r').read()
    config = re.sub('(^|\n)(#)?(ListenAddress|AddressFamily) .*', '', config)
    config += '\n'.join([
        '',  # make sure we have a blank line at the end before adding more
        'AddressFamily inet6',
        'ListenAddress ' + listen_ip,
        'UseDNS no'
    ])
    try:
        open('/etc/ssh/sshd_config', 'w+').write(config)
        sys.stderr.write('sshd configured to listen on %s\n' % listen_ip)
    except:
        sys.stderr.write('Unable to write sshd configuration file.')


def configure_gunicorn():
    """
    """
    mgr = ip.IPManager()

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
    pidfile = "/var/run/gunicorn.pid"
    logfile = "/tmp/gunicorn.log"
    """
    config = textwrap.dedent(config % args).lstrip()

    try:
        open('/etc/akanda_gunicorn_config', 'w+').write(config)
        sys.stderr.write('http configured to listen on %s\n' % listen_ip)
    except:
        sys.stderr.write('Unable to write gunicorn configuration file.')
