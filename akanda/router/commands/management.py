# Copyright 2014 DreamHost, LLC
# Copyright 2015 Akanda, Inc
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


import argparse
import re
import sys

import netaddr

from akanda.router import defaults
from akanda.router import utils
from akanda.router.drivers import ip


def configure_ssh(listen_ip):
    """
    """
    config = open('/etc/ssh/sshd_config', 'r').read()
    config = re.sub(
        '(^|\n)(#)?(ListenAddress|AddressFamily|UseDNS) .*',
        '',
        config
    )

    config += '\n'.join([
        '',  # make sure we have a blank line at the end before adding more
        'AddressFamily inet%s' % ('6' if listen_ip.version == 6 else ''),
        'ListenAddress ' + str(listen_ip),
        'UseDNS no'
    ])
    try:
        open('/etc/ssh/sshd_config', 'w+').write(config)
        sys.stderr.write('sshd configured to listen on %s\n' % listen_ip)
    except:
        sys.stderr.write('Unable to write sshd configuration file.')


def configure_gunicorn(listen_ip):
    """
    """
    if listen_ip.version == 6:
        bind = "'[%s]:%d'" % (listen_ip, defaults.API_SERVICE)
    else:
        bind = "'%s:%d'" % (listen_ip, defaults.API_SERVICE)

    config = open('/etc/akanda_gunicorn_config', 'r').read()
    config = re.sub('\nbind(\s)?\=(\s)?.*', '\nbind = %s' % bind, config)

    try:
        open('/etc/akanda_gunicorn_config', 'w+').write(config)
        sys.stderr.write('http configured to listen on %s\n' % listen_ip)
    except:
        sys.stderr.write('Unable to write gunicorn configuration file.')


def configure_management():
    parser = argparse.ArgumentParser(
        description='Configure Management Interface'
    )
    parser.add_argument('mac_address', metavar='lladdr', type=str)
    parser.add_argument('ip_address', metavar='ipaddr', type=str)
    args = parser.parse_args()

    ip_addr = netaddr.IPNetwork(args.ip_address)

    mgr = ip.IPManager()

    for intf in mgr.get_interfaces():
        if args.mac_address == intf.lladdr:
            if not intf.is_up:
                mgr.up(intf)

            if ip_addr not in intf.addresses:
                if ip_addr.version == 6:
                    real_ifname = mgr.generic_to_host(intf.ifname)
                    utils.execute([
                        'sysctl',
                        '-w',
                        'net.ipv6.conf.%s.accept_dad=0' % real_ifname
                    ])

                intf.addresses.append(ip_addr)
                mgr.update_interface(intf)
                configure_ssh(ip_addr.ip)
                configure_gunicorn(ip_addr.ip)
        break
