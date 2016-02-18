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


import operator
import os
import time
import itertools

import netaddr

from astara_router.drivers import base
from astara_router import utils


CONF_DIR = '/etc/dnsmasq.d'
RC_PATH = '/etc/init.d/dnsmasq'
DEFAULT_LEASE = 86400


class DHCPManager(base.Manager):
    """A class to manage dnsmasq."""
    def __init__(self, root_helper='sudo'):
        """
        Initializes DHCPManager class.

        :type root_helper: str
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(DHCPManager, self).__init__(root_helper)

    def delete_all_config(self):
        """
        Deletes all the dnsmasq configuration files (in <CONF_DIR>) that end in
        .conf.
        """
        for f in os.listdir(CONF_DIR):
            if f.endswith('.conf'):
                os.remove(os.path.join(CONF_DIR, f))

    def update_network_dhcp_config(self, ifname, network):
        """
        Updates the dnsmasq.conf config, enabling dhcp configuration for nova
        networks that are mapped to tenants and disabling networks that do not
        map to tenants.

        :type ifname: str
        :param ifname:
        :type network:
        :param network:

        """
        if network.is_tenant_network:
            config_data = self._build_dhcp_config(ifname, network)
        else:
            config_data = self._build_disabled_config(ifname)

        file_path = os.path.join(CONF_DIR, '%s.conf' % ifname)
        utils.replace_file('/tmp/dnsmasq.conf', config_data)
        utils.execute(['mv', '/tmp/dnsmasq.conf', file_path], self.root_helper)

    def _build_disabled_config(self, ifname):
        """
        Appends "except-interface" for <ifname>. This is used to disable an
        interface in the dnsmasq file and should be called from the wrapper
        update_network_dhcp_config.

        :type ifname: str
        :param ifname: Name of the interface to add an exception to in dnsmasq
                       configuration.
        :rtype: str
        """
        return 'except-interface=%s\n' % ifname

    def _build_dhcp_config(self, ifname, network):
        """
        Creates <config> containing dnsmasq configuration information for
        <ifname>/<network>.  Should be called from wrapper
        update_network_dhcp_config.

        :type ifname: str
        :param ifname:
        :type network:
        :param network:
        :rtype: dict
        """
        config = ['interface=%s' % ifname]

        for index, subnet in enumerate(network.subnets):
            if not subnet.dhcp_enabled:
                continue

            tag = '%s_%s' % (ifname, index)

            config.append('dhcp-range=set:%s,%s,%s,%ss' %
                          (tag,
                           subnet.cidr.network,
                           'static',
                           DEFAULT_LEASE))

            if subnet.cidr.version == 6:
                option_label = 'option6'
            else:
                option_label = 'option'

            config.extend(
                'dhcp-option=tag:%s,%s:dns-server,%s' % (tag, option_label, s)
                for s in subnet.dns_nameservers
            )

            config.extend(
                'dhcp-option=tag:%s,%s:classless-static-route,%s,%s' %
                (tag, option_label, r.destination, r.next_hop)
                for r in subnet.host_routes
            )

        for a in network.address_allocations:
            dhcp_addresses = map(netaddr.IPAddress, a.dhcp_addresses)
            dhcp_addresses = sorted(dhcp_addresses)
            groups = itertools.groupby(dhcp_addresses, key=operator.attrgetter('version'))
            dhcp_addresses = [str(next(members)) for k, members in groups]
            config.extend([
                'dhcp-host=%s,%s,%s' % ( a.mac_address,
                    ','.join('[%s]' % ip if ':' in ip else ip
                             for ip in dhcp_addresses),
                    a.hostname)
            ])

        return '\n'.join(config)

    def restart(self):
        """
        Restarts dnsmasq service using the system provided init script.
        """
        try:
            utils.execute([RC_PATH, 'stop'], self.root_helper)
        except:
            pass

        # dnsmasq can get confused on startup
        remaining = 5
        while remaining:
            remaining -= 1
            try:
                utils.execute(
                    [RC_PATH, 'start'], self.root_helper
                )
                return
            except Exception:
                if remaining <= 0:
                    raise
                time.sleep(1)
