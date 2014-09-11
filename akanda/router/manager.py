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


import os
import re

from akanda.router import models
from akanda.router.drivers import (bird, dnsmasq, ip, metadata,
                                   iptables, arp, hostname)


class Manager(object):
    def __init__(self, state_path='.'):
        self.state_path = os.path.abspath(state_path)
        self.ip_mgr = ip.IPManager()
        self.ip_mgr.ensure_mapping()
        self._config = models.Configuration()

    def management_address(self, ensure_configuration=False):
        return self.ip_mgr.get_management_address(ensure_configuration)

    @property
    def config(self):
        """Make config a read-only property.

        To update the value, update_config() must called to change the global
        state of router.
        """

        return self._config

    def update_config(self, config, cache):
        self._config = config

        self.update_hostname()
        self.update_interfaces()
        self.update_dhcp()
        self.update_metadata()
        self.update_bgp_and_radv()
        self.update_firewall()
        self.update_routes(cache)
        self.update_arp()

        # TODO(mark): update_vpn

    def update_hostname(self):
        mgr = hostname.HostnameManager()
        mgr.update(self.config)

    def update_interfaces(self):
        self.ip_mgr.update_interfaces(self.config.interfaces)

    def update_dhcp(self):
        mgr = dnsmasq.DHCPManager()

        mgr.delete_all_config()
        for network in self.config.networks:
            real_ifname = self.ip_mgr.generic_to_host(network.interface.ifname)
            mgr.update_network_dhcp_config(real_ifname, network)
        mgr.restart()

    def update_metadata(self):
        mgr = metadata.MetadataManager()
        should_restart = mgr.networks_have_changed(self.config)
        mgr.save_config(self.config)
        if should_restart:
            mgr.restart()
        else:
            mgr.ensure_started()

    def update_bgp_and_radv(self):
        mgr = bird.BirdManager()
        mgr.save_config(self.config, self.ip_mgr.generic_mapping)
        mgr.restart()

    def update_firewall(self):
        mgr = iptables.IPTablesManager()
        mgr.save_config(self.config, self.ip_mgr.generic_mapping)
        mgr.restart()

    def update_routes(self, cache):
        mgr = ip.IPManager()
        mgr.update_default_gateway(self.config)
        mgr.update_host_routes(self.config, cache)

    def update_arp(self):
        mgr = arp.ARPManager()
        mgr.remove_stale_entries(self.config)

    def get_interfaces(self):
        return self.ip_mgr.get_interfaces()

    def get_interface(self, ifname):
        return self.ip_mgr.get_interface(ifname)

    def _map_virtual_to_real_interfaces(self, virt_data):
        rules = []

        rules.extend(
            '%s = "%s"' % i for i in self.ip_mgr.generic_mapping.items()
        )

        rules.append(re.sub('([\s!])(ge\d+([\s:]|$))', r'\1$\2', virt_data))
        return '\n'.join(rules)


class ManagerProxy(object):
    def __init__(self):
        self.instance = None

    def __getattr__(self, name):
        if not self.instance:
            self.instance = Manager()
        return getattr(self.instance, name)

manager = ManagerProxy()
