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


import logging
import re

from akanda.router.drivers import base


LOG = logging.getLogger(__name__)


class ARPManager(base.Manager):
    """
    A class to interact with entries in the ARP cache.  Currently only really
    provides support for deleting stuff from the cache.
    """
    EXECUTABLE = '/usr/sbin/arp'

    def remove_stale_entries(self, config):
        """
        A wrapper function that iterates over the networks in <config> and
        removes arp entries that no longer have any networks associated with
        them.  This function calls _delete_from_arp_cache to do the actual
        deletion and makes calls to _mac_address_for_ip to match arp entries
        to network interface IPs.

        :type config: akanda.router.models.Configuration
        :param config: An akanda.router.models.Configuration object containing
                       configuration information for the system's network setup.
        """
        for network in config.networks:
            for a in network.address_allocations:
                for ip in a.dhcp_addresses:
                    address_for_ip = self._mac_address_for_ip(ip)
                    if address_for_ip and address_for_ip != a.mac_address:
                        self._delete_from_arp_cache(ip)

    def _mac_address_for_ip(self, ip):
        """
        Matches a networks IP address to an arp entry.  This is used to
        associate arp entries with networks that are configured on the system
        and to determine which arp entries are stale through process of
        elemination.

        :type ip: str
        :param ip: IP address to search for in the ARP table.
        """
        cmd_out = self.sudo('-an')
        match = re.search(' \(%s\) at ([^\s]+)' % ip, cmd_out)
        if match and match.groups():
            return match.group(1)

    def _delete_from_arp_cache(self, ip):
        """
        Runs `arp -d <ip>` to delete <ip> from the arp cache.

        :type ip: str
        :param ip: IP address to search for in the ARP table.
        """
        self.sudo('-d', ip)
