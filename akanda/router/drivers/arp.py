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
    EXECUTABLE = '/usr/sbin/arp'

    def remove_stale_entries(self, config):
        for network in config.networks:
            for a in network.address_allocations:
                for ip in a.dhcp_addresses:
                    address_for_ip = self._mac_address_for_ip(ip)
                    if address_for_ip and address_for_ip != a.mac_address:
                        self._delete_from_arp_cache(ip)

    def _mac_address_for_ip(self, ip):
        cmd_out = self.sudo('-an')
        match = re.search(' \(%s\) at ([^\s]+)' % ip, cmd_out)
        if match and match.groups():
            return match.group(1)

    def _delete_from_arp_cache(self, ip):
        self.sudo('-d', ip)
