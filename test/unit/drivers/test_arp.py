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


import mock
import unittest2

from akanda.router.drivers import arp

config = mock.Mock()
network = mock.Mock()
alloc = mock.Mock()
network.address_allocations = [alloc]
config.networks = [network]


class ARPTest(unittest2.TestCase):

    def setUp(self):
        self.mgr = arp.ARPManager()

    @mock.patch.object(alloc, 'dhcp_addresses', ['10.10.10.200'])
    def test_ip_not_in_table(self):
        # If there's a DHCP address that isn't in ARP, do nothing.
        output = '''
? (10.10.10.2) at fa:16:3e:4b:7a:f0 on vio2
? (10.10.10.3) at fa:16:3e:4c:0e:27 on vio2
? (208.113.176.1) at 78:fe:3d:d3:b5:c1 on vio1
'''
        with mock.patch.object(self.mgr, 'sudo') as sudo:
            sudo.return_value = output
            self.mgr.remove_stale_entries(
                config
            )
            sudo.assert_called_with('-an')

    @mock.patch.object(alloc, 'mac_address', 'fa:16:3e:4b:7a:f0')
    @mock.patch.object(alloc, 'dhcp_addresses', ['10.10.10.2'])
    def test_ip_mac_address_matches(self):
        # If a DHCP address is in ARP, and the mac address is correct, do
        # nothing.
        output = '''
? (10.10.10.2) at fa:16:3e:4b:7a:f0 on vio2
? (10.10.10.3) at fa:16:3e:4c:0e:27 on vio2
? (208.113.176.1) at 78:fe:3d:d3:b5:c1 on vio1
'''
        with mock.patch.object(self.mgr, 'sudo') as sudo:
            sudo.return_value = output
            self.mgr.remove_stale_entries(
                config
            )
            sudo.assert_called_with('-an')

    @mock.patch.object(alloc, 'mac_address', 'fa:20:30:40:50:f0')
    @mock.patch.object(alloc, 'dhcp_addresses', ['10.10.10.2'])
    def test_ip_mac_address_mismatch(self):
        # If a DHCP address is in ARP, and the mac address has changed,
        # delete the old record.
        output = '''
? (10.10.10.2) at fa:16:3e:4b:7a:f0 on vio2
? (10.10.10.3) at fa:16:3e:4c:0e:27 on vio2
? (208.113.176.1) at 78:fe:3d:d3:b5:c1 on vio1
'''
        with mock.patch.object(self.mgr, 'sudo') as sudo:
            sudo.return_value = output
            self.mgr.remove_stale_entries(
                config
            )
            sudo.assert_has_calls([
                mock.call('-an'),
                mock.call('-d', '10.10.10.2')
            ])
