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
import socket
import unittest2

from akanda.router import models
from akanda.router.drivers import arp

config = mock.Mock()
network = mock.Mock()
alloc = mock.Mock()
network.address_allocations = [alloc]
config.networks = [network]

def _AF_PACKET_supported():
    try:
        from socket import AF_PACKET
        return True
    except:
        return False


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

    def test_send_gratuitous_arp_for_config(self):
        config = models.RouterConfiguration({
            'networks': [{
                'network_id': 'ABC456',
                'interface': {
                    'ifname': 'ge1',
                    'name': 'ext',
                },
                'subnets': [{
                    'cidr': '172.16.77.0/24',
                    'gateway_ip': '172.16.77.1',
                    'dhcp_enabled': True,
                    'dns_nameservers': []
                }],
                'network_type': models.Network.TYPE_EXTERNAL,
            }],
            'floating_ips': [{
                'fixed_ip': '192.168.0.2',
                'floating_ip': '172.16.77.50'
            },{
                'fixed_ip': '192.168.0.3',
                'floating_ip': '172.16.77.51'
            },{
                'fixed_ip': '192.168.0.4',
                'floating_ip': '172.16.77.52'
            },{
                'fixed_ip': '192.168.0.5',
                'floating_ip': '172.16.77.53'
            }]
        })

        with mock.patch('akanda.router.utils.execute') as execute:
            self.mgr.send_gratuitous_arp_for_floating_ips(
                config,
                lambda x: x.replace('ge', 'eth')
            )
            assert execute.call_args_list == [
                mock.call(
                    ['akanda-gratuitous-arp', 'eth1', '172.16.77.50'], 'sudo'
                ),
                mock.call(
                    ['akanda-gratuitous-arp', 'eth1', '172.16.77.51'], 'sudo'
                ),
                mock.call(
                    ['akanda-gratuitous-arp', 'eth1', '172.16.77.52'], 'sudo'
                ),
                mock.call(
                    ['akanda-gratuitous-arp', 'eth1', '172.16.77.53'], 'sudo'
                )
            ]

    @unittest2.skipIf(
        not _AF_PACKET_supported(),
        'socket.AF_PACKET not supported on this platform'
    )
    @mock.patch('socket.socket')
    def test_send_gratuitous_arp(self, socket_constr):
        socket_inst = socket_constr.return_value
        socket_inst.getsockname.return_value = (
            None, None, None, None, 'A1:B2:C3:D4:E5:F6'
        )

        arp._send_gratuitous_arp('eth1', '1.2.3.4')
        socket_constr.assert_called_once_with(
            socket.AF_PACKET, socket.SOCK_RAW
        )
        socket_inst.bind.assert_called_once_with((
            'eth1',
            0x0806
        ))
        data = socket_inst.send.call_args_list[0][0][0]
        assert data == ''.join([
            '\xff\xff\xff\xff\xff\xff',  # Broadcast destination
            'A1:B2:C3:D4:E5:F6',  # Source hardware address
            '\x08\x06',  # HTYPE ARP
            '\x00\x01',  # Ethernet
            '\x08\x00',  # Protocol IPv4
            '\x06',  # HADDR length, 6 for IEEE 802 MAC addresses
            '\x04',  # PADDR length, 4 for IPv4
            '\x00\x02',  # OPER, 2 = ARP Reply
            'A1:B2:C3:D4:E5:F6',  # Source MAC
            '\x01\x02\x03\x04',  # Source IP
            'A1:B2:C3:D4:E5:F6',  # Target MAC matches
            '\x01\x02\x03\x04'  # Target IP matches
        ])
