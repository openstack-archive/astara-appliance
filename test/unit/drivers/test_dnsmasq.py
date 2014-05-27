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


from unittest2 import TestCase

import mock
import netaddr

from akanda.router import models
from akanda.router.drivers import dnsmasq
ext_subnet = mock.Mock()
ext_subnet.gateway_ip = netaddr.IPAddress('dead:beef::1')

ext_subnet.cidr = netaddr.IPNetwork('dead:beef::/64')
ext_subnet.dns_nameservers = []
ext_subnet.host_routes = [models.StaticRoute('172.16.0.0/16', '192.168.1.1')]
ext_subnet.dns_nameservers = ['8.8.8.8', '8.8.4.4']

ext_net = mock.Mock()
ext_net.subnets = [ext_subnet]
ext_net.is_internal_network = False
ext_net.is_external_network = True
ext_net.is_tenant_network = False
ext_net.interface.ifname = 'ge0'
ext_net.address_allocations = [models.Allocation(
    'fa:da:fa:da:fa:da:',
    {'192.168.1.2': True, 'dead:beef::2': False},  # ip: DHCP enabled
    '192-168-1-2.local',
    'e3300819-d7b9-4d8d-9d7c-a6380ff78ca7'
)]

v6_subnet = mock.Mock()
v6_subnet.gateway_ip = netaddr.IPAddress('face::1')
v6_subnet.cidr = netaddr.IPNetwork('face::/64')
v6_subnet.dns_nameservers = []

v4_subnet = mock.Mock()
v4_subnet.gateway_ip = netaddr.IPAddress('9.9.9.1')
v4_subnet.cidr = netaddr.IPNetwork('9.9.9.0/24')
v4_subnet.dns_nameservers = []

int_net = mock.Mock()
int_net.subnets = [v4_subnet, v6_subnet]
int_net.is_internal_network = True
int_net.is_external_network = False
int_net.is_tenant_network = True
int_net.interface.ifname = 'ge1'

mgt_net = mock.Mock()
mgt_net.subnets = []
mgt_net.is_internal_network = False
mgt_net.is_external_network = False
mgt_net.is_tenant_network = False
mgt_net.interface.ifname = 'ge2'

CONFIG = mock.Mock()
CONFIG.networks = [ext_net, int_net, mgt_net]
IF_MAP = {'ge0': 'en0', 'ge1': 'en1', 'ge2': 'en2'}


class DnsmasqTestCase(TestCase):
    """
    """
    def setUp(self):
        self.mock_execute = mock.patch('akanda.router.utils.execute').start()
        self.mock_replace_file = mock.patch(
            'akanda.router.utils.replace_file'
        ).start()
        self.addCleanup(mock.patch.stopall)

        self.mgr = dnsmasq.DHCPManager()

    def test_update_network_dhcp_config_tenant_net(self):
        mock_net = mock.Mock()
        mock_net.is_tenant_network = True
        with mock.patch.object(self.mgr, '_build_dhcp_config') as build_config:
            build_config.return_value = 'the_config'

            self.mgr.update_network_dhcp_config('em1', mock_net)

            build_config.assert_called_once_with('em1', mock_net)

            self.mock_replace_file.assert_called_once_with(
                '/tmp/dnsmasq.conf',
                'the_config'
            )
            self.mock_execute.assert_called_once_with(
                ['mv', '/tmp/dnsmasq.conf', '/etc/dnsmasq.d/em1.conf'],
                'sudo'
            )

    def test_build_dhcp_config(self):
        config = self.mgr._build_dhcp_config('ge0', ext_net)
        assert config == '\n'.join([
            'interface=ge0',
            'dhcp-range=set:ge0_0,dead:beef::,static,86400s',
            'dhcp-option=tag:ge0_0,option6:dns-server,8.8.8.8',
            'dhcp-option=tag:ge0_0,option6:dns-server,8.8.4.4',
            ('dhcp-option=tag:ge0_0,option6:classless-static-route,'
             '172.16.0.0/16,192.168.1.1'),
            'dhcp-host=fa:da:fa:da:fa:da:,192.168.1.2,192-168-1-2.local'
        ]), config

    def test_restart(self):
        self.mgr.restart()
        self.mock_execute.assert_has_calls([
            mock.call(['/etc/rc.d/dnsmasq', 'stop'], 'sudo'),
            mock.call(['/etc/rc.d/dnsmasq', 'start'], 'sudo')
        ])
