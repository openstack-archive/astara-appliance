from unittest2 import TestCase

import mock
import netaddr
import re
import textwrap

from akanda.router.drivers import dnsmasq
ext_subnet = mock.Mock()
ext_subnet.gateway_ip = netaddr.IPAddress('dead:beef::1')
ext_subnet.cidr = netaddr.IPNetwork('dead:beef::/64')
ext_subnet.dns_nameservers = []

ext_net = mock.Mock()
ext_net.subnets = [ext_subnet]
ext_net.is_internal_network = False
ext_net.is_external_network = True
ext_net.is_tenant_network = False
ext_net.interface.ifname = 'ge0'

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

    def test_restart(self):
        self.mgr.restart()
        self.mock_execute.assert_has_calls([
            mock.call(['/etc/rc.d/dnsmasq', 'stop'], 'sudo'),
            mock.call(['/etc/rc.d/dnsmasq', 'start'], 'sudo')
        ])
