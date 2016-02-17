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
import re
import textwrap

from astara_router.drivers import bird
ext_subnet = mock.Mock()
ext_subnet.gateway_ip = netaddr.IPAddress('dead:beef::1')
ext_subnet.cidr = netaddr.IPNetwork('dead:beef::/64')
ext_subnet.dns_nameservers = ["1.2.3.4"]

ext_net = mock.Mock()
ext_net.subnets = [ext_subnet]
ext_net.is_internal_network = False
ext_net.is_external_network = True
ext_net.is_tenant_network = False
ext_net.interface.ifname = 'ge0'

int_subnet = mock.Mock()
int_subnet.gateway_ip = netaddr.IPAddress('face::1')
int_subnet.cidr = netaddr.IPNetwork('face::/64')
int_subnet.dns_nameservers = ["1.2.3.4"]

int_net = mock.Mock()
int_net.subnets = [int_subnet]
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
CONFIG.asn = 4321
CONFIG.neighbor_asn = 65000
IF_MAP = {'ge0': 'en0', 'ge1': 'en1', 'ge2': 'en2'}


class BirdTestCase(TestCase):
    """
    """
    def setUp(self):
        self.mock_execute = mock.patch('astara_router.utils.execute').start()
        self.mock_replace_file = mock.patch(
            'astara_router.utils.replace_file'
        ).start()
        self.addCleanup(mock.patch.stopall)

        self.mgr = bird.BirdManager()

    def test_save_config(self):
        with mock.patch.object(bird, 'build_config') as mock_build_config:
            mock_build_config.return_value = 'the_config'

            self.mgr.save_config(mock.sentinel.config, mock.sentinel.if_map)

            mock_build_config.assert_called_once_with(
                mock.sentinel.config,
                mock.sentinel.if_map
            )

            self.mock_replace_file.assert_called_once_with(
                '/tmp/bird6.conf',
                'the_config'
            )
            self.mock_execute.assert_called_once_with(
                ['mv', '/tmp/bird6.conf', '/etc/bird/bird6.conf'],
                'sudo astara-rootwrap /etc/rootwrap.conf'
            )

    def test_restart(self):
        self.mgr.restart()
        self.mock_execute.assert_has_calls([
            mock.call(['service', 'bird6', 'status'],
                      'sudo astara-rootwrap /etc/rootwrap.conf'),
            mock.call(['servoce', 'bird6', 'reload'],
                      'sudo astara-rootwrap /etc/rootwrap.conf'),
        ])

    def test_restart_failure(self):
        with mock.patch('astara_router.utils.execute') as execute:
            execute.side_effect = [Exception('status failed!'), None]
            self.mgr.restart()
            execute.assert_has_calls([
                mock.call(['service', 'bird6', 'status'],
                          'sudo astara-rootwrap /etc/rootwrap.conf'),
                mock.call(['service', 'bird6', 'start'],
                          'sudo astara-rootwrap /etc/rootwrap.conf'),
            ])

    def test_build_config(self):
        patches = {
            '_build_global_config': mock.Mock(return_value='global'),
            '_build_kernel_config': mock.Mock(return_value='kernel'),
            '_build_device_config': mock.Mock(return_value='device'),
            '_build_static_config': mock.Mock(return_value='static'),
            '_build_direct_config': mock.Mock(return_value='direct'),
            '_build_bgp_config': mock.Mock(return_value='bgp'),
            '_build_radv_config': mock.Mock(return_value='radv')
        }
        with mock.patch.multiple(bird, **patches):
            result = bird.build_config(
                mock.sentinel.config,
                mock.sentinel.if_map
            )

            expected = [
                'global', 'kernel', 'device', 'static', 'direct', 'bgp', 'radv'
            ]
            self.assertEqual(result, '\n'.join(expected))

    def test_find_external_v4_ip_has_v4(self):
        config = mock.Mock()
        config.external_v4_id = '9.9.9.1'
        self.assertEqual(bird._find_external_v4_ip(config), '9.9.9.1')

    def test_find_external_v4_id_no_v4(self):
        config = mock.Mock()
        config.external_v4_id = None

        result = bird._find_external_v4_ip(config)
        self.assertTrue(re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', result))

    def test_build_global_config(self):
        with mock.patch.object(bird, '_find_external_v4_ip') as ext_v4_id:
            ext_v4_id.return_value = '9.9.9.9'

            result = bird._build_global_config(mock.sentinel.config)
            ext_v4_id.assert_called_once_with(mock.sentinel.config)
            self.assertEqual(
                result,
                'log syslog {warning, error, info};\nrouter id 9.9.9.9;'
            )

    def test_build_kernel_config(self):
        result = bird._build_kernel_config()
        expected = (
            'protocol kernel {\n'
            '    learn;\n'
            '    scan time 20;\n'
            '    import all;\n'
            '    export all;\n'
            '}'
        )
        self.assertEqual(expected, result)

    def test_build_device_config(self):
        self.assertEqual(
            bird._build_device_config(),
            'protocol device {\n    scan time 10;\n}'
        )

    def test_build_static_config(self):
        self.assertFalse(bird._build_static_config(mock.Mock()))

    def test_build_direct_config(self):
        result = bird._build_direct_config(mock.Mock(), IF_MAP)
        expected = 'protocol direct {\n    interface "en0","en1","en2";\n}'
        self.assertEqual(result, expected)

    def test_build_ospf_config(self):
        expected = """
            protocol ospf {
                export all;
                rfc1583compat yes;
                area 0 {
                    interface "en0" {
                        cost 10;
                        type broadcast;
                    };
                    interface "en1" {
                        cost 10;
                        stub yes;
                    };
                };
            };
        """
        expected = textwrap.dedent(expected).strip()
        result = bird._build_ospf_config(CONFIG, IF_MAP)
        self.assertEqual(result, expected)

    def test_build_bgp_config(self):
        expected = """
            filter bgp_out {
                if ! (source = RTS_DEVICE) then reject;
                if net ~ fc00::/7 then reject;
                if net = face::/64 then accept;
                else reject;
            }

            protocol bgp {
                local as 4321;
                neighbor dead:beef::1 as 65000;
                import all;
                export filter bgp_out;
                rr client;
            }
        """
        expected = textwrap.dedent(expected).strip()
        result = bird._build_bgp_config(CONFIG, IF_MAP)
        self.assertEqual(result, expected)

    def test_build_radv_config(self):
        expected = """
            protocol radv {
                interface "en1" {
                    max ra interval 600;
                    rdnss local yes;
                    prefix face::/64 {
                        autonomous off;
                    };
                    rdnss {
                        lifetime mult 10;
                        ns 1.2.3.4;
                    };
                };
            }
        """
        expected = textwrap.dedent(expected).strip()
        result = bird._build_radv_config(CONFIG, IF_MAP)
        self.assertEqual(result, expected)
