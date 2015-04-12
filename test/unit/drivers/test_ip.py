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
from cStringIO import StringIO

from unittest2 import TestCase
import mock
import netaddr

from akanda.router import models
from akanda.router.drivers import ip

SAMPLE_OUTPUT = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether fa:16:3e:34:ba:28 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::f816:3eff:fe34:ba28/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether fa:16:3e:7a:d8:64 brd ff:ff:ff:ff:ff:ff
    inet 192.168.105.2/24 brd 192.168.105.255 scope global eth1
    inet6 fe80::f816:3eff:fe7a:d864/64 scope link
       valid_lft forever preferred_lft forever"""  # noqa

SAMPLE_SINGLE_OUTPUT = """3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether fa:16:3e:7a:d8:64 brd ff:ff:ff:ff:ff:ff
    inet 192.168.105.2/24 brd 192.168.105.255 scope global eth1
    inet6 fe80::f816:3eff:fe7a:d864/64 scope link
       valid_lft forever preferred_lft forever"""  # noqa


class IPTestCase(TestCase):

    def setUp(self):
        self.execute_patch = mock.patch('akanda.router.utils.execute')
        self.mock_execute = self.execute_patch.start()

    def tearDown(self):
        self.execute_patch.stop()

    def test_init(self):
        mgr = ip.IPManager()
        self.assertEqual(mgr.host_mapping.keys(), [])

    def test_get_interfaces(self):
        iface_a = mock.Mock()
        iface_a.ifname = 'em0'

        iface_b = mock.Mock()
        iface_b.ifname = 'em1'
        ifaces = 'akanda.router.drivers.ip._parse_interfaces'
        with mock.patch(ifaces) as parse:
            parse.return_value = [iface_a, iface_b]
            mgr = ip.IPManager()
            interfaces = mgr.get_interfaces()
            self.assertEqual(interfaces, [iface_a, iface_b])

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ip', 'addr', 'show'])])

    def test_get_interface(self):
        iface_a = mock.Mock()
        iface_a.ifname = 'em0'
        iface = 'akanda.router.drivers.ip._parse_interface'
        ifaces = 'akanda.router.drivers.ip._parse_interfaces'
        with mock.patch(iface) as parse:
            with mock.patch(ifaces) as pi:
                pi.return_value = [iface_a]
                parse.return_value = iface_a
                mgr = ip.IPManager()
                interface = mgr.get_interface('ge0')
                self.assertEqual(interface, iface_a)
                self.assertEqual(iface_a.ifname, 'ge0')

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ip', 'addr', 'show'])])

    def test_ensure_mapping_uninitialized(self):
        attr = 'get_interfaces'
        with mock.patch.object(ip.IPManager, attr) as get_ifaces:
            mgr = ip.IPManager()
            mgr.ensure_mapping()

            get_ifaces.assert_called_once_with()

    def test_ensure_mapping_initialized(self):
        attr = 'get_interfaces'
        with mock.patch.object(ip.IPManager, attr) as get_ifaces:
            mgr = ip.IPManager()
            mgr.host_mapping['em0'] = 'ge0'
            mgr.ensure_mapping()

            self.assertEqual(get_ifaces.call_count, 0)

    def test_is_valid(self):
        mgr = ip.IPManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}
        self.assertTrue(mgr.is_valid('ge0'))

    def test_generic_to_host(self):
        mgr = ip.IPManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}
        self.assertEqual(mgr.generic_to_host('ge0'), 'em0')
        self.assertIsNone(mgr.generic_to_host('ge1'))

    def test_host_to_generic(self):
        mgr = ip.IPManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}
        self.assertEqual(mgr.host_to_generic('em0'), 'ge0')
        self.assertIsNone(mgr.host_to_generic('em1'))

    def test_update_interfaces(self):
        iface_a = mock.Mock()
        iface_b = mock.Mock()

        attr = 'update_interface'
        with mock.patch.object(ip.IPManager, attr) as update:
            mgr = ip.IPManager()
            mgr.update_interfaces([iface_a, iface_b])
            update.assert_has_calls([mock.call(iface_a), mock.call(iface_b)])

    def test_up(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'

        mgr = ip.IPManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}

        mgr.up(iface)

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ip', 'link', 'set', 'em0', 'up'], 'sudo')])

    def test_down(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'

        mgr = ip.IPManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}

        mgr.down(iface)

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ip', 'link', 'set', 'em0', 'down'], 'sudo')])

    def _update_interface_test_hlpr(self, new_iface, old_iface,
                                    ignore_link_local=True):
        mock_methods = {
            'generic_to_host': mock.Mock(return_value='em0'),
            'get_interface': mock.Mock(return_value=old_iface),
            '_update_addresses': mock.Mock()}

        with mock.patch.multiple(ip.IPManager, **mock_methods):
            mgr = ip.IPManager()
            mgr.update_interface(
                new_iface,
                ignore_link_local=ignore_link_local,
            )

            mock_methods['generic_to_host'].assert_called_once_with('ge0')
            mock_methods['get_interface'].assert_called_once_with('ge0')
            mock_methods['_update_addresses'].assert_called_once_with(
                'em0', new_iface, old_iface)

    def test_update_interface(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = []

        self._update_interface_test_hlpr(iface, old_iface)

    def test_update_interface_ignore_link_local(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = [netaddr.IPAddress('fe80::1')]

        self._update_interface_test_hlpr(iface, old_iface)
        self.assertEqual(old_iface.addresses, [])

    def test_update_interface_do_not_ignore_link_local(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []

        link_local = netaddr.IPAddress('fe80::1')

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = [link_local]

        self._update_interface_test_hlpr(iface, old_iface, False)
        self.assertEqual(old_iface.addresses, [link_local])

    def test_update_addresses(self):
        iface = mock.Mock()
        old_iface = mock.Mock()

        with mock.patch.object(ip.IPManager, '_update_set') as us:
            mgr = ip.IPManager()
            mgr._update_addresses('em0', iface, old_iface)

            us.assert_called_once_with(
                'em0',
                iface,
                old_iface,
                'all_addresses',
                mock.ANY,
                mock.ANY,
                mock.ANY
            )

    def test_address_add(self):
        cmd = '/sbin/ip'
        v4 = netaddr.IPNetwork('192.168.105.2/24')
        v6 = netaddr.IPNetwork('fdca:3ba5:a17a:acda:20c:29ff:fe94:723d/64')
        iface = mock.Mock(all_addresses=[v4, v6], ifname='em0')
        old_iface = mock.Mock(all_addresses=[], ifname='em0')

        mgr = ip.IPManager()
        with mock.patch.object(
            mgr, 'generic_to_host', lambda x: x.replace('ge', 'em')
        ):
            mgr._update_addresses('em0', iface, old_iface)
            assert self.mock_execute.call_args_list == [
                mock.call([
                    cmd, 'addr', 'add', '192.168.105.2/24', 'brd', '+', 'dev',
                    'em0'
                ], 'sudo'),
                mock.call([cmd, 'link', 'set', 'em0', 'up'], 'sudo'),
                mock.call([cmd, 'addr', 'show', 'em0']),
                mock.call([
                    cmd, '-6', 'addr', 'add',
                    'fdca:3ba5:a17a:acda:20c:29ff:fe94:723d/64', 'dev', 'em0'
                ], 'sudo'),
                mock.call([cmd, 'link', 'set', 'em0', 'up'], 'sudo'),
                mock.call([cmd, 'addr', 'show', 'em0'])
            ]

    def test_address_remove(self):
        cmd = '/sbin/ip'
        v4 = netaddr.IPNetwork('192.168.105.2/24')
        v6 = netaddr.IPNetwork('fdca:3ba5:a17a:acda:20c:29ff:fe94:723d/64')
        iface = mock.Mock(all_addresses=[])
        old_iface = mock.Mock(all_addresses=[v4, v6])

        mgr = ip.IPManager()
        mgr._update_addresses('em0', iface, old_iface)
        assert self.mock_execute.call_args_list == [
            mock.call([cmd, 'addr', 'del', str(v4), 'dev', 'em0'], 'sudo'),
            mock.call(['conntrack', '-D', '-d', str(v4.ip)], 'sudo'),
            mock.call(['conntrack', '-D', '-q', str(v4.ip)], 'sudo'),
            mock.call([
                cmd, '-6', 'addr', 'del', str(v6), 'dev', 'em0'
            ], 'sudo'),
        ]

    def test_update_set(self):
        iface = mock.Mock()
        a = netaddr.IPNetwork('192.168.101.2/24')
        b = netaddr.IPNetwork('192.168.102.2/24')
        c = netaddr.IPNetwork('192.168.103.2/24')
        iface.all_addresses = [a, b]
        iface.ifname = 'em0'

        old_iface = mock.Mock()
        old_iface.all_addresses = [b, c]
        old_iface.ifname = 'em0'

        add = lambda g: ('addr', 'add', '/'.join(map(str, g)), 'dev', 'em0')
        delete = lambda g: ('addr', 'del', '/'.join(map(str, g)), 'dev', 'em0')
        mutator = lambda x: (x.ip, x.prefixlen)

        mgr = ip.IPManager()
        with mock.patch.object(
            mgr, 'generic_to_host', lambda x: x.replace('ge', 'em')
        ):
            mgr._update_set('em0', iface, old_iface, 'all_addresses', add,
                            delete, mutator=mutator)

            assert self.mock_execute.call_args_list == [
                mock.call([
                    '/sbin/ip', 'addr', 'add', str(a), 'dev', 'em0'
                ], 'sudo'),
                mock.call(['/sbin/ip', 'link', 'set', 'em0', 'up'], 'sudo'),
                mock.call(['/sbin/ip', 'addr', 'show', 'em0']),
                mock.call([
                    '/sbin/ip', 'addr', 'del', str(c), 'dev', 'em0'
                ], 'sudo'),
                mock.call(['conntrack', '-D', '-d', str(c.ip)], 'sudo'),
                mock.call(['conntrack', '-D', '-q', str(c.ip)], 'sudo'),
            ]

    def test_update_set_no_diff(self):
        iface = mock.Mock()
        iface.all_addresses = ['a', 'b']

        old_iface = mock.Mock()
        old_iface.all_addresses = ['a', 'b']

        add = lambda g: ('em0', 'add', g)
        delete = lambda g: ('em0', 'del', g)

        mgr = ip.IPManager()
        mgr._update_set('em0', iface, old_iface, 'all_addresses', add, delete)
        self.assertEqual(self.mock_execute.call_count, 0)


class TestDisableDAD(TestCase):
    """
    Duplicate Address Detection should be auto-disabled for non-external
    networks.
    """

    def setUp(self):
        self.execute_patch = mock.patch('akanda.router.utils.execute')
        self.mock_execute = self.execute_patch.start()

    def tearDown(self):
        self.execute_patch.stop()

    def test_dad_for_external(self):
        mgr = ip.IPManager()
        with mock.patch.object(mgr, 'generic_to_host', lambda x: x):
            mgr.disable_duplicate_address_detection(models.Network(
                'ABC123',
                models.Interface('eth1'),
                network_type=models.Network.TYPE_EXTERNAL
            ))
            assert self.mock_execute.call_count == 0

    def test_dad_for_management(self):
        mgr = ip.IPManager()
        with mock.patch.object(mgr, 'generic_to_host', lambda x: x):
            mgr.disable_duplicate_address_detection(models.Network(
                'ABC123',
                models.Interface('eth0'),
                network_type=models.Network.TYPE_MANAGEMENT
            ))
        assert self.mock_execute.call_count == 1
        assert self.mock_execute.call_args_list == [
            mock.call([
                'sysctl', '-w', 'net.ipv6.conf.eth0.accept_dad=0'
            ], 'sudo'),
        ]

    def test_dad_for_internal(self):
        mgr = ip.IPManager()
        with mock.patch.object(mgr, 'generic_to_host', lambda x: x):
            mgr.disable_duplicate_address_detection(models.Network(
                'ABC123',
                models.Interface('eth2'),
                network_type=models.Network.TYPE_INTERNAL
            ))
        assert self.mock_execute.call_count == 1
        assert self.mock_execute.call_args_list == [
            mock.call([
                'sysctl', '-w', 'net.ipv6.conf.eth2.accept_dad=0'
            ], 'sudo'),
        ]

    def test_sysctl_failure(self):
        logger = ip.LOG
        logger.level = logging.DEBUG
        buff = StringIO()
        handler = logging.StreamHandler(buff)

        self.mock_execute.side_effect = RuntimeError
        mgr = ip.IPManager()
        with mock.patch.object(mgr, 'generic_to_host', lambda x: x):
            try:
                logger.addHandler(handler)
                mgr.disable_duplicate_address_detection(models.Network(
                    'ABC123',
                    models.Interface('eth0'),
                    network_type=models.Network.TYPE_MANAGEMENT
                ))
                assert 'Failed to disable v6 dad on eth0' in buff.getvalue()
            finally:
                logger.removeHandler(handler)

class ParseTestCase(TestCase):
    def test_parse_interfaces(self):
        with mock.patch.object(ip, '_parse_interface') as parse:
            parse.side_effect = lambda x: x

            retval = ip._parse_interfaces(SAMPLE_OUTPUT)
            self.assertEqual(len(retval), 3)

    def test_parse_interfaces_with_filter(self):
        with mock.patch.object(ip, '_parse_interface') as parse:
            parse.side_effect = lambda x: x
            retval = ip._parse_interfaces(SAMPLE_OUTPUT, ['eth'])
            self.assertEqual(len(retval), 2)

            for chunk in retval:
                assert re.search('^[0-9]: eth', chunk) is not None

    def test_parse_interface(self):
        retval = ip._parse_interface(SAMPLE_SINGLE_OUTPUT)
        self.assertEqual(retval.ifname, 'eth1')
        self.assertEqual(retval.lladdr, 'fa:16:3e:7a:d8:64')
        self.assertEqual(retval.mtu, 1500)
        self.assertEqual(retval.flags, [
            'BROADCAST',
            'MULTICAST',
            'UP',
            'LOWER_UP'
        ])

    def test_parse_head(self):
        expected = dict(
            ifname='eth1',
            mtu=1500,
            flags=['BROADCAST', 'MULTICAST', 'UP', 'LOWER_UP']
        )
        retval = ip._parse_head(SAMPLE_SINGLE_OUTPUT.split('\n')[0])
        self.assertEqual(retval, expected)

    def test_parse_lladdr(self):
        retval = ip._parse_lladdr(SAMPLE_SINGLE_OUTPUT.split('\n')[1])
        self.assertEqual(
            retval,
            'fa:16:3e:7a:d8:64'
        )

    def test_parse_inet(self):
        inet_sample = SAMPLE_SINGLE_OUTPUT.split('\n')[2].strip()
        retval = ip._parse_inet(inet_sample)

        self.assertEqual(str(retval),
                         str(netaddr.IPNetwork('192.168.105.2/24')))

    def test_parse_inet6(self):
        inet_sample = SAMPLE_SINGLE_OUTPUT.split('\n')[3].strip()
        retval = ip._parse_inet(inet_sample)

        self.assertEqual(
            str(retval),
            str(netaddr.IPNetwork('fe80::f816:3eff:fe7a:d864/64'))
        )
