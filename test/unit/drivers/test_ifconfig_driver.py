from unittest2 import TestCase

import mock
import netaddr

from akanda.router.drivers import ifconfig


SAMPLE_OUTPUT = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 33152
\tpriority: 0
\tgroups: lo
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x5
\tinet 127.0.0.1 netmask 0xff000000
em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tlladdr 08:00:27:7a:6f:46
\tpriority: 0
\tmedia: Ethernet autoselect (1000baseT full-duplex)
\tstatus: active
\tinet6 fe80::a00:27ff:fe7a:6f46%em0 prefixlen 64 scopeid 0x1
em1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tlladdr 08:00:27:32:1f:d1
\tpriority: 0
\tgroups: egress
\tmedia: Ethernet autoselect (1000baseT full-duplex)
\tstatus: active
\tinet6 fe80::a00:27ff:fe32:1fd1%em1 prefixlen 64 scopeid 0x2
\tinet 10.0.3.15 netmask 0xffffff00 broadcast 10.0.3.255
em2: flags=8802<BROADCAST,SIMPLEX,MULTICAST> mtu 1500
\tlladdr 08:00:27:53:cd:c8
\tpriority: 0
\tmedia: Ethernet autoselect (1000baseT full-duplex)
\tstatus: active
enc0: flags=0<>
\tpriority: 0
\tgroups: enc
\tstatus: active
pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33152
\tpriority: 0
\tgroups: pflog
"""

SAMPLE_SINGLE_OUTPUT = (
    """em1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tlladdr 08:00:27:32:1f:d1
\tpriority: 0
\tgroups: egress
\tmedia: Ethernet autoselect (1000baseT full-duplex)
\tstatus: active
\tinet6 fe80::a00:27ff:fe32:1fd1%em1 prefixlen 64 scopeid 0x2
\tinet 10.0.3.15 netmask 0xffffff00 broadcast 10.0.3.255
""")


class IfconfigTestCase(TestCase):
    """
    """
    def setUp(self):
        self.execute_patch = mock.patch('akanda.router.utils.execute')
        self.mock_execute = self.execute_patch.start()

    def tearDown(self):
        self.execute_patch.stop()

    def test_init(self):
        mgr = ifconfig.InterfaceManager()
        self.assertEqual(mgr.host_mapping.keys(), [])

    def test_get_interfaces(self):
        iface_a = mock.Mock()
        iface_a.ifname = 'em0'

        iface_b = mock.Mock()
        iface_b.ifname = 'em1'
        ifaces = 'akanda.router.drivers.ifconfig._parse_interfaces'
        with mock.patch(ifaces) as parse:
            parse.return_value = [iface_a, iface_b]
            mgr = ifconfig.InterfaceManager()
            interfaces = mgr.get_interfaces()
            self.assertEqual(interfaces, [iface_a, iface_b])

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ifconfig', '-a'])])

    def test_get_interface(self):
        iface_a = mock.Mock()
        iface_a.ifname = 'em0'
        iface = 'akanda.router.drivers.ifconfig._parse_interface'
        ifaces = 'akanda.router.drivers.ifconfig._parse_interfaces'
        with mock.patch(iface) as parse:
            with mock.patch(ifaces) as pi:
                pi.return_value = [iface_a]
                parse.return_value = iface_a
                mgr = ifconfig.InterfaceManager()
                interface = mgr.get_interface('ge0')
                self.assertEqual(interface, iface_a)
                self.assertEqual(iface_a.ifname, 'ge0')

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ifconfig', '-a'])])

    def test_ensure_mapping_uninitialized(self):
        attr = 'get_interfaces'
        with mock.patch.object(ifconfig.InterfaceManager, attr) as get_ifaces:
            mgr = ifconfig.InterfaceManager()
            mgr.ensure_mapping()

            get_ifaces.assert_called_once_with()

    def test_ensure_mapping_initialized(self):
        attr = 'get_interfaces'
        with mock.patch.object(ifconfig.InterfaceManager, attr) as get_ifaces:
            mgr = ifconfig.InterfaceManager()
            mgr.host_mapping['em0'] = 'ge0'
            mgr.ensure_mapping()

            self.assertEqual(get_ifaces.call_count, 0)

    def test_is_valid(self):
        mgr = ifconfig.InterfaceManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}
        self.assertTrue(mgr.is_valid('ge0'))

    def test_generic_to_host(self):
        mgr = ifconfig.InterfaceManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}
        self.assertEqual(mgr.generic_to_host('ge0'), 'em0')
        self.assertIsNone(mgr.generic_to_host('ge1'))

    def test_host_to_generic(self):
        mgr = ifconfig.InterfaceManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}
        self.assertEqual(mgr.host_to_generic('em0'), 'ge0')
        self.assertIsNone(mgr.host_to_generic('em1'))

    def test_update_interfaces(self):
        iface_a = mock.Mock()
        iface_b = mock.Mock()

        attr = 'update_interface'
        with mock.patch.object(ifconfig.InterfaceManager, attr) as update:
            mgr = ifconfig.InterfaceManager()
            mgr.update_interfaces([iface_a, iface_b])
            update.assert_has_calls([mock.call(iface_a), mock.call(iface_b)])

    def test_up(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'

        mgr = ifconfig.InterfaceManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}

        mgr.up(iface)

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ifconfig', 'em0', 'up'], 'sudo')])

    def test_down(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'

        mgr = ifconfig.InterfaceManager()
        mgr.host_mapping = {'em0': 'ge0'}
        mgr.generic_mapping = {'ge0': 'em0'}

        mgr.down(iface)

        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ifconfig', 'em0', 'down'], 'sudo')])

    def _update_interface_test_hlpr(self, new_iface, old_iface,
                                    ignore_link_local=True,
                                    ignore_egress_group=True):
        mock_methods = {
            'generic_to_host': mock.Mock(return_value='em0'),
            'get_interface': mock.Mock(return_value=old_iface),
            '_update_description': mock.Mock(),
            '_update_groups': mock.Mock(),
            '_update_addresses': mock.Mock()}

        with mock.patch.multiple(ifconfig.InterfaceManager, **mock_methods):
            mgr = ifconfig.InterfaceManager()
            mgr.update_interface(
                new_iface,
                ignore_link_local=ignore_link_local,
                ignore_egress_group=ignore_egress_group
            )

            mock_methods['generic_to_host'].assert_called_once_with('ge0')
            mock_methods['get_interface'].assert_called_once_with('ge0')
            mock_methods['_update_description'].assert_called_once_with(
                'em0', new_iface)
            mock_methods['_update_groups'].assert_called_once_with(
                'em0', new_iface, old_iface)
            mock_methods['_update_addresses'].assert_called_once_with(
                'em0', new_iface, old_iface)

    def test_update_interface(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = []
        old_iface.groups = []

        self._update_interface_test_hlpr(iface, old_iface)

    def test_update_interface_ignore_link_local(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = [netaddr.IPAddress('fe80::1')]
        old_iface.groups = []

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
        old_iface.groups = []

        self._update_interface_test_hlpr(iface, old_iface, False)
        self.assertEqual(old_iface.addresses, [link_local])

    def test_update_interface_ignore_egress(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []
        iface.groups = []

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = []
        old_iface.groups = ['egress']

        self._update_interface_test_hlpr(iface, old_iface)
        self.assertEqual(old_iface.groups, [])

    def test_update_interface_do_not_ignore_egress(self):
        iface = mock.Mock()
        iface.ifname = 'ge0'
        iface.addresses = []
        iface.groups = []

        link_local = netaddr.IPAddress('fe80::1')

        old_iface = mock.Mock(name='old')
        old_iface.ifname = 'ge0'
        old_iface.addresses = []
        old_iface.groups = ['egress']

        self._update_interface_test_hlpr(
            iface,
            old_iface,
            ignore_egress_group=False
        )
        self.assertEqual(old_iface.groups, ['egress'])

    def test_update_description(self):
        iface = mock.Mock()
        iface.description = 'internal'

        mgr = ifconfig.InterfaceManager()
        mgr._update_description('em0', iface)
        self.mock_execute.assert_has_calls(
            [mock.call(['/sbin/ifconfig', 'em0', 'description', 'internal'],
                       'sudo')])

    def test_update_groups(self):
        iface = mock.Mock()
        old_iface = mock.Mock()

        with mock.patch.object(ifconfig.InterfaceManager, '_update_set') as us:
            mgr = ifconfig.InterfaceManager()
            mgr._update_groups('em0', iface, old_iface)

            us.assert_called_once_with('em0', iface, old_iface, 'groups',
                                       mock.ANY, mock.ANY)

    def test_update_addresses(self):
        iface = mock.Mock()
        old_iface = mock.Mock()

        with mock.patch.object(ifconfig.InterfaceManager, '_update_set') as us:
            mgr = ifconfig.InterfaceManager()
            mgr._update_addresses('em0', iface, old_iface)

            us.assert_called_once_with('em0', iface, old_iface, 'addresses',
                                       mock.ANY, mock.ANY, mock.ANY)

    def test_update_set(self):
        iface = mock.Mock()
        iface.groups = ['a', 'b']

        old_iface = mock.Mock()
        old_iface.groups = ['b', 'c']

        add = lambda g: ('em0', 'group', g)
        delete = lambda g: ('em0', '-group', g)

        mgr = ifconfig.InterfaceManager()
        mgr._update_set('em0', iface, old_iface, 'groups', add, delete)

        self.mock_execute.assert_has_calls([
            mock.call(['/sbin/ifconfig', 'em0', 'group', 'a'], 'sudo'),
            mock.call(['/sbin/ifconfig', 'em0', '-group', 'c'], 'sudo')
        ])

    def test_update_set_no_diff(self):
        iface = mock.Mock()
        iface.groups = ['a', 'b']

        old_iface = mock.Mock()
        old_iface.groups = ['a', 'b']

        add = lambda g: ('em0', 'group', g)
        delete = lambda g: ('em0', '-group', g)

        mgr = ifconfig.InterfaceManager()
        mgr._update_set('em0', iface, old_iface, 'groups', add, delete)
        self.assertEqual(self.mock_execute.call_count, 0)


class ParseTestCase(TestCase):
    def test_parse_interfaces(self):
        with mock.patch.object(ifconfig, '_parse_interface') as parse:
            parse.side_effect = lambda x: x

            retval = ifconfig._parse_interfaces(SAMPLE_OUTPUT)
            self.assertEqual(len(retval), 6)

    def test_parse_interfaces_with_filter(self):
        with mock.patch.object(ifconfig, '_parse_interface') as parse:
            parse.side_effect = lambda x: x

            retval = ifconfig._parse_interfaces(SAMPLE_OUTPUT, ['em'])
            self.assertEqual(len(retval), 3)

            for chunk in retval:
                self.assertTrue(chunk.startswith('em'))

    def test_parse_interface(self):
        retval = ifconfig._parse_interface(SAMPLE_SINGLE_OUTPUT)
        self.assertEqual(retval.ifname, 'em1')
        self.assertEqual(retval.flags,
                         ['UP', 'BROADCAST', 'RUNNING',
                          'SIMPLEX', 'MULTICAST'])
        self.assertEqual(retval.mtu, 1500)

    def test_parse_head(self):
        expected = dict(
            ifname='em1',
            flags=['UP', 'BROADCAST', 'RUNNING', 'SIMPLEX', 'MULTICAST'],
            mtu=1500)
        retval = ifconfig._parse_head(SAMPLE_SINGLE_OUTPUT.split('\n')[0])
        self.assertEqual(retval, expected)

    def test_parse_inet(self):
        inet_sample = SAMPLE_SINGLE_OUTPUT.split('\n')[-2].strip()
        retval = ifconfig._parse_inet(inet_sample)

        self.assertEqual(retval, netaddr.IPNetwork('10.0.3.15/24'))

    def test_parse_inet6(self):
        inet_sample = SAMPLE_SINGLE_OUTPUT.split('\n')[-3].strip()
        retval = ifconfig._parse_inet(inet_sample)

        self.assertEqual(retval,
                         netaddr.IPNetwork('fe80::a00:27ff:fe32:1fd1/64'))

    def test_parse_other_options(self):
        lladdr_sample = SAMPLE_SINGLE_OUTPUT.split('\n')[1].strip()
        retval = ifconfig._parse_other_params(lladdr_sample)
        self.assertEqual(retval, [('lladdr', '08:00:27:32:1f:d1')])
