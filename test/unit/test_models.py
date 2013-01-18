import textwrap

import mock
import netaddr
from unittest2 import TestCase

from akanda.router import models


class InterfaceModelTestCase(TestCase):
    """
    """
    def test_ifname(self):
        iface = models.Interface(ifname="em0")
        self.assertEquals(iface.ifname, "em0")

    def test_to_dict(self):
        iface = models.Interface()
        result = iface.to_dict()
        expected = [
            'addresses', 'description', 'groups', 'ifname', 'lladdr',
            'media', 'mtu', 'state']
        self.assertTrue(isinstance(result, dict))
        self.assertItemsEqual(result.keys(), expected)

    def test_to_dict_extended(self):
        iface = models.Interface()
        result = iface.to_dict(True)
        expected = [
            'addresses', 'description', 'groups', 'ifname', 'lladdr',
            'media', 'mtu', 'state', 'flags', 'extra_params']
        self.assertTrue(isinstance(result, dict))
        self.assertItemsEqual(result.keys(), expected)

    def test_repr(self):
        iface = models.Interface(ifname='ge0', addresses=['192.168.1.1/24'])
        expected = "<Interface: ge0 ['192.168.1.1/24']>"
        self.assertEqual(expected, repr(iface))

    def test_eq_other_none(self):
        iface = models.Interface(ifname='ge0', addresses=['192.168.1.1/24'])
        self.assertNotEqual(iface, None)

    def test_eq_other_same_instance(self):
        iface = models.Interface(ifname='ge0', addresses=['192.168.1.1/24'])
        self.assertEqual(iface, iface)

    def test_eq_other_same_values(self):
        iface = models.Interface(ifname='ge0', addresses=['192.168.1.1/24'])
        iface2 = models.Interface(ifname='ge0', addresses=['192.168.1.1/24'])
        self.assertEqual(iface, iface2)

    def test_eq_other_changed_values(self):
        iface = models.Interface(ifname='ge0', addresses=['192.168.1.1/24'])
        iface2 = models.Interface(ifname='ge1', addresses=['192.168.1.2/24'])
        self.assertNotEqual(iface, iface2)

    def test_description(self):
        iface = models.Interface()
        iface.description = 'the_description'
        self.assertEqual('the_description', iface.description)

    def test_description_failure(self):
        iface = models.Interface()
        with self.assertRaises(ValueError):
            iface.description = 'the description'

    def test_is_up_extra_params(self):
        self.assertFalse(models.Interface().is_up)
        iface = models.Interface(state='up')
        self.assertTrue(iface.is_up)

    def test_is_up_flags(self):
        self.assertFalse(models.Interface().is_up)
        iface = models.Interface(flags=['UP'])
        self.assertTrue(iface.is_up)

    def test_from_dict(self):
        d = {'ifname': 'ge0',
             'addresses': ['192.168.1.1/24'],
             'state': 'up',
             'flags': ['UP', 'BROADCAST'],
             'lladdr': 'aa:bb:cc:dd:ee:ff'}
        iface = models.Interface.from_dict(d)
        self.assertEqual(iface.ifname, 'ge0')
        self.assertEqual(iface.addresses,
                         [netaddr.IPNetwork('192.168.1.1/24')])
        self.assertEqual(iface.extra_params["state"], 'up')
        self.assertEqual(iface.flags, ['UP', 'BROADCAST'])
        self.assertEqual(iface.lladdr, 'aa:bb:cc:dd:ee:ff')

    def test_from_dict_function(self):
        d = dict(ifname='ge0',
                 addresses=['192.168.1.1/24'],
                 flags=['UP', 'BROADCAST'],
                 lladdr='aa:bb:cc:dd:ee:ff')
        iface = models.Interface.from_dict(d)
        self.assertEqual(iface.ifname, 'ge0')
        self.assertEqual(iface.addresses,
                         [netaddr.IPNetwork('192.168.1.1/24')])
        self.assertEqual(iface.flags, ['UP', 'BROADCAST'])
        self.assertEqual(iface.lladdr, 'aa:bb:cc:dd:ee:ff')


class FilterRuleModelTestCase(TestCase):
    def test_filter_rule(self):
        fr = models.FilterRule(action='pass', family='inet',
                               destination='192.168.1.1/32')

        self.assertEqual(fr.action, 'pass')
        self.assertEqual(fr.family, 'inet')
        self.assertEqual(fr.destination, netaddr.IPNetwork('192.168.1.1/32'))

    def test_setattr_action_valid(self):
        fr = models.FilterRule(action='block')
        self.assertEqual(fr.action, 'block')

    def test_setattr_action_invalid(self):
        with self.assertRaises(ValueError):
            models.FilterRule(action='reject')

    def test_setattr_invalid_family(self):
        with self.assertRaises(ValueError):
            models.FilterRule(action='pass', family='raw')

    def test_setattr_source_destination_cidr(self):
        fr = models.FilterRule(action='pass',
                               destination='192.168.1.2/32')
        self.assertEqual(fr.destination, netaddr.IPNetwork('192.168.1.2/32'))

        fr = models.FilterRule(action='pass',
                               source='192.168.1.2/32')
        self.assertEqual(fr.source, netaddr.IPNetwork('192.168.1.2/32'))

    def test_setattr_source_destination_label(self):
        fr = models.FilterRule(action='pass',
                               destination='foo')
        self.assertEqual(fr.destination, 'foo')

        fr = models.FilterRule(action='pass',
                               source='bar')
        self.assertEqual(fr.source, 'bar')

    def test_setattr_redirect(self):
        fr = models.FilterRule(action='pass',
                               redirect='192.168.1.1')
        self.assertEqual(fr.redirect, netaddr.IPAddress('192.168.1.1'))

    def test_setattr_port(self):
        fr = models.FilterRule(action='pass',
                               source_port='22')
        self.assertEqual(fr.source_port, 22)

        fr = models.FilterRule(action='pass',
                               destination_port='23')
        self.assertEqual(fr.destination_port, 23)

    def test_setattr_port_none(self):
        fr = models.FilterRule(action='pass',
                               destination_port=None)
        self.assertIs(fr.destination_port, None)

    def test_setattr_protocol_valid(self):
        for p in ['tcp', 'udp', 'imcp']:
            fr = models.FilterRule(action='pass', protocol=p)
            self.assertEqual(fr.protocol, p)

    def test_setattr_protocol_invalid(self):
        with self.assertRaises(ValueError):
            models.FilterRule(action='pass', protocol='made_up_proto')

    def _pf_rule_test_helper(self, d, expected):
        fr = models.FilterRule(**d)
        self.assertEqual(fr.pf_rule, expected)

    def test_pf_rule_basic(self):
        self._pf_rule_test_helper(dict(action='pass'), 'pass')
        self._pf_rule_test_helper(dict(action='block'), 'block')

    def test_pf_rule_interface(self):
        self._pf_rule_test_helper(dict(action='pass', interface='ge0'),
                                  'pass on ge0')

    def test_pf_rule_family(self):
        self._pf_rule_test_helper(dict(action='block', family='inet6'),
                                  'block inet6')

    def test_pf_rule_protocol(self):
        self._pf_rule_test_helper(dict(action='block', protocol='tcp'),
                                  'block proto tcp')

    def test_pf_rule_source_table(self):
        self._pf_rule_test_helper(dict(action='block', source='foo'),
                                  'block from foo')

    def test_pf_rule_source_address(self):
        args = dict(action='block', source='192.168.1.0/24')
        self._pf_rule_test_helper(args, 'block from 192.168.1.0/24')

    def test_pf_rule_source_port(self):
        args = dict(action='block', source_port=22)
        self._pf_rule_test_helper(args, 'block from port 22')

    def test_pf_rule_source_address_and_port(self):
        args = dict(action='pass', source='192.168.1.1/32', source_port=22)
        self._pf_rule_test_helper(args, 'pass from 192.168.1.1/32 port 22')

    def test_pf_rule_destination_interface(self):
        args = dict(action='block', destination_interface="ge1")
        self._pf_rule_test_helper(args, 'block to ge1')

    def test_pf_rule_destination_table(self):
        args = dict(action='block', destination="foo")
        self._pf_rule_test_helper(args, 'block to foo')

    def test_pf_rule_destination_address(self):
        args = dict(action='block', destination="192.168.1.0/24")
        self._pf_rule_test_helper(args, 'block to 192.168.1.0/24')

    def test_pf_rule_destination_port(self):
        args = dict(action='block', destination_port="23")
        self._pf_rule_test_helper(args, 'block to port 23')

    def test_pf_rule_destination_address_and_port(self):
        args = dict(action='block', destination='192.168.1.2/32',
                    destination_port="23")
        self._pf_rule_test_helper(args, 'block to 192.168.1.2/32 port 23')

    def test_pf_rule_redirect(self):
        args = dict(action='pass',
                    destination_port="23",
                    redirect="192.168.1.1")
        self._pf_rule_test_helper(args, 'pass to port 23 rdr-to 192.168.1.1')

    def test_pf_rule_redirect_port(self):
        args = dict(action='pass',
                    destination_port="23",
                    redirect_port="24")
        self._pf_rule_test_helper(args, 'pass to port 23 rdr-to port 24')

    def test_pf_rule_from_dict(self):
        args = dict(action='pass',
                    destination_port="23",
                    redirect="192.168.1.2")

        pr = models.FilterRule.from_dict(args)
        self.assertEqual(pr.action, 'pass')
        self.assertEqual(pr.destination_port, 23)
        self.assertEqual(pr.redirect, netaddr.IPAddress('192.168.1.2'))


class AnchorTestCase(TestCase):
    def test_anchor(self):
        a = models.Anchor('foo', [])
        self.assertEqual(a.name, 'foo')
        self.assertEqual(a.rules, [])

    def test_anchor_external_pf_rule(self):
        a = models.Anchor('foo', [])
        self.assertEqual(a.external_pf_rule('/etc/pf'),
                         'anchor foo\nload anchor foo from /etc/pf/foo')

    def test_anchor_pf_rule_empty(self):
        a = models.Anchor('foo', [])
        self.assertEqual(a.pf_rule, 'anchor foo {\n\n}')

    def test_anchor_pf_rule(self):
        fr = models.FilterRule(action='block', interface="ge0")
        a = models.Anchor('foo', [fr])
        self.assertEqual(a.pf_rule, 'anchor foo {\nblock on ge0\n}')


class AddressBookTestCase(TestCase):
    def test_entry(self):
        ab = models.AddressBookEntry('foo', ['192.168.1.0/24'])
        self.assertEqual(ab.name, 'foo')
        self.assertEqual(ab.cidrs, [netaddr.IPNetwork('192.168.1.0/24')])

    def test_pf_rule(self):
        ab = models.AddressBookEntry('foo', ['192.168.1.0/24'])
        self.assertEqual(ab.pf_rule, 'table <foo> {192.168.1.0/24}')

    def test_external_pf_rule(self):
        ab = models.AddressBookEntry('foo', ['192.168.1.0/24'])
        self.assertEqual(ab.external_pf_rule('/etc'),
                         'table foo\npersist file "/etc/foo"')

    def test_external_table_data(self):
        ab = models.AddressBookEntry('foo', ['192.168.1.0/24',
                                             '172.16.16.0/16'])
        self.assertEqual(ab.external_table_data(),
                         '192.168.1.0/24\n172.16.16.0/16')


class LabelTestCase(TestCase):
    def test_label(self):
        l = models.Label('foo', ['192.168.1.0/24'])
        self.assertEqual(l.name, 'foo')
        self.assertEqual(l.cidrs, [netaddr.IPNetwork('192.168.1.0/24')])

    def test_pf_rule(self):
        l = models.Label('foo', ['192.168.1.0/24'])
        self.assertEqual(l.pf_rule,
                         'match out on egress to {192.168.1.0/24} label "foo"')


class AllocationTestCase(TestCase):
    def test_allocation(self):
        a = models.Allocation(
            'aa:bb:cc:dd:ee:ff',
            {'192.168.1.1': True},  # ipaddr: enable_dhcp
            'hosta.com',
            'device_id'
        )
        self.assertEqual(a.mac_address, 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(a.hostname, 'hosta.com')
        self.assertEqual(a.ip_addresses, {'192.168.1.1': True})
        self.assertEqual(a.device_id, 'device_id')


class StaticRouteTestCase(TestCase):
    def test_static_route(self):
        sr = models.StaticRoute('0.0.0.0/0', '192.168.1.1')
        self.assertEqual(sr.destination, netaddr.IPNetwork('0.0.0.0/0'))
        self.assertEqual(sr.next_hop, netaddr.IPAddress('192.168.1.1'))

    def test_eq_none(self):
        sr = models.StaticRoute('0.0.0.0/0', '192.168.1.1')
        self.assertNotEqual(sr, None)

    def test_eq_equal(self):
        sr1 = models.StaticRoute('0.0.0.0/0', '192.168.1.1')
        sr2 = models.StaticRoute('0.0.0.0/0', '192.168.1.1')
        self.assertEqual(sr1, sr2)

    def test_eq_not_equal(self):
        sr1 = models.StaticRoute('0.0.0.0/0', '192.168.1.1')
        sr2 = models.StaticRoute('172.16.0.0/16', '192.168.1.1')
        self.assertNotEqual(sr1, sr2)


class SubnetTestCase(TestCase):
    def test_subnet(self):
        s = models.Subnet('192.168.1.0/24', '192.168.1.1', True, ['8.8.8.8'],
                          [])

        self.assertEqual(s.cidr, netaddr.IPNetwork('192.168.1.0/24'))
        self.assertEqual(s.gateway_ip, netaddr.IPAddress('192.168.1.1'))
        self.assertTrue(s.dhcp_enabled)
        self.assertEqual(s.dns_nameservers, [netaddr.IPAddress('8.8.8.8')])
        self.assertEqual(s.host_routes, [])


class NetworkTestCase(TestCase):
    def test_network(self):
        interface = mock.Mock()

        n = models.Network('id', interface, 'name')

        self.assertEqual(n.id, 'id')
        self.assertEqual(n.interface, interface)
        self.assertEqual(n.name, 'name')

    def test_network_type_valid(self):
        n = models.Network('id', None, network_type='external')
        self.assertEqual(n.network_type, 'external')

        n = models.Network('id', None, network_type='internal')
        self.assertEqual(n.network_type, 'internal')

        n = models.Network('id', None, network_type='isolated')
        self.assertEqual(n.network_type, 'isolated')

        n = models.Network('id', None, network_type='management')
        self.assertEqual(n.network_type, 'management')

    def test_network_type_invalid(self):
        with self.assertRaises(ValueError):
            n = models.Network('id', None, network_type='invalid')

    def test_v4_conf_service_valid(self):
        n = models.Network('id', None, v4_conf_service='dhcp')
        self.assertEqual(n.v4_conf_service, 'dhcp')

        n = models.Network('id', None, v4_conf_service='static')
        self.assertEqual(n.v4_conf_service, 'static')

    def test_v4_conf_service_invalid(self):
        with self.assertRaises(ValueError):
            n = models.Network('id', None, v4_conf_service='invalid')

    def test_v6_conf_service_valid(self):
        n = models.Network('id', None, v6_conf_service='dhcp')
        self.assertEqual(n.v6_conf_service, 'dhcp')

        n = models.Network('id', None, v6_conf_service='static')
        self.assertEqual(n.v6_conf_service, 'static')

        n = models.Network('id', None, v6_conf_service='ra')
        self.assertEqual(n.v6_conf_service, 'ra')

    def test_v6_conf_service_invalid(self):
        with self.assertRaises(ValueError):
            n = models.Network('id', None, v6_conf_service='invalid')


class ConfigurationTestCase(TestCase):
    def test_init_only_networks(self):
        subnet = dict(
            cidr='192.168.1.0/24',
            gateway_ip='192.168.1.1',
            dhcp_enabled=True,
            dns_nameservers=['8.8.8.8'])

        network = dict(
            network_id='netid',
            name='thenet',
            interface=dict(ifname='ge0', addresses=['192.168.1.1/24']),
            allocations=[],
            subnets=[subnet])

        c = models.Configuration(dict(networks=[network]))
        self.assertEqual(len(c.networks), 1)
        self.assertEqual(c.networks[0],
                         models.Network.from_dict(network))

    def test_init_only_static_routes(self):
        routes = [('0.0.0.0/0', '192.168.1.1'),
                  ('172.16.77.0/16', '192.168.1.254')]
        c = models.Configuration(dict(networks=[], static_routes=routes))

        self.assertEqual(len(c.static_routes), 2)
        self.assertEqual(
            c.static_routes,
            [models.StaticRoute(*routes[0]), models.StaticRoute(*routes[1])])

    def test_init_address_book(self):
        ab = {"webservers": ["192.168.57.101/32", "192.168.57.230/32"]}

        c = models.Configuration(dict(networks=[], address_book=ab))
        self.assertEqual(
            c.address_book.get('webservers'),
            models.AddressBookEntry('webservers', ab['webservers']))

    def test_init_label(self):
        labels = {"external": ["192.168.57.0/24"]}

        c = models.Configuration(dict(networks=[], labels=labels))
        self.assertEqual(
            c.labels[0],
            models.Label('external', ['192.168.57.0/24']))

    def test_init_empty_anchor(self):
        anchor_dict = dict(
            name='theanchor',
            rules=[])

        c = models.Configuration(dict(networks=[], anchors=[anchor_dict]))
        self.assertEqual(len(c.anchors), 1)

    def test_init_anchor(self):
        test_rule = dict(action='block', source='192.168.1.1/32')
        anchor_dict = dict(name='theanchor', rules=[test_rule])

        c = models.Configuration(dict(networks=[], anchors=[anchor_dict]))
        self.assertEqual(len(c.anchors), 1)
        self.assertEqual(len(c.anchors[0].rules), 1)
        self.assertEqual(c.anchors[0].rules[0].action, 'block')

    def _validate_test_helper(self, rule_dict, expect_errors=False):
        network = dict(
            network_id='netid',
            name='thenet',
            interface=dict(ifname='ge0', addresses=['192.168.1.1/24']),
            allocations=[])

        ab = {"webservers": ["192.168.57.101/32", "192.168.57.230/32"]}
        anchor_dict = dict(name='theanchor', rules=[rule_dict])

        c = models.Configuration(
            dict(networks=[network], anchors=[anchor_dict], address_book=ab))

        errors = c.validate()

        if expect_errors:
            return errors
        else:
            self.assertEqual(errors, [])

    def test_validate_block_all(self):
        rule = dict(action='block')
        self._validate_test_helper(rule)

    def test_validate_pass_all(self):
        rule = dict(action='pass')
        self._validate_test_helper(rule)

    def test_validate_interface_valid(self):
        rule = dict(action='pass', interface='ge0')
        self._validate_test_helper(rule)

    def test_validate_interface_invalid(self):
        rule = dict(action='pass', interface='lo0')
        errors = self._validate_test_helper(rule, True)
        self.assertEqual(len(errors), 1)

    def test_validate_source_valid_addressbook(self):
        rule = dict(action='pass', source='webservers')
        self._validate_test_helper(rule)

    def test_validate_source_valid_cidr(self):
        rule = dict(action='pass', source='192.168.1.1/32')
        self._validate_test_helper(rule)

    def test_validate_source_invalid(self):
        rule = dict(action='pass', source='foo')
        errors = self._validate_test_helper(rule, True)
        self.assertEqual(len(errors), 1)

    def test_validate_dest_valid_addressbook(self):
        rule = dict(action='pass', destination='webservers')
        self._validate_test_helper(rule)

    def test_validate_dest_valid_cidr(self):
        rule = dict(action='pass', destination='192.168.1.1/32')
        self._validate_test_helper(rule)

    def test_validate_destination_invalid(self):
        rule = dict(action='pass', destination='foo')
        errors = self._validate_test_helper(rule, True)
        self.assertEqual(len(errors), 1)

    def test_to_dict(self):
        c = models.Configuration({'networks': []})
        expected = dict(networks=[],
                        address_book={},
                        static_routes=[],
                        anchors=[])

        self.assertEqual(c.to_dict(), expected)

    def _pf_config_test_helper(self, conf_dict, test_expectations):
        base = ['block']

        expected = '\n'.join(base + test_expectations + [''])

        attrs = dict(
            BASE_RULES=base,
            MANAGEMENT_PORTS=[22],
            OUTBOUND_TCP_PORTS=[80],
            OUTBOUND_UDP_PORTS=[53])

        with mock.patch.multiple('akanda.router.defaults', **attrs) as defs:
            c = models.Configuration(conf_dict)
            self.assertEqual(c.pf_config, expected)

    def test_pf_config_default(self):
        self._pf_config_test_helper({'networks': []}, [])

    def test_pf_config_nat(self):
        ext_net = dict(network_id='ext',
                       interface=dict(ifname='ge0'),
                       network_type='external')
        int_net = dict(network_id='int',
                       interface=dict(ifname='ge1'),
                       network_type='internal')

        self._pf_config_test_helper(
            {'networks': [ext_net, int_net]},
            ['pass on ge0 inet6 proto ospf',
             ('pass in quick on ge1 proto tcp to 169.254.169.254 port http '
              'rdr-to 127.0.0.1 port 9601'),
             'pass out on ge0 from ge1:network to any nat-to ge0',
             'pass quick on ge1 proto udp from port 68 to port 67',
             'pass quick on ge1 proto udp from port 546 to port 547',
             'pass in on ge1 proto tcp to any port {80}',
             'pass in on ge1 proto udp to any port {53}'])

    def test_pf_config_isolated(self):
        ext_net = dict(network_id='ext',
                       interface=dict(ifname='ge0'),
                       network_type='external')
        int_net = dict(network_id='int',
                       interface=dict(ifname='ge1'),
                       network_type='isolated')

        self._pf_config_test_helper(
            {'networks': [ext_net, int_net]},
            ['pass on ge0 inet6 proto ospf',
             ('pass in quick on ge1 proto tcp to 169.254.169.254 port http '
              'rdr-to 127.0.0.1 port 9601'),
             'block from ge1:network to any'])

    def test_pf_config_management(self):
        ext_net = dict(network_id='ext',
                       interface=dict(ifname='ge0'),
                       network_type='external')
        int_net = dict(network_id='int',
                       interface=dict(ifname='ge1'),
                       network_type='management')

        self._pf_config_test_helper(
            {'networks': [ext_net, int_net]},
            ['pass on ge0 inet6 proto ospf',
             'pass quick proto tcp from ge1:network to ge1 port { 22 }',
             'pass quick proto tcp from ge1 to ge1:network port 9697',
             'block in quick on !ge1 to ge1:network'])

    def test_pf_config_with_addressbook(self):
        ext_net = dict(network_id='ext',
                       interface=dict(ifname='ge0'),
                       network_type='external')
        ab = dict(foo=['192.168.1.1/24'])

        self._pf_config_test_helper(
            {'networks': [ext_net], 'address_book': ab},
            ['pass on ge0 inet6 proto ospf',
             'table <foo> {192.168.1.1/24}'])

    def test_pf_config_with_anchor(self):
        ext_net = dict(network_id='ext',
                       interface=dict(ifname='ge0'),
                       network_type='external')
        anchor = dict(name='foo',
                      rules=[dict(action='pass',
                                  protocol='tcp',
                                  destination_port=22)])
        self._pf_config_test_helper(
            {'networks': [ext_net], 'anchors': [anchor]},
            ['pass on ge0 inet6 proto ospf',
             'anchor foo {\npass proto tcp to port 22\n}'])

    def test_pf_config_with_label(self):
        ext_net = dict(network_id='ext',
                       interface=dict(ifname='ge0'),
                       network_type='external')
        label = dict(foo=['192.168.1.0/24'])

        self._pf_config_test_helper(
            {'networks': [ext_net], 'labels': label},
            ['pass on ge0 inet6 proto ospf',
             'match out on egress to {192.168.1.0/24} label "foo"'])
