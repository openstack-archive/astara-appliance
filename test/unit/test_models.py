from unittest2 import TestCase

import netaddr

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
        self.assertEqual(a.pf_rule, 'anchor foo {\n\n}\n')

    def test_anchor_pf_rule(self):
        fr = models.FilterRule(action='block', interface="ge0")
        a = models.Anchor('foo', [fr])
        self.assertEqual(a.pf_rule, 'anchor foo {\nblock on ge0\n}\n')


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


class AllocationTestCase(TestCase):
    def test_allocation(self):
        a = models.Allocation('aa:bb:cc:dd:ee:ff', 'hosta.com', '192.168.1.1')
        self.assertEqual(a.lladdr, 'aa:bb:cc:dd:ee:ff')
        self.assertEqual(a.hostname, 'hosta.com')
        self.assertEqual(a.ip_address, '192.168.1.1')


class StaticRouteTestCase(TestCase):
    def test_static_route(self):
        sr = models.StaticRoute('0.0.0.0/0', '192.168.1.1')
        self.assertEqual(sr.destination, netaddr.IPNetwork('0.0.0.0/0'))
        self.assertEqual(sr.next_hop, netaddr.IPAddress('192.168.1.1'))
