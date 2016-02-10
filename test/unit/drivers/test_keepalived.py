# Copyright 2016 Akanda, Inc.
#
# Author: Akanda, Inc.
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

from astara_router.drivers import keepalived


class KeepalivedVipAddressTestCase(TestCase):
    def test_vip_address(self):
        addr = netaddr.IPNetwork('10.0.0.1/32')
        vip = keepalived.KeepalivedVipAddress(
            address=addr, interface='eth0')
        self.assertEqual(vip.address, addr)
        self.assertEqual(vip.interface, 'eth0')

    def test_vip_address_equal(self):
        addr = netaddr.IPNetwork('10.0.0.1/32')
        vip1 = keepalived.KeepalivedVipAddress(
            address=addr, interface='eth0')
        addr = netaddr.IPNetwork('10.0.0.1/32')
        vip2 = keepalived.KeepalivedVipAddress(
            address=addr, interface='eth0')
        self.assertTrue(vip1 == vip2)

    def test_vip_address_not_equal(self):
        addr = netaddr.IPNetwork('10.0.0.1/32')
        vip1 = keepalived.KeepalivedVipAddress(
            address=addr, interface='eth0')
        addr = netaddr.IPNetwork('10.0.0.21/32')
        vip2 = keepalived.KeepalivedVipAddress(
            address=addr, interface='eth0')
        self.assertFalse(vip1 == vip2)


class KeepalivedRouteTestCase(TestCase):
    def test_keepalived_route(self):
        route = keepalived.KeepalivedRoute(
            destination='10.0.0.0/24',
            gateway='10.0.0.1')
        self.assertEqual(route.destination, '10.0.0.0/24')
        self.assertEqual(route.gateway, '10.0.0.1')

    def test_keepalived_route_equal(self):
        route1 = keepalived.KeepalivedRoute(
            destination='10.0.0.0/24',
            gateway='10.0.0.1')
        route2 = keepalived.KeepalivedRoute(
            destination='10.0.0.0/24',
            gateway='10.0.0.1')
        self.assertTrue(route1 == route2)

    def test_keepalived_route_not_equal(self):
        route1 = keepalived.KeepalivedRoute(
            destination='10.0.0.0/24',
            gateway='10.0.0.1')
        route2 = keepalived.KeepalivedRoute(
            destination='10.0.0.0/24',
            gateway='10.0.0.2')
        self.assertFalse(route1 == route2)


class KeepalivedInstanceTestCase(TestCase):
    def setUp(self):
        self.instance = keepalived.KeepalivedInstance(
            interface='eth0',
            vrrp_id=1,
            unicast_src_ip='10.0.0.1')

    def test_init(self):
        self.assertEqual(self.instance.interface, 'eth0')
        self.assertEqual(self.instance.vrrp_id, 1)
        self.assertEqual(self.instance.unicast_src_ip, '10.0.0.1')
        self.assertEqual(self.instance.name, 'astara_vrrp_eth0')

    @mock.patch.object(keepalived, 'KeepalivedVipAddress')
    def test_add_vip(self, fake_vip):
        addr = netaddr.IPNetwork('10.0.0.1/32')
        fake_vip.return_value = 'fake_vip'
        self.instance.add_vip(addr)
        self.assertIn('fake_vip', self.instance.vips)
        fake_vip.assert_called_with(addr, self.instance.interface)

    @mock.patch.object(keepalived, 'KeepalivedRoute')
    def test_add_route(self, fake_route):
        fake_route.return_value = 'fake_route'
        self.instance.add_route('10.0.0.0/24', '10.0.0.1')
        self.assertIn('fake_route', self.instance.routes)
        fake_route.assert_called_with('10.0.0.0/24', '10.0.0.1')


class KeepalivedManagerTestCase(TestCase):
    def setUp(self):
        super(KeepalivedManagerTestCase, self).setUp()
        self.fake_instance = mock.Mock(
            spec=keepalived.KeepalivedInstance, name='fake_instance')
        self.get_instance_p = mock.patch.object(
            keepalived.KeepalivedManager, '_get_instance')
        self.fake_get_instance = self.get_instance_p.start()
        self.fake_get_instance.return_value = self.fake_instance
        self.addCleanup(self.get_instance_p.stop)
        self.mgr = keepalived.KeepalivedManager()
        self.mgr.instances = {
            'eth0': self.fake_instance
        }

    def test_set_management_address(self):
        self.mgr.set_management_address('10.0.0.1')
        self.assertEqual(self.fake_instance.unicast_src_ip, '10.0.0.1')

    def test_set_default_gateway(self):
        self.mgr.set_default_gateway(
            ip_version=4, gateway_ip='10.0.0.1', interface='eth0')
        self.fake_instance.add_route.assert_called_with(
            'default', '10.0.0.1')

    def test_set_default_gateway_v6(self):
        ip = 'fdca:3ba5:a17a:acda:f816:3eff:fe5d:84'
        self.mgr.set_default_gateway(
            ip_version=6, gateway_ip=ip, interface='eth0')
        self.fake_instance.add_route.assert_called_with(
            'default6', ip)

    def test_set_priority(self):
        self.mgr.set_priority(60)
        self.assertEqual(self.mgr.priority, 60)
