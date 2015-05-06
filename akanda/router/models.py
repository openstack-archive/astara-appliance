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


import abc
import re

import netaddr

GROUP_NAME_LENGTH = 15
DEFAULT_AS = 64512


class ModelBase(object):
    __metaclass__ = abc.ABCMeta

    def __eq__(self, other):
        return type(self) == type(other) and vars(self) == vars(other)


class Interface(ModelBase):
    """
    """
    def __init__(self, ifname=None, addresses=[], groups=None, flags=None,
                 lladdr=None, mtu=1500, media=None,
                 description=None, **extra_params):
        self.ifname = ifname
        self.description = description
        self.addresses = addresses
        self.groups = [g[:GROUP_NAME_LENGTH] for g in (groups or [])]
        self.flags = flags or []
        self.lladdr = lladdr
        self.mtu = mtu
        self.media = media
        self.extra_params = extra_params
        self._aliases = []

    def __repr__(self):
        return '<Interface: %s %s>' % (self.ifname,
                                       [str(a) for a in self.addresses])

    def __eq__(self, other):
        """Check model equality only on limit fields."""
        return (type(self) == type(other) and
                self.ifname == other.ifname and
                self.all_addresses == other.all_addresses and
                self.description == other.description and
                self.mtu == other.mtu and
                self.groups == other.groups)

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        if not value:
            self._description = ''
        elif re.match('\w*$', value):
            self._description = value
        else:
            raise ValueError('Description must be chars from [a-zA-Z0-9_]')

    @property
    def addresses(self):
        return self._addresses

    @addresses.setter
    def addresses(self, value):
        self._addresses = [netaddr.IPNetwork(a) for a in value]

    @property
    def aliases(self):
        return self._aliases

    @aliases.setter
    def aliases(self, value):
        self._aliases = [netaddr.IPNetwork(a) for a in value]

    @property
    def all_addresses(self):
        return self._addresses + self._aliases

    @property
    def is_up(self):
        if self.extra_params.get('state', '').lower() == 'up':
            return 'UP'
        return 'UP' in self.flags

    @property
    def first_v4(self):
        return self._first_addr_for_version(4)

    @property
    def first_v6(self):
        return self._first_addr_for_version(6)

    def _first_addr_for_version(self, version):
        addrs = sorted(a.ip for a in self._addresses if a.version == version)

        if addrs:
            return addrs[0]

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    def to_dict(self, extended=False):
        include = ['ifname', 'groups', 'mtu', 'lladdr', 'media']
        if extended:
            include.extend(['flags', 'extra_params'])
        retval = dict(
            [(k, v) for k, v in vars(self).iteritems() if k in include])
        retval['description'] = self.description
        retval['addresses'] = self.addresses
        retval['state'] = (self.is_up and 'up') or 'down'
        return retval


class FilterRule(ModelBase):
    """
    """
    def __init__(self, action=None, direction=None, interface=None,
                 family=None, protocol=None, source=None, source_port=None,
                 destination_interface=None,
                 destination=None, destination_port=None,
                 redirect=None, redirect_port=None):

        self.action = action
        self.direction = direction
        self.interface = interface
        self.family = family
        self.protocol = protocol
        self.source = source
        self.source_port = source_port
        self.destination_interface = destination_interface
        self.destination = destination
        self.destination_port = destination_port
        self.redirect = redirect
        self.redirect_port = redirect_port

    def __setattr__(self, name, value):
        if name != 'action' and not value:
            pass
        elif name == 'action':
            if value not in ('pass', 'block'):
                raise ValueError("Action must be 'pass' or 'block' not '%s'" %
                                 value)
        elif name in ('source', 'destination'):
            if '/' in value:
                value = netaddr.IPNetwork(value)
            elif value.lower() == 'any':
                value = None  # any is the default so conver to None
        elif name == 'direction':
            if value not in ('in', 'out'):
                raise ValueError(
                    "Direction must be 'in' or 'out' not '%s'" % value
                )
        elif name == 'redirect':
            value = netaddr.IPAddress(value)
        elif name.endswith('_port'):
            value = int(value)
        elif name == 'family':
            if value not in ('inet', 'inet6'):
                raise ValueError("Family must be 'inet', 'inet6', None and not"
                                 " %s" % value)
        elif name == 'protocol':
            if value not in ('tcp', 'udp', 'imcp'):
                raise ValueError("Protocol must be tcp|udp|imcp not '%s'." %
                                 value)

        super(FilterRule, self).__setattr__(name, value)

    @classmethod
    def from_dict(cls, d):
        return FilterRule(**d)

    @staticmethod
    def _format_ip_or_table(obj):
        if isinstance(obj, netaddr.IPNetwork):
            return str(obj)
        else:  # must be table name
            return '<%s>' % obj


class Anchor(ModelBase):
    def __init__(self, name, rules=[]):
        self.name = name
        self.rules = rules


class AddressBookEntry(ModelBase):
    def __init__(self, name, cidrs=[]):
        self.name = name
        self.cidrs = cidrs

    @property
    def cidrs(self):
        return self._cidrs

    @cidrs.setter
    def cidrs(self, values):
        self._cidrs = [netaddr.IPNetwork(a) for a in values]

    def external_table_data(self):
        return '\n'.join(map(str, self.cidrs))


class Allocation(ModelBase):
    def __init__(self, mac_address, ip_addresses, hostname, device_id):
        self.mac_address = mac_address
        self.ip_addresses = ip_addresses or {}
        self.hostname = hostname
        self.device_id = device_id

    @property
    def dhcp_addresses(self):
        return [ip for ip, dhcp in self.ip_addresses.items() if dhcp]

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['mac_address'],
            d['ip_addresses'],
            d['hostname'],
            d['device_id'],
        )


class FloatingIP(ModelBase):
    def __init__(self, floating_ip, fixed_ip):
        self.floating_ip = floating_ip
        self.fixed_ip = fixed_ip
        self.network = None

    @property
    def floating_ip(self):
        return self._floating_ip

    @floating_ip.setter
    def floating_ip(self, value):
        self._floating_ip = netaddr.IPAddress(value)

    @property
    def fixed_ip(self):
        return self._fixed_ip

    @fixed_ip.setter
    def fixed_ip(self, value):
        self._fixed_ip = netaddr.IPAddress(value)

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['floating_ip'],
            d['fixed_ip']
        )


class StaticRoute(ModelBase):
    def __init__(self, destination, next_hop):
        self.destination = destination
        self.next_hop = next_hop

    @property
    def destination(self):
        return self._destination

    @destination.setter
    def destination(self, value):
        self._destination = netaddr.IPNetwork(value)

    @property
    def next_hop(self):
        return self._next_hop

    @next_hop.setter
    def next_hop(self, value):
        self._next_hop = netaddr.IPAddress(value)

    def to_dict(self):
        return dict(destination=self.destination, next_hop=self.next_hop)


class Label(ModelBase):
    def __init__(self, name, cidrs=[]):
        self.name = name
        self.cidrs = cidrs

    @property
    def cidrs(self):
        return self._cidrs

    @cidrs.setter
    def cidrs(self, values):
        self._cidrs = [netaddr.IPNetwork(a) for a in values]


class Subnet(ModelBase):
    def __init__(self, cidr, gateway_ip, dhcp_enabled=True,
                 dns_nameservers=None, host_routes=None):
        self.cidr = cidr
        self.gateway_ip = gateway_ip
        self.dhcp_enabled = bool(dhcp_enabled)
        self.dns_nameservers = dns_nameservers
        self.host_routes = host_routes

    @property
    def cidr(self):
        return self._cidr

    @cidr.setter
    def cidr(self, value):
        self._cidr = netaddr.IPNetwork(value)

    @property
    def gateway_ip(self):
        return self._gateway_ip

    @gateway_ip.setter
    def gateway_ip(self, value):
        if value:
            self._gateway_ip = netaddr.IPAddress(value)
        else:
            self._gateway_ip = None

    @property
    def dns_nameservers(self):
        return self._dns_nameservers

    @dns_nameservers.setter
    def dns_nameservers(self, value):
        self._dns_nameservers = [netaddr.IPAddress(a) for a in value]

    @classmethod
    def from_dict(cls, d):
        host_routes = [StaticRoute(r['destination'], r['nexthop'])
                       for r in d.get('host_routes', [])]
        return cls(
            d['cidr'],
            d['gateway_ip'],
            d['dhcp_enabled'],
            d['dns_nameservers'],
            host_routes)


class Network(ModelBase):
    SERVICE_STATIC = 'static'
    SERVICE_RA = 'ra'
    SERVICE_DHCP = 'dhcp'
    TYPE_EXTERNAL = 'external'
    TYPE_INTERNAL = 'internal'
    TYPE_ISOLATED = 'isolated'
    TYPE_MANAGEMENT = 'management'

    # TODO(mark): add subnet support for Quantum subnet host routes

    def __init__(self, id_, interface, name='', network_type=TYPE_ISOLATED,
                 v4_conf_service=SERVICE_STATIC,
                 v6_conf_service=SERVICE_STATIC,
                 address_allocations=None,
                 subnets=None):
        self.id = id_
        self.interface = interface
        self.name = name
        self.network_type = network_type
        self.v4_conf_service = v4_conf_service
        self.v6_conf_service = v6_conf_service
        self.address_allocations = address_allocations or []
        self.subnets = subnets or []
        self.floating_ips = []

    @property
    def is_tenant_network(self):
        return self._network_type in (self.TYPE_INTERNAL, self.TYPE_ISOLATED)

    @property
    def is_internal_network(self):
        return self._network_type == self.TYPE_INTERNAL

    @property
    def is_external_network(self):
        return self._network_type == self.TYPE_EXTERNAL

    @property
    def is_management_network(self):
        return self._network_type == self.TYPE_MANAGEMENT

    @property
    def network_type(self):
        return self._network_type

    @network_type.setter
    def network_type(self, value):
        network_types = (self.TYPE_EXTERNAL, self.TYPE_INTERNAL,
                         self.TYPE_ISOLATED, self.TYPE_MANAGEMENT)
        if value not in network_types:
            msg = ('network must be one of %s not (%s).' %
                   ('|'.join(network_types), value))
            raise ValueError(msg)
        self._network_type = value

    @property
    def v4_conf_service(self):
        return self._v4_conf_service

    @v4_conf_service.setter
    def v4_conf_service(self, value):
        if value not in (self.SERVICE_DHCP, self.SERVICE_STATIC):
            msg = ('v4_conf_service must be one of dhcp|static not (%s).' %
                   value)
            raise ValueError(msg)
        self._v4_conf_service = value

    @property
    def v6_conf_service(self):
        return self._v6_conf_service

    @v6_conf_service.setter
    def v6_conf_service(self, value):
        if value not in (self.SERVICE_DHCP, self.SERVICE_RA,
                         self.SERVICE_STATIC):
            msg = ('v6_conf_service must be one of dhcp|ra|static not (%s).' %
                   value)
            raise ValueError(msg)
        self._v6_conf_service = value

    def to_dict(self):
        return dict(
            network_id=self.id,
            interface=self.interface,
            name=self.name,
            network_type=self.network_type,
            v4_conf_service=self.v4_conf_service,
            v6_conf_service=self.v6_conf_service,
            address_allocations=self.address_allocations
        )

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['network_id'],
            interface=Interface.from_dict(d['interface']),
            name=d.get('name', ''),
            network_type=d.get('network_type', cls.TYPE_ISOLATED),
            v6_conf_service=d.get('v6_conf_service', cls.SERVICE_STATIC),
            v4_conf_service=d.get('v4_conf_service', cls.SERVICE_STATIC),
            address_allocations=[
                Allocation.from_dict(a) for a in d.get('allocations', [])],
            subnets=[Subnet.from_dict(s) for s in d.get('subnets', [])])


class Configuration(ModelBase):
    def __init__(self, conf_dict={}):
        gw = conf_dict.get('default_v4_gateway')
        self.default_v4_gateway = netaddr.IPAddress(gw) if gw else None
        self.asn = conf_dict.get('asn', DEFAULT_AS)
        self.neighbor_asn = conf_dict.get('neighbor_asn', self.asn)
        self.networks = [
            Network.from_dict(n) for n in conf_dict.get('networks', [])]

        self.static_routes = [StaticRoute(*r) for r in
                              conf_dict.get('static_routes', [])]

        self.address_book = dict(
            (name, AddressBookEntry(name, cidrs)) for name, cidrs in
            conf_dict.get('address_book', {}).iteritems())

        self.anchors = [
            Anchor(a['name'], [FilterRule.from_dict(r) for r in a['rules']])
            for a in conf_dict.get('anchors', [])]

        self.labels = [
            Label(name, cidr) for name, cidr in
            conf_dict.get('labels', {}).iteritems()]

        self.floating_ips = [
            FloatingIP.from_dict(fip)
            for fip in conf_dict.get('floating_ips', [])
        ]
        self.tenant_id = conf_dict.get('tenant_id')

        self.hostname = conf_dict.get('hostname')

        self._attach_floating_ips(self.floating_ips)

    def validate(self):
        """Validate anchor rules to ensure that ifaces and tables exist."""
        errors = []

        interfaces = set(n.interface.ifname for n in self.networks)
        for anchor in self.anchors:
            for rule in anchor.rules:
                for iface in (rule.interface, rule.destination_interface):
                    if iface and iface not in interfaces:
                        errors.append((rule, '%s does not exist' % iface))

                for address in (rule.source, rule.destination):
                    if not address or isinstance(address, netaddr.IPNetwork):
                        pass
                    elif address in self.address_book:
                        pass
                    else:
                        reason = '%s is not in the address book' % address
                        errors.append((rule, reason))

        return ["'%s' %s" % e for e in errors]

    def _attach_floating_ips(self, floating_ips):
        ext_cidr_map = {}
        int_cidr_map = {}

        for network in self.networks:
            if network.is_external_network:
                m = ext_cidr_map
            elif network.is_internal_network:
                m = int_cidr_map
            else:
                continue
            m.update((s.cidr, network) for s in network.subnets)

        for fip in floating_ips:
            # add address to external interface
            for ext_cidr, net in ext_cidr_map.items():
                if fip.floating_ip in ext_cidr:
                    addr = '%s/%s' % (fip.floating_ip, ext_cidr.prefixlen)
                    net.interface.aliases += [netaddr.IPNetwork(addr)]
                    net.floating_ips.append(fip)
                    break

            # add to internal
            for int_cidr, net in int_cidr_map.items():
                if fip.fixed_ip in int_cidr:
                    fip.network = net

    def to_dict(self):
        fields = ('networks', 'address_book', 'anchors', 'static_routes')
        return dict((f, getattr(self, f)) for f in fields)

    @property
    def external_v4_id(self):
        addrs = [n.interface.first_v4
                 for n in self.networks if n.is_external_network]

        # remove any none
        addrs = sorted(a for a in addrs if a)

        if addrs:
            return addrs[0]

    @property
    def interfaces(self):
        return [n.interface for n in self.networks if n.interface]

    @property
    def management_address(self):
        addrs = []
        for net in self.networks:
            if net.is_management_network:
                addrs.extend((net.interface.first_v4, net.interface.first_v6))

        addrs = sorted(a for a in addrs if a)

        if addrs:
            return addrs[0]
