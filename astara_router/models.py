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
import itertools
import re

import netaddr

from astara_router import settings

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
                 lladdr=None, mtu=None, media=None,
                 description=None, management=False, **extra_params):
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
        self.management = management

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
    def __init__(self, id_, cidr, gateway_ip, dhcp_enabled=True,
                 dns_nameservers=None, host_routes=None):
        self.id = id_
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
            d['id'],
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
    TYPE_LOADBALANCER = 'loadbalancer'

    # TODO(mark): add subnet support for Quantum subnet host routes

    def __init__(self, id_, interface, name='', network_type=TYPE_ISOLATED,
                 v4_conf_service=SERVICE_STATIC,
                 v6_conf_service=SERVICE_STATIC,
                 address_allocations=None,
                 subnets=None, ha=False):
        self.id = id_
        self.interface = interface
        self.name = name
        self.network_type = network_type
        self.v4_conf_service = v4_conf_service
        self.v6_conf_service = v6_conf_service
        self.address_allocations = address_allocations or []
        self.subnets = subnets or []
        self.floating_ips = []
        self.ha = ha

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
    def is_loadbalancer_network(self):
	return self._network_type == self.TYPE_LOADBALANCER

    @property
    def network_type(self):
        return self._network_type

    @network_type.setter
    def network_type(self, value):
        network_types = (self.TYPE_EXTERNAL, self.TYPE_INTERNAL,
                         self.TYPE_ISOLATED, self.TYPE_MANAGEMENT,
                         self.TYPE_LOADBALANCER)
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
        missing = []
        for k in ['network_id', 'interface']:
            if not d.get(k):
                missing.append(k)
        if missing:
            raise ValueError('Missing required data: %s.' % missing)

        if d.get('network_type') == cls.TYPE_MANAGEMENT:
            d['interface']['management'] = True
        else:
            d['interface']['management'] = False

        return cls(
            d['network_id'],
            interface=Interface.from_dict(d['interface']),
            name=d.get('name', ''),
            network_type=d.get('network_type', cls.TYPE_ISOLATED),
            v6_conf_service=d.get('v6_conf_service', cls.SERVICE_STATIC),
            v4_conf_service=d.get('v4_conf_service', cls.SERVICE_STATIC),
            address_allocations=[
                Allocation.from_dict(a) for a in d.get('allocations', [])],
            subnets=[Subnet.from_dict(s) for s in d.get('subnets', [])],
            ha=d.get('ha', False))


class LoadBalancer(ModelBase):
    def __init__(self, id_, tenant_id, name, admin_state_up, status,
                 vip_address, vip_port=None, listeners=()):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.admin_state_up = admin_state_up
        self.status = status
        self.vip_address = vip_address
        self.vip_port = vip_port
        self.listeners = listeners

    @classmethod
    def from_dict(cls, d):
        if d.get('listeners'):
            d['listeners'] = [
                Listener.from_dict(l) for l in d.get('listeners', [])
            ]
        if d.get('vip_port'):
            d['vip_port'] = Port.from_dict(d.get('vip_port'))
        out = cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['admin_state_up'],
            d['status'],
            d['vip_address'],
            d['vip_port'],
            d['listeners'],
        )
        return out


class Listener(ModelBase):
    def __init__(self, id_, tenant_id, name, admin_state_up, protocol,
                 protocol_port, default_pool=None):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.admin_state_up = admin_state_up
        self.protocol = protocol
        self.protocol_port = protocol_port
        self.default_pool = default_pool

    @classmethod
    def from_dict(cls, d):
        if d.get('default_pool'):
            def_pool = Pool.from_dict(d['default_pool'])
        else:
            def_pool = None

        return cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['admin_state_up'],
            d['protocol'],
            d['protocol_port'],
            def_pool,
        )

    def to_dict(self):
        fields = ('id', 'tenant_id', 'name', 'admin_state_up', 'protocol',
                  'protocol_port')
        out = dict((f, getattr(self, f)) for f in fields)
        if self.default_pool:
            out['default_pool'] = self.default_pool.to_dict()
        else:
            out['default_pool'] = None
        return out


class Pool(ModelBase):
    def __init__(self, id_, tenant_id, name, admin_state_up, lb_algorithm,
                 protocol, healthmonitor=None, session_persistence=None,
                 members=()):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.admin_state_up = admin_state_up
        self.lb_algorithm = lb_algorithm
        self.protocol = protocol
        self.healthmonitor = healthmonitor
        self.session_persistence = session_persistence
        self.members = members

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['admin_state_up'],
            d['lb_algorithm'],
            d['protocol'],
            d.get('healthmonitor'),
            d.get('session_persistence'),
            [Member.from_dict(m) for m in d.get('members', [])],
        )

    def to_dict(self):
        fields = ('id', 'tenant_id', 'name', 'admin_state_up',
                  'lb_algorithm', 'protocol', 'healthmonitor',
                  'session_persistence')
        out = dict((f, getattr(self, f)) for f in fields)
        out['members'] = [m.to_dict() for m in self.members]
        return out


class Member(ModelBase):
    def __init__(self, id_, tenant_id, admin_state_up, address, protocol_port,
                 weight, subnet=None):
        self.id = id_
        self.tenant_id = tenant_id
        self.admin_state_up = admin_state_up
        self.address = str(netaddr.IPAddress(address))
        self.protocol_port = protocol_port
        self.weight = weight
        self.subnet = subnet

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['tenant_id'],
            d['admin_state_up'],
            d['address'],
            d['protocol_port'],
            d['weight'],
        )

    def to_dict(self):
        fields = ('id', 'tenant_id', 'admin_state_up', 'address',
                  'protocol_port', 'weight', 'subnet')
        return dict((f, getattr(self, f)) for f in fields)


class Port(ModelBase):
    def __init__(self, id_, device_id='', fixed_ips=None, mac_address='',
                 network_id='', device_owner='', name=''):
        self.id = id_
        self.device_id = device_id
        self.fixed_ips = fixed_ips or []
        self.mac_address = mac_address
        self.network_id = network_id
        self.device_owner = device_owner
        self.name = name

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['device_id'],
            fixed_ips=[FixedIp.from_dict(fip) for fip in d['fixed_ips']],
            mac_address=d['mac_address'],
            network_id=d['network_id'],
            device_owner=d['device_owner'],
            name=d['name'])

    def to_dict(self):
        fields = ('id', 'device_id', 'mac_address', 'network_id',
                  'device_owner', 'name')
        out = dict((f, getattr(self, f)) for f in fields)
        out['fixed_ips'] = [fip.to_dict() for fip in self.fixed_ips]
        return out


class FixedIp(ModelBase):
    def __init__(self, subnet_id, ip_address):
        self.subnet_id = subnet_id
        self.ip_address = netaddr.IPAddress(ip_address)

    @classmethod
    def from_dict(cls, d):
        return cls(d['subnet_id'], d['ip_address'])

    def to_dict(self):
        fields = ('subnet_id', 'ip_address')
        return dict((f, getattr(self, f)) for f in fields)


class DeadPeerDetection(ModelBase):
    def __init__(self, action, interval, timeout):
        self.action = action
        self.interval = interval
        self.timeout = timeout

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['action'],
            d['interval'],
            d['timeout']
        )


class Lifetime(ModelBase):
    def __init__(self, units, value):
        self.units = units
        self.value = value

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['units'],
            d['value']
        )


class EndpointGroup(ModelBase):
    def __init__(self, id_, tenant_id, name, type_, endpoints=()):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.type = type_
        if type_ == 'cidr':
            self.endpoints = [netaddr.IPNetwork(ep) for ep in endpoints]
        else:
            self.endpoints = endpoints
        self.subnet_map = {}

    @property
    def cidrs(self):
        if self.type == 'subnet':
            return [
                self.subnet_map[ep].cidr
                for ep in self.endpoints
                if ep in self.subnet_map
            ]
        else:
            return self.endpoints

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['type'],
            d['endpoints']
        )


class IkePolicy(ModelBase):
    def __init__(self, id_, tenant_id, name, ike_version, auth_algorithm,
                 encryption_algorithm, pfs, phase1_negotiation_mode, lifetime):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.ike_version = ike_version
        self.auth_algorithm = auth_algorithm
        self.encryption_algorithm = encryption_algorithm
        self.pfs = pfs
        self.phase1_negotiation_mode = phase1_negotiation_mode
        self.lifetime = lifetime

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['ike_version'],
            d['auth_algorithm'],
            d['encryption_algorithm'],
            d['pfs'],
            d['phase1_negotiation_mode'],
            Lifetime.from_dict(d['lifetime'])
        )


class IpsecPolicy(ModelBase):
    def __init__(self, id_, tenant_id, name, transform_protocol,
                 auth_algorithm, encryption_algorithm, encapsulation_mode,
                 lifetime, pfs):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.transform_protocol = transform_protocol
        self.auth_algorithm = auth_algorithm
        self.encryption_algorithm = encryption_algorithm
        self.encapsulation_mode = encapsulation_mode
        self.lifetime = lifetime
        self.pfs = pfs

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['transform_protocol'],
            d['auth_algorithm'],
            d['encryption_algorithm'],
            d['encapsulation_mode'],
            Lifetime.from_dict(d['lifetime']),
            d['pfs']
        )


class IpsecSiteConnection(ModelBase):
    def __init__(self, id_, tenant_id, name, peer_address, peer_id,
                 admin_state_up, route_mode, mtu, initiator, auth_mode, psk,
                 dpd, status, vpnservice_id, local_ep_group=None,
                 peer_ep_group=None, peer_cidrs=[], ikepolicy=None,
                 ipsecpolicy=None):
        self.id = id_
        self.tenant_id = tenant_id
        self.name = name
        self.peer_address = netaddr.IPAddress(peer_address)
        self.peer_id = peer_id
        self.route_mode = route_mode
        self.mtu = mtu
        self.initiator = initiator
        self.auth_mode = auth_mode
        self.psk = psk
        self.dpd = dpd
        self.status = status
        self.admin_state_up = admin_state_up
        self.vpnservice_id = vpnservice_id
        self.ipsecpolicy = ipsecpolicy
        self.ikepolicy = ikepolicy
        self.local_ep_group = local_ep_group
        self.peer_ep_group = peer_ep_group
        self.peer_cidrs = [netaddr.IPNetwork(pc) for pc in peer_cidrs]

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['tenant_id'],
            d['name'],
            d['peer_address'],
            d['peer_id'],
            d['admin_state_up'],
            d['route_mode'],
            d['mtu'],
            d['initiator'],
            d['auth_mode'],
            d['psk'],
            DeadPeerDetection.from_dict(d['dpd']),
            d['status'],
            d['vpnservice_id'],
            peer_cidrs=d['peer_cidrs'],
            ikepolicy=IkePolicy.from_dict(d['ikepolicy']),
            ipsecpolicy=IpsecPolicy.from_dict(d['ipsecpolicy']),
            local_ep_group=EndpointGroup.from_dict(d['local_ep_group']),
            peer_ep_group=EndpointGroup.from_dict(d['peer_ep_group']),
        )


class VpnService(ModelBase):
    def __init__(self, id_, name, status, admin_state_up, external_v4_ip,
                 external_v6_ip, router_id, subnet_id=None,
                 ipsec_site_connections=()):
        self.id = id_
        self.name = name
        self.status = status
        self.admin_state_up = admin_state_up
        self.external_v4_ip = netaddr.IPAddress(external_v4_ip)
        self.external_v6_ip = netaddr.IPAddress(external_v6_ip)
        self.router_id = router_id
        self.subnet_id = subnet_id
        self.ipsec_site_connections = ipsec_site_connections

    def get_external_ip(self, peer_ip):
        if peer_ip.version == '6':
            return self.external_v6_ip
        else:
            return self.external_v4_ip

    @classmethod
    def from_dict(cls, d):
        return cls(
            d['id'],
            d['name'],
            d['status'],
            d['admin_state_up'],
            d['external_v4_ip'],
            d['external_v6_ip'],
            d['router_id'],
            d.get('subnet_id'),
            [IpsecSiteConnection.from_dict(c) for c in d['ipsec_connections']]
        )


class SystemConfiguration(ModelBase):
    service_name = 'system'

    def __init__(self, conf_dict={}):
        self.tenant_id = conf_dict.get('tenant_id')
        self.hostname = conf_dict.get('hostname')
        self.networks = [
            Network.from_dict(n) for n in conf_dict.get('networks', [])]
        self.ha = conf_dict.get('ha_resource', False)
        self.ha_config = conf_dict.get('ha_config', {})
        gw = conf_dict.get('default_v4_gateway')
        self.default_v4_gateway = netaddr.IPAddress(gw) if gw else None

    def validate(self):
        # TODO: Improve this interface, it currently sucks.
        errors = []
        for attr in ['tenant_id', 'hostname']:
            if not getattr(self, attr):
                errors.append((attr, 'Config does not contain a %s' % attr))
        return errors

    @property
    def management_address(self):
        addrs = []
        for net in self.networks:
            if net.is_management_network:
                addrs.extend((net.interface.first_v4, net.interface.first_v6))

        addrs = sorted(a for a in addrs if a)

        if addrs:
            return addrs[0]

    @property
    def interfaces(self):
        return [n.interface for n in self.networks if n.interface]

    def to_dict(self):
        fields = ('tenant_id', 'hostname', 'management_address', 'interfaces')
        return dict((f, getattr(self, f)) for f in fields)


class RouterConfiguration(SystemConfiguration):
    service_name = 'router'

    def __init__(self, conf_dict={}):
        super(RouterConfiguration, self).__init__(conf_dict)
        self.asn = conf_dict.get('asn', DEFAULT_AS)
        self.neighbor_asn = conf_dict.get('neighbor_asn', self.asn)
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

        orchestrator_conf = conf_dict.get('orchestrator', {})
        self.metadata_address = orchestrator_conf.get(
            'address', settings.ORCHESTRATOR_METADATA_ADDRESS)
        self.metadata_port = orchestrator_conf.get(
            'metadata_port', settings.ORCHESTRATOR_METADATA_PORT)

        self.floating_ips = [
            FloatingIP.from_dict(fip)
            for fip in conf_dict.get('floating_ips', [])
        ]

        self._attach_floating_ips(self.floating_ips)

        self.vpn = [
            VpnService.from_dict(s)
            for s in conf_dict.get('vpn', {}).get('ipsec', [])
        ]

        self._link_subnets()

    def validate(self):
        """Validate anchor rules to ensure that ifaces and tables exist."""
        interfaces = set(n.interface.ifname for n in self.networks)
        errors = []
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

    def _link_subnets(self):
        subnet_map = {}
        for n in self.networks:
            for s in n.subnets:
                subnet_map[s.id] = s

        vpn_conn_generator = (v.ipsec_site_connections for v in self.vpn)

        for conn in itertools.chain.from_iterable(vpn_conn_generator):
            if conn.local_ep_group.type == 'subnet':
                conn.local_ep_group.subnet_map = subnet_map

    def to_dict(self):
        fields = (
            'networks', 'address_book', 'anchors', 'static_routes', 'vpn'
        )
        return dict((f, getattr(self, f)) for f in fields)

    @property
    def external_v4_id(self):
        addrs = [n.interface.first_v4
                 for n in self.networks if n.is_external_network]

        # remove any none
        addrs = sorted(a for a in addrs if a)

        if addrs:
            return addrs[0]


class LoadBalancerConfiguration(SystemConfiguration):
    service_name = 'loadbalancer'

    def __init__(self, conf_dict={}):
        super(LoadBalancerConfiguration, self).__init__(conf_dict)
        self.id = conf_dict.get('id')
        self.name = conf_dict.get('name')
        if conf_dict:
            self._loadbalancer = LoadBalancer.from_dict(conf_dict)
            self.vip_port = self._loadbalancer.vip_port
            self.vip_address = self._loadbalancer.vip_address
            self.listeners = self._loadbalancer.listeners
        else:
            self.vip_port = None
            self.vip_address = None
            self.listeners = []

    def validate(self):
        super(LoadBalancerConfiguration, self).validate()
        errors = []
        if not self.id:
            errors.append(['id', 'Missing in config id'])
        return errors

    def to_dict(self):
        if self.vip_port:
            vip_port = self.vip_port.to_dict()
        else:
            vip_port = {}
        return {
            'id': self.id,
            'name': self.name,
            'vip_port': vip_port,
            'vip_address': self.vip_address,
            'listeners': [l.to_dict() for l in self.listeners],
        }

SERVICE_MAP = {
    RouterConfiguration.service_name: RouterConfiguration,
    LoadBalancerConfiguration.service_name: LoadBalancerConfiguration,
}


def get_config_model(service):
    return SERVICE_MAP[service]
