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


import functools
import logging
import re

import netaddr

from akanda.router import models
from akanda.router.drivers import base
from akanda.router import utils

LOG = logging.getLogger(__name__)


GENERIC_IFNAME = 'ge'
PHYSICAL_INTERFACES = ['lo', 'eth', 'em', 're', 'en', 'vio', 'vtnet']
ULA_PREFIX = 'fdca:3ba5:a17a:acda::/64'


class IPManager(base.Manager):
    """
    A class that provides a pythonic interface to unix system network
    configuration information.
    """

    EXECUTABLE = '/sbin/ip'

    def __init__(self, root_helper='sudo'):
        """Initializes resources for the IPManager class"""
        super(IPManager, self).__init__(root_helper)
        self.next_generic_index = 0
        self.host_mapping = {}
        self.generic_mapping = {}

    def ensure_mapping(self):
        """
        Creates a mapping of generic interface names (e.g., ge0, ge1) to
        physical interface names (eth1, eth2) if one does not already exist.
        """
        if not self.host_mapping:
            self.get_interfaces()

    def get_interfaces(self):
        """
        Returns a list of the available network interfaces.  This information
        is obtained through the `ip addr show` system command.
        """
        interfaces = _parse_interfaces(self.do('addr', 'show'),
                                       filters=PHYSICAL_INTERFACES)

        interfaces.sort(key=lambda x: x.ifname)
        for i in interfaces:
            if i.ifname not in self.host_mapping:
                generic_name = 'ge%d' % self.next_generic_index
                self.host_mapping[i.ifname] = generic_name
                self.next_generic_index += 1

            # change ifname to generic version
            i.ifname = self.host_mapping[i.ifname]
        self.generic_mapping = dict((v, k) for k, v in
                                    self.host_mapping.iteritems())

        return interfaces

    def get_interface(self, ifname):
        """
        Returns network configuration information for the requested network
        interface.  This information is obtained through the system command `ip
        addr show <ifname>`.

        :param ifname: the name of the interface to retrieve, e.g., `eth1`
        :type ifname: str
        :rtype: akanda.router.model.Interface
        """
        real_ifname = self.generic_to_host(ifname)
        retval = _parse_interface(self.do('addr', 'show', real_ifname))
        retval.ifname = ifname
        return retval

    def is_valid(self, ifname):
        """
        Validates if the supplied interface is a valid system network
        interface.  Returns `True` if <ifname> is a valid interface.  Returns
        `False` if <ifname> is not a valid interface.

        :param ifname: the name of the interface to retrieve, e.g., `eth1`
        :type ifname: str
        """
        self.ensure_mapping()
        return ifname in self.generic_mapping

    def generic_to_host(self, generic_name):
        """
        Translates a generic interface name into the physical network interface
        name.
        :param ifname: the generic name to translate, e.g., `ge0`
        :type ifname: str
        :rtype: str
        """
        self.ensure_mapping()
        return self.generic_mapping.get(generic_name)

    def host_to_generic(self, real_name):
        """
        Translates a physical interface name into the generic network interface
        name.
        :param ifname: the physical name to translate, e.g., `eth0`
        :type ifname: str
        :rtype: str
        """
        self.ensure_mapping()
        return self.host_mapping.get(real_name)

    def update_interfaces(self, interfaces):
        """
        Wrapper function that accepts a list of interfaces and iterates over
        them, calling update_interface(<interface>) in order to update
        their configuration.
        """
        for i in interfaces:
            self.update_interface(i)

    def up(self, interface):
        """
        Sets the administrative mode for the network link on interface
        <interface> to "up".
        :param interface: the interface to mark up
        :type interface: akanda.router.models.Interface
        """
        real_ifname = self.generic_to_host(interface.ifname)
        self.sudo('link', 'set', real_ifname, 'up')
        return self.get_interface(interface.ifname)

    def down(self, interface):
        """
        Sets the administrative mode for the network link on interface
        <interface> to "down".
        :param interface: the interface to mark down
        :type interface: akanda.router.models.Interface
        """
        real_ifname = self.generic_to_host(interface.ifname)
        self.sudo('link', 'set', real_ifname, 'down')

    def update_interface(self, interface, ignore_link_local=True):
        """
        Updates a network interface, particularly its addresses
        :param interface: the interface to update
        :type interface: akanda.router.models.Interface
        :param ignore_link_local: When True, link local addresses will not be
                                  added/removed
        :type ignore_link_local: bool
        """
        real_ifname = self.generic_to_host(interface.ifname)
        old_interface = self.get_interface(interface.ifname)

        if ignore_link_local:
            interface.addresses = [a for a in interface.addresses
                                   if not a.is_link_local()]
            old_interface.addresses = [a for a in old_interface.addresses
                                       if not a.is_link_local()]
        # Must update primary before aliases otherwise will lose address
        # in case where primary and alias are swapped.
        self._update_addresses(real_ifname, interface, old_interface)

    def _update_addresses(self, real_ifname, interface, old_interface):
        """
        Compare the state of an interface, and add/remove address that have
        changed.
        :param real_ifname: the name of the interface to modify
        :param real_ifname: str
        :param interface: the new interface reference
        :type interface: akanda.router.models.Interface
        :param old_interface: the reference to the current network interface
        :type old_interface: akanda.router.models.Interface
        """

        def _gen_cmd(cmd, address):
            """
            Generates an `ip addr (add|del) <cidr> dev <ifname>` command.
            """
            family = {4: 'inet', 6: 'inet6'}[address[0].version]
            args = ['addr', cmd, '%s/%s' % (address[0], address[1])]
            if family == 'inet' and cmd == 'add':
                args += ['brd', '+']
            args += ['dev', real_ifname]
            if family == 'inet6':
                args = ['-6'] + args
            return args

        add = functools.partial(_gen_cmd, 'add')
        delete = functools.partial(_gen_cmd, 'del')
        mutator = lambda a: (a.ip, a.prefixlen)

        self._update_set(real_ifname, interface, old_interface,
                         'all_addresses', add, delete, mutator)

    def _update_set(self, real_ifname, interface, old_interface, attribute,
                    fmt_args_add, fmt_args_delete, mutator=lambda x: x):
        """
        Compare the set of addresses (the current set and the desired set)
        for an interface and generate a series of `ip addr add` and `ip addr
        del` commands.
        """

        next_set = set(mutator(i) for i in getattr(interface, attribute))
        prev_set = set(mutator(i) for i in getattr(old_interface, attribute))

        if next_set == prev_set:
            return

        for item in (next_set - prev_set):
            self.sudo(*fmt_args_add(item))
            self.up(interface)

        for item in (prev_set - next_set):
            self.sudo(*fmt_args_delete(item))
            ip, prefix = item
            if ip.version == 4:
                self._delete_conntrack_state(ip)

    def update_default_gateway(self, config):
        """
        Sets the default gateway for v4 and v6 via the use of `ip route add`.

        :type config: akanda.router.models.Configuration
        """
        # Track whether we have set the default gateways, by IP
        # version.
        gw_set = {
            4: False,
            6: False,
        }

        ifname = None
        for net in config.networks:
            if not net.is_external_network:
                continue
            ifname = net.interface.ifname

        # The default v4 gateway is pulled out as a special case
        # because we only want one but we might have multiple v4
        # subnets on the external network. However, sometimes the RUG
        # can't figure out what that value is, because it thinks we
        # don't have any external IP addresses, yet. In that case, it
        # doesn't give us a default.
        if config.default_v4_gateway:
            self._set_default_gateway(config.default_v4_gateway, ifname)
            gw_set[4] = True

        # Look through our networks and make sure we have a default
        # gateway set for each IP version, if we have an IP for that
        # version on the external net. If we haven't already set the
        # v4 gateway, this picks the gateway for the first subnet we
        # find, which might be wrong.
        for net in config.networks:
            if not net.is_external_network:
                continue

            for subnet in net.subnets:
                if subnet.gateway_ip and not gw_set[subnet.gateway_ip.version]:
                    self._set_default_gateway(
                        subnet.gateway_ip,
                        net.interface.ifname
                    )
                    gw_set[subnet.gateway_ip.version] = True

    def update_host_routes(self, config, cache):
        """
        Update the network routes.  This is primarily used to support static
        routes that users provide to neutron.

        :type config: akanda.router.models.Configuration
        :param cache: a dbm cache for storing the "last applied routes".
                      Because Linux does not differentiate user-provided routes
                      from, for example, the default gateway, this is necessary
                      so that subsequent calls to this method can determine
                      "what changed" for the user-provided routes.
        :type cache: dogpile.cache.region.CacheRegion
        """
        db = cache.get_or_create('host_routes', lambda: {})
        for net in config.networks:

            # For each subnet...
            for subnet in net.subnets:
                cidr = str(subnet.cidr)

                # determine the set of previously written routes for this cidr
                if cidr not in db:
                    db[cidr] = set()

                current = db[cidr]

                # build a set of new routes for this cidr
                latest = set()
                for r in subnet.host_routes:
                    latest.add((r.destination, r.next_hop))

                # If the set of previously written routes contains routes that
                # aren't defined in the new config, run commands to delete them
                for x in current - latest:
                    if self._alter_route(net.interface.ifname, 'del', *x):
                        current.remove(x)

                # If the new config contains routes that aren't defined in the
                # set of previously written routes, run commands to add them
                for x in latest - current:
                    if self._alter_route(net.interface.ifname, 'add', *x):
                        current.add(x)

                if not current:
                    del db[cidr]

        cache.set('host_routes', db)

    def _get_default_gateway(self, version):
        """
        Gets the default gateway.

        :param version: the IP version, 4 or 6
        :type version: int
        :rtype: str
        """
        try:
            cmd_out = self.sudo('-%s' % version, 'route', 'show')
        except:
            # assume the route is missing and use defaults
            pass
        else:
            for l in cmd_out.splitlines():
                l = l.strip()
                if l.startswith('default'):
                    match = re.search('via (?P<gateway>[^ ]+)', l)
                    if match:
                        return match.group('gateway')

    def _set_default_gateway(self, gateway_ip, ifname):
        """
        Sets the default gateway.

        :param gateway_ip: the IP address to set as the default gateway_ip
        :type gateway_ip: netaddr.IPAddress
        :param ifname: the interface name (in our case, of the external
                       network)
        :type ifname: str
        """
        version = 4
        if gateway_ip.version == 6:
            version = 6
        current = self._get_default_gateway(version)
        desired = str(gateway_ip)
        ifname = self.generic_to_host(ifname)

        if current and current != desired:
            # Remove the current gateway and add the desired one
            self.sudo(
                '-%s' % version, 'route', 'del', 'default', 'via', current,
                'dev', ifname
            )
            return self.sudo(
                '-%s' % version, 'route', 'add', 'default', 'via', desired,
                'dev', ifname
            )
        if not current:
            # Add the desired gateway
            return self.sudo(
                '-%s' % version, 'route', 'add', 'default', 'via', desired,
                'dev', ifname
            )

    def _alter_route(self, ifname, action, destination, next_hop):
        """
        Apply/remove a custom (generally, user-supplied) route using the `ip
        route add/delete` command.

        :param ifname: The name of the interface on which to alter the route
        :type ifname: str
        :param action: The action, 'add' or 'del'
        :type action: str
        :param destination: The destination CIDR
        :type destination: netaddr.IPNetwork
        :param next_hop: The next hop IP addressj
        :type next_hop: netaddr.IPAddress
        """
        version = destination.version
        ifname = self.generic_to_host(ifname)
        try:
            LOG.debug(self.sudo(
                '-%s' % version, 'route', action, str(destination), 'via',
                str(next_hop), 'dev', ifname
            ))
            return True
        except RuntimeError as e:
            # Since these are user-supplied custom routes, it's very possible
            # that adding/removing them will fail.  A failure to apply one of
            # these custom rules, however, should *not* cause an overall router
            # failure.
            LOG.warn('Route could not be %sed: %s' % (action, unicode(e)))
            return False

    def disable_duplicate_address_detection(self, network):
        """
        Disabled duplicate address detection for a specific interface.

        :type network: akanda.models.Network
        """
        # For non-external networks, duplicate address detection isn't
        # necessary (and it sometimes results in race conditions for services
        # that attempt to bind to addresses before they're ready).

        if network.network_type != network.TYPE_EXTERNAL:
            real_ifname = self.generic_to_host(network.interface.ifname)
            try:
                utils.execute([
                    'sysctl', '-w', 'net.ipv6.conf.%s.accept_dad=0'
                    % real_ifname
                ], self.root_helper)
            except RuntimeError:
                LOG.debug(
                    'Failed to disable v6 dad on %s' % real_ifname
                )

    def _delete_conntrack_state(self, ip):
        """
        Explicitly remove an IP from in-kernel connection tracking.

        :param ip: The IP address to remove
        :type ip: netaddr.IPAddress
        """

        # If no flow entries are deleted, `conntrack -D` will return 1
        try:
            utils.execute(['conntrack', '-D', '-d', str(ip)], self.root_helper)
        except RuntimeError:
            LOG.debug(
                'Failed deleting ingress connection state of %s' % ip
            )
        try:
            utils.execute(['conntrack', '-D', '-q', str(ip)], self.root_helper)
        except RuntimeError:
            LOG.debug(
                'Failed deleting egress connection state of %s' % ip
            )


def get_rug_address():
    """ Return the RUG address """
    net = netaddr.IPNetwork(ULA_PREFIX)
    return str(netaddr.IPAddress(net.first + 1))


def _parse_interfaces(data, filters=None):
    """
    Parse the output of `ip addr show`.

    :param data: the output of `ip addr show`
    :type data: str
    :param filter: a list of valid interface names to match on
    :type data: list of str
    :rtype: list of akanda.router.models.Interface
    """
    retval = []
    for iface_data in re.split('(^|\n)(?=[0-9]: \w+\d{0,3}:)', data, re.M):
        if not iface_data.strip():
            continue
        number, interface = iface_data.split(': ', 1)

        # FIXME (mark): the logic works, but should be more readable
        for f in filters or ['']:
            if f == '':
                break
            elif interface.startswith(f) and interface[len(f)].isdigit():
                break
        else:
            continue

        retval.append(_parse_interface(iface_data))
    return retval


def _parse_interface(data):
    """
    Parse details for an interface, given its data from `ip addr show <ifname>`

    :rtype: akanda.router.models.Interface
    """
    retval = dict(addresses=[])
    for line in data.split('\n'):
        if line.startswith(' '):
            line = line.strip()
            if line.startswith('inet'):
                retval['addresses'].append(_parse_inet(line))
            elif 'link/ether' in line:
                retval['lladdr'] = _parse_lladdr(line)
        else:
            retval.update(_parse_head(line))

    return models.Interface.from_dict(retval)


def _parse_head(line):
    """
    Parse the line of `ip addr show` that contains the interface name, MTU, and
    flags.
    """
    retval = {}
    m = re.match(
        '[0-9]+: (?P<if>\w+\d{1,3}): <(?P<flags>[^>]+)> mtu (?P<mtu>[0-9]+)',
        line
    )
    if m:
        retval['ifname'] = m.group('if')
        retval['mtu'] = int(m.group('mtu'))
        retval['flags'] = m.group('flags').split(',')
    return retval


def _parse_inet(line):
    """
    Parse a line of `ip addr show` that contains an address.
    """
    tokens = line.split()
    return netaddr.IPNetwork(tokens[1])


def _parse_lladdr(line):
    """
    Parse the line of `ip addr show` that contains the hardware address.
    """
    tokens = line.split()
    return tokens[1]
