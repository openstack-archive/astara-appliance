import re

import netaddr

from akanda.router import models
from akanda.router.drivers import base


GENERIC_IFNAME = 'ge'
PHYSICAL_INTERFACES = ['em', 're', 'en']


class InterfaceManager(base.Manager):
    """
    """
    EXECUTABLE = '/sbin/ifconfig'

    def __init__(self, root_helper='sudo'):
        super(InterfaceManager, self).__init__(root_helper)
        self.next_generic_index = 0
        self.host_mapping = {}
        self.generic_mapping = {}

    def _ensure_mapping(self):
        if not self.host_mapping:
            self.get_interfaces()

    def get_interfaces(self):
        interfaces = _parse_interfaces(self.do('-a'),
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
        real_ifname = self.generic_to_host(ifname)
        retval = _parse_interface(self.do(real_ifname))
        retval.ifname = ifname
        return retval

    def is_valid(self, ifname):
        self._ensure_mapping()
        return ifname in self.generic_mapping

    def generic_to_host(self, generic_name):
        self._ensure_mapping()
        return self.generic_mapping.get(generic_name)

    def host_to_generic(self, real_name):
        self._ensure_mapping()
        return self.host_mapping.get(real_name)

    def update_interfaces(self, interfaces):
        for i in interfaces:
            self.update_interface(i)

    def up(self, interface):
        real_ifname = self.generic_to_host(interface.ifname)
        self.sudo(real_ifname, 'up')

    def down(self, interface):
        real_ifname = self.generic_to_host(interface.ifname)
        self.sudo(real_ifname, 'down')

    def update_interface(self, interface):
        real_ifname = self.generic_to_host(interface.ifname)
        old_interface = self.get_interface(real_ifname)

        self._update_description(real_ifname, interface)
        self._update_groups(real_ifname, interface, old_interface)
        # Must update primary before aliases otherwise will lose address
        # in case where primary and alias are swapped.
        self._update_addresses(real_ifname, interface, old_interface)

    def _update_description(self, real_ifname, interface):
        self.sudo(real_ifname, 'description', interface.description)

    def _update_groups(self, real_ifname, interface, old_interface):
        add = lambda g: (real_ifname, 'group', g)
        delete = lambda g: (real_ifname, '-group', g)

        self._update_set(real_ifname, interface, old_interface, 'groups',
                         add, delete)

    def _update_addresses(self, real_ifname, interface, old_interface):
        add = lambda a: (real_ifname, 'alias',
                         str(a.ip), 'prefixlen', a.prefixlen)
        delete = lambda a: (real_ifname, '-alias',
                            str(a.ip), 'prefixlen', a.prefixlen)

        self._update_set(real_ifname, interface, old_interface,
                         'addresses', add, delete)

    def _update_set(self, real_ifname, interface, old_interface, attribute,
                    fmt_args_add, fmt_args_delete):

        next_set = set(getattr(interface, attribute))
        prev_set = set(getattr(old_interface, attribute))

        if next_set == prev_set:
            return

        for item in (next_set - prev_set):
            self.sudo(fmt_args_add(item))

        for item in (prev_set - next_set):
            self.sudo(fmt_args_delete(item))


def _parse_interfaces(data, filters=None):
    retval = []
    for iface_data in re.split('(^|\n)(?=\w+\d{1,3}: flag)', data, re.M):
        if not iface_data.strip():
            continue

        for f in filters or ['']:
            if iface_data.startswith(f):
                break
        else:
            continue

        retval.append(_parse_interface(iface_data))
    return retval


def _parse_interface(data):
    retval = dict(addresses=[])
    for line in data.split('\n'):
        if line.startswith('\t'):
            line = line.strip()
            if line.startswith('inet'):
                retval['addresses'].append(_parse_inet(line))
            else:
                retval.update(_parse_other_params(line))
        else:
            retval.update(_parse_head(line))

    return models.Interface.from_dict(retval)


def _parse_head(line):
    retval = {}
    m = re.match(
        '(?P<ifname>\w*): flags=\d*<(?P<flags>[\w,]*)> mtu (?P<mtu>\d*)',
        line)
    if m:
        retval['ifname'] = m.group('ifname')
        retval['flags'] = m.group('flags').split(',')
        retval['mtu'] = int(m.group('mtu'))
    return retval


def _parse_inet(line):
    tokens = line.split()
    if tokens[0] == 'inet6':
        ip = tokens[1].split('%')[0]
        mask = tokens[3]
    else:
        ip = tokens[1]
        mask = str(netaddr.IPAddress(int(tokens[3], 16)))
    return netaddr.IPNetwork('%s/%s' % (ip, mask))


def _parse_other_params(line):
    # TODO (mark): remove the no cover for FreeBSD variant of ifconfig
    if line.startswith('options'):  # pragma nocover
        m = re.match('options=[0-9a-f]*<(?P<options>[\w,]*)>', line)
        return m.groupdict()
    else:
        key, value = line.split(' ', 1)

        if key == 'ether':  # pragma nocover
            key = 'lladdr'
        elif key.endswith(':'):
            key = key[:-1]

        return [(key, value)]
