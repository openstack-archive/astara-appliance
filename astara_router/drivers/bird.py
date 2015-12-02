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
import random
import textwrap

from astara_router.drivers import base
from astara_router import utils


LOG = logging.getLogger(__name__)
CONF_PATH = '/etc/bird/bird6.conf'
DEFAULT_AREA = 0


class BirdManager(base.Manager):
    """
    A class to interact with BIRD, an internet routing protocol daemon.
    """
    def __init__(self, root_helper='sudo'):
        """
        Initializes BirdManager class.

        :type root_helper: string
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(BirdManager, self).__init__(root_helper)

    def save_config(self, config, if_map):
        """
        Writes config file for bird daemon.

        :type config: astara_router.models.Configuration
        :param config:
        :type if_map: dict
        :param if_map: A (dict) mapping of generic to physical hostname, e.g.:
                       {'ge0': 'eth0', 'ge1': 'eth1'}
        """
        config_data = build_config(config, if_map)

        utils.replace_file('/tmp/bird6.conf', config_data)
        utils.execute(['mv', '/tmp/bird6.conf', CONF_PATH], self.root_helper)

    def restart(self):
        """
        Restart the BIRD daemon using the system provided init scripts.
        """
        try:
            utils.execute(['/etc/init.d/bird6', 'status'], self.root_helper)
        except:  # pragma no cover
            utils.execute(['/etc/init.d/bird6', 'start'], self.root_helper)
        else:  # pragma no cover
            utils.execute(['/etc/init.d/bird6', 'reload'], self.root_helper)


def build_config(config, interface_map):
    """
    Generate a configuration file for the BIRD daemon with interface mapping
    provided by <interface_map>.

    :type interface_map: dict
    :param interface_map: A (dict) mapping of generic to physical hostname:
                          {'ge0': 'eth0', 'ge1': 'eth1'}
    :rtype: str
    """
    config_data = [
        _build_global_config(config),
        _build_kernel_config(),
        _build_device_config(),
        _build_static_config(config),
        _build_direct_config(config, interface_map),
        # _build_ospf_config(config, interface_map),
        _build_bgp_config(config, interface_map),
        _build_radv_config(config, interface_map),
    ]

    return '\n'.join(config_data)


def _find_external_v4_ip(config):
    """
    Determines the external IPv4 address.

    :type config: astara_router.models.Configuration
    :param config:
    :rtype: str
    """
    v4_id = config.external_v4_id

    if v4_id:
        return v4_id
    else:  # fallback to random value
        return '0.0.%d.%d' % (random.randint(0, 255), random.randint(0, 255))


def _build_global_config(config):
    """
    Generate the "global" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :rtype: str
    """
    retval = [
        'log syslog {warning, error, info};',
        'router id %s;' % _find_external_v4_ip(config),
    ]
    return '\n'.join(retval)


def _build_kernel_config():
    """
    Generate the "kernel" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :rtype: str
    """
    config = """
    protocol kernel {
        learn;
        scan time 20;
        import all;
        export all;
    }"""

    return textwrap.dedent(config).strip()


def _build_device_config():
    """
    Generate the "device" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :rtype: str
    """
    return 'protocol device {\n    scan time 10;\n}'


def _build_static_config(config):
    """
    Generate the "static" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :rtype:
    """
    retval = []
    # TODO: setup static routes
    return '\n'.join(retval).replace('\t', '    ')


def _build_direct_config(config, interface_map):
    """
    Generate the "direct" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :type interface_map: dict
    :param interface_map:
    :rtype:
    """
    tmpl = "protocol direct {\n    interface %s;\n}"
    retval = tmpl % ','.join(
        '"%s"' % i for i in sorted(interface_map.values())
    )
    return textwrap.dedent(retval)


def _build_ospf_config(config, interface_map):
    """
    Generate the "ospf" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :type interface_map: dict
    :param interface_map:
    :rtype:
    """
    retval = [
        'protocol ospf {',
        '\texport all;',
        '\trfc1583compat yes;',
        '\tarea %d {' % DEFAULT_AREA
    ]

    for net in config.networks:
        ifname = interface_map.get(net.interface.ifname)
        if ifname and net.is_internal_network:
            modifier = 'stub yes'
        elif ifname and net.is_external_network:
            modifier = 'type broadcast'
        else:
            continue

        retval.extend([
            '\t\tinterface "%s" {' % ifname,
            '\t\t\tcost 10;',
            '\t\t\t%s;' % modifier,
            '\t\t};'
        ])

    retval.extend([
        '\t};',
        '};'
    ])
    return '\n'.join(retval).replace('\t', '    ')


def _build_bgp_config(config, interface_map):
    """
    Generate the "BGP" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :type interface_map: dict
    :param interface_map:
    :rtype:
    """

    # build the filter rule
    retval = [
        'filter bgp_out {',
        '\tif ! (source = RTS_DEVICE) then reject;',
        '\tif net ~ fc00::/7 then reject;',  # filter out private addresses
    ]

    for net in config.networks:
        if not net.is_internal_network:
            continue
        retval.extend(
            '\tif net = %s then accept;' % s.cidr
            for s in net.subnets if s.cidr.version == 6 and s.gateway_ip
        )

    retval.extend(
        [
            '\telse reject;',
            '}',
            ''
        ]
    )

    # build the bgp rule
    for net in config.networks:
        ifname = interface_map.get(net.interface.ifname)

        if not net.is_external_network or not ifname:
            continue

        v6_subnets = (s for s in net.subnets
                      if s.cidr.version == 6 and s.gateway_ip)

        for subnet in v6_subnets:
            retval.extend([
                'protocol bgp {',
                '\tlocal as %d;' % config.asn,
                '\tneighbor %s as %d;' % (subnet.gateway_ip,
                                          config.neighbor_asn),
                '\timport all;',
                '\texport filter bgp_out;',
                '\trr client;',
                '}'
            ])

    return '\n'.join(retval).replace('\t', '    ')


def _build_radv_config(config, interface_map):
    """
    Generate the "radv" section of the BIRD daemon configuration.

    :type config: astara_router.models.Configuration
    :param config:
    :type interface_map: dict
    :param interface_map:
    :rtype:
    """
    retval = [
        'protocol radv {',
    ]

    for net in config.networks:
        if not net.is_tenant_network:
            continue

        v6_subnets = [s for s in net.subnets if s.cidr.version == 6]

        if not v6_subnets:
            continue

        real_ifname = interface_map.get(net.interface.ifname)

        if not real_ifname:
            continue

        retval.extend([
            '\tinterface "%s" {' % real_ifname,
            '\t\tmax ra interval 600;',
            '\t\trdnss local yes;'
        ])
        for subnet in v6_subnets:
            retval.append('\t\tprefix %s {' % subnet.cidr)
            if subnet.dhcp_enabled:
                retval.append('\t\t\tautonomous off;')
            retval.append('\t\t};')

            if subnet.dns_nameservers:
                retval.append('\t\trdnss {')
                retval.append('\t\t\tlifetime mult 10;')

                for ns in subnet.dns_nameservers:
                    retval.append('\t\t\tns %s;' % ns)

                retval.append('\t\t};')
        retval.append('\t};')

    retval.append('}')
    return '\n'.join(retval).replace('\t', '    ')
