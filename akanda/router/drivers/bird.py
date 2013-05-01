import logging
import random
import textwrap

from akanda.router.drivers import base
from akanda.router import utils


LOG = logging.getLogger(__name__)
CONF_PATH = '/etc/bird6.conf'
BIRD = '/usr/local/sbin/bird'
BIRDC = '/usr/local/bin/birdc'
DEFAULT_AREA = 0
DEFAULT_AS = 64512


class BirdManager(base.Manager):
    def __init__(self, root_helper='sudo'):
        super(BirdManager, self).__init__(root_helper)

    def save_config(self, config, if_map):
        config_data = build_config(config, if_map)

        utils.replace_file('/tmp/bird6.conf', config_data)
        utils.execute(['mv', '/tmp/bird6.conf', CONF_PATH], self.root_helper)

    def restart(self):
        try:
            utils.execute(['/etc/rc.d/bird', 'stop'], self.root_helper)
        except:  # pragma no cover
            # failure is ok here
            pass
        utils.execute(['/etc/rc.d/bird', 'start'], self.root_helper)


def build_config(config, interface_map):
    config_data = [
        _build_global_config(config),
        _build_kernel_config(),
        _build_device_config(),
        _build_static_config(config),
        _build_direct_config(config, interface_map),
        #_build_ospf_config(config, interface_map),
        _build_bgp_config(config, interface_map),
        _build_radv_config(config, interface_map),
    ]

    return '\n'.join(config_data)


def _find_external_v4_ip(config):
    v4_id = config.external_v4_id

    if v4_id:
        return v4_id
    else:  # fallback to random value
        return '0.0.%d.%d' % (random.randint(0, 255), random.randint(0, 255))


def _build_global_config(config):
    retval = [
        'log syslog {warning, error, info};',
        'router id %s;' % _find_external_v4_ip(config),
    ]
    return '\n'.join(retval)


def _build_kernel_config():
    config = """
    protocol kernel {
        learn;
        scan time 20;
        import all;
        export all;
    }"""

    return textwrap.dedent(config).strip()


def _build_device_config():
    return 'protocol device {\n    scan time 10;\n}'


def _build_static_config(config):
    retval = []
    # TODO: setup static routes
    return '\n'.join(retval).replace('\t', '    ')


def _build_direct_config(config, interface_map):
    tmpl = "protocol direct {\n    interface %s;\n}"
    retval = tmpl % ','.join('"%s"' % i for i in interface_map.values())
    return textwrap.dedent(retval)


def _build_ospf_config(config, interface_map):
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
                '\tlocal as %d;' % DEFAULT_AS,
                '\tneighbor %s as %d;' % (subnet.gateway_ip, DEFAULT_AS),
                '\timport all;',
                '\texport filter bgp_out;',
                '\trr client;',
                '}'
            ])

    return '\n'.join(retval).replace('\t', '    ')


def _build_radv_config(config, interface_map):
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
            '\t\tmax ra interval 10;',
            '\t\trdnss local yes;'
        ])
        for subnet in v6_subnets:
            retval.append('\t\tprefix %s {' % subnet.cidr)
            if subnet.dhcp_enabled:
                retval.append('\t\t\tautonomous off;')
            retval.append('\t\t};')

            if subnet.dns_nameservers:
                retval.append('\t\trdnss {')
                retval.append('\t\t\tlifetime mult 10')

                for ns in subnet.dns_nameservers:
                    retval.append('\t\t\tns %s;' % ns)

                retval.append('\t\t};')
        retval.append('\t};')

    retval.append('}')
    return '\n'.join(retval).replace('\t', '    ')
