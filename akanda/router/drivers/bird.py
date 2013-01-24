import logging
import random
import textwrap

from akanda.router.drivers import base
from akanda.router.utils import execute, replace_file


LOG = logging.getLogger(__name__)
CONF_PATH = '/etc/bird6.conf'
BIRD = '/usr/local/sbin/bird'
BIRDC = '/usr/local/bin/birdc'
DEFAULT_AREA = 0


class BirdManager(base.Manager):
    def __init__(self, root_helper='sudo'):
        super(BirdManager, self).__init__(root_helper)

    def save_config(self, config, if_map):
        config_data = build_config(config, if_map)

        replace_file('/tmp/bird6.conf', config_data)
        execute(['mv', '/tmp/bird6.conf', CONF_PATH], self.root_helper)

    def restart(self):
        try:
            execute(['/etc/rc.d/bird', 'stop'], self.root_helper)
        except:
            # failure is ok here
            pass
        execute(['/etc/rc.d/bird', 'start'], self.root_helper)


def build_config(config, interface_map):
    config_data = [
        'log syslog {warning, error, info};',
        'router id %s;' % _find_external_v4_ip(config),
        _build_kernel_config(),
        _build_device_config(),
        _build_static_config(config),
        _build_ospf_config(config, interface_map),
        _build_radv_config(config, interface_map),
    ]

    return '\n'.join(config_data)


def _find_external_v4_ip(config):
    v4_id = config.external_v4_id

    if v4_id:
        return v4_id
    else:  # fallback to random value
        return '0.0.%d.%d' % (random.randInt(0, 255), random.randInt(0, 255))


def _build_kernel_config():
    config = """
    protocol kernel {
        learn;
        scan time 20;
        import all;
        export all;
    }"""

    return textwrap.dedent(config)


def _build_device_config():
    return 'protocol device {\n    scan time 10;\n}'


def _build_static_config(config):
    # TODO: setup static routes
    return ''


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
