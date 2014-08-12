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

import re
import itertools


from akanda.router.drivers import base
from akanda.router.models import Network
from akanda.router import defaults, utils


class Rule(object):

    def __init__(self, rule, ip_version=None):
        self.rule = rule
        self.ip_version = ip_version

    def __str__(self):
        return self.rule

    @property
    def for_v4(self):
        return self.ip_version in (None, 4)

    @property
    def for_v6(self):
        return self.ip_version in (None, 6)


class IPTablesManager(base.Manager):
    """
    """

    def save_config(self, config, interface_map):
        '''
        Save iptables-persistent firewall rules to disk.

        :param config: The akanda configuration to save to disk
        :type config: akanda.rug.models.Configuration
        :param interface_map: A mapping of virtual ('ge0') to physical ('eth0')
                              interface names
        :type interface_map: dict
        '''
        rules = itertools.chain(
            self._build_filter_table(config),
            self._build_nat_table(config)
        )

        for version, rules in zip((4, 6), itertools.tee(rules)):
            data = '\n'.join(map(
                str,
                [r for r in rules if getattr(r, 'for_v%s' % version)]
            ))

            # Map virtual interface names
            real_name = interface_map.get('ge0')[:-1]
            ifname_re = '\-(?P<flag>i|o)(?P<ws>[\s!])(?P<not>!?)(?P<if>ge)(?P<no>\d+)'  # noqa
            ifname_sub = r'-\g<flag>\g<ws>\g<not>%s\g<no>' % real_name
            data = re.sub(ifname_re, ifname_sub, data) + '\n'

            utils.replace_file('/tmp/ip%stables.rules' % version, data)

            utils.execute([
                'mv',
                '/tmp/ip%stables.rules' % version,
                '/etc/iptables/rules.v%s' % version
            ], self.root_helper)

    def restart(self):
        '''
        Reload firewall rules via iptables-persistent
        '''
        utils.execute(
            ['/etc/init.d/iptables-persistent', 'restart'],
            self.root_helper
        )

    def get_rules(self):
        '''
        Return the output of `iptables` and `ip6tables`.
        This function is used by akanda-rug -> HTTP as a test for "router
        aliveness".

        :rtype: str
        '''
        v4 = utils.execute(['iptables', '-L', '-n'])
        v6 = utils.execute(['ip6tables', '-L', '-n'])
        return v4 + v6

    def get_external_network(self, config):
        '''
        Returns the external network

        :rtype: akanda.router.models.Interface
        '''
        return self.networks_by_type(config, Network.TYPE_EXTERNAL)[0]

    def networks_by_type(self, config, type):
        '''
        Returns the external network

        :rtype: akanda.router.models.Interface
        '''
        return filter(lambda n: n.network_type == type, config.networks)

    def _build_filter_table(self, config):
        '''
        Build a list of iptables and ip6tables rules to be written to disk.

        :param config: the akanda configuration object:
        :type config: akanda.router.models.Configuration
        :param rules: the list of rules to append to
        :type rules: a list of akanda.router.drivers.iptables.Rule objects
        '''
        return itertools.chain(
            self._build_default_filter_rules(),
            self._build_management_filter_rules(config),
            self._build_internal_network_filter_rules(config)
        )

    def _build_default_filter_rules(self):
        '''
        Build rules for default filter policies and ICMP handling
        '''
        return (
            Rule('*filter'),
            Rule(':INPUT DROP [0:0]'),
            Rule(':FORWARD ACCEPT [0:0]'),
            Rule(':OUTPUT ACCEPT [0:0]'),
            Rule('-A INPUT -i lo -j ACCEPT'),
            Rule(
                '-A INPUT -p icmp --icmp-type echo-request -j ACCEPT',
                ip_version=4
            ),
            Rule(
                '-A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT',
                ip_version=6
            )
        )

    def _build_management_filter_rules(self, config):
        '''
        Add rules specific to the management network, like allowances for SSH,
        the HTTP API, and metadata proxying on the management interface.
        '''
        rules = []

        for network in self.networks_by_type(config, Network.TYPE_MANAGEMENT):

            # Open SSH, the HTTP API (5000) and the Nova metadata proxy (9697)
            for port in (
                defaults.SSH, defaults.API_SERVICE, defaults.RUG_META_PORT
            ):
                rules.append(Rule(
                    '-A INPUT -i %s -p tcp -m tcp --dport %s -j ACCEPT' % (
                        network.interface.ifname,
                        port
                    ), ip_version=6
                ))

            # Disallow any other management network traffic
            rules.append(Rule('-A INPUT -i !%s -d %s -j DROP' % (
                network.interface.ifname,
                network.interface.first_v6
            ), ip_version=6))

        return rules

    def _build_internal_network_filter_rules(self, config):
        '''
        Add rules specific to private tenant networks.
        '''
        rules = []
        ext_if = self.get_external_network(config).interface

        for network in self.networks_by_type(config, Network.TYPE_INTERNAL):

            for version, address, dhcp_port in (
                (4, network.interface.first_v4, defaults.DHCP),
                (6, network.interface.first_v6, defaults.DHCPV6)
            ):
                if address:
                    # Basic state-matching rules. Allows packets related to a
                    # pre-established session to pass.
                    rules.append(Rule(
                        '-A FORWARD -d %s -o %s -m state '
                        '--state RELATED,ESTABLISHED -j ACCEPT' % (
                            address,
                            network.interface.ifname
                        ), ip_version=version
                    ))

                    # Allow DHCP
                    rules.append(Rule(
                        '-A INPUT -i %s -p udp -m udp --dport %s -j ACCEPT' % (
                            network.interface.ifname,
                            dhcp_port
                        ), ip_version=version
                    ))
                    rules.append(Rule(
                        '-A INPUT -i %s -p tcp -m tcp --dport %s -j ACCEPT' % (
                            network.interface.ifname,
                            dhcp_port
                        ), ip_version=version
                    ))

            # Allow pre-established metadata sessions to pass
            rules.append(Rule(
                '-A FORWARD -s %s -o %s -m state '
                '--state RELATED,ESTABLISHED -j ACCEPT' % (
                    defaults.METADATA_DEST_ADDRESS,
                    network.interface.ifname
                ), ip_version=4
            ))

            rules.append(Rule(
                '-A INPUT -i %s -j ACCEPT' % network.interface.ifname
            ))
            rules.append(Rule(
                '-A INPUT -i %s -m state '
                '--state RELATED,ESTABLISHED -j ACCEPT' % ext_if.ifname
            ))

        rules.append(Rule('COMMIT'))
        return rules

    def _build_nat_table(self, config):
        '''
        Add rules for generic v4 NAT for the internal tenant networks
        '''
        rules = [
            Rule('*nat', ip_version=4),
            Rule(':PREROUTING ACCEPT [0:0]', ip_version=4),
            Rule(':INPUT ACCEPT [0:0]', ip_version=4),
            Rule(':OUTPUT ACCEPT [0:0]', ip_version=4),
            Rule(':POSTROUTING ACCEPT [0:0]', ip_version=4),
        ]

        rules.extend(self._build_v4_nat(config))
        rules.extend(self._build_floating_ips(config))

        rules.append(Rule('COMMIT', ip_version=4))
        return rules

    def _build_v4_nat(self, config):
        rules = []
        ext_if = self.get_external_network(config).interface

        # Add a masquerade catch-all for VMs without floating IPs
        rules.append(Rule(
            '-A POSTROUTING -o %s -j MASQUERADE' % ext_if.ifname,
            ip_version=4
        ))

        for network in self.networks_by_type(config, Network.TYPE_INTERNAL):
            # Forward metadata requests on the management interface
            rules.append(Rule(
                '-A PREROUTING -s %s -d %s -p tcp -m tcp '
                '--dport %s -j DNAT --to-destination 127.0.0.1:%s' % (
                    network.interface.first_v4,
                    defaults.METADATA_DEST_ADDRESS,
                    defaults.HTTP,
                    defaults.internal_metadata_port(
                        network.interface.ifname
                    )
                ), ip_version=4
            ))

            # NAT for IPv4
            ext_v4 = sorted(
                a.ip for a in ext_if._addresses if a.version == 4
            )[0]
            rules.append(Rule(
                '-A POSTROUTING -s %s -o %s -j SNAT --to %s' % (
                    network.interface.first_v4,
                    network.interface.ifname,
                    str(ext_v4)
                ), ip_version=4
            ))

        return rules

    def _build_floating_ips(self, config):
        '''
        Add rules for neutron FloatingIPs.
        '''
        rules = []
        ext_if = self.get_external_network(config).interface
        ext_v4 = sorted(
            a.ip for a in ext_if._addresses if a.version == 4
        )[0]

        # Route floating IP addresses
        for fip in self.get_external_network(config).floating_ips:
            rules.append(Rule('-A POSTROUTING -o %s -s %s -j SNAT --to %s' % (
                ext_if.ifname,
                fip.fixed_ip,
                fip.floating_ip
            ), ip_version=4))
            rules.append(Rule(
                '-A PREROUTING -i %s -d %s -j DNAT --to-destination %s' % (
                    ext_if.ifname,
                    str(ext_v4),
                    fip.fixed_ip
                ), ip_version=4
            ))

        return rules
