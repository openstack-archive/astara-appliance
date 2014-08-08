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
        rules = []

	self._build_filter_table(config, interface_map, rules)
	self._build_nat_table(config, interface_map, rules)

        v4_data = '\n'.join(map(str, filter(lambda x: x.for_v4, rules)))
        v6_data = '\n'.join(map(str, filter(lambda x: x.for_v6, rules)))

        real_name = interface_map.get('ge0')[:-1]

        # Map virtual interface names
        ifname_re = '\-(?P<flag>i|o)(?P<ws>[\s!])(?P<not>!?)(?P<if>ge)(?P<no>\d+)'  # noqa
        ifname_sub = r'-\g<flag>\g<ws>\g<not>%s\g<no>' % real_name
        v4_data = re.sub(ifname_re, ifname_sub, v4_data) + '\n'
        v6_data = re.sub(ifname_re, ifname_sub, v6_data) + '\n'

        utils.replace_file('/tmp/iptables.rules', v4_data)
        utils.replace_file('/tmp/ip6tables.rules', v6_data)

        utils.execute(
            ['mv', '/tmp/iptables.rules', '/etc/iptables/rules.v4'],
            self.root_helper
        )
        utils.execute(
            ['mv', '/tmp/ip6tables.rules', '/etc/iptables/rules.v6'],
            self.root_helper
        )

    def restart(self):
        utils.execute(
            ['/etc/init.d/iptables-persistent', 'restart'],
            self.root_helper
        )

    def get_rules(self):
        v4 = utils.execute(['iptables', '-L', '-n'])
        v6 = utils.execute(['ip6tables', '-L', '-n'])
        return v4 + v6

    def get_external_network(self, config):
        for n in config.networks:
            if n.network_type == Network.TYPE_EXTERNAL:
                return n

    def _build_filter_table(self, config, interface_map, rules):
        ext_if = self.get_external_network(config).interface

        # Drop INPUT/OUTPUT by default
        rules.extend([
            Rule('*filter'),
            Rule(':INPUT DROP [0:0]'),
            Rule(':FORWARD ACCEPT [0:0]'),
            Rule(':OUTPUT ACCEPT [0:0]')
        ])

        # Allow ICMP and ICMP6
        rules.append(Rule(
            '-A INPUT -p icmp --icmp-type echo-request -j ACCEPT',
            ip_version=4
        ))
        rules.append(Rule(
            '-A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT',
            ip_version=6
        ))

        for network in [
            n for n in config.networks
            if n.network_type == Network.TYPE_MANAGEMENT
        ]:

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

        for network in [
            n for n in config.networks
            if n.network_type == Network.TYPE_INTERNAL
        ]:

            if network.interface.first_v4:

                # Basic v4 state-matching rules. Allows packets related to a
                # pre-established session to pass.
                rules.append(Rule(
                    '-A FORWARD -d %s -o %s -m state '
                    '--state RELATED,ESTABLISHED -j ACCEPT' % (
                        network.interface.first_v4,
                        network.interface.ifname
                    ), ip_version=4
                ))

                # Allow v4 DHCP
                rules.append(Rule(
                    '-A INPUT -i %s -p udp -m udp --dport %s -j ACCEPT' % (
                        network.interface.ifname,
                        defaults.DHCP
                    ), ip_version=4
                ))
                rules.append(Rule(
                    '-A INPUT -i %s -p tcp -m tcp --dport %s -j ACCEPT' % (
                        network.interface.ifname,
                        defaults.DHCP
                    ), ip_version=4
                ))

            if network.interface.first_v6:

                # Basic v6 state-matching rules. Allows packets related to a
                # pre-established session to pass.
                rules.append(Rule(
                    '-A FORWARD -d %s -o %s -m state '
                    '--state RELATED,ESTABLISHED -j ACCEPT' % (
                        network.interface.first_v6,
                        network.interface.ifname
                    ), ip_version=6
                ))

                # Allow v6 DHCP
                rules.append(Rule(
                    '-A INPUT -i %s -p udp -m udp --dport %s -j ACCEPT' % (
                        network.interface.ifname,
                        defaults.DHCPV6,
                    ), ip_version=6
                ))
                rules.append(Rule(
                    '-A INPUT -i %s -p tcp -m tcp --dport %s -j ACCEPT' % (
                        network.interface.ifname,
                        defaults.DHCPV6,
                    ), ip_version=6
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

    def _build_nat_table(self, config, interface_map, rules):
        ext_if = self.get_external_network(config).interface

        rules.extend([
            Rule('*nat', ip_version=4),
            Rule(':PREROUTING ACCEPT [0:0]', ip_version=4),
            Rule(':INPUT ACCEPT [0:0]', ip_version=4),
            Rule(':OUTPUT ACCEPT [0:0]', ip_version=4),
            Rule(':POSTROUTING ACCEPT [0:0]', ip_version=4),
        ])

        for network in config.networks:

            if network.network_type == Network.TYPE_INTERNAL:

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

        # Route floating IP addresses
        for fip in self.get_external_network(config).floating_ips:
            rules.append(Rule('-A POSTROUTING -o %s -s %s -j SNAT --to %s' % (
                ext_if.ifname,
                fip.fixed_ip,
                fip.floating_ip
            ), ip_version=4))

        rules.append(Rule('COMMIT', ip_version=4))
