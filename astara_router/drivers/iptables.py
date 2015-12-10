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
import os

from astara_router.drivers import base
from astara_router.models import Network
from astara_router import defaults, utils


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

        :param config: The astara configuration to save to disk
        :type config: astara.rug.models.Configuration
        :param interface_map: A mapping of virtual ('ge0') to physical ('eth0')
                              interface names
        :type interface_map: dict
        '''
        rules = itertools.chain(
            self._build_filter_table(config),
            self._build_nat_table(config),
            self._build_mangle_table(config),
            self._build_raw_table(config)
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
        Reload firewall rules via [netfilter/iptables]-persistent
        Note that at some point iptables-persistent merged into
        netfilter-persistent as a plugin, so use that instead if it is
        available
        '''
        _init = '/etc/init.d/%s-persistent'
        if os.path.isfile(_init % 'netfilter'):
            init = _init % 'netfilter'
        else:
            init = _init % 'iptables'

        utils.execute(
            [init, 'restart'],
            self.root_helper
        )

    def get_rules(self):
        '''
        Return the output of `iptables` and `ip6tables`.
        This function is used by astara orchestrator -> HTTP as a test for
        "router aliveness".

        :rtype: str
        '''
        v4 = utils.execute(['iptables', '-L', '-n'])
        v6 = utils.execute(['ip6tables', '-L', '-n'])
        return v4 + v6

    def get_external_network(self, config):
        '''
        Returns the external network

        :rtype: astara_router.models.Network
        '''
        return self.networks_by_type(config, Network.TYPE_EXTERNAL)[0]

    def get_management_network(self, config):
        '''
        Returns the management network

        :rtype: astara_router.models.Network
        '''
        return self.networks_by_type(config, Network.TYPE_MANAGEMENT)[0]

    def get_internal_networks(self, config):
        '''
        Returns the internal networks

        :rtype: [astara_router.models.Network]
        '''
        return self.networks_by_type(config, Network.TYPE_INTERNAL)

    def networks_by_type(self, config, type):
        '''
        Returns the external network

        :rtype: astara_router.models.Interface
        '''
        return filter(lambda n: n.network_type == type, config.networks)

    def _build_filter_table(self, config):
        '''
        Build a list of iptables and ip6tables rules to be written to disk.

        :param config: the astara configuration object:
        :type config: astara_router.models.Configuration
        :param rules: the list of rules to append to
        :type rules: a list of astara_router.drivers.iptables.Rule objects
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
                '-A INPUT -p icmpv6 -j ACCEPT',
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

            # Allow established mgt traffic
            rules.append(Rule(
                '-A INPUT -i %s -m state --state RELATED,ESTABLISHED -j ACCEPT'
                % network.interface.ifname
            ))

            # Open SSH, the HTTP API (5000) and the Nova metadata proxy (9697)
            for port in (
                defaults.SSH, defaults.API_SERVICE,
                defaults.ORCHESTRATOR_METADATA_PORT
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

        for network in self.get_internal_networks(config):

            for version, address, dhcp_port in (
                (4, network.interface.first_v4, defaults.DHCP),
                (6, network.interface.first_v6, defaults.DHCPV6)
            ):
                if address:
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
        ]

        rules.extend(self._build_public_snat_chain(config))

        rules.extend([
            Rule(':PREROUTING ACCEPT [0:0]', ip_version=4),
            Rule(':INPUT ACCEPT [0:0]', ip_version=4),
            Rule(':OUTPUT ACCEPT [0:0]', ip_version=4),
            Rule(':POSTROUTING ACCEPT [0:0]', ip_version=4),
        ])

        rules.extend(self._build_floating_ips(config))
        rules.extend(self._build_v4_nat(config))

        rules.append(Rule('COMMIT', ip_version=4))
        return rules

    def _build_v4_nat(self, config):
        rules = []

        for network in self.get_internal_networks(config):
            if network.interface.first_v4:
                # Forward metadata requests on the management interface
                rules.append(Rule(
                    '-A PREROUTING -i %s -d %s -p tcp -m tcp '
                    '--dport %s -j DNAT --to-destination %s:%s' % (
                        network.interface.ifname,
                        defaults.METADATA_DEST_ADDRESS,
                        defaults.HTTP,
                        network.interface.first_v4,
                        defaults.internal_metadata_port(
                            network.interface.ifname
                        )
                    ), ip_version=4
                ))

        # Add a masquerade catch-all for VMs without floating IPs
        ext_if = self.get_external_network(config).interface
        rules.append(Rule(
            '-A POSTROUTING -o %s -j MASQUERADE' % (
                ext_if.ifname
            ), ip_version=4
        ))

        return rules

    def _build_floating_ips(self, config):
        '''
        Add rules for neutron FloatingIPs.
        '''
        rules = []
        ext_if = self.get_external_network(config).interface

        # NAT floating IP addresses
        for fip in self.get_external_network(config).floating_ips:

            # Neutron has a bug whereby you can create a floating ip that has
            # mixed IP versions between the fixed and floating address.  If
            # people create these accidentally, just ignore them (because
            # iptables will barf if it encounters them)
            if fip.fixed_ip.version == fip.floating_ip.version:
                rules.append(Rule(
                    '-A PREROUTING -i %s -d %s -j DNAT --to-destination %s' % (
                        ext_if.ifname,
                        fip.floating_ip,
                        fip.fixed_ip
                    ), ip_version=4
                ))
                for network in self.get_internal_networks(config):
                    rules.append(Rule(
                        '-A PREROUTING -i %s -d %s -j DNAT '
                        '--to-destination %s' % (
                            network.interface.ifname,
                            fip.floating_ip,
                            fip.fixed_ip
                        ), ip_version=4
                    ))

        if rules:
            for network in self.get_internal_networks(config):
                for subnet in network.subnets:
                    if subnet.cidr.version == 4:
                        rules.append(
                            Rule('-A POSTROUTING -s %s -j PUBLIC_SNAT' % (
                                subnet.cidr
                            ), ip_version=4)
                        )

        return rules

    def _build_public_snat_chain(self, config):
        '''
        Build a chain for SNAT for neutron FloatingIPs.  This chain ignores NAT
        for traffic marked as private.
        '''
        rules = [
            Rule(':PUBLIC_SNAT - [0:0]', ip_version=4),
            Rule(
                '-A PUBLIC_SNAT -m mark --mark 0xACDA -j RETURN',
                ip_version=4
            )
        ]

        external_network = self.get_external_network(config)

        # NAT floating IP addresses
        for fip in external_network.floating_ips:

            if fip.fixed_ip.version == fip.floating_ip.version:
                rules.append(
                    Rule('-A PUBLIC_SNAT -s %s -j SNAT --to %s' % (
                        fip.fixed_ip,
                        fip.floating_ip
                    ), ip_version=4)
                )

        # Add source NAT for VMs without floating IPs
        mgt_if = self.get_management_network(config).interface
        rules.append(Rule(
            '-A PUBLIC_SNAT ! -o %s -j SNAT --to %s' % (
                mgt_if.ifname,
                str(external_network.interface.first_v4)
            ),
            ip_version=4
        ))

        return rules

    def _build_mangle_table(self, config):
        rules = [
            Rule('*mangle', ip_version=4),
            Rule(':INPUT - [0:0]', ip_version=4),
            Rule(':OUTPUT - [0:0]', ip_version=4),
            Rule(':FORWARD - [0:0]', ip_version=4),
            Rule(':PREROUTING - [0:0]', ip_version=4),
            Rule(':POSTROUTING - [0:0]', ip_version=4),
            Rule(
                ('-A POSTROUTING -p udp -m udp --dport 68 '
                 '-j CHECKSUM --checksum-fill'),
                ip_version=4),
            Rule('COMMIT', ip_version=4)
        ]
        return rules

    def _build_raw_table(self, config):
        '''
        Add raw rules (so we can mark private traffic and avoid NATing it)
        '''
        rules = [
            Rule('*raw', ip_version=4),
            Rule(':INPUT - [0:0]', ip_version=4),
            Rule(':OUTPUT - [0:0]', ip_version=4),
            Rule(':FORWARD - [0:0]', ip_version=4),
            Rule(':PREROUTING - [0:0]', ip_version=4)
        ]
        ext_if = self.get_external_network(config).interface
        rules.append(Rule(
            '-A PREROUTING -i %s -j MARK --set-mark 0xACDA' % ext_if.ifname,
            ip_version=4
        ))

        for network in self.networks_by_type(config, Network.TYPE_INTERNAL):
            if network.interface.first_v4:
                address = sorted(
                    str(a) for a in network.interface.addresses
                    if a.version == 4
                )[0]
                rules.append(Rule(
                    '-A PREROUTING -d %s -j MARK --set-mark 0xACDA' % address,
                    ip_version=4
                ))

        rules.append(Rule(':POSTROUTING - [0:0]', ip_version=4))
        rules.append(Rule('COMMIT', ip_version=4))
        return rules
