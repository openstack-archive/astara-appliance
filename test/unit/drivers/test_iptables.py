from copy import deepcopy
from unittest import TestCase

import mock
import netaddr

from astara_router import models
from astara_router.drivers import iptables

CONFIG = models.RouterConfiguration({
    'networks': [{
        'network_id': 'ABC123',
        'interface': {
            'ifname': 'eth0',
            'addresses': [
                'fdca:3ba5:a17a:acda:f816:3eff:fe66:33b6/64',
                'fe80::f816:3eff:fe66:33b6/64'
            ]
        },
        'name': 'mgt',
        'network_type': models.Network.TYPE_MANAGEMENT,
    }, {
        'network_id': 'ABC456',
        'interface': {
            'ifname': 'eth1',
            'addresses': [
                '172.16.77.2/24',
                'fdee:9f85:83be:0:f816:3eff:fe42:a9f/48'
            ]
        },
        'name': 'ext',
        'network_type': models.Network.TYPE_EXTERNAL,
        'subnets': [{
            'cidr': '172.16.77.0/24',
            'gateway_ip': '172.16.77.1',
            'dhcp_enabled': True,
            'dns_nameservers': []
        }]
    }, {
        'network_id': 'ABC789',
        'interface': {
            'ifname': 'eth2',
            'addresses': [
                '192.168.0.1/24',
                'fdd6:a1fa:cfa8:9df::1/64'
            ]
        },
        'name': 'internal',
        'network_type': models.Network.TYPE_INTERNAL,
        'subnets': [{
            'cidr': '192.168.0.0/24',
            'gateway_ip': '192.168.0.1',
            'dhcp_enabled': True,
            'dns_nameservers': []
        }]
    }],
    'floating_ips': [{
        'fixed_ip': '192.168.0.2',
        'floating_ip': '172.16.77.50'
    }]
})

V4_OUTPUT = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':FORWARD ACCEPT [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -p icmp --icmp-type echo-request -j ACCEPT',
    '-A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT',
    '-A INPUT -i eth2 -p udp -m udp --dport 67 -j ACCEPT',
    '-A INPUT -i eth2 -p tcp -m tcp --dport 67 -j ACCEPT',
    '-A INPUT -i eth2 -j ACCEPT',
    '-A INPUT -i eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT',
    'COMMIT',
    '*nat',
    ':PUBLIC_SNAT - [0:0]',
    '-A PUBLIC_SNAT -m mark --mark 0xACDA -j RETURN',
    '-A PUBLIC_SNAT -s 192.168.0.2 -j SNAT --to 172.16.77.50',
    '-A PUBLIC_SNAT ! -o eth0 -j SNAT --to 172.16.77.2',
    ':PREROUTING ACCEPT [0:0]',
    ':INPUT ACCEPT [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    ':POSTROUTING ACCEPT [0:0]',
    '-A PREROUTING -i eth1 -d 172.16.77.50 -j DNAT --to-destination 192.168.0.2',  # noqa
    '-A PREROUTING -i eth2 -d 172.16.77.50 -j DNAT --to-destination 192.168.0.2',  # noqa
    '-A POSTROUTING -s 192.168.0.0/24 -j PUBLIC_SNAT',
    '-A PREROUTING -i eth2 -d 169.254.169.254 -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.0.1:9602',  # noqa
    '-A POSTROUTING -o eth1 -j MASQUERADE',
    'COMMIT',
    '*mangle',
    ':INPUT - [0:0]',
    ':OUTPUT - [0:0]',
    ':FORWARD - [0:0]',
    ':PREROUTING - [0:0]',
    ':POSTROUTING - [0:0]',
    '-A POSTROUTING -p udp -m udp --dport 68 -j CHECKSUM --checksum-fill',
    'COMMIT',
    '*raw',
    ':INPUT - [0:0]',
    ':OUTPUT - [0:0]',
    ':FORWARD - [0:0]',
    ':PREROUTING - [0:0]',
    '-A OUTPUT -j MARK --set-mark 0xACDA',
    '-A PREROUTING -i eth1 -j MARK --set-mark 0xACDA',
    '-A PREROUTING -d 192.168.0.1/24 -j MARK --set-mark 0xACDA',
    ':POSTROUTING - [0:0]',
    'COMMIT'
]

V6_OUTPUT = [
    '*filter',
    ':INPUT DROP [0:0]',
    ':FORWARD ACCEPT [0:0]',
    ':OUTPUT ACCEPT [0:0]',
    '-A INPUT -i lo -j ACCEPT',
    '-A INPUT -p icmpv6 -j ACCEPT',
    '-A INPUT -i eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT',
    '-A INPUT -i eth0 -p tcp -m tcp --dport 22 -j ACCEPT',
    '-A INPUT -i eth0 -p tcp -m tcp --dport 5000 -j ACCEPT',
    '-A INPUT -i eth0 -p tcp -m tcp --dport 9697 -j ACCEPT',
    '-A INPUT -i !eth0 -d fdca:3ba5:a17a:acda:f816:3eff:fe66:33b6 -j DROP',
    '-A INPUT -i eth2 -p udp -m udp --dport 546 -j ACCEPT',
    '-A INPUT -i eth2 -p tcp -m tcp --dport 546 -j ACCEPT',
    '-A INPUT -i eth2 -j ACCEPT',
    '-A INPUT -i eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT',
    'COMMIT'
]


class TestIPTablesRouterConfiguration(TestCase):

    def setUp(self):
        super(TestIPTablesRouterConfiguration, self).setUp()
        self.execute = mock.patch('astara_router.utils.execute').start()
        self.replace = mock.patch('astara_router.utils.replace_file').start()
        self.patches = [self.execute, self.replace]

    def tearDown(self):
        super(TestIPTablesRouterConfiguration, self).tearDown()
        for p in self.patches:
            p.stop()

    def test_complete(self):
        mgr = iptables.IPTablesManager()
        mgr.save_config(CONFIG, {
            'ge0': 'eth0',
            'ge1': 'eth1',
            'ge2': 'eth2'
        })

        assert self.replace.call_count == 2

        assert mock.call(
            '/tmp/ip4tables.rules',
            '\n'.join(V4_OUTPUT) + '\n'
        ) in self.replace.call_args_list

        assert mock.call(
            '/tmp/ip6tables.rules',
            '\n'.join(V6_OUTPUT) + '\n'
        ) in self.replace.call_args_list

        assert self.execute.call_args_list == [
            mock.call(
                ['mv', '/tmp/ip4tables.rules', '/etc/iptables/rules.v4'],
                'sudo astara-rootwrap /etc/rootwrap.conf'
            ),
            mock.call(
                ['mv', '/tmp/ip6tables.rules', '/etc/iptables/rules.v6'],
                'sudo astara-rootwrap /etc/rootwrap.conf'
            )
        ]

    @mock.patch('os.path.isfile')
    def test_restart_iptables_persistent(self, mock_isfile):
        mock_isfile.return_value = False
        mgr = iptables.IPTablesManager()
        mgr.restart()
        assert self.execute.call_args_list == [
            mock.call(['service', 'iptables-persistent', 'restart'],
                      'sudo astara-rootwrap /etc/rootwrap.conf')
        ]

    @mock.patch('os.path.isfile')
    def test_restart_netfilter_persistent(self, mock_isfile):
        mock_isfile.return_value = True
        mgr = iptables.IPTablesManager()
        mgr.restart()
        assert self.execute.call_args_list == [
            mock.call(['service', 'netfilter-persistent', 'restart'],
                      'sudo astara-rootwrap /etc/rootwrap.conf')
        ]

    def test_mixed_floating_ip_versions(self):
        # Neutron has a bug whereby you can create a floating ip that has
        # mixed IP versions between the fixed and floating address.  If
        # people create these accidentally, just ignore them (because
        # iptables will barf if it encounters them)
        mgr = iptables.IPTablesManager()
        config = deepcopy(CONFIG)
        config.floating_ips[0].fixed_ip = netaddr.IPAddress(
            'fdca:3ba5:a17a:acda:f816:3eff:fe66:33b6'
        )
        assert map(str, mgr._build_floating_ips(CONFIG)) == [
            '-A PREROUTING -i eth1 -d 172.16.77.50 -j DNAT --to-destination 192.168.0.2',  # noqa
            '-A PREROUTING -i eth2 -d 172.16.77.50 -j DNAT --to-destination 192.168.0.2',  # noqa
            '-A POSTROUTING -s 192.168.0.0/24 -j PUBLIC_SNAT'
        ]
        assert mgr._build_floating_ips(config) == []

    @mock.patch.object(iptables.IPTablesManager, 'get_external_network')
    def test_no_ext_port(self, fake_get_ext_net):
        fake_get_ext_net.return_value = None
        mgr = iptables.IPTablesManager()
        mgr.save_config(CONFIG, {
            'ge0': 'eth0',
            'ge1': 'eth1',
            'ge2': 'eth2'
        })
