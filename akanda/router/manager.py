import os
import re

from akanda.router import models
from akanda.router.drivers import bird, dnsmasq, ifconfig, metadata, pf, route


class Manager(object):
    def __init__(self, state_path='.'):
        self.state_path = os.path.abspath(state_path)
        self.if_mgr = ifconfig.InterfaceManager()
        self.if_mgr.ensure_mapping()
        self._config = models.Configuration()

    def management_address(self, ensure_configuration=False):
        return self.if_mgr.get_management_address(ensure_configuration)

    @property
    def config(self):
        """Make config a read-only property.

        To update the value, update_config() must called to change the global
        state of router.
        """

        return self._config

    def update_config(self, config):
        self._config = config

        self.update_interfaces()
        self.update_dhcp()
        self.update_metadata()
        self.update_bgp_and_radv()
        self.update_pf()
        self.update_routes()

        #TODO(mark): update_vpn

    def update_interfaces(self):
        self.if_mgr.update_interfaces(self.config.interfaces)

    def update_dhcp(self):
        mgr = dnsmasq.DHCPManager()

        for network in self.config.networks:
            real_ifname = self.if_mgr.generic_to_host(network.interface.ifname)
            mgr.update_network_dhcp_config(real_ifname, network)
        mgr.restart()

    def update_metadata(self):
        mgr = metadata.MetadataManager()
        mgr.save_config(self.config)
        mgr.restart()

    def update_bgp_and_radv(self):
        mgr = bird.BirdManager()
        mgr.save_config(self.config, self.if_mgr.generic_mapping)
        mgr.restart()

    def update_pf(self):
        rule_data = self.config.pf_config
        rule_data = self._map_virtual_to_real_interfaces(rule_data)
        mgr = pf.PFManager()
        mgr.update_conf(rule_data)

    def update_routes(self):
        mgr = route.RouteManager()
        mgr.update_default(self.config)

    def get_interfaces(self):
        return self.if_mgr.get_interfaces()

    def get_interface(self, ifname):
        return self.if_mgr.get_interface(ifname)

    def _map_virtual_to_real_interfaces(self, virt_data):
        rules = []

        rules.extend(
            '%s = "%s"' % i for i in self.if_mgr.generic_mapping.items()
        )

        rules.append(re.sub('([\s!])(ge\d+([\s:]|$))', r'\1$\2', virt_data))
        return '\n'.join(rules)


class ManagerProxy(object):
    def __init__(self):
        self.instance = None

    def __getattr__(self, name):
        if not self.instance:
            self.instance = Manager()
        return getattr(self.instance, name)

manager = ManagerProxy()
