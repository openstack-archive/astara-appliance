import os
import re

from akanda.router import models, utils
from akanda.router.drivers import dnsmasq, ifconfig, pf

DHCP_DIR = 'dhcp'
PF_FILENAME = 'pf.conf'


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
        return self._config

    def update_config(self, config):
        self._config = config

        self.update_interfaces()
        self.update_dhcp()
        self.update_pf()
        self.update_routes()

        #TODO(mark): update_vpn

    def update_interfaces(self):
        self.if_mgr.update_interfaces(self.config.interfaces)

    def update_dhcp(self):
        pass
        #dhcp_dir = os.path.join(self.state_path, 'dhcp')
        #ifmgr = ifconfig.InterfaceManager()
        #mgr = dnsmasq.DHCPManager(dhcp_dir)
        #mgr.update([(ifmgr.generic_to_host(n.interface.name), n.allocations)
        #            for n in self.config.networks
        #            if n.v4_conf_service==models.Network.DHCP])

    def update_pf(self):
        pf_path = os.path.join(self.state_path, PF_FILENAME)
        rule_data = self.config.pf_config
        rule_data = self._map_virtual_to_real_interfaces(rule_data)
        mgr = pf.PFManager()
        mgr.update_conf(rule_data)

    def update_routes(self):
        pass

    def get_interfaces(self):
        return self.if_mgr.get_interfaces()

    def get_interface(self, ifname):
        return self.if_mgr.get_interface(ifname)

    def _map_virtual_to_real_interfaces(self, virt_data):
        rules = []
        name_map = self.if_mgr.generic_mapping.items()

        rules.extend(
            ['%s = "%s"' % i for i in self.if_mgr.generic_mapping.items()])

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
