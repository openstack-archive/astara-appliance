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


import os
import re

from astara_router import models
from astara_router import settings
from astara_router.drivers import (arp, bird, dnsmasq, hostname, ip, iptables,
                                   loadbalancer, metadata)

from astara_router.drivers.vpn import ipsec


class ServiceManagerBase(object):
    def __init__(self, state_path='.'):
        self._config = None
        self.state_path = os.path.abspath(state_path)
        self._vrrp_ip_mgr = None
        self._reload_callbacks = []

    @property
    def ip_mgr(self):
        ip_mgr = ip.IPManager()
        ip_mgr.ensure_mapping()

        if not self._config:
            # we do not yet have config, so use standard ip manager for
            # ensuring initial intrefaces
            return ip_mgr
        if self._config and self._config.ha:
            if not self._vrrp_ip_mgr:
                self._vrrp_ip_mgr = ip.VRRPIPManager()
                self._reload_callbacks.append(self._vrrp_ip_mgr.reload)

            # peers and prio can change and be updated via config, need to
            # ensure the vrrp manager is up to date every access.
            self._vrrp_ip_mgr.set_peers(
                self._config.ha_config.get('peers', []))
            self._vrrp_ip_mgr.set_priority(
                self._config.ha_config.get('priority', 0))

            return self._vrrp_ip_mgr
        else:
            # we may not yet have config, so use standard ip manager for
            # ensuring initial interfaces
            return ip_mgr

    @property
    def config(self):
        """Make config a read-only property.

        To update the value, update_config() must called to change the global
        state of appliance.
        """
        return self._config

    def update_config(self, config, cache):
        pass

    def update_interfaces(self):
        if self._config is None:
            return
        for network in self._config.networks:
            self.ip_mgr.disable_duplicate_address_detection(network)

        self.ip_mgr.update_interfaces(self._config.interfaces)

    def reload_config(self):
        """Calls any post-config reload callbacks to reload services

        Required for things like keepalived, which gets its config built
        by multiple drivers, in order to avoid unncessary restarts.
        """
        [cb() for cb in self._reload_callbacks]


class SystemManager(ServiceManagerBase):
    def __init__(self, state_path='.'):
        super(SystemManager, self).__init__(state_path)
        self._config = models.SystemConfiguration()

    def update_config(self, config, cache):
        self._config = config
        self.update_hostname()
        self.update_interfaces()

    def update_hostname(self):
        mgr = hostname.HostnameManager()
        mgr.update(self._config)


class RouterManager(ServiceManagerBase):

    def update_config(self, config, cache):
        self._config = config
        self.update_interfaces()
        self.update_dhcp()
        self.update_metadata()
        self.update_bgp_and_radv()
        self.update_firewall()
        self.update_routes(cache)
        self.update_arp()
        self.update_ipsec_vpn()
        self.reload_config()

    def update_dhcp(self):
        mgr = dnsmasq.DHCPManager()
        mgr.delete_all_config()
        for network in self._config.networks:
            real_ifname = self.ip_mgr.generic_to_host(network.interface.ifname)
            mgr.update_network_dhcp_config(real_ifname, network)
        mgr.restart()

    def update_metadata(self):
        mgr = metadata.MetadataManager()
        should_restart = mgr.should_restart(self._config)
        mgr.save_config(self._config)
        if should_restart:
            mgr.restart()
        else:
            mgr.ensure_started()

    def update_bgp_and_radv(self):
        mgr = bird.BirdManager()
        mgr.save_config(self._config, self.ip_mgr.generic_mapping)
        mgr.restart()

    def update_firewall(self):
        mgr = iptables.IPTablesManager()
        mgr.save_config(self._config, self.ip_mgr.generic_mapping)
        mgr.restart()

    def update_routes(self, cache):
        self.ip_mgr.update_default_gateway(self._config)
        self.ip_mgr.update_host_routes(self._config, cache)

    def update_arp(self):
        mgr = arp.ARPManager()
        mgr.send_gratuitous_arp_for_floating_ips(
            self._config,
            self.ip_mgr.generic_to_host
        )
        mgr.remove_stale_entries(self._config)

    def update_ipsec_vpn(self):
        mgr = ipsec.StrongswanManager()

        if self._config.vpn:
            mgr.save_config(self._config)
            mgr.restart()
        else:
            mgr.stop()

    def get_interfaces(self):
        return self.ip_mgr.get_interfaces()

    def get_interface(self, ifname):
        return self.ip_mgr.get_interface(ifname)

    def _map_virtual_to_real_interfaces(self, virt_data):
        rules = []

        rules.extend(
            '%s = "%s"' % i for i in self.ip_mgr.generic_mapping.items()
        )

        rules.append(re.sub('([\s!])(ge\d+([\s:]|$))', r'\1$\2', virt_data))
        return '\n'.join(rules)

    def get_config_or_default(self):
        # This is a hack to provide compatability with the original API, see
        # Manager.config()
        if not self._config:
            return models.RouterConfiguration()
        else:
            return self._config


class LoadBalancerManager(ServiceManagerBase):
    def __init__(self, state_path='.'):
        super(LoadBalancerManager, self).__init__(state_path)
        self.lb_manager = loadbalancer.get_loadbalancer_driver(
            # xxx pull from cfg
            loadbalancer.CONFIGURED_LB_DRIVER)()

    def update_config(self, config, cache):
        self._config = config
        self.lb_manager.update_config(self.config)


SERVICE_MANAGER_MAP = {
    'router': RouterManager,
    'loadbalancer': LoadBalancerManager,
}


class Manager(object):
    def __init__(self, state_path='.'):
        self.state_path = os.path.abspath(state_path)
        self.ip_mgr = ip.IPManager()
        self.ip_mgr.ensure_mapping()

        # Holds the common system config
        self._system_config = models.SystemConfiguration()

        # Holds config models for various services (router, loadbalancer)
        self._service_configs = []

        self._service_managers = {
            'system': SystemManager()
        }
        self._load_managers()

    def _load_managers(self):
        for svc in settings.ENABLED_SERVICES:
            manager = SERVICE_MANAGER_MAP.get(svc)
            if manager:
                self._service_managers[svc] = manager()

    def get_manager(self, service):
        try:
            return self._service_managers[service]
        except:
            raise Exception('No such service manager loaded for appliance '
                            'service %s' % service)

    def management_address(self, ensure_configuration=False):
        return self.ip_mgr.get_management_address(ensure_configuration)

    @property
    def router(self):
        """Returns the router manager.
        This is mostly to keep compat with the existing API.
        """
        return self.get_manager('router')

    @property
    def system_config(self):
        """Make config a read-only property.

        To update the value, update_config() must called to change the global
        state of appliance.
        """

        return self._system_config

    @property
    def service_configs(self):
        """Make config a read-only property.

        To update the value, update_config() must called to change the global
        state of router.
        """

        return self._service_configs

    def update_config(self, system_config, service_configs, cache):
        self._system_config = system_config
        self._service_configs = service_configs

        # first update the system config
        manager = self.get_manager(self.system_config.service_name)
        manager.update_config(self.system_config, cache)

        for svc_cfg in self.service_configs:
            manager = self.get_manager(svc_cfg.service_name)
            manager.update_config(svc_cfg, cache)

    @property
    def config(self):
        out = {}
        if 'router' in self._service_managers:
            # The original appliance API provides router config
            # in the root 'configuration' key.  We want to move that
            # to the 'services' bucket but provide compat to those who might
            # still be expecting it in the root. This seeds the root with the
            # default empty values if no router is associated with the
            # appliance and allows for
            # ['configuration']['services']['router'] to be None at the same
            # time.
            router_cfg = self.router.get_config_or_default().to_dict()
            out = router_cfg
        else:
            out = {}

        out['services'] = {}
        for svc in SERVICE_MANAGER_MAP:
            try:
                manager = self.get_manager(svc)
            except:
                continue
            out['services'][svc] = manager.config

        out['system'] = self.system_config
        return out


class ManagerProxy(object):
    def __init__(self):
        self.instance = None

    def __getattr__(self, name):
        if not self.instance:
            self.instance = Manager()
        return getattr(self.instance, name)

manager = ManagerProxy()
