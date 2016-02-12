# Copyright (c) 2016 Akanda, Inc. All Rights Reserved.
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

from astara_router.drivers import base, conntrackd
from astara_router import utils


class KeepalivedVipAddress(object):
    """A virtual address entry of a keepalived configuration."""

    def __init__(self, address, interface):
        self.address = address
        self.interface = interface

    def __eq__(self, other):
        return (isinstance(other, KeepalivedVipAddress) and
                self.address.ip == other.address.ip)


class KeepalivedRoute(object):
    """A virtual route entry in keepalived instance configuration"""
    def __init__(self, destination, gateway):
        self.destination = destination
        self.gateway = gateway

    def __eq__(self, other):
        return (
            isinstance(other, KeepalivedRoute) and
            (self.destination, self.gateway) ==
            (other.destination, other.gateway)
        )


class KeepalivedInstance(object):
    def __init__(self, interface, unicast_src_ip, vrrp_id, state='BACKUP',
                 garp_master_delay=60):
        self.interface = interface
        self.vrrp_id = vrrp_id
        self.unicast_src_ip = unicast_src_ip
        self.name = 'astara_vrrp_' + interface
        self.state = state
        self.garp_master_delay = 60
        self.vips = []
        self.routes = []

    def add_vip(self, address):
        vip = KeepalivedVipAddress(address, self.interface)
        if vip not in self.vips:
            self.vips.append(vip)

    def add_route(self, destination, gateway):
        route = KeepalivedRoute(destination, gateway)
        if route not in self.routes:
            self.routes.append(route)


class KeepalivedManager(base.Manager):
    CONFIG_FILE_TEMPLATE = os.path.join(
        os.path.dirname(__file__), 'keepalived.conf.template')

    # Debian defaults
    CONFIG_FILE = '/etc/keepalived/keepalived.conf'
    PID_FILE = '/var/run/keepalived.pid'

    EXECUTABLE = 'service'

    def __init__(self, root_helper='sudo astara-rootwrap /etc/rootwrap.conf'):
        super(KeepalivedManager, self).__init__(root_helper)
        self.instances = {}
        self.unicast_src_ip = None
        self.config_tmpl = utils.load_template(self.CONFIG_FILE_TEMPLATE)
        self.peers = []
        self.priority = 0
        self.notify_script = conntrackd.ConntrackdManager.NOTIFY_SCRIPT
        self._last_config_hash = None

    def set_management_address(self, address):
        """Specify the address used for keepalived cluster communication"""
        self.unicast_src_ip = address
        for instance in self.instances.values():
            instance.unicast_src_ip = address

    def _get_instance(self, interface):
            if interface in self.instances:
                return self.instances[interface]

            vrrp_id = len(self.instances) + 1
            self.instances[interface] = KeepalivedInstance(
                interface, self.unicast_src_ip, vrrp_id=vrrp_id)
            return self.instances[interface]

    def _is_running(self):
        if not os.path.isfile(self.PID_FILE):
            return False

        pid = open(self.PID_FILE).read().strip()
        proc_cmd = os.path.join('/proc', pid, 'cmdline')
        if not os.path.isfile(proc_cmd):
            return False

        if 'keepalived' not in open(proc_cmd).read():
            return False

        return True

    def add_vrrp_instance(self, interface, addresses):
        instance = self._get_instance(interface)
        [instance.add_vip(addr) for addr in addresses]

    def config(self):
        return self.config_tmpl.render(
            priority=self.priority,
            peers=self.peers,
            notify_script=self.notify_script,
            vrrp_instances=self.instances.values())

    def reload(self):
        try:
            last_config_hash = utils.hash_file(self.CONFIG_FILE)
        except IOError:
            last_config_hash = None

        utils.replace_file('/tmp/keepalived.conf', self.config())
        utils.execute(
            ['mv', '/tmp/keepalived.conf', '/etc/keepalived/keepalived.conf'],
            self.root_helper)

        if utils.hash_file(self.CONFIG_FILE) == last_config_hash:
            return

        if self._is_running():
            self.sudo('keepalived', 'reload')
        else:
            self.sudo('keepalived', 'restart')

    def set_default_gateway(self, ip_version, gateway_ip, interface):
        instance = self._get_instance(interface)
        if ip_version == 6:
            default = 'default6'
        else:
            default = 'default'
        instance.add_route(default, gateway_ip)

    def set_priority(self, priority):
        self.priority = priority
