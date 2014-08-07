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


import json
import logging

from akanda.router.defaults import internal_metadata_port
from akanda.router.drivers import base
from akanda.router.utils import execute, replace_file


LOG = logging.getLogger(__name__)
CONF_PATH = '/etc/metadata.conf'
METADATA_PROXY = '/usr/local/bin/metadata_proxy'


class MetadataManager(base.Manager):
    def __init__(self, root_helper='sudo'):
        super(MetadataManager, self).__init__(root_helper)

    def networks_have_changed(self, config):
        net_ids = set(
            [net.id for net in config.networks if net.is_tenant_network]
        )
        try:
            config_dict = json.load(open(CONF_PATH))
        except:
            # If we can't read the file, assume networks were added/removed
            return True
        config_dict.pop('tenant_id')
        return net_ids != set(config_dict.keys())

    def save_config(self, config):
        config_data = build_config(config)

        replace_file(
            '/tmp/metadata.conf',
            json.dumps(config_data, sort_keys=True)
        )
        execute(['mv', '/tmp/metadata.conf', CONF_PATH], self.root_helper)

    def ensure_started(self):
        try:
            execute(['/etc/init.d/metadata', 'status'], self.root_helper)
        except:
            execute(['/etc/init.d/metadata', 'start'], self.root_helper)

    def restart(self):
        try:
            execute(['/etc/init.d/metadata', 'stop'], self.root_helper)
        except:
            # failure is ok here
            pass
        execute(['/etc/init.d/metadata', 'start'], self.root_helper)


def build_config(config):
    config_data = {}

    for net in config.networks:
        if not net.is_tenant_network:
            continue

        ip_instance_map = {}
        for a in net.address_allocations:
            for ip in a.ip_addresses:
                ip_instance_map[ip] = a.device_id

        config_data[net.id] = {
            'listen_port': internal_metadata_port(net.interface.ifname),
            'ip_instance_map': ip_instance_map
        }

    config_data['tenant_id'] = config.tenant_id
    return config_data
