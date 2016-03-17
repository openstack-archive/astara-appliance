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

from astara_router.settings import internal_metadata_port
from astara_router.drivers import base
from astara_router.utils import execute, replace_file


CONF_PATH = '/etc/metadata.conf'


class MetadataManager(base.Manager):
    """
    A class to provide facilities to interact with the Nova metadata service.
    """

    def __init__(self, root_helper='sudo astara-rootwrap /etc/rootwrap.conf'):
        """
        Initializes MetataManager class.

        :type root_helper: str
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(MetadataManager, self).__init__(root_helper)

    def should_restart(self, config):
        """
        This function determines if the networks have changed since <config>
        was initialized.

        :type config: astara_router.models.Configuration
        :param config: An astara_router.models.Configuration object containing
                       the current configuration of the system's networks.
        :rtype: bool
        """
        net_ids = set(
            [net.id for net in config.networks if net.is_tenant_network]
        )
        try:
            config_dict = json.load(open(CONF_PATH))
        except:
            # If we can't read the file, assume networks were added/removed
            return True

        orchestrator_addr = config_dict.get('orchestrator_metadata_address')
        orchestrator_port = config_dict.get('orchestrator_metadata_port')

        return (
            net_ids != set(config_dict.get('networks', {}).keys()) or
            orchestrator_addr != config.metadata_address or
            orchestrator_port != config.metadata_port)

    def save_config(self, config):
        """
        Writes <config> to the metadata configuration file (<CONF_PATH>).

        :type config: astara_router.models.Configuration
        :param config: An astara_router.models.Configuration object containing
                       the configuration of metadata service.
        """
        config_data = build_config(config)

        replace_file(
            '/tmp/metadata.conf',
            json.dumps(config_data, sort_keys=True)
        )
        execute(['mv', '/tmp/metadata.conf', CONF_PATH], self.root_helper)

    def ensure_started(self):
        """
        Checks if the metadata service is started and starts it if it is
        determined to be stopped.
        """
        try:
            execute(['service', 'metadata', 'status'], self.root_helper)
        except:
            execute(['service', 'metadata', 'start'], self.root_helper)

    def restart(self):
        """
        Restarts the metadata service using the init script.
        """
        try:
            execute(['service', 'metadata', 'stop'], self.root_helper)
        except:
            # failure is ok here
            pass
        execute(['service', 'metadata', 'start'], self.root_helper)


def build_config(config):
    """
    Determines the configuration of the metadata service.

    :type config: astara_router.models.Configuration
    :param config:
    :rtype: astara_router.models.Configuration
    """
    network_data = {}

    for net in config.networks:
        if not net.is_tenant_network:
            continue

        ip_instance_map = {}
        for a in net.address_allocations:
            for ip in a.ip_addresses:
                ip_instance_map[ip] = a.device_id

        network_data[net.id] = {
            'listen_port': internal_metadata_port(net.interface.ifname),
            'ip_instance_map': ip_instance_map
        }

    return {
        'tenant_id': config.tenant_id,
        'orchestrator_metadata_address': config.metadata_address,
        'orchestrator_metadata_port': config.metadata_port,
        'networks': network_data,
    }
