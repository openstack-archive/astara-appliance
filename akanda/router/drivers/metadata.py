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

    def save_config(self, config):
        config_data = build_config(config)

        replace_file('/tmp/metadata.conf', json.dumps(config_data))
        execute(['mv', '/tmp/metadata.conf', CONF_PATH], self.root_helper)

    def restart(self):
        try:
            execute(['/etc/rc.d/metadata', 'stop'], self.root_helper)
        except:
            # failure is ok here
            pass
        execute(['/etc/rc.d/metadata', 'start'], self.root_helper)


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

    return config_data
