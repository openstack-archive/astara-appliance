import logging
import re

from akanda.router.drivers import base


LOG = logging.getLogger(__name__)


class ARPManager(base.Manager):
    EXECUTABLE = '/usr/sbin/arp'

    def remove_stale_entries(self, config):
        for network in config.networks:
            for a in network.address_allocations:
                for ip in a.dhcp_addresses:
                    address_for_ip = self._mac_address_for_ip(ip)
                    if address_for_ip and address_for_ip != a.mac_address:
                        self._delete_from_arp_cache(ip)

    def _mac_address_for_ip(self, ip):
        cmd_out = self.sudo('-an')
        match = re.search(' \(%s\) at ([^\s]+)' % ip, cmd_out)
        if match and match.groups():
            return match.group(1)

    def _delete_from_arp_cache(self, ip):
        self.sudo('-d', ip)
