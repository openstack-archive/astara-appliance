import logging

from akanda.router.drivers import base


LOG = logging.getLogger(__name__)


class RouteManager(base.Manager):
    EXECUTABLE = '/sbin/route'

    def __init__(self, root_helper='sudo'):
        super(RouteManager, self).__init__(root_helper)

    def update_v4_default(self, config):
        for net in config.networks:
            if not net.is_external_network:
                continue

            for subnet in net.subnets:
                if subnet.cidr.version == 4 and subnet.gateway_ip:
                    self._set_default_gateway(subnet.gateway_ip)

    def _set_default_gateway(self, gateway_ip):
        try:
            current = self.sudo('get', '0.0.0.0/0')
        except:
            current = None

        if current and 'no such process' not in current.lower():
            return self.sudo('change', '0.0.0.0/0', str(gateway_ip))
        else:
            return self.sudo('add', '0.0.0.0/0', str(gateway_ip))
