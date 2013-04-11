import logging

from akanda.router.drivers import base


LOG = logging.getLogger(__name__)


class RouteManager(base.Manager):
    EXECUTABLE = '/sbin/route'

    def __init__(self, root_helper='sudo'):
        super(RouteManager, self).__init__(root_helper)

    def update_default(self, config):
        for net in config.networks:
            if not net.is_external_network:
                continue

            for subnet in net.subnets:
                if subnet.gateway_ip:
                    self._set_default_gateway(subnet.gateway_ip)

    def _set_default_gateway(self, gateway_ip):
        version = '-inet'
        if gateway_ip.version == 6:
            version += '6'
        try:
            current = self.sudo('get', version, 'default')
        except:
            current = None

        if current and 'no such process' not in current.lower():
            return self.sudo('change', version, 'default', str(gateway_ip))
        else:
            return self.sudo('add', version, 'default', str(gateway_ip))
