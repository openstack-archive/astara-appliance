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
                if subnet.cidr.version == 4 and subnet.gateway_ip:
                    self._set_default_gateway(subnet.gateway_ip, '0.0.0.0/0')
                elif subnet.cidr.version == 6 and subnet.gateway_ip:
                    self._set_default_v6_gateway(subnet.gateway_ip, '::')

    def _set_default_gateway(self, gateway_ip, prefix):
        net = '-inet'
        if ':' in prefix:
            net += '6'
        try:
            current = self.sudo('get', net, prefix)
        except:
            current = None

        if current and 'no such process' not in current.lower():
            return self.sudo('change', net, prefix, str(gateway_ip))
        else:
            return self.sudo('add', net, prefix, str(gateway_ip))
