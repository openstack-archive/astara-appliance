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


import logging

from akanda.router.drivers import base


LOG = logging.getLogger(__name__)


class RouteManager(base.Manager):
    EXECUTABLE = '/sbin/route'

    def __init__(self, root_helper='sudo'):
        super(RouteManager, self).__init__(root_helper)

    def update_default(self, config):
        # Track whether we have set the default gateways, by IP
        # version.
        gw_set = {
            4: False,
            6: False,
        }

        # The default v4 gateway is pulled out as a special case
        # because we only want one but we might have multiple v4
        # subnets on the external network. However, sometimes the RUG
        # can't figure out what that value is, because it thinks we
        # don't have any external IP addresses, yet. In that case, it
        # doesn't give us a default.
        if config.default_v4_gateway:
            self._set_default_gateway(config.default_v4_gateway)
            gw_set[4] = True

        # Look through our networks and make sure we have a default
        # gateway set for each IP version, if we have an IP for that
        # version on the external net. If we haven't already set the
        # v4 gateway, this picks the gateway for the first subnet we
        # find, which might be wrong.
        for net in config.networks:
            if not net.is_external_network:
                continue

            for subnet in net.subnets:
                if subnet.gateway_ip and not gw_set[subnet.gateway_ip.version]:
                    self._set_default_gateway(subnet.gateway_ip)
                    gw_set[subnet.gateway_ip.version] = True

    def update_host_routes(self, config, db):
        for net in config.networks:

            # For each subnet...
            for subnet in net.subnets:
                cidr = str(subnet.cidr)

                # determine the set of previously written routes for this cidr
                if cidr not in db:
                    db[cidr] = set()

                current = db[cidr]

                # build a set of new routes for this cidr
                latest = set()
                for r in subnet.host_routes:
                    latest.add((r.destination, r.next_hop))

                # If the set of previously written routes contains routes that
                # aren't defined in the new config, run commands to delete them
                for x in current - latest:
                    if self._alter_route('delete', *x):
                        current.remove(x)

                # If the new config contains routes that aren't defined in the
                # set of previously written routes, run commands to add them
                for x in latest - current:
                    if self._alter_route('add', *x):
                        current.add(x)

                # This assignment *is* necessary - Python's `shelve`
                # implementation isn't smart enough to capture the changes to
                # the reference above, so this setitem call triggers a DB sync
                if current:
                    db[cidr] = current
                else:
                    del db[cidr]

    def _get_default_gateway(self, version):
        current = None
        try:
            cmd_out = self.sudo('-n', 'get', version, 'default')
        except:
            # assume the route is missing and use defaults
            pass
        else:
            if 'no such process' in cmd_out.lower():
                # There is no gateway
                return None
            for l in cmd_out.splitlines():
                l = l.strip()
                if l.startswith('gateway:'):
                    return l.partition(':')[-1].strip()
        return current

    def _set_default_gateway(self, gateway_ip):
        version = '-inet'
        if gateway_ip.version == 6:
            version += '6'
        current = self._get_default_gateway(version)
        desired = str(gateway_ip)

        if not current:
            # Set the gateway
            return self.sudo('add', version, 'default', desired)
        if current != desired:
            # Update the current gateway
            return self.sudo('change', version, 'default', desired)
        # Nothing to do
        return ''

    def _alter_route(self, action, destination, next_hop):
        version = '-inet'
        if destination.version == 6:
            version += '6'
        try:
            LOG.debug(
                self.sudo(action, version, str(destination), str(next_hop))
            )
            return True
        except RuntimeError as e:
            # Since these are user-supplied custom routes, it's very possible
            # that adding/removing them will fail.  A failure to apply one of
            # these custom rules, however, should *not* cause an overall router
            # failure.
            LOG.warn('Route could not be %sed: %s' % (action, unicode(e)))
            return False
