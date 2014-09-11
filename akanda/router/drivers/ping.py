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

import netaddr

from akanda.router.drivers import base
from akanda.router import utils


LOG = logging.getLogger(__name__)


class PingManager(base.Manager):
    """
    A class which provide a facade to the system ping utility. Supports both
    IPv4 and IPv6.
    """

    exe_map = {
        4: '/bin/ping',
        6: '/bin/ping6'
    }

    def __init__(self, root_helper='sudo'):
        """
        Initializes PingManager class.

        :type root_helper: str
        :param root_helper: System utility to escalate privileges.
        """
        super(PingManager, self).__init__(root_helper)

    def do(self, ip):
        """
        Sends a single ICMP packet to <ip> using the systems ping utility.

        :type ip: str
        :param ip: The IP address to send ICMP packets to.
        :rtype: bool. If <ip> responds to the ICMP packet, returns True else,
                returns False
        """
        version = netaddr.IPAddress(ip).version
        args = ['-c', '1', ip]
        try:
            utils.execute([self.exe_map.get(version)] + args)
            return True
        except RuntimeError:
            return False
