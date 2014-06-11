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

    exe_map = {
        4: '/sbin/ping',
        6: '/sbin/ping6'
    }

    def __init__(self, root_helper='sudo'):
        super(PingManager, self).__init__(root_helper)

    def do(self, ip):
        version = netaddr.IPAddress(ip).version
        args = ['-c', '1', ip]
        try:
            utils.execute([self.exe_map.get(version)] + args)
            return True
        except RuntimeError:
            return False
