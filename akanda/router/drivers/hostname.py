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
import re

from akanda.router.drivers import (base, ip)
from akanda.router import utils


LOG = logging.getLogger(__name__)


class HostnameManager(base.Manager):
    EXECUTABLE = '/bin/hostname'

    def update(self, config):
        self.update_hostname(config)
        self.update_hosts(config)

    def update_hostname(self, config):
        self.sudo(config.hostname)
        utils.replace_file('/etc/hostname', config.hostname)

    def update_hosts(self, config):
        mgr = ip.IPManager()
        listen_ip = mgr.get_management_address()
        config_data = '\n'.join([
            '127.0.0.1  localhost',
            '::1     localhost ip6-localhost ip6-loopback',
            '\t'.join([listen_ip, config.hostname])
        ])
        utils.replace_file('/etc/hosts', config_data)

