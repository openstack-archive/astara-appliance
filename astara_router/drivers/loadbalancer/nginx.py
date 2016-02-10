# Copyright (c) 2015 Akanda, Inc. All Rights Reserved.
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


import os

from astara_router.drivers import base
from astara_router.utils import execute, load_template


class NginxLB(base.Manager):
    NAME = 'nginx'
    CONFIG_PATH = '/etc/nginx/sites-enabled/'
    CONFIG_FILE_TEMPLATE = os.path.join(
        os.path.dirname(__file__), 'nginx.conf.template')
    INIT = 'nginx'

    def __init__(self, root_helper='sudo astara-rootwrap /etc/rootwrap.conf'):
        """
        Initializes NginxLB class.

        :type root_helper: str
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(NginxLB, self).__init__(root_helper)
        self.config_tmpl = load_template(self.CONFIG_FILE_TEMPLATE)

    def _render_config_template(self, path, config):
        with open(path, 'w') as out:
            out.write(
                self.config_tmpl.render(loadbalancer=config)
            )

    def restart(self):
        execute(['service', self.INIT, 'restart'], self.root_helper)

    def update_config(self, config):
        path = os.path.join(
            self.CONFIG_PATH, 'ak-loadbalancer-%s.conf' % config.id)
        self._render_config_template(path=path, config=config)
        self.restart()


class NginxPlusLB(NginxLB):
    NAME = 'nginxplus'
    CONFIG_FILE = '/tmp/nginx_plus.conf'
    INIT = 'nginxplus'
