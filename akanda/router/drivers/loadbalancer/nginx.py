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

from akanda.router.drivers import base


class NginxLB(base.Manager):
    NAME = 'nginx'
    CONFIG_FILE = '/tmp/nginx.conf'
    INIT = 'nginx'

    def __init__(self, root_helper='sudo'):
        """
        Initializes DHCPManager class.

        :type root_helper: str
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(NginxLB, self).__init__(root_helper)


    def restart(self):
        # Will eventually restart the service
        #utils.excute(['service', INIT, restart'])
        pass

    def update_config(self, config):
        # Writes a dummy config
        with open(self.CONFIG_FILE, 'w') as out:
            out.write('Config file for LB: %s' % config.id)
        self.restart()


class NginxPlusLB(NginxLB):
    NAME = 'nginxplus'
    CONFIG_FILE = '/tmp/nginx_plus.conf'
    INIT = 'nginxplus'
