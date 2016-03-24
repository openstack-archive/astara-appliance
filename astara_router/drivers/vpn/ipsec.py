# Copyright 2016 Akanda, Inc
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

import jinja2

from astara_router.drivers import base
from astara_router import utils

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


STRONGSWAN_TRANSLATIONS = {
    "3des": "3des",
    "aes-128": "aes128",
    "aes-256": "aes256",
    "aes-192": "aes192",
    "group2": "modp1024",
    "group5": "modp1536",
    "group14": "modp2048",
    "group15": "modp3072",
    "bi-directional": "start",
    "response-only": "add",
}


class StrongswanManager(base.Manager):
    """
    A class to interact with strongswan, an IPSEC VPN daemon.
    """
    def __init__(self, root_helper='sudo astara-rootwrap /etc/rootwrap.conf'):
        """
        Initializes StrongswanManager class.

        :type root_helper: string
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(StrongswanManager, self).__init__(root_helper)

    def save_config(self, config):
        """
        Writes config file for strongswan daemon.

        :type config: astara_router.models.Configuration
        """

        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(TEMPLATE_DIR)
        )

        env.filters['strongswan'] = lambda v: STRONGSWAN_TRANSLATIONS.get(v, v)

        templates = ('ipsec.conf', 'ipsec.secrets')

        for template_name in templates:
            tmpl = env.get_template(template_name+'.j2')

            tmp = os.path.join('/tmp', template_name)
            utils.replace_file(tmp, tmpl.render(vpnservices=config.vpn))

        for template_name in templates:
            tmp = os.path.join('/tmp', template_name)
            etc = os.path.join('/etc', template_name)
            utils.execute(['mv', tmp, etc], self.root_helper)

    def restart(self):
        """
        Restart the Strongswan daemon using the system provided init scripts.
        """
        try:
            utils.execute(
                ['service', 'strongswan', 'status'],
                self.root_helper
            )
        except:  # pragma no cover
            utils.execute(['service', 'strongswan', 'start'], self.root_helper)
        else:  # pragma no cover
            utils.execute(
                ['service', 'strongswan', 'reload'],
                self.root_helper
            )

    def stop(self):
        """
        Stop the Strongswan daemon using the system provided init scripts.
        """
        try:
            utils.execute(
                ['service', 'strongswan', 'stop'],
                self.root_helper
            )
        except:  # pragma no cover
            pass
