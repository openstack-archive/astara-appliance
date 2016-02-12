# Copyright (c) 2016 Akanda, Inc. All Rights Reserved.
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
from astara_router.utils import execute, load_template, hash_file


class ConntrackdManager(base.Manager):
    """
    A class to provide facilities to interact with the conntrackd daemon.
    """
    EXECUTABLE = '/etc/init.d/conntrackd'
    CONFIG_FILE_TEMPLATE = os.path.join(
        os.path.dirname(__file__), 'conntrackd.conf.template')

    # Debian defaults
    CONFIG_FILE = '/etc/conntrackd/conntrackd.conf'

    # Debian installs this to /usr/share/doc/examples/sync but our
    # DIB recipe will install it here.
    NOTIFY_SCRIPT = '/etc/conntrackd/primary-backup.sh'


    def __init__(self, root_helper='sudo'):
        """
        Initializes ConntrackdManager class.

        :type root_helper: str
        :param root_helper: System utility used to gain escalate privileges.
        """
        super(ConntrackdManager, self).__init__(root_helper)
        self._config_templ = load_template(self.CONFIG_FILE_TEMPLATE)
        self._should_restart = False

    def save_config(self, config, generic_to_host):
        """
        Renders template and writes to the conntrackd file

        :type config: astara_router.models.Configuration
        :param config: An astara_router.models.Configuration object containing
                       the ha_config configuration.
        :param generic_to_host: A callable used to resolve generic interface
                                name to system interface name.
        """

        mgt_interface = None
        for interface in config.interfaces:
            if interface.management:
                if interface.first_v6:
                    mgt_interface = interface
                    break
        mgt_addr = mgt_interface.first_v6 or mgt_interface.first_v4
        ctxt = {
            'source_address': str(mgt_addr),
            'management_ip_version': mgt_addr.version,
            'destination_address': config.ha_config['peers'][0],
            'interface': generic_to_host(interface.ifname),
        }

        try:
            old_config_hash = hash_file(self.CONFIG_FILE)
        except IOError:
            old_config_hash = None

        with open(self.CONFIG_FILE, 'w') as out:
            out.write(self._config_templ.render(ctxt))

        if old_config_hash != hash_file(self.CONFIG_FILE):
            self._should_restart = True

    def restart(self):
        """
        Restarts the conntrackd daemon if config has been changed
        """
        if not self._should_restart:
            return
        self.sudo('restart')
