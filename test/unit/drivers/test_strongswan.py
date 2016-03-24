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


from unittest2 import TestCase

import mock
import netaddr
import re
import textwrap

from astara_router.drivers.vpn import ipsec

class StrongswanTestCase(TestCase):
    """
    """
    def setUp(self):
        self.mock_execute = mock.patch('astara_router.utils.execute').start()
        self.mock_replace_file = mock.patch(
            'astara_router.utils.replace_file'
        ).start()
        self.addCleanup(mock.patch.stopall)

        self.mgr = ipsec.StrongswanManager()

    def test_save_config(self):
        mock_config = mock.Mock()
        with mock.patch.object(ipsec, 'jinja2') as mock_jinja:

            mock_env = mock_jinja.Environment.return_value
            mock_get_template = mock_env.get_template
            mock_render_rv = mock_get_template.return_value.render.return_value

            self.mgr.save_config(mock_config)

            mock_get_template.assert_has_calls([
                mock.call('ipsec.conf.j2'),
                mock.call().render(vpnservices=mock_config.vpn),
                mock.call('ipsec.secrets.j2'),
                mock.call().render(vpnservices=mock_config.vpn),
            ])

            self.mock_replace_file.assert_has_calls([
                mock.call('/tmp/ipsec.conf', mock_render_rv),
                mock.call('/tmp/ipsec.secrets', mock_render_rv),
            ])

            sudo = 'sudo astara-rootwrap /etc/rootwrap.conf'

            self.mock_execute.assert_has_calls([
                mock.call(['mv','/tmp/ipsec.conf', '/etc/ipsec.conf'], sudo),
                mock.call(
                   ['mv', '/tmp/ipsec.secrets', '/etc/ipsec.secrets'],
                   sudo
                ),
            ])

    def test_restart(self):
        self.mgr.restart()
        self.mock_execute.assert_has_calls([
            mock.call(['service', 'strongswan', 'status'],
                      'sudo astara-rootwrap /etc/rootwrap.conf'),
            mock.call(['service', 'strongswan', 'reload'],
                      'sudo astara-rootwrap /etc/rootwrap.conf'),
        ])

    def test_restart_failure(self):
        with mock.patch('astara_router.utils.execute') as execute:
            execute.side_effect = [Exception('status failed!'), None]
            self.mgr.restart()
            execute.assert_has_calls([
                mock.call(['service', 'strongswan', 'status'],
                          'sudo astara-rootwrap /etc/rootwrap.conf'),
                mock.call(['service', 'strongswan', 'start'],
                          'sudo astara-rootwrap /etc/rootwrap.conf'),
            ])

    def test_stop(self):
        self.mgr.stop()
        self.mock_execute.assert_has_calls([
            mock.call(['service', 'strongswan', 'stop'],
                      'sudo astara-rootwrap /etc/rootwrap.conf'),
        ])
