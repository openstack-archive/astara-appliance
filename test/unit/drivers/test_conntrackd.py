# Copyright 2016 Akanda, Inc.
#
# Author: Akanda, Inc.
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

import __builtin__

from unittest2 import TestCase
import mock

from test.unit import fakes

from astara_router.drivers import conntrackd


class ConntrackddManagerTestCase(TestCase):
    def setUp(self):
        super(ConntrackddManagerTestCase, self).setUp()
        self.mgr = conntrackd.ConntrackdManager()
        self.mgr._config_templ = mock.Mock(
            render=mock.Mock()
        )

    @mock.patch.object(__builtin__, 'open')
    @mock.patch.object(conntrackd, 'hash_file')
    def test_save_config(self, fake_hash, fake_open):
        fake_config_file = mock.MagicMock(spec=file, name='foo')
        fake_open.return_value.__enter__.return_value = fake_config_file
        fake_generic_to_host = mock.Mock(return_value='eth0')
        fake_interface = fakes.fake_interface()
        fake_mgt_interface = fakes.fake_mgt_interface()
        ha_config = {
            'peers': ['10.0.0.2'],
        }
        fake_config = mock.Mock(
            interfaces=[fake_interface, fake_mgt_interface],
            ha_config=ha_config,
        )

        fake_hash.side_effect = ['hash1', 'hash2']
        self.mgr._config_templ.render.return_value = 'new_config'
        self.mgr.save_config(fake_config, fake_generic_to_host)
        self.mgr._config_templ.render.assert_called_with(dict(
            source_address=str(fake_mgt_interface.addresses[0].ip),
            management_ip_version=4,
            destination_address='10.0.0.2',
            interface='eth0',
        ))
        fake_config_file.write.assert_called_with('new_config')
        self.assertTrue(self.mgr._should_restart)

    @mock.patch.object(conntrackd.ConntrackdManager, 'sudo')
    def test_restart(self, fake_sudo):
        self.mgr._should_restart = True
        self.mgr.restart()
        fake_sudo.assert_called_with('restart')

    @mock.patch.object(conntrackd.ConntrackdManager, 'sudo')
    def test_restart_skip(self, fake_sudo):
        self.mgr._should_restart = False
        self.mgr.restart()
        self.assertFalse(fake_sudo.called)
