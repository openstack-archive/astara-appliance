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

import __builtin__

import json
import mock

from unittest2 import TestCase

from astara_router.drivers import metadata

CONFIG = mock.Mock()
CONFIG.hostname = 'astara'
CONFIG.management_address = 'fdca:3ba5:a17a:acda:f816:3eff:fe66:33b6'


class HostnameTestCase(TestCase):
    """
    """
    def setUp(self):
        self.mgr = metadata.MetadataManager()
        self.config_dict = {
            'networks': {'tenant_net_id': [], 'public_net_id': []},
            'orchestrator_metadata_address': '10.0.0.1',
            'orchestrator_metadata_port': '5000',
        }

        tenant_net = mock.Mock(
            is_tenant_network=mock.Mock(return_value=True),
            id='tenant_net_id',
        )
        public_net = mock.Mock(
            is_tenant_network=mock.Mock(return_value=False),
            id='public_net_id',
        )

        self.config = mock.Mock()
        self.config.networks = [tenant_net, public_net]
        self.config.metadata_address = '10.0.0.1'
        self.config.metadata_port = '5000'

    def _test_should_restart(self, exp_result):
        config_json = json.dumps(self.config_dict)
        with mock.patch.object(
            __builtin__, 'open', mock.mock_open(read_data=config_json)
        ):
            self.assertEqual(
                self.mgr.should_restart(self.config), exp_result)

    def test_should_restart_false(self):
        self._test_should_restart(False)

    def test_should_restart_true_networks_change(self):
        self.config_dict['networks'] = {
            'foo_net_id': [], 'public_net_id': []}
        self._test_should_restart(True)

    def test_should_restart_true_metadata_addr_change(self):
        self.config_dict['orchestrator_metadata_address'] = '11.1.1.1'
        self._test_should_restart(True)

    def test_should_restart_true_metadata_port_change(self):
        self.config_dict['orchestrator_metadata_port'] = '6000'
        self._test_should_restart(True)

    def test_should_restart_true_config_read_err(self):
        with mock.patch.object(
            __builtin__, 'open', mock.mock_open()
        ) as _o:
            _o.side_effect = IOError()
            self.assertEqual(
                self.mgr.should_restart(self.config), True)
