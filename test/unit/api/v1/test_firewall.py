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


"""
Base classes for Router API tests.
"""
import flask
import mock
from unittest2 import TestCase

from astara_router.api import v1


class FirewallAPITestCase(TestCase):
    """
    """
    def setUp(self):
        ip_mgr_patch = mock.patch.object(
            v1.firewall.iptables,
            'IPTablesManager'
        )
        self.iptables_mgr = ip_mgr_patch.start().return_value
        self.addCleanup(mock.patch.stopall)
        self.app = flask.Flask('firewall_test')
        self.app.register_blueprint(v1.firewall.blueprint)
        self.test_app = self.app.test_client()

    def _test_passthrough_helper(self, resource_name, method_name,
                                 response_code=200):
        mock_method = getattr(self.iptables_mgr, method_name)
        mock_method.return_value = 'the_value'
        result = self.test_app.get('/v1/firewall/%s' % resource_name)
        self.assertEqual(response_code, result.status_code)
        self.assertTrue(mock_method.called)
        self.assertEqual(result.data, 'the_value')

    def test_get_rules(self):
        self._test_passthrough_helper('rules', 'get_rules')
