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
from unittest import TestCase

import flask

from astara_router.api import v1


class BaseAPITestCase(TestCase):
    """
    This test case contains the unit tests for the Python server implementation
    of the Router API. The focus of these tests is to ensure that the server is
    behaving appropriately.
    """
    def setUp(self):
        self.app = flask.Flask('base_test')
        self.app.register_blueprint(v1.base.blueprint)
        self.test_app = self.app.test_client()

    def test_root(self):
        rv = self.test_app.get('/v1/base', follow_redirects=True)
        self.assertEqual(rv.data, 'Astara appliance API service is active')
        self.assertEqual(rv.status_code, 200)
