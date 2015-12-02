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


import json
import subprocess
from unittest2 import TestCase

import flask
import mock
import netaddr

from astara_router import models
from astara_router import utils


class ModelSerializerTestCase(TestCase):
    """
    """
    def test_default(self):
        data = {
            "a": [1, 2, 3],
            "b": {"c": 4},
            "d": "e",
            "f": u"g",
            "h": 42,
            "i": float(3),
            "j": False,
            "k": None,
            "l": (4, 5, 6),
            "m": 12345671238792347L,
            "n": netaddr.IPNetwork('192.168.1.1/24'),
        }
        expected = (
            '{"a": [1, 2, 3], "b": {"c": 4}, "d": "e", "f": "g", '
            '"h": 42, "i": 3.0, "j": false, "k": null, '
            '"l": [4, 5, 6], "m": 12345671238792347, "n": "192.168.1.1/24"}')
        serialized = json.dumps(data, cls=utils.ModelSerializer,
                                sort_keys=True)
        self.assertEqual(serialized, expected)

    def test_default_with_set(self):
        data = {"a": set([1, 2, 3])}
        expected = '{"a": [1, 2, 3]}'
        serialized = json.dumps(data, cls=utils.ModelSerializer,
                                sort_keys=True)
        self.assertEqual(serialized, expected)

    def test_default_ipaddress(self):
        data = dict(a=netaddr.IPAddress('192.168.1.1'))
        expected = '{"a": "192.168.1.1"}'
        serialized = json.dumps(data, cls=utils.ModelSerializer,
                                sort_keys=True)
        self.assertEqual(serialized, expected)

    def test_default_ipnetwork(self):
        data = dict(a=netaddr.IPNetwork('192.168.1.1/24'))
        expected = '{"a": "192.168.1.1/24"}'
        serialized = json.dumps(data, cls=utils.ModelSerializer,
                                sort_keys=True)
        self.assertEqual(serialized, expected)

    def test_model_base_to_dict(self):
        data = dict(r=models.StaticRoute('192.168.1.0/24', '172.16.77.1'))
        expected = ('{"r": {"destination": "192.168.1.0/24", '
                    '"next_hop": "172.16.77.1"}}')
        serialized = json.dumps(data, cls=utils.ModelSerializer,
                                sort_keys=True)
        self.assertEqual(serialized, expected)

    def test_model_base_fallback_to_vars(self):
        data = dict(a=models.Anchor('foo', []))
        expected = '{"a": {"name": "foo", "rules": []}}'
        serialized = json.dumps(data, cls=utils.ModelSerializer,
                                sort_keys=True)
        self.assertEqual(serialized, expected)


class FlaskJsonResponse(TestCase):
    def test_no_args(self):
        @utils.json_response
        def f():
            return dict(a=1)

        retval = f()
        self.assertIsInstance(retval, flask.Response)
        self.assertEqual(retval.data, '{"a": 1}')
        self.assertEqual(retval.status_code, 200)

    def test_with_args(self):
        @utils.json_response
        def f(arg1, kwarg1=None):
            return dict(arg1=arg1, kwarg1=kwarg1)

        retval = f(1, "foo")
        self.assertIsInstance(retval, flask.Response)
        self.assertEqual(retval.data, '{"arg1": 1, "kwarg1": "foo"}')
        self.assertEqual(retval.status_code, 200)


class ExecuteTest(TestCase):

    def test_execute_exception(self):
        with mock.patch('subprocess.check_output') as co:
            co.side_effect = subprocess.CalledProcessError(
                1, ['command', 'with', 'args'],
                output='output text',
            )
            try:
                utils.execute(['command', 'with', 'args'])
            except RuntimeError as e:
                self.assertIn('output text', str(e))

    def test_execute_exception_real(self):
        try:
            utils.execute(['/bin/ls', '/no-such-directory'])
        except RuntimeError as e:
            self.assertIn('cannot access', str(e))
