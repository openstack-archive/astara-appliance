import json
from unittest2 import TestCase

import flask
import netaddr

from akanda.router import models
from akanda.router import utils


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
            '"i": 3.0, "h": 42, "k": null, "j": false, '
            '"m": 12345671238792347, "l": [4, 5, 6], "n": "192.168.1.1/24"}')
        serialized = json.dumps(data, cls=utils.ModelSerializer)
        self.assertEqual(serialized, expected)

    def test_default_with_set(self):
        data = {"a": set([1, 2, 3])}
        expected = '{"a": [1, 2, 3]}'
        serialized = json.dumps(data, cls=utils.ModelSerializer)
        self.assertEqual(serialized, expected)

    def test_default_ipaddress(self):
        data = dict(a=netaddr.IPAddress('192.168.1.1'))
        expected = '{"a": "192.168.1.1"}'
        serialized = json.dumps(data, cls=utils.ModelSerializer)
        self.assertEqual(serialized, expected)

    def test_default_ipnetwork(self):
        data = dict(a=netaddr.IPNetwork('192.168.1.1/24'))
        expected = '{"a": "192.168.1.1/24"}'
        serialized = json.dumps(data, cls=utils.ModelSerializer)
        self.assertEqual(serialized, expected)

    def test_model_base_to_dict(self):
        data = dict(r=models.StaticRoute('192.168.1.0/24', '172.16.77.1'))
        expected = ('{"r": {"next_hop": "172.16.77.1", '
                    '"destination": "192.168.1.0/24"}}')
        serialized = json.dumps(data, cls=utils.ModelSerializer)
        self.assertEqual(serialized, expected)

    def test_model_base_fallback_to_vars(self):
        data = dict(a=models.Anchor('foo', []))
        expected = '{"a": {"rules": [], "name": "foo"}}'
        serialized = json.dumps(data, cls=utils.ModelSerializer)
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
