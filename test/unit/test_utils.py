import json
from unittest import TestCase

import netaddr

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
