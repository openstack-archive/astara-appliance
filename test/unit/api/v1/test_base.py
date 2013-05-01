"""
Base classes for Router API tests.
"""
from unittest import TestCase

import flask

from akanda.router.api import v1


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
        self.assertEqual(rv.data, 'Akanda appliance API service is active')
        self.assertEqual(rv.status_code, 200)
