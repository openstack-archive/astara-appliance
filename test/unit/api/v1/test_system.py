"""
Base classes for System Router API tests.
"""
from unittest import TestCase

import flask
import json
import mock

from akanda.router.api import v1


class SystemAPITestCase(TestCase):
    """
    This test case contains the unit tests for the Python server implementation
    of the Router API. The focus of these tests is to ensure that the server is
    behaving appropriately.
    """
    def setUp(self):
        self.app = flask.Flask('system_test')
        self.app.register_blueprint(v1.system.blueprint)
        self.test_app = self.app.test_client()

    def test_get_interface(self):
        with mock.patch.object(v1.system.manager, 'get_interface') as get_if:
            get_if.return_value = 'ge1'
            result = self.test_app.get('/v1/system/interface/ge1')
            get_if.assert_called_once_with('ge1')
            self.assertEqual(
                json.loads(result.data),
                {'interface': 'ge1'}
            )

    def test_get_interfaces(self):
        with mock.patch.object(v1.system.manager, 'get_interfaces') as get_ifs:
            get_ifs.return_value = ['ge0', 'ge1']
            result = self.test_app.get('/v1/system/interfaces')
            get_ifs.assert_called_once_with()
            self.assertEqual(
                json.loads(result.data),
                {'interfaces': ['ge0', 'ge1']}
            )

    def test_get_configuration(self):
        result = self.test_app.get('/v1/system/config')
        expected = {
            'configuration': {
                'address_book': {},
                'networks': [],
                'static_routes': [],
                'anchors': []
            }
        }
        self.assertEqual(json.loads(result.data), expected)

    def test_put_configuration_returns_405(self):
        result = self.test_app.put(
            '/v1/system/config',
            data='plain text',
            content_type='text/plain'
        )
        self.assertEqual(result.status_code, 415)

    def test_put_configuration_returns_422_for_ValueError(self):
        with mock.patch('akanda.router.models.Configuration') as Config:
            Config.side_effect = ValueError
            result = self.test_app.put(
                '/v1/system/config',
                data=json.dumps({'networks': [{}]}),  # malformed dict
                content_type='application/json'
            )
            self.assertEqual(result.status_code, 422)

    def test_put_configuration_returns_422_for_errors(self):
        with mock.patch('akanda.router.models.Configuration') as Config:
            Config.return_value.validate.return_value = ['error1']
            result = self.test_app.put(
                '/v1/system/config',
                data=json.dumps({'networks': [{}]}),  # malformed dict
                content_type='application/json'
            )
            self.assertEqual(result.status_code, 422)
            self.assertEqual(
                result.data,
                'The config failed to validate.\nerror1'
            )

    def test_put_configuration_returns_200(self):
        with mock.patch.object(v1.system.manager, 'update_config') as update:
            result = self.test_app.put(
                '/v1/system/config',
                data=json.dumps({}),
                content_type='application/json'
            )

            self.assertEqual(result.status_code, 200)
            self.assertTrue(json.loads(result.data))
