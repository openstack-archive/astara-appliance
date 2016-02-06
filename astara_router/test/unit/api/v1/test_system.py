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
Base classes for System Router API tests.
"""
import unittest
import distutils

from dogpile.cache import make_region
import flask
import json
import mock

from astara_router import manager
from astara_router.api import v1


SYSTEM_CONFIG = {
    'tenant_id': 'foo_tenant_id',
    'hostname': 'foohostname',
}


class SystemAPITestCase(unittest.TestCase):
    """
    This test case contains the unit tests for the Python server implementation
    of the Router API. The focus of these tests is to ensure that the server is
    behaving appropriately.
    """
    def setUp(self):
        self.app = flask.Flask('system_test')
        self.app.register_blueprint(v1.system.blueprint)
        self.test_app = self.app.test_client()
        # Replace the default cache with an in-memory version.
        self._old_cache = v1.system._cache
        v1.system._cache = make_region().configure(
            'dogpile.cache.memory',
        )

    def tearDown(self):
        v1.system._cache = self._old_cache
        super(SystemAPITestCase, self).tearDown()

    @unittest.skipIf(
        not distutils.spawn.find_executable('ip'),
        'unsupported platform'
    )
    def test_get_interface(self):
        with mock.patch.object(
            v1.system.manager.router, 'get_interface'
        ) as get_if:
            get_if.return_value = 'ge1'
            result = self.test_app.get('/v1/system/interface/ge1')
            get_if.assert_called_once_with('ge1')
            self.assertEqual(
                json.loads(result.data),
                {'interface': 'ge1'}
            )

    @unittest.skipIf(
        not distutils.spawn.find_executable('ip'),
        'unsupported platform'
    )
    def test_get_interfaces(self):
        with mock.patch.object(
            v1.system.manager.router, 'get_interfaces'
        ) as get_ifs:
            get_ifs.return_value = ['ge0', 'ge1']
            result = self.test_app.get('/v1/system/interfaces')
            get_ifs.assert_called_once_with()
            self.assertEqual(
                json.loads(result.data),
                {'interfaces': ['ge0', 'ge1']}
            )

    @unittest.skipIf(
        not distutils.spawn.find_executable('ip'),
        'unsupported platform'
    )
    @mock.patch.object(manager, 'settings')
    @mock.patch.object(v1.system, 'settings')
    def test_get_configuration(self, fake_api_settings, fake_mgr_settings):
        fake_api_settings.ENABLED_SERVICES = ['router', 'loadbalancer']
        fake_mgr_settings.ENABLED_SERVICES = ['router', 'loadbalancer']

        result = self.test_app.get('/v1/system/config')
        expected = {
            'configuration': {
                'address_book': {},
                'anchors': [],
                'networks': [],
                'services': {
                    'loadbalancer': None,
                    'router': None
                },
                'static_routes': [],
                'system': {
                    'hostname': None,
                    'interfaces': [],
                    'management_address': None,
                    'tenant_id': None
                }
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
        with mock.patch('astara_router.models.RouterConfiguration') as Config:
            Config.side_effect = ValueError
            result = self.test_app.put(
                '/v1/system/config',
                data=json.dumps({'networks': [{}]}),  # malformed dict
                content_type='application/json'
            )
            self.assertEqual(result.status_code, 422)

    def test_put_configuration_returns_422_for_errors(self):
        with mock.patch('astara_router.models.SystemConfiguration') as Config:
            Config.return_value.validate.return_value = ['error1']
            result = self.test_app.put(
                '/v1/system/config',
                data=json.dumps(SYSTEM_CONFIG),
                content_type='application/json'
            )
            self.assertEqual(result.status_code, 422)
            self.assertEqual(
                result.data,
                'The config failed to validate.\nerror1'
            )

    @unittest.skipIf(
        not distutils.spawn.find_executable('ip'),
        'unsupported platform'
    )
    @mock.patch('astara_router.api.v1.system._get_cache')
    @mock.patch('astara_router.models.SystemConfiguration')
    @mock.patch.object(v1.system.manager, 'update_config')
    def test_put_configuration_returns_200(
        self, mock_update, fake_system_config, fake_cache
    ):
        fake_cache.return_value = 'fake_cache'
        sys_config_obj = mock.Mock()
        sys_config_obj.validate = mock.Mock()
        sys_config_obj.validate.return_value = []
        fake_system_config.return_value = sys_config_obj

        result = self.test_app.put(
            '/v1/system/config',
            data=json.dumps({
                'tenant_id': 'foo_tenant_id',
                'hostname': 'foo_hostname',
            }),
            content_type='application/json'
        )

        self.assertEqual(result.status_code, 200)
        self.assertTrue(json.loads(result.data))
        mock_update.assert_called_with(
            cache='fake_cache', service_configs=[],
            system_config=sys_config_obj)

    @mock.patch('astara_router.manager.Manager.config',
                new_callable=mock.PropertyMock, return_value={})
    @mock.patch('astara_router.api.v1.system._get_cache')
    @mock.patch('astara_router.models.RouterConfiguration')
    @mock.patch('astara_router.models.SystemConfiguration')
    @mock.patch.object(v1.system.manager, 'update_config')
    def test_put_configuration_with_router(
        self, mock_update, fake_system_config, fake_router_config,
        fake_cache, fake_config
    ):
        fake_config.return_value = 'foo'
        fake_cache.return_value = 'fake_cache'
        sys_config_obj = mock.Mock()
        sys_config_obj.validate = mock.Mock()
        sys_config_obj.validate.return_value = []
        fake_system_config.return_value = sys_config_obj

        router_config_obj = mock.Mock()
        router_config_obj.validate = mock.Mock()
        router_config_obj.validate.return_value = []
        fake_router_config.return_value = router_config_obj

        result = self.test_app.put(
            '/v1/system/config',
            data=json.dumps({
                'tenant_id': 'foo_tenant_id',
                'hostname': 'foo_hostname',
                'asn': 'foo_asn',
            }),
            content_type='application/json'
        )
        self.assertEqual(result.status_code, 200)
        self.assertTrue(json.loads(result.data))
        mock_update.assert_called_with(
            cache='fake_cache', service_configs=[router_config_obj],
            system_config=sys_config_obj)

    @mock.patch('astara_router.models.get_config_model')
    @mock.patch.object(manager, 'settings')
    @mock.patch.object(v1.system, 'settings')
    @mock.patch('astara_router.manager.Manager.config',
                new_callable=mock.PropertyMock, return_value={})
    @mock.patch('astara_router.api.v1.system._get_cache')
    @mock.patch('astara_router.models.LoadBalancerConfiguration')
    @mock.patch('astara_router.models.SystemConfiguration')
    @mock.patch.object(v1.system.manager, 'update_config')
    def test_put_configuration_with_adv_services(
        self, mock_update,
        fake_system_config, fake_lb_config, fake_cache, fake_config,
        fake_api_settings, fake_mgr_settings, fake_get_config_model
    ):
        fake_api_settings.ENABLED_SERVICES = ['loadbalancer']
        fake_mgr_settings.ENABLED_SERVICES = ['loadbalancer']
        fake_config.return_value = 'foo'
        fake_cache.return_value = 'fake_cache'
        sys_config_obj = mock.Mock()
        sys_config_obj.validate = mock.Mock()
        sys_config_obj.validate.return_value = []
        fake_system_config.return_value = sys_config_obj

        lb_config_obj = mock.Mock()
        lb_config_obj.validate = mock.Mock()
        lb_config_obj.validate.return_value = []
        fake_lb_config.return_value = lb_config_obj
        fake_get_config_model.return_value = fake_lb_config

        result = self.test_app.put(
            '/v1/system/config',
            data=json.dumps({
                'tenant_id': 'foo_tenant_id',
                'hostname': 'foo_hostname',
                'services': {
                    'loadbalancer': {'id': 'foo'}
                }
            }),
            content_type='application/json'
        )
        self.assertEqual(result.status_code, 200)
        self.assertTrue(json.loads(result.data))
        mock_update.assert_called_with(
            cache='fake_cache', service_configs=[lb_config_obj],
            system_config=sys_config_obj)

    @mock.patch('astara_router.models.get_config_model')
    @mock.patch.object(manager, 'settings')
    @mock.patch.object(v1.system, 'settings')
    @mock.patch('astara_router.manager.Manager.config',
                new_callable=mock.PropertyMock, return_value={})
    @mock.patch('astara_router.api.v1.system._get_cache')
    @mock.patch('astara_router.models.LoadBalancerConfiguration')
    @mock.patch('astara_router.models.SystemConfiguration')
    @mock.patch.object(v1.system.manager, 'update_config')
    def test_put_configuration_with_disabled_svc_returns_400(
        self, mock_update,
        fake_system_config, fake_lb_config, fake_cache, fake_config,
        fake_api_settings, fake_mgr_settings, fake_get_config_model
    ):
        fake_api_settings.ENABLED_SERVICES = ['foo']
        fake_mgr_settings.ENABLED_SERVICES = ['foo']
        fake_config.return_value = 'foo'
        fake_cache.return_value = 'fake_cache'
        sys_config_obj = mock.Mock()
        sys_config_obj.validate = mock.Mock()
        sys_config_obj.validate.return_value = []
        fake_system_config.return_value = sys_config_obj

        lb_config_obj = mock.Mock()
        lb_config_obj.validate = mock.Mock()
        lb_config_obj.validate.return_value = []
        fake_lb_config.return_value = lb_config_obj
        fake_get_config_model.return_value = fake_lb_config

        result = self.test_app.put(
            '/v1/system/config',
            data=json.dumps({
                'tenant_id': 'foo_tenant_id',
                'hostname': 'foo_hostname',
                'services': {
                    'loadbalancer': {'id': 'foo'}
                }
            }),
            content_type='application/json'
        )
        self.assertEqual(result.status_code, 400)
