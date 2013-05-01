"""
Base classes for Router API tests.
"""
import flask
import json
import mock
from unittest2 import TestCase

from akanda.router.api import v1
from akanda.router.drivers.pf import PFManager


class FirewallAPITestCase(TestCase):
    """
    """
    def setUp(self):
        pf_mgr_patch = mock.patch.object(v1.firewall.pf, 'PFManager')
        self.pf_mgr = pf_mgr_patch.start().return_value
        self.addCleanup(mock.patch.stopall)
        self.app = flask.Flask('firewall_test')
        self.app.register_blueprint(v1.firewall.blueprint)
        self.test_app = self.app.test_client()

    def _test_passthrough_helper(self, resource_name, method_name,
                                 response_code=200):
        mock_method = getattr(self.pf_mgr, method_name)
        mock_method.return_value = 'the_value'
        result = self.test_app.get('/v1/firewall/%s' % resource_name)
        self.assertEqual(response_code, result.status_code)
        self.assertTrue(mock_method.called)
        self.assertEqual(result.data, 'the_value')

    def test_get_rules(self):
        self._test_passthrough_helper('rules', 'get_rules')

    def test_get_states(self):
        self._test_passthrough_helper('states', 'get_states')

    def test_get_anchors(self):
        self._test_passthrough_helper('anchors', 'get_anchors')

    def test_get_sources(self):
        self._test_passthrough_helper('sources', 'get_sources')

    def test_get_info(self):
        self._test_passthrough_helper('info', 'get_info')

    def test_get_timeouts(self):
        self._test_passthrough_helper('timeouts', 'get_timeouts')

    def test_get_tables(self):
        self._test_passthrough_helper('tables', 'get_tables')

    def test_get_memory(self):
        self._test_passthrough_helper('memory', 'get_memory')

    def test_get_labels(self, reset_flag=False):
        expected = {'labels': 'thelabels'}
        self.pf_mgr.get_labels.return_value = 'thelabels'
        method = 'post' if reset_flag else 'get'
        args = (True, ) if reset_flag else ()
        result = getattr(self.test_app, method)('/v1/firewall/labels')
        self.assertEqual(result.status_code, 200)
        self.pf_mgr.get_labels.assert_called_once_with(*args)
        self.assertEqual(json.loads(result.data), expected)

    def test_get_labels_reset(self):
        self.test_get_labels(True)
