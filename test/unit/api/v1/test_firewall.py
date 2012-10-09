"""
Base classes for Router API tests.
"""
from unittest import TestCase

import flask
from mock import patch

from akanda.router.api import v1
from akanda.router.drivers.pf import PFManager
from .fakes import FakePFManager
from .payloads import routerapi_firewall as payload


class FirewallAPITestCase(TestCase):
    """
    """
    def setUp(self):
        self.app = flask.Flask('firewall_test')
        self.app.register_blueprint(v1.firewall.blueprint)
        self.test_app = self.app.test_client()

    @patch.object(PFManager, 'get_rules', FakePFManager.fake_get_rules)
    def test_get_rules(self):
        result = self.test_app.get('/v1/firewall/rules').data.strip()
        expected = payload.sample_pfctl_sr.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_states', FakePFManager.fake_get_states)
    def test_get_states(self):
        result = self.test_app.get('/v1/firewall/states').data.strip()
        expected = payload.sample_pfctl_ss.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_anchors', FakePFManager.fake_get_anchors)
    def test_get_anchors(self):
        result = self.test_app.get('/v1/firewall/anchors').data.strip()
        expected = payload.sample_pfctl_sA.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_sources', FakePFManager.fake_get_sources)
    def test_get_sources(self):
        result = self.test_app.get('/v1/firewall/sources').data.strip()
        expected = payload.sample_pfctl_sS.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_info', FakePFManager.fake_get_info)
    def test_get_info(self):
        result = self.test_app.get('/v1/firewall/info').data.strip()
        expected = payload.sample_pfctl_si.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_timeouts', FakePFManager.fake_get_timeouts)
    def test_get_timeouts(self):
        result = self.test_app.get('/v1/firewall/timeouts').data.strip()
        expected = payload.sample_pfctl_st.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_labels', FakePFManager.fake_get_labels)
    def test_get_labels(self):
        result = self.test_app.get('/v1/firewall/labels').data.strip()
        expected = payload.sample_pfctl_sl.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_tables', FakePFManager.fake_get_tables)
    def test_get_tables(self):
        result = self.test_app.get('/v1/firewall/tables').data.strip()
        expected = payload.sample_pfctl_sT.strip()
        self.assertEqual(result, expected)

    @patch.object(PFManager, 'get_memory', FakePFManager.fake_get_memory)
    def test_get_memory(self):
        result = self.test_app.get('/v1/firewall/memory').data.strip()
        expected = payload.sample_pfctl_sm.strip()
        self.assertEqual(result, expected)
