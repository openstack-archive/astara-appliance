import argparse
import json
import tempfile
import unittest
from collections import OrderedDict

import eventlet
import mock

from astara_router import metadata_proxy

config = json.dumps({
    "tenant_id": "ABC123",
    "orchestrator_metadata_address": "192.168.25.30",
    "orchestrator_metadata_port": 9697,
    "networks": {
        "net1": {
            "listen_port": 9602, 'ip_instance_map': {'10.10.10.2': 'VM1'}},
        "net2": {
            "listen_port": 9603, 'ip_instance_map': {'10.10.10.2': 'VM2'}},
    }
})

class TestMetadataProxy(unittest.TestCase):

    @mock.patch('eventlet.monkey_patch', mock.Mock())
    @mock.patch('eventlet.listen')
    @mock.patch.object(argparse.ArgumentParser, 'parse_args')
    @mock.patch.object(eventlet.GreenPool, 'spawn_n')
    @mock.patch.object(eventlet.GreenPool, 'waitall', mock.Mock())
    def test_spawn(self, spawn, parse_args, listen):
        with tempfile.NamedTemporaryFile() as f:
            f.write(config)
            f.flush()
            parse_args.return_value = mock.Mock(
                daemonize=False,
                config_file=f.name
            )
            metadata_proxy.main()
            listen.assert_has_calls(
                [mock.call(('0.0.0.0', 9602), backlog=128),
                 mock.call(('0.0.0.0', 9603), backlog=128)],
                any_order=True
            )
            # call_args need to be order before we can test it
            spawn_args = sorted(spawn.call_args_list, key=lambda y: y[0][2].network_id)
            server, socket, app = spawn_args[0][0]
            assert server == eventlet.wsgi.server
            assert isinstance(app, metadata_proxy.NetworkMetadataProxyHandler)
            assert app.tenant_id == 'ABC123'
            assert app.network_id in 'net1'
            assert app.config_file == f.name

            server, socket, app = spawn_args[1][0]
            assert server == eventlet.wsgi.server
            assert isinstance(app, metadata_proxy.NetworkMetadataProxyHandler)
            assert app.tenant_id == 'ABC123'
            assert app.network_id in 'net2'
            assert app.config_file == f.name

    @mock.patch('requests.get')
    def test_request_proxying(self, get):
        with tempfile.NamedTemporaryFile() as f:
            f.write(config)
            f.flush()
            wsgi = metadata_proxy.NetworkMetadataProxyHandler(
                'ABC123',
                'net1',
                f.name
            )
            assert wsgi.config_mtime == 0
            get.return_value.status_code = 200
            wsgi._proxy_request('10.10.10.2', '/', '')
            get.assert_called_once_with(
                'http://[192.168.25.30]:9697/',
                headers={
                    'X-Quantum-Network-ID': 'net1',
                    'X-Forwarded-For': '10.10.10.2',
                    'X-Tenant-ID': 'ABC123',
                    'X-Instance-ID': u'VM1'
                }
            )
            assert wsgi.config_mtime > 0
            mtime = wsgi.config_mtime

            wsgi._proxy_request('10.10.10.2', '/', '')
            assert wsgi.config_mtime == mtime
