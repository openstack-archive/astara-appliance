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


import argparse
import atexit
import contextlib
import json
import functools
import logging
import os
import sys
import urlparse

import eventlet
import eventlet.wsgi
import requests
from werkzeug import exceptions
from werkzeug import wrappers

from akanda.router import defaults
from akanda.router.drivers import ip

LOG = logging.getLogger(__name__)


class NetworkMetadataProxyHandler(object):
    """Proxy metadata request onto the RUG proxy
       The proxy allows access resources that are not accessible within the
       isolated tenant context.
    """

    def __init__(self, tenant_id, network_id, config_file):
        self.tenant_id = tenant_id
        self.network_id = network_id
        self.config_file = config_file
        self.config_mtime = 0
        self._ip_instance_map = {}

    def __call__(self, environ, start_response):
        request = wrappers.Request(environ)

        LOG.debug("Request: %s", request)
        try:
            response = self._proxy_request(request.remote_addr,
                                           request.path,
                                           request.query_string)
        except Exception:
            LOG.exception("Unexpected error.")
            msg = ('An unknown error has occurred. '
                   'Please try your request again.')
            response = exceptions.InternalServerError(description=unicode(msg))

        return response(environ, start_response)

    @property
    def ip_instance_map(self):
        config_mtime = os.stat(self.config_file).st_mtime
        if config_mtime > self.config_mtime:
            LOG.debug("Metadata proxy configuration has changed; reloading...")
            config_dict = json.load(open(self.config_file))
            self._ip_instance_map = config_dict[
                self.network_id
            ]['ip_instance_map']
            self.config_mtime = config_mtime
        return self._ip_instance_map

    def _proxy_request(self, remote_address, path_info, query_string):
        headers = {
            'X-Forwarded-For': remote_address,
            'X-Instance-ID': self.ip_instance_map.get(remote_address, ''),
            'X-Quantum-Network-ID': self.network_id,
            'X-Tenant-ID': self.tenant_id
        }

        url = urlparse.urlunsplit((
            'http',
            '[%s]:%d' % (ip.get_rug_address(), defaults.RUG_META_PORT),
            path_info,
            query_string,
            ''))

        response = requests.get(url, headers=headers)

        if response.status_code == requests.codes.ok:
            LOG.debug(response)
            return wrappers.Response(response.content, mimetype='text/plain')
        elif response.status_code == requests.codes.not_found:
            return exceptions.NotFound()
        elif response.status_code == requests.codes.internal_server_error:
            msg = 'Remote metadata server experienced an error.'
            return exceptions.InternalServerError(description=unicode(msg))
        else:
            raise Exception('Unexpected response code: %s' % response.status)


def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        """Daemonize process by doing Stevens double fork."""
        # fork first time
        _fork()

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # fork second time
        _fork()

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        stdin = file(stdin, 'r')
        stdout = file(stdout, 'a+')
        stderr = file(stderr, 'a+', 0)
        os.dup2(stdin.fileno(), sys.stdin.fileno())
        os.dup2(stdout.fileno(), sys.stdout.fileno())
        os.dup2(stderr.fileno(), sys.stderr.fileno())

        # write a pidfile
        pidfile = '/var/run/metadata.pid'
        atexit.register(functools.partial(os.remove, pidfile))
        pid = str(os.getpid())
        with contextlib.closing(open(pidfile, 'w+')) as f:
            f.write("%s\n" % pid)


def _fork():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError, e:
        sys.stderr.write("fork failed %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)


def main():
    eventlet.monkey_patch()

    parser = argparse.ArgumentParser()
    parser.add_argument("-D", "--no-daemon", help="don't daemonize",
                        action="store_false", dest='daemonize', default=True)
    parser.add_argument("config_file", help="Proxy configuration file")
    args = parser.parse_args()

    try:
        config_dict = json.load(open(args.config_file))
    except IOError:
        raise SystemError('Unable to open config file at %s.' %
                          args.config_file)
    except:
        raise SystemError('Unable to parse config file at %s.' %
                          args.config_file)

    if args.daemonize:
        daemonize()

    pool = eventlet.GreenPool(1000)

    tenant_id = config_dict.pop('tenant_id')
    for network_id, config in config_dict.items():
        app = NetworkMetadataProxyHandler(tenant_id,
                                          network_id,
                                          args.config_file)
        socket = eventlet.listen(('0.0.0.0', config['listen_port']),
                                 backlog=128)
        pool.spawn_n(eventlet.wsgi.server, socket, app, custom_pool=pool)

    pool.waitall()
