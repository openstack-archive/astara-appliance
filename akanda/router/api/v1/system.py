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
Blueprint for the "system" portion of the version 1 of the API.
"""
from flask import Response
from flask import abort, request
from dogpile.cache import make_region

from akanda.router import models
from akanda.router import utils
from akanda.router.manager import manager

blueprint = utils.blueprint_factory(__name__)

_cache = None
def get_cache():
    global _cache
    if _cache is None:
        _cache = make_region().configure(
            'dogpile.cache.dbm',
            arguments={
                "filename": "/etc/akanda-state"
            }
        )
    return _cache


@blueprint.route('/interface/<ifname>')
@utils.json_response
def get_interface(ifname):
    '''
    Show interface parameters given an interface name.
    For example ge1, ge2 for generic ethernet
    '''
    return dict(interface=manager.get_interface(ifname))


@blueprint.route('/interfaces')
@utils.json_response
def get_interfaces():
    '''
    Show all interfaces and parameters
    '''
    return dict(interfaces=manager.get_interfaces())


@blueprint.route('/config', methods=['GET'])
@utils.json_response
def get_configuration():
    """Return the current router configuration."""
    return dict(configuration=manager.config)


@blueprint.route('/config', methods=['PUT'])
@utils.json_response
def put_configuration():
    if request.content_type != 'application/json':
        abort(415)

    try:
        config_candidate = models.Configuration(request.json)
    except ValueError, e:
        return Response(
            'The config failed to deserialize.\n' + str(e),
            status=422)

    errors = config_candidate.validate()
    if errors:
        return Response(
            'The config failed to validate.\n' + '\n'.join(errors),
            status=422)

    manager.update_config(config_candidate, get_cache())
    return dict(configuration=manager.config)
