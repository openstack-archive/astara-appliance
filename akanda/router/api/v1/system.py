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

# Managed by _get_cache()
_cache = None


# This needs to move to config
ADVANCED_SERVICES = [
    'loadbalancer',
]


def _get_cache():
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
    return dict(interface=manager.router.get_interface(ifname))


@blueprint.route('/interfaces')
@utils.json_response
def get_interfaces():
    '''
    Show all interfaces and parameters
    '''
    return dict(interfaces=manager.router.get_interfaces())


@blueprint.route('/config', methods=['GET'])
@utils.json_response
def get_configuration():
    """Return the current router configuration."""
    return dict(configuration=manager.router.config)


@blueprint.route('/config', methods=['PUT'])
@utils.json_response
def put_configuration():
    if request.content_type != 'application/json':
        abort(415)

    try:
        system_config_candidate = models.SystemConfiguration(request.json)
    except ValueError, e:
        return Response(
            'The system config failed to deserialize.\n' + str(e),
            status=422)

    errors = system_config_candidate.validate()
    if errors:
        return Response(
            'The config failed to validate.\n' + '\n'.join(errors),
            status=422)

    # Config requests to a router appliance will always contain a default ASN,
    # so we can key on that for now.  Later on we need to move router stuff
    # to the extensible list of things the appliance can handle
    if request.json.get('asn'):
        try:
            router_config_candidate = models.RouterConfiguration(request.json)
        except ValueError, e:
            return Response(
                'The router config failed to deserialize.\n' + str(e),
                status=422)

        errors = router_config_candidate.validate()
        if errors:
            return Response(
                'The config failed to validate.\n' + '\n'.join(errors),
                status=422)
    else:
        router_config_candidate = None

    if router_config_candidate:
        advanced_service_configs = [router_config_candidate]
    else:
        advanced_service_configs = []

    for svc in ADVANCED_SERVICES:
        if not request.json.get(svc):
            continue

        config_model = models.get_config_model(service=svc)
        if not config_model:
            continue

        try:
            svc_config_candidate = config_model(request.json.get(svc))
        except ValueError, e:
            return Response(
                'The %s config failed to deserialize.\n' + str(e) %
                config_model.service_name, status=422)

        errors = svc_config_candidate.validate()
        if errors:
            return Response(
                'The %s config failed to validate.\n' + '\n'.join(errors),
                config_model.service_name, status=422)

        advanced_service_configs.append(svc_config_candidate)

    manager.update_config(
        system_config=system_config_candidate,
        service_configs=advanced_service_configs,
        cache=_get_cache())

    # XXX need to fix this and serialize config in repsonse
    return dict(configuration={})
