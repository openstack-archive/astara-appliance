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
Blueprint for the "status" portion of the version 1 of the API.
"""
from flask import request

from astara_router import utils
from astara_router.drivers import ping

blueprint = utils.blueprint_factory(__name__)


@blueprint.before_request
def get_manager():
    request.ping_mgr = ping.PingManager()


@blueprint.route('/')
@utils.json_response
def status():
    """ Return router healt status """

    retval = {}
    # Attempt to reach public Google DNS as an ext network test
    retval['v4'] = request.ping_mgr.do('8.8.8.8')
    retval['v6'] = request.ping_mgr.do('2001:4860:4860::8888')
    return retval
