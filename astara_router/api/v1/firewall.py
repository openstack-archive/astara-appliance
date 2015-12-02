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
Blueprint for version 1 of the firewall API.
"""

from flask import request

from astara_router import utils
from astara_router.drivers import iptables


blueprint = utils.blueprint_factory(__name__)


@blueprint.before_request
def get_manager():
    request.iptables_mgr = iptables.IPTablesManager()


@blueprint.route('/rules')
def get_rules():
    '''
    Show loaded firewall rules by iptables
    '''
    return request.iptables_mgr.get_rules()
