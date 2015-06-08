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


"""Set up the API server application instance
"""
import flask

from akanda.router.api import v1
from akanda.router.debug import handle_traceback
from akanda.router.manager import manager

app = flask.Flask(__name__)
app.register_blueprint(v1.base.blueprint)
app.register_blueprint(v1.system.blueprint)
app.register_blueprint(v1.firewall.blueprint)
app.register_blueprint(v1.status.blueprint)
app.register_error_handler(500, handle_traceback)


@app.before_request
def attach_config():
    '''
        Attach any configuration before instantiating API
    '''
    pass


def main():
    # TODO(mark): make this use a config file ie
    # app.config.from_object('akanda.router.config.Default')
    # manager.state_path = app.config['STATE_PATH']

    raise Exception('This is broken!')
    app.run(host=manager.management_address(ensure_configuration=True),
            port=5000)
