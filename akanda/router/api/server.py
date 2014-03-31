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

    app.run(host=manager.management_address(ensure_configuration=True),
            port=5000)
