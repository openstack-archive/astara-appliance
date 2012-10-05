"""Set up the API server application instance
"""
import flask

from akanda.router.api import v1
from akanda.router.manager import manager

app = flask.Flask(__name__)
app.register_blueprint(v1.base)
app.register_blueprint(v1.system)
app.register_blueprint(v1.firewall)


@app.before_request
def attach_config():
    '''
        Attach any configuration before instantiating API
    '''
    pass


def main():
    app.debug = False
    #TODO(mark): make this use a config file ie
    # app.config.from_object('akanda.router.config.Default')
    # manager.state_path = app.config['STATE_PATH']

    app.run(host=manager.management_address(ensure_configuration=True),
            port=5000)
