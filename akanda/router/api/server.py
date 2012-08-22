"""Set up the API server application instance
"""

import flask

from akanda.router.api import v1

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
    #TODO(mark): make this use a config file
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
