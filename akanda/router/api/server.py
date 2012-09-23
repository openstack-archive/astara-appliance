"""Set up the API server application instance
"""
import logging
import logging.handlers

import daemon
import lockfile
import flask

from akanda.router.api import v1
from akanda.router.manager import manager

handler = logging.handlers.TimedRotatingFileHandler(
    '/var/log/akanda', when='D', interval=1, backupCount=10)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s %(lineno)d]'))

app = flask.Flask(__name__)
app.register_blueprint(v1.base)
app.register_blueprint(v1.system)
app.register_blueprint(v1.firewall)
app.logger.addHandler(handler)

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

def daemonize():
    pidfile = lockfile.FileLock('/var/run/akanda.pid')
    with daemon.DaemonContext(pidfile=pidfile, stdout=file('/tmp/stdout', 'w+'), stderr=file('/tmp/stderr', 'w+')):
        main()
