
# Configures which advanced service drivers are loaded by this
# instance of the appliance.
ENABLED_SERVICES = ['router']

# If akanda_local_settings.py is located in your python path,
# it can be used to override the defaults. DIB will install this
# into /usr/local/share/akanda and append that path to the gunicorn's
# python path.
try:
    from akanda_local_settings import *  # noqa
except ImportError:
    pass
