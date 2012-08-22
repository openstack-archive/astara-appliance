"""
Blueprint for the "base" portion of the version 1 of the API.
"""
from akanda.router import utils


base = utils.blueprint_factory(__name__)


@base.before_request
def attach_config():
    #Use for attaching config prior to starting
    pass


@base.route('/')
def welcome():
    '''
    Show welcome message
    '''
    return 'Welcome to the Akanda appliance'
