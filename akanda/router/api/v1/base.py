"""
Blueprint for the "base" portion of the version 1 of the API.
"""
from akanda.router import utils


blueprint = utils.blueprint_factory(__name__)


@blueprint.before_request
def attach_config():
    #Use for attaching config prior to starting
    pass


@blueprint.route('/')
def welcome():
    '''
    Show welcome message
    '''
    return 'Welcome to the Akanda appliance'
