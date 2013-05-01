"""
Blueprint for the "base" portion of the version 1 of the API.
"""
from akanda.router import utils


blueprint = utils.blueprint_factory(__name__)


@blueprint.route('/')
def welcome():
    '''
    Show welcome message
    '''
    return 'Akanda appliance API service is active'
