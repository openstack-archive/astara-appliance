"""
Blueprint for version 1 of the firewall API.
"""

from flask import request

from akanda.router import utils
from akanda.router.drivers import pf


blueprint = utils.blueprint_factory(__name__)


@blueprint.before_request
def get_manager():
    request.pf_mgr = pf.PFManager()


@blueprint.route('/rules')
def get_rules():
    '''
    Show loaded firewall rules by pfctl
    '''
    return request.pf_mgr.get_rules()


@blueprint.route('/states')
def get_states():
    '''
    Show firewall state table
    '''
    return request.pf_mgr.get_states()


@blueprint.route('/anchors')
def get_anchors():
    '''
    Show loaded firewall anchors by pfctl
    '''
    return request.pf_mgr.get_anchors()


@blueprint.route('/sources')
def get_sources():
    '''
    Show loaded firewall sources by pfctl
    '''
    return request.pf_mgr.get_sources()


@blueprint.route('/info')
def get_info():
    '''
    Show verbose running firewall information
    '''
    return request.pf_mgr.get_info()


@blueprint.route('/tables')
def get_tables():
    '''
    Show loaded firewall tables by pfctl
    '''
    return request.pf_mgr.get_tables()


@blueprint.route('/labels')
@utils.json_response
def get_labels():
    '''
    Show loaded firewall labels by pfctl
    '''
    return dict(labels=request.pf_mgr.get_labels())


@blueprint.route('/labels', methods=['POST'])
@utils.json_response
def reset_labels():
    '''
    Show loaded firewall labels by pfctl and reset the counters
    '''
    return dict(labels=request.pf_mgr.get_labels(True))


@blueprint.route('/timeouts')
def get_timeouts():
    '''
    Show firewall connection timeouts
    '''
    return request.pf_mgr.get_timeouts()


@blueprint.route('/memory')
def get_memory():
    '''
    Show firewall memory
    '''
    return request.pf_mgr.get_memory()
