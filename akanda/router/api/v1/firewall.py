"""
Blueprint for version 1 of the firewall API.
"""

from flask import request

from akanda.router import utils
from akanda.router.drivers import pf


firewall = utils.blueprint_factory(__name__)


@firewall.before_request
def get_manager():
    request.pf_mgr = pf.PFManager()


@firewall.route('/rules')
def get_rules():
    '''
    Show loaded firewall rules by pfctl
    '''
    return request.pf_mgr.get_rules()


@firewall.route('/states')
def get_states():
    '''
    Show firewall state table
    '''
    return request.pf_mgr.get_states()


@firewall.route('/anchors')
def get_anchors():
    '''
    Show loaded firewall anchors by pfctl
    '''
    return request.pf_mgr.get_anchors()


@firewall.route('/sources')
def get_sources():
    '''
    Show loaded firewall sources by pfctl
    '''
    return request.pf_mgr.get_sources()


@firewall.route('/info')
def get_info():
    '''
    Show verbose running firewall information
    '''
    return request.pf_mgr.get_info()


@firewall.route('/tables')
def get_tables():
    '''
    Show loaded firewall tables by pfctl
    '''
    return request.pf_mgr.get_tables()


@firewall.route('/labels')
def get_labels():
    '''
    Show loaded firewall labels by pfctl
    '''
    return request.pf_mgr.get_labels()


@firewall.route('/timeouts')
def get_timeouts():
    '''
    Show firewall connection timeouts
    '''
    return request.pf_mgr.get_timeouts()


@firewall.route('/memory')
def get_memory():
    '''
    Show firewall memory
    '''
    return request.pf_mgr.get_memory()
