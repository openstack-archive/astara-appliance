"""
Blueprint for version 1 of the firewall API.
"""
from akanda.router import utils
from akanda.router.drivers import pf


firewall = utils.blueprint_factory(__name__)


@firewall.route('/rules')
def get_rules():
    '''
    Show loaded firewall rules by pfctl
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_rules()
    return results


@firewall.route('/states')
def get_states():
    '''
    Show firewall state table
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_states()
    return results


@firewall.route('/anchors')
def get_anchors():
    '''
    Show loaded firewall anchors by pfctl
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_anchors()
    return results


@firewall.route('/sources')
def get_sources():
    '''
    Show loaded firewall sources by pfctl
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_sources()
    return results


@firewall.route('/info')
def get_info():
    '''
    Show verbose running firewall information
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_info()
    return results


@firewall.route('/tables')
def get_tables():
    '''
    Show loaded firewall tables by pfctl
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_tables()
    return results


@firewall.route('/labels')
def get_labels():
    '''
    Show loaded firewall labels by pfctl
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_labels()
    return results


@firewall.route('/timeouts')
def get_timeouts():
    '''
    Show firewall connection timeouts
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_timeouts()
    return results


@firewall.route('/memory')
def get_memory():
    '''
    Show firewall memory
    '''
    pf_mgr = pf.PFManager()
    results = pf_mgr.get_memory()
    return results
