from akanda.router.drivers import base
from akanda.router.utils import execute, replace_file
from akanda.router import models


class PFManager(base.Manager):
    """
    """
    EXECUTABLE = '/sbin/pfctl'

    def _show(self, flag, prefix=''):
        return self.sudo('-%ss%s' % (prefix, flag))

    def get_rules(self):
        # -sr
        return self._show('r')

    def get_states(self):
        # -ss
        return self._show('s')

    def get_anchors(self):
        # -sA
        return self._show('A')

    def get_sources(self):
        # -sS
        return self._show('S')

    def get_info(self):
        # -si
        return self._show('i')

    def get_tables(self):
        # -sT
        return self._show('T')

    def get_labels(self, reset=False):
        prefix = 'vz' if reset else ''
        data = self._show('l', prefix)
        return [self._parse_label_line(l)
                for l in data.strip().split('\n') if l]

    def get_timeouts(self):
        # -st
        return self._show('t')

    def get_memory(self):
        # -sm
        return self._show('m')

    def update_conf(self, conf_data):
        replace_file('/tmp/pf.conf', conf_data)
        execute(['mv', '/tmp/pf.conf', '/etc/pf.conf'], self.root_helper)
        self.sudo('-f', '/etc/pf.conf')

    def _parse_label_line(self, line):
        parts = line.strip().split()
        values = [int(i) for i in parts[1:]]
        return {'name': parts[0],
                'total_packets': values[2],
                'total_bytes': values[3],
                'packets_in': values[4],
                'bytes_in': values[5],
                'packets_out': values[6],
                'bytes_out': values[7]}


class TableManager(base.Manager):
    """
    """
    EXECUTABLE = '/sbin/pfctl'

    def __init__(self, name):
        self.name = name

    def add(self, cidr):
        self._sudo('-t', self.name, '-T', 'add', str(cidr))

    def delete(self, cidr):
        self._sudo('-t', self.name, '-T', 'delete', str(cidr))

    def show(self):
        return self._sudo('-t', self.name, '-T', self.name)


def _parse_pf_rules(data, filters=None):
    '''
    Parser for pfctl -sr
    '''
    retval = []
    return retval


def _parse_pf_rule(line):
    '''
    Parser for pfctl -sr
    '''
    retval = {}
    return models.PFManager.from_dict(retval)
