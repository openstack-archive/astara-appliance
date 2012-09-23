import logging
import os
import re
from cStringIO import StringIO

from akanda.router.drivers import base
from akanda.router.utils import execute, replace_file


LOG = logging.getLogger(__name__)
RUN_DIR = '/var/run/dhcp'
PID_FILE = os.path.join(RUN_DIR, 'dnsmasq.pid')
HOSTS_FILE = os.path.join(RUN_DIR, 'dnsmasq.hosts')
OPTS_FILE = os.path.join(RUN_DIR, 'dnsmasq.opts')


class DnsManager(base.Manager):
    """
    """
    EXECUTABLE = '/sbin/dnsmasq'

    def __init__(self, interfaces, allocations,
                 domain='akanda.local', root_helper='sudo'):
        super(DnsManager, self).__init__(root_helper=root_helper)
        self.interfaces = interfaces
        self.allocations = allocations
        self.domain = domain
        # XXX self.tags is referenced in a couple places but never explicitly
        # set; this should probably be done here; please fix
        self._make_tags()

        cmd = [
            '--no-hosts',
            '--no-resolv',
            '--strict-order',
            '--bind-interfaces',
            '--except-interface=lo',
            '--domain=%s' % self.domain,
            '--pid-file=%s' % PID_FILE,
            '--dhcp-hostsfile=%s' % HOSTS_FILE,
            '--dhcp-optsfile=%s' % OPTS_FILE,
            '--leasefile-ro',
        ]

        for interface in interfaces:
            cmd.append('--interface=%s' % interface.ifname)
            for address in interface.addresses:
                cmd.append('--dhcp-range=set:%s,%s,%s,%ss' %
                           (self.tags[address.ip],
                            address.network,
                            'static',
                            120))

        self._output_hosts_file()
        self._output_opts_file()

        self.sudo(cmd)

    def __del__(self):
        #FIXME: ensure the pid is actually dnsmasq
        execute(['kill', '-9', self.pid], self.root_helper)

    @property
    def pid(self):
        try:
            return int(open(PID_FILE, 'r').read())
        except:
            return

    def update_allocations(self, allocations):
        """Rebuilds the dnsmasq config and signal the dnsmasq to reload."""
        self.allocations = allocations
        self._output_hosts_file()
        execute(['kill', '-HUP', self.pid], self.root_helper)
        LOG.debug('Reloading allocations')

    def _make_tags(self):
        i = 0
        for interface in self.interfaces:
            for address in self.addresses:
                # XXX tags is not defined anywhere... please fix
                if address in tags:
                    raise ValueError('Duplicate network')
                self.tags[address] = 'tag%d' % i
                i += 1

    def _output_hosts_file(self):
        """Writes a dnsmasq compatible hosts file."""
        r = re.compile('[:.]')
        buf = StringIO()

        for alloc in self.allocations:
            name = '%s.%s' % (r.sub('-', alloc.ip_address),
                              self.domain)
            buf.write('%s,%s,%s\n' %
                      (alloc.mac_address, name, alloc.ip_address))

        replace_file(HOSTS_FILE, buf.getvalue())

    def _output_opts_file(self):
        """Write a dnsmasq compatible options file."""
        # TODO (mark): add support for nameservers
        options = []
        for interface in self.interfaces:
            options.append((self.tags[interface.ip],
                            'option',
                            'router',
                            interface.ip))

        # XXX name is never used; please fix (remove it or use it)
        name = self.get_conf_file_name('opts')
        replace_file(OPTS_FILE,
                     '\n'.join(['tag:%s,%s:%s,%s' % o for o in options]))
