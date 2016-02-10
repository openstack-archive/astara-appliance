

from astara_router.drivers import base



KEEPALIVED_CONFIG = '/etc/keepalived/keepalived.conf'

VRRP_VIPS_TEMPLATE = """
    virtual_ipaddress {
        %(primary_vip_config)s
    }
    virtual_ipaddress_excluded {
        %(additional_vip_configs)s
    }
"""

VRRP_INSTANCE_TEMPLATE = """
vrrp_instance astara_appliance_vrrp_%(interface)s {
    state BACKUP
    interface %(interface)s
    virtual_router_id %(id)s
    priority 50
    garp_master_delay 60
    mcast_src_ip %(mcast_src_ip)s
    %(vips_config)s
}
"""

class KeepalivedVipAddress(object):
    """A virtual address entry of a keepalived configuration."""

    def __init__(self, ip_address, interface_name, scope=None):
        self.ip_address = ip_address
        self.interface_name = interface_name
        self.scope = scope

    def __eq__(self, other):
        return (isinstance(other, KeepalivedVipAddress) and
                self.ip_address == other.ip_address)

    def __str__(self):
        return '[%s, %s, %s]' % (self.ip_address,
                                 self.interface_name,
                                 self.scope)

    def build_config(self):
        result = '%s dev %s' % (self.ip_address, self.interface_name)
        if self.scope:
            result += ' scope %s' % self.scope
        return result


class KeepalivedManager(base.Manager):
    def __init__(self):
        super(KeepalivedManager, self).__init__()
        self.vips = {}
        self.mcast_src_ip = None

    def set_management_address(self, address):
        """Specify the address used for keepalived cluster communication"""
        self.mcast_src_ip = address

    def add_vips(self, interface, addresses):
        for addr in addresses:
            vip = KeepalivedVipAddress(addr, interface)
            if interface not in self.vips:
                self.vips[interface] = [vip]
            else:
                self.vips[interface].append(vip)

    def _build_vips_config(self, vips):
        primary_vip = vips[0]
        additional_vips = vips[1:]
        out  = VRRP_VIPS_TEMPLATE % {
            'primary_vip_config': primary_vip.build_config(),
            'additional_vip_configs': '\n'.join(v.build_config() for v in additional_vips),
        }
        return out

    def config(self):
        out = ""
        for interface, vips in self.vips.items():
            out += VRRP_INSTANCE_TEMPLATE % {
                'id': self.vips.keys().index(interface),
                'interface': interface,
                'mcast_src_ip': self.mcast_src_ip,
                'vips_config': self._build_vips_config(vips)
            }

        return out

    def reload(self):
        with open(KEEPALIVED_CONFIG, 'w') as out:
            out.write(self.config())
        try:
            self.sudo('/etc/init.d/keepalived', 'restart')
        except:
            pass
