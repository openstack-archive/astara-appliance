# Copyright 2014 DreamHost, LLC
#
# Author: DreamHost, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import argparse
import logging
import re
import socket
import struct

from akanda.router import utils
from akanda.router.drivers import base
from akanda.router.models import Network


LOG = logging.getLogger(__name__)


def send_gratuitous_arp():
    parser = argparse.ArgumentParser(
        description='Send a gratuitous ARP'
    )
    parser.add_argument('ifname', metavar='ifname', type=str)
    parser.add_argument('address', metavar='address', type=str)
    args = parser.parse_args()

    return _send_gratuitous_arp(args.ifname, args.address)


def _send_gratuitous_arp(ifname, address):
    """
    Send a gratuitous ARP reply.  Generally used when Floating IPs are
    associated.
    :type ifname: str
    :param ifname: The real name of the interface to send an ARP on
    :type address: str
    :param address: The source IPv4 address
    """
    HTYPE_ARP = 0x0806
    PTYPE_IPV4 = 0x0800

    # Bind to the socket
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((ifname, HTYPE_ARP))
    hwaddr = sock.getsockname()[4]

    # Build a gratuitous ARP packet
    gratuitous_arp = [
        struct.pack("!h", 1),  # HTYPE Ethernet
        struct.pack("!h", PTYPE_IPV4),  # PTYPE IPv4
        struct.pack("!B", 6),  # HADDR length, 6 for IEEE 802 MAC addresses
        struct.pack("!B", 4),  # PADDR length, 4 for IPv4
        struct.pack("!h", 2),  # OPER, 2 = ARP Reply

        # Sender's hardware and protocol address are duplicated in the
        # target fields

        hwaddr,  # Sender MAC
        socket.inet_aton(address),  # Sender IP address
        hwaddr,  # Target MAC
        socket.inet_aton(address)  # Target IP address
    ]
    frame = [
        '\xff\xff\xff\xff\xff\xff',  # Broadcast destination
        hwaddr,  # Source address
        struct.pack("!h", HTYPE_ARP),
        ''.join(gratuitous_arp)
    ]
    sock.send(''.join(frame))
    sock.close()


class ARPManager(base.Manager):
    """
    A class to interact with entries in the ARP cache.  Currently only really
    provides support for deleting stuff from the cache.
    """
    EXECUTABLE = '/usr/sbin/arp'

    def send_gratuitous_arp_for_floating_ips(self, config, generic_to_host):
        """
        Send a gratuitous ARP for every Floating IP.
        :type config: akanda.router.models.Configuration
        :param config: An akanda.router.models.Configuration object containing
                       configuration information for the system's network
                       setup.
        :type generic_to_host: callable
        :param generic_to_host: A callable which translates a generic interface
                                name (e.g., "ge0") to a physical name (e.g.,
                                "eth0")
        """
        external_nets = filter(
            lambda n: n.network_type == Network.TYPE_EXTERNAL,
            config.networks
        )
        for net in external_nets:
            for fip in net.floating_ips:
                utils.execute([
                    'akanda-gratuitous-arp',
                    generic_to_host(net.interface.ifname),
                    str(fip.floating_ip)
                ], self.root_helper)

    def remove_stale_entries(self, config):
        """
        A wrapper function that iterates over the networks in <config> and
        removes arp entries that no longer have any networks associated with
        them.  This function calls _delete_from_arp_cache to do the actual
        deletion and makes calls to _mac_address_for_ip to match arp entries
        to network interface IPs.

        :type config: akanda.router.models.Configuration
        :param config: An akanda.router.models.Configuration object containing
                       configuration information for the system's network
                       setup.
        """
        for network in config.networks:
            for a in network.address_allocations:
                for ip in a.dhcp_addresses:
                    address_for_ip = self._mac_address_for_ip(ip)
                    if address_for_ip and address_for_ip != a.mac_address:
                        self._delete_from_arp_cache(ip)

    def _mac_address_for_ip(self, ip):
        """
        Matches a network's IP address to an arp entry.  This is used to
        associate arp entries with networks that are configured on the system
        and to determine which arp entries are stale through process of
        elemination.

        :type ip: str
        :param ip: IP address to search for in the ARP table.
        """
        cmd_out = self.sudo('-an')
        match = re.search(' \(%s\) at ([^\s]+)' % ip, cmd_out)
        if match and match.groups():
            return match.group(1)

    def _delete_from_arp_cache(self, ip):
        """
        Runs `arp -d <ip>` to delete <ip> from the arp cache.

        :type ip: str
        :param ip: IP address to search for in the ARP table.
        """
        try:
            self.sudo('-d', ip)
        except:
            # It's possible that these have already been cleaned up
            pass
