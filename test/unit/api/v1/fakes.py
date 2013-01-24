from akanda.router import models


class FakeIFManager(object):
    """
    The methods implemented here in the fake interface manager should not be
    built using the payloads, since that's what we're using to verify the data.
    Instead, each method should create akanda objects as needed that will
    serialize to the appropriate data to return the proper payload.
    """
    @classmethod
    def fake_get_interface(cls, ifname):
        return models.Interface(
            media="Ethernet autoselect (1000baseT full-duplex,master)",
            state="up",
            ifname="ge1",
            groups=["egress"],
            lladdr="00:0c:29:e8:f9:2e",
            addresses=["fe80::20c:29ff:fee8:f92e/64", "192.168.229.129/24"])

    @classmethod
    def fake_get_interfaces(cls):
        iface1 = models.Interface(
            media="null", state="down", ifname="ge0", groups=["enc"],
            lladdr="null", addresses=[])
        iface2 = models.Interface(
            media="Ethernet autoselect (1000baseT full-duplex,master)",
            state="up", ifname="ge1", groups=["egress"],
            lladdr="00:0c:29:e8:f9:2e",
            addresses=["fe80::20c:29ff:fee8:f92e/64", "192.168.229.129/24"])
        iface3 = models.Interface(
            media="Ethernet autoselect (1000baseT full-duplex,master)",
            state="up", ifname="ge2", groups=[],
            lladdr="00:0c:29:e8:f9:38",
            addresses=["192.168.57.101/24", "fe80::20c:29ff:fee8:f938/64"])
        return [iface1, iface2, iface3]


class FakePFManager(object):
    """
    The methods implemented here in the fake PF manager should not be
    built using the payloads, since that's what we're using to verify the data.
    Instead, each method should create akanda objects as needed that will
    serialize to the appropriate data to return the proper payload.

    However, since for version 1 we are simply presenting the actual textual
    results of the commands and not converting them to models, we just do
    straight-up text here.
    """
    @classmethod
    def fake_get_rules(self):
        return ('pass all flags S/SA\n'
                'block drop in on ! lo0 proto tcp from '
                'any to any port 6000:6010')

    @classmethod
    def fake_get_states(self):
        return ('all tcp 192.168.229.129:22 <- 192.168.229.1:52130'
                '       ESTABLISHED:ESTABLISHED\n'
                'all udp 192.168.229.255:17500 <- 192.168.229.1:17500'
                '       NO_TRAFFIC:SINGLE\n'
                'all udp 172.16.5.255:17500 <- 172.16.5.1:17500'
                '       NO_TRAFFIC:SINGLE')

    @classmethod
    def fake_get_anchors(self):
        return ('dh\n'
                'dh-ssh\n'
                'dh-www\n'
                'goodguys')

    @classmethod
    def fake_get_sources(self):
        return ("""
No ALTQ support in kernel
ALTQ related functions disabled
            """)

    @classmethod
    def fake_get_info(self):
        return("""
Status: Enabled for 0 days 01:57:48              Debug: err

State Table                          Total             Rate
  current entries                        4
  searches                            5638            0.8/s
  inserts                               86            0.0/s
  removals                              82            0.0/s
Counters
  match                                 86            0.0/s
  bad-offset                             0            0.0/s
  fragment                               0            0.0/s
  short                                  0            0.0/s
  normalize                              0            0.0/s
  memory                                 0            0.0/s
  bad-timestamp                          0            0.0/s
  congestion                             0            0.0/s
  ip-option                              0            0.0/s
  proto-cksum                            0            0.0/s
  state-mismatch                         0            0.0/s
  state-insert                           0            0.0/s
  state-limit                            0            0.0/s
  src-limit                              0            0.0/s
  synproxy                               0            0.0/s
""")

    @classmethod
    def fake_get_timeouts(self):
        return ("""
tcp.first                   120s
tcp.opening                  30s
tcp.established           86400s
tcp.closing                 900s
tcp.finwait                  45s
tcp.closed                   90s
tcp.tsdiff                   30s
udp.first                    60s
udp.single                   30s
udp.multiple                 60s
icmp.first                   20s
icmp.error                   10s
other.first                  60s
other.single                 30s
other.multiple               60s
frag                         30s
interval                     10s
adaptive.start             6000 states
adaptive.end              12000 states
src.track                     0s
""")

    @classmethod
    def fake_get_labels(self):
        return {'name': 'test_label',
                'total_packets': 10,
                'total_bytes': 256,
                'packets_in': 5,
                'bytes_in': 128,
                'packets_out': 50,
                'bytes_out': 128}

    @classmethod
    def fake_get_memory(self):
        return ('states        hard limit    10000\n'
                'src-nodes     hard limit    10000\n'
                'frags         hard limit     5000\n'
                'tables        hard limit     1000\n'
                'table-entries hard limit   200000')

    @classmethod
    def fake_get_tables(self):
        return ("""
table <block_hosts> persist
table <private> const { 10/8, 172.16/12, 192.168/16, 224/8 }
""")
