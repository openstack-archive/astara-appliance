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
