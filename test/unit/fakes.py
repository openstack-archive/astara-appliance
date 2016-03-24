from copy import copy
import netaddr

from astara_router import models


FAKE_SYSTEM_DICT = {
    "tenant_id": "d22b149cee9b4eac8349c517eda00b89",
    "hostname": "ak-loadbalancer-d22b149cee9b4eac8349c517eda00b89",
    "networks": [
        {
            "v4_conf_service": "static",
            "network_type": "loadbalancer",
            "v6_conf_service": "static",
            "network_id": "b7fc9b39-401c-47cc-a07d-9f8cde75ccbf",
            "allocations": [],
            "subnets": [
                {
                    "id": "98a6270e-cf5f-4a60-9d7f-0d4524c00606",
                    "host_routes": [],
                    "cidr": "192.168.0.0/24",
                    "gateway_ip": "192.168.0.1",
                    "dns_nameservers": [],
                    "dhcp_enabled": True,
                },
                {
                    "id": "ext-subnet-id",
                    "host_routes": [],
                    "cidr": "fdd6:a1fa:cfa8:6af6::/64",
                    "gateway_ip": "fdd6:a1fa:cfa8:6af6::1",
                    "dns_nameservers": [],
                    "dhcp_enabled": False
                }],
            "interface": {
                "ifname": "ge1",
                "addresses": [
                    "192.168.0.137/24",
                    "fdd6:a1fa:cfa8:6af6:f816:3eff:fea0:8082/64"
                ]
            },
        },
        {
            "v4_conf_service": "static",
            "network_type": "management",
            "v6_conf_service": "static",
            "network_id": "43dc2fad-f6f9-4668-9695-fed50f7768aa",
            "allocations": [],
            "subnets": [
                {
                    "id": "mgt-subnet-id",
                    "host_routes": [],
                    "cidr": "fdca:3ba5:a17a:acda::/64",
                    "gateway_ip": "fdca:3ba5:a17a:acda::1",
                    "dns_nameservers": [],
                    "dhcp_enabled": True}
            ],
            "interface": {
                "ifname": "ge0",
                "addresses": ["fdca:3ba5:a17a:acda:f816:3eff:fee0:e1b0/64"]
            },
        }]
}

FAKE_LOADBALANCER_DICT = {
    "id": "8ac54799-b143-48e5-94d4-e5e989592229",
    "status": "ACTIVE",
    "name": "balancer1",
    "admin_state_up": True,
    "tenant_id": "d22b149cee9b4eac8349c517eda00b89",
    "vip_port": {
        "name": "loadbalancer-8ac54799-b143-48e5-94d4-e5e989592229",
        "network_id": "b7fc9b39-401c-47cc-a07d-9f8cde75ccbf",
        "device_owner": "neutron:LOADBALANCERV2",
        "mac_address": "fa:16:3e:a0:80:82",
        "fixed_ips": [
            {
                "subnet_id": "8c58b558-be54-45de-9873-169fe845bb80",
                "ip_address": "192.168.0.137"
            },
            {
                "subnet_id": "89fe7a9d-be92-469c-9a1e-503a39462ed1",
                "ip_address": "fdd6:a1fa:cfa8:6af6:f816:3eff:fea0:8082"}
        ],
        "id": "352e2867-06c6-4ced-8e81-1c016991fb38",
        "device_id": "8ac54799-b143-48e5-94d4-e5e989592229"
    },
    "vip_address": "192.168.0.137",
    "id": "8ac54799-b143-48e5-94d4-e5e989592229",
    "listeners": [],
}

FAKE_LISTENER_DICT = {
    'admin_state_up': True,
    'default_pool': None,
    'id': '8dca64a2-beaa-484e-a3c8-59c9b63913e0',
    'name': 'listener1',
    'protocol': 'HTTP',
    'protocol_port': 80,
    'tenant_id': 'd22b149cee9b4eac8349c517eda00b89'
}

FAKE_POOL_DICT = {
    'admin_state_up': True,
    'healthmonitor': None,
    'id': u'255c4d63-6199-4afc-abec-48c5ab46ac2e',
    'lb_algorithm': u'ROUND_ROBIN',
    'members': [],
    'name': u'pool1',
    'protocol': u'HTTP',
    'session_persistence': None,
    'tenant_id': u'd22b149cee9b4eac8349c517eda00b89'
}

FAKE_MEMBER_DICT = {
    'address': u'192.168.0.194',
    'admin_state_up': True,
    'id': u'30fc9549-7804-4196-bb86-8ebabc3a79e2',
    'protocol_port': 80,
    'subnet': None,
    'tenant_id': u'd22b149cee9b4eac8349c517eda00b89',
    'weight': 1
}

FAKE_LIFETIME_DICT = {
    'units': u'seconds',
    'value': 3600,
}

FAKE_DEAD_PEER_DETECTION_DICT = {
    'action': u'hold',
    'interval': 30,
    'timeout': 120
}

FAKE_IKEPOLICY_DICT = {
    'auth_algorithm': u'sha1',
    'encryption_algorithm': u'aes-128',
    'id': u'2b7dddc7-721f-4b93-bff3-20a7ff765726',
    'ike_version': u'v1',
    'lifetime': FAKE_LIFETIME_DICT,
    'name': u'ikepolicy1',
    'pfs': u'group5',
    'phase1_negotiation_mode': u'main',
    'tenant_id': u'd01558034b144068a4884fa7d8c03cc8'
}

FAKE_IPSECPOLICY_DICT = {
    'auth_algorithm': u'sha1',
    'encapsulation_mode': u'tunnel',
    'encryption_algorithm': u'aes-128',
    'id': u'48f7ab18-f900-4ebe-9ef6-b1cc675f4e51',
    'lifetime': FAKE_LIFETIME_DICT,
    'name': u'ipsecpolicy1',
    'pfs': u'group5',
    'tenant_id': u'd01558034b144068a4884fa7d8c03cc8',
    'transform_protocol': u'esp'
}

FAKE_LOCAL_ENDPOINT_DICT = {
    'endpoints': [u'98a6270e-cf5f-4a60-9d7f-0d4524c00606'],
    'id': u'3fbb0b1f-3fbe-4f97-9ec7-eba7f6009b94',
    'name': u'local',
    'tenant_id': u'd01558034b144068a4884fa7d8c03cc8',
    'type': u'subnet'
}

FAKE_PEER_ENDPOINT_DICT = {
    'endpoints': ['172.31.155.0/24'],
    'id': u'dc15b31c-54a6-4b83-a4b0-7a6b136bbb5b',
    'name': u'peer',
    'tenant_id': u'd01558034b144068a4884fa7d8c03cc8',
    'type': u'cidr'
}

FAKE_IPSEC_CONNECTION_DICT = {
    'admin_state_up': True,
    'auth_mode': u'psk',
    'dpd': FAKE_DEAD_PEER_DETECTION_DICT,
    'id': u'bfb6da63-7979-405d-9193-eda5601cf74b',
    'ikepolicy': FAKE_IKEPOLICY_DICT,
    'initiator': u'bi-directional',
    'ipsecpolicy': FAKE_IPSECPOLICY_DICT,
    'local_ep_group': FAKE_LOCAL_ENDPOINT_DICT,
    'mtu': 1420,
    'name': u'theconn',
    'peer_address': '172.24.4.129',
    'peer_cidrs': [],
    'peer_ep_group': FAKE_PEER_ENDPOINT_DICT,
    'peer_id': u'172.24.4.129',
    'psk': u'secrete',
    'route_mode': u'static',
    'status': u'PENDING_CREATE',
    'tenant_id': u'd01558034b144068a4884fa7d8c03cc8',
    'vpnservice_id': u'1d5ff89a-d03f-4d57-b696-34ef5c53ae28'
}

FAKE_IPSEC_VPNSERVICE_DICT = {
    'admin_state_up': True,
    'external_v4_ip': '172.24.4.2',
    'external_v6_ip': '2001:db8::1',
    'id': u'1d5ff89a-d03f-4d57-b696-34ef5c53ae28',
    'ipsec_connections': [FAKE_IPSEC_CONNECTION_DICT],
    'name': u'thevpn',
    'router_id': u'3d6d9ede-9b20-4610-9804-54ce1ef2bb43',
    'status': u'PENDING_CREATE',
    'subnet_id': None
}

FAKE_VPN_DICT = {
    'vpn': {
        'ipsec': [FAKE_IPSEC_VPNSERVICE_DICT]
    }
}

FAKE_SYSTEM_WITH_VPN_DICT = dict(FAKE_SYSTEM_DICT, vpn=FAKE_VPN_DICT['vpn'])


def fake_loadbalancer_dict(listener=False, pool=False, members=False):
    lb_dict = copy(FAKE_LOADBALANCER_DICT)

    if listener:
        lb_dict['listeners'] = [copy(FAKE_LISTENER_DICT)]

    if pool:
        if not listener:
            raise Exception("Cannot create pool without a listener")
        lb_dict['listeners'][0]['default_pool'] = \
            copy(FAKE_POOL_DICT)

    if members:
        if not pool:
            raise Exception("Cannot create member without a pool")
        lb_dict['listeners'][0]['default_pool']['members'] = \
            [copy(FAKE_MEMBER_DICT)]
    return lb_dict


def _fake_interface(ifname, addresses=None, management=False):
    addresses = addresses or ['10.0.0.1']
    return models.Interface(
        ifname=ifname,
        description='fake_interface',
        addresses=[netaddr.IPAddress(addr) for addr in addresses],
        management=management,
    )


def fake_interface(ifname='ge1', addresses=None):
    return _fake_interface(
        ifname=ifname, addresses=(addresses or ['10.0.0.1']), management=False)


def fake_mgt_interface(ifname='ge0', addresses=None):
    return _fake_interface(
        ifname=ifname, addresses=(addresses or ['11.0.0.1']), management=True)
