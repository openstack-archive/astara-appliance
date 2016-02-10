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
                    "host_routes": [],
                    "cidr": "192.168.0.0/24",
                    "gateway_ip": "192.168.0.1",
                    "dns_nameservers": [],
                    "dhcp_enabled": True
                },
                {
                    "host_routes": [],
                    "cidr": "fdd6:a1fa:cfa8:6af6::/64",
                    "gateway_ip": "fdd6:a1fa:cfa8:6af6::1",
                    "dns_nameservers": [],
                    "dhcp_enabled": False
                }],
            "interface": {
                "ifname": "ge1",
                "addresses": [
                    "192.168.0.137/24", "fdd6:a1fa:cfa8:6af6:f816:3eff:fea0:8082/64"
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
        "device_id": "8ac54799-b143-48e5-94d4-e5e989592229"},
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
