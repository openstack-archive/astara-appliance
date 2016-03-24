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

import re


SSH = 22
SMTP = 25
DNS = 53
HTTP = 80
BGP = 179
HTTPS = 443
HTTP_ALT = 8080
API_SERVICE = 5000

DHCP = 67
DHCPV6 = 546

ISAKMP = 500
IPSEC_NAT_T = 4500

NFS_DEVELOPMENT = [111, 1110, 2049, 4045]

MANAGEMENT_PORTS = [SSH, API_SERVICE]  # + NFS_DEVELOPMENT

# destination address for AWS compliant metadata guests
METADATA_DEST_ADDRESS = '169.254.169.254'

# port for internal network metadata proxy
BASE_METADATA_PORT = 9600

# default address of orchestrator metadata service
ORCHESTRATOR_METADATA_ADDRESS = 'fdca:3ba5:a17a:acda::1'

# default port for orchestrator metadata service
ORCHESTRATOR_METADATA_PORT = 9697


def internal_metadata_port(ifname):
    return BASE_METADATA_PORT + int(re.sub('[a-zA-Z]', '', ifname))

# Configures which advanced service drivers are loaded by this
# instance of the appliance.
ENABLED_SERVICES = ['router']
