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


SSH = 22
SMTP = 25
DNS = 53
HTTP = 80
HTTPS = 443
HTTP_ALT = 8080
API_SERVICE = 5000

NFS_DEVELOPMENT = [111, 1110, 2049, 4045]

MANAGEMENT_PORTS = [SSH, API_SERVICE]  # + NFS_DEVELOPMENT

BASE_RULES = [
    'set skip on lo',
    'match in all scrub (no-df)',
    'block log (all)',  # FIXME: remove log (all)
    'pass proto icmp6 all',
    'pass inet proto icmp icmp-type { echoreq, unreach }'
]

# destination address for AWS compliant metadata guests
METADATA_DEST_ADDRESS = '169.254.169.254'

# port for internal network metadata proxy
BASE_METADATA_PORT = 9600

# port for rug metadata service
RUG_META_PORT = 9697


def internal_metadata_port(ifname):
    return BASE_METADATA_PORT + int(ifname[2:])
