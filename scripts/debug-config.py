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


import sys
import pdb
from astara_router.models import Configuration

if __name__ == '__main__':
    # Simple script that helps debug faulty configurations
    with open(sys.argv[1], 'r') as c:
        try:
            conf = Configuration(conf_dict=eval(c.read()))
            print conf
            print '-' * 80
            print conf.validate()
            print '-' * 80
        except Exception as e:
            pdb.set_trace()
