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


import mock
import unittest2

from akanda.router.drivers import pf

config = mock.Mock()
network = mock.Mock()
alloc = mock.Mock()
network.address_allocations = [alloc]
config.networks = [network]


class PFTest(unittest2.TestCase):

    def setUp(self):
        self.mgr = pf.PFManager()

    @mock.patch.object(pf, 'execute')
    @mock.patch.object(pf, 'replace_file')
    def test_update_error_includes_file_contents(self, ex, rf):
        # Verify that the error message from pf includes the contents
        # of the config file.
        with mock.patch.object(self.mgr, 'sudo') as sudo:
            sudo.side_effect = RuntimeError('base message')
            try:
                self.mgr.update_conf('conf data')
            except RuntimeError as e:
                self.assertIn('conf data', unicode(e))
