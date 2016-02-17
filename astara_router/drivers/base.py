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


from astara_router import utils


class Manager(object):
    """
    A base class that provides access to common functions used in other driver
    modules.
    """

    def __init__(self, root_helper='sudo astara-rootwrap /etc/rootwrap.conf'):
        """
        Initializes Manager class. <root_helper> provides a facility to specify
        how this class accesses escalated privileges. Defaults to 'sudo'.

        :type root_helper: str
        :param root_helper: The method used to obtain escalated privileges.
                            This command will be passed just before the command
                            passed to self.sudo/do.  If root_helper is 'sudo'
                            then this will look like: `sudo ls`.
        """
        self.root_helper = root_helper

    def sudo(self, *args):
        """
        Executes command <args> with the specified flags through the
        root_helper facility (i.e. escalated privileges).

        :type args: tuple
        :param args: A command, and flags, to execute.
        :rtype: tuple
        """
        return utils.execute([self.EXECUTABLE] + list(args), self.root_helper)

    def do(self, *args):
        """
        Executes command <args> with specified flags and without escalated
        privileges.

        :type args: tuple
        :param args: A command, and flags, to execute.
        :rtype: tuple
        """
        return utils.execute([self.EXECUTABLE] + list(args))
