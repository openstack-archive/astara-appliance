#!/usr/bin/python
#
# Copyright (c) 2015 Akanda, Inc. All Rights Reserved.
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

# This is a utility script to query version codename from the version of
# the package according to setup.cfg or PBR.  We use this to determine what
# version of  the image we're building in the gate publishing jobs, which
# checks this out from a detached head.

import ConfigParser
import sys

from pbr import version as pbr_version


VERSION_MAP = {
    '8': 'trunk',
    '7': 'liberty',
    '2015.1': 'kilo',
    '2014.2': 'juno',
}


def version_from_pbr():
    version = pbr_version.VersionInfo('akanda')
    return str(version)


def version_from_setup_cfg():
    setup_cfg = ConfigParser.RawConfigParser()
    setup_cfg.read('setup.cfg')

    try:
        version = setup_cfg.get('metadata', 'version')
        return version
    except ConfigParser.NoOptionError:
        pass


if __name__ == '__main__':
    version = version_from_setup_cfg()
    if not version:
        version = version_from_pbr()
    version = str(version).split('.')

    codename = None
    if int(version[0]) < 2014:
        # newer versioning scheme, ie 7.0.0
        codename = VERSION_MAP.get(version[0])
    else:
        # older, ie 2015.1
        date_version = '.'.join(version[:2])
        codename = VERSION_MAP.get(date_version)

    if not codename:
        print ('ERROR: Could not determine version codename ' \
              'version %s' % version)
        sys.exit(1)

    print codename
