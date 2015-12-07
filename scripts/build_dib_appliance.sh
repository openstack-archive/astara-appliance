#!/bin/bash -xe
# Copyright 2015 Akanda, Inc.
#
# Author: Akanda, Inc.
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

# This builds an akanda appliance VM image at
# $SRC_ROOT/build/akanda_appliance.qcow2, containing the akanda-appliance code
# as it is currently checked out in this local repository.

SRC_ROOT="$(dirname $0)/.."
IMG_OUT=$SRC_ROOT/build/akanda_appliance

AKANDA_DEBIAN_RELEASE=${AKANDA_DEBIAN_RELEASE:-"jessie"}
BASE_ELEMENTS="vm debian akanda"
EXTRA_ELEMENTS="$@"

GIT_HEAD="$(cd $SRC_ROOT && git log | head -n1 | awk '{ print $2 }')"

echo "Building astara-appliance from $GIT_HEAD"

DIB_REPOLOCATION_akanda=$SRC_ROOT \
DIB_REPOREF_akanda=$GIT_HEAD \
ELEMENTS_PATH=$SRC_ROOT/diskimage-builder/elements \
DIB_RELEASE=$AKANDA_DEBIAN_RELEASE DIB_EXTLINUX=1 \
disk-image-create $BASE_ELEMENTS $EXTRA_ELEMENTS -o $IMG_OUT
