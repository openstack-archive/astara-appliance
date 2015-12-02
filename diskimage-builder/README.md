This directory contains elements necessary to build the Astara appliance with
the diskimage-builder from the OpenStack project.

1) Install diskimage-builder via:

    pip install diskimage-builder
    or source at:
    http://git.openstack.org/cgit/openstack/diskimage-builder

2) Ensure a few require packages are installed:
 - debootstrap
 - qemu-utils

3) Add elements to path
    $ export ELEMENTS_PATH=~/astara-appliance/diskimage-builder/elements

4) Build image
    $ DIB_RELEASE=jessie DIB_EXTLINUX=1 disk-image-create debian vm astara

5) If you're testing with kvm, don't forget to build the nocloud iso image


