This is the base element for building an Akanda appliance image.

Ansible is required on the local system.

Advanced service drivers may be enabled in the appliance by setting
``DIB_AKANDA_ADVANCED_SERVICES``. This defaults to enabling only the
router driver, but you may enabled other avialable drivers ie:

DIB_AKANDA_ADVANCED_SERVICES=router,loadbalancer
