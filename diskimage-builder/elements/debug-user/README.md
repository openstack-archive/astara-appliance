
Creates a sudo privileged user in the appliance VM that can be used for
debugging connectivity issues via the console, when SSH connectivity is
not possible. Note that an 'astara' user is created by the RUG and setup
to authenticate using a SSH public key. This element should only be included
when building images for develoment environments.

The username and password can be set in the build environment as
$DIB_ASTARA_APPLIANCE_DEBUG_USER and $DIB_ASTARA_APPLIANCE_DEBUG_PASSWORD
The defaults are astara-debug/astara.
