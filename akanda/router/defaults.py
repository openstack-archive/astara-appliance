SSH = 22
SMTP = 25
DNS = 53
HTTP = 80
HTTPS = 443
HTTP_ALT = 8080
API_SERVICE = 5000

NFS_DEVELOPMENT = [111, 1110, 2049, 4045]

MANAGEMENT_PORTS = [SSH, API_SERVICE]  # + NFS_DEVELOPMENT
OUTBOUND_TCP_PORTS = [SSH, SMTP, HTTP, HTTPS, HTTP_ALT]
OUTBOUND_UDP_PORTS = [DNS]

BASE_RULES = [
    'set skip on lo',
    'match in all scrub (no-df)',
    'block log (all)',  # FIXME: remove log (all)
    'pass proto icmp6 all',
    'pass inet proto icmp icmp-type { echoreq, unreach }'
]
