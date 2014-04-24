MAJ=5                    # Version major number
MIN=3                    # Version minor number
ARCH=$(uname -p)         # Architecture
TZ=UTC                   # Time zones are in /usr/share/zoneinfo

BASEURL=ftp://ftp3.usa.openbsd.org/pub/OpenBSD
MIRROR=$BASEURL/$MAJ.$MIN/$ARCH
PKG_PATH=$BASEURL/$MAJ.$MIN/packages/$ARCH
APPLIANCE_BASE_DIR="/root/akanda-appliance"
APPLIANCE_SCRIPT_DIR="$APPLIANCE_BASE_DIR/scripts"

# Additional packages that should be installed on the akanda live cd
PACKAGES="ntp python-2.7.3p1 py-pip wget dnsmasq bird-v6-1.3.9p0"

DNS=8.8.8.8

echo "[*] Creating motd file..."
cat >/etc/motd <<EOF
    ___   ___                       .___
   /   \\  \\  | - L3 for OpenStack - | _/
  /  _  \\ |  | _______    ____    __| | ____
 /  /_\\  \\|  |/ /\\__  \\  /    \\  / __ |\\__  \\
/    |    \\    <  / __ \\|   |  \\/ /_/ | / __ \\_
\\____|__  /__|_ \\(____  /___|  /\\____ |(____  /
        \\/     \\/     \\/     \\/      \\/     \\/
Welcome to Akanda: Powered by OpenBSD.


EOF

echo "[*] Setting name..."
cat > /etc/myname <<EOF
akanda
EOF

echo "[*] Modifying the library path..."
cat > /root/.cshrc << EOF
# Workaround for missing libraries:
export LD_LIBRARY_PATH=/usr/local/lib
EOF

echo "[*] Using DNS ($DNS) in livecd environment..."
echo "nameserver $DNS" > /etc/resolv.conf

echo "[*] Disabling services...."
cat > /etc/rc.conf.local <<EOF
spamlogd_flags=NO
inetd=NO
amd_master=NO
EOF

echo "[*] Installing additional packages..."
cat > /tmp/packages.sh <<EOF
#!/bin/sh -e
export PKG_PATH=$(echo $PKG_PATH | sed 's#\ ##g')
for i in $PACKAGES
do
   pkg_add -i \$i
done
EOF

chmod +x /tmp/packages.sh
/tmp/packages.sh || exit 1
rm /tmp/packages.sh

mkdir /etc/dnsmasq.d
cat > /etc/dnsmasq.conf <<EOF
bind-interfaces
leasefile-ro
domain-needed
bogus-priv
no-hosts
no-poll
strict-order
dhcp-lease-max=256
conf-dir=/etc/dnsmasq.d
EOF

echo "[*] Installing akanda software..."
cat > /tmp/akanda.sh <<EOF
#!/bin/sh -e
export LD_LIBRARY_PATH=/usr/local/lib

ln -sf /usr/local/bin/python2.7 /usr/local/bin/python
ln -sf /usr/local/bin/pip-2.7 /usr/local/bin/pip

pip install greenlet==0.4.0
pip install eventlet==0.12.1

cd $APPLIANCE_BASE_DIR
python setup.py install
EOF

cd /root

chmod +x /tmp/akanda.sh
/tmp/akanda.sh || exit 1
rm /tmp/akanda.sh

echo "[*] Add rc.d scripts...."
cp $APPLIANCE_SCRIPT_DIR/etc/rc.d/sshd /etc/rc.d/sshd
cp $APPLIANCE_SCRIPT_DIR/etc/rc.d/metadata /etc/rc.d/metadata
chmod 555 /etc/rc.d/sshd
chmod 555 /etc/rc.d/metadata

echo "[*] Add some stuff to sysctl.conf"
cat > $WDIR/etc/sysctl.conf <<EOF
net.inet6.ip6.dad_count=0
EOF

echo "[*] Add rc.local file...."
cp $APPLIANCE_SCRIPT_DIR/etc/rc.local /etc/rc.local

echo "[*] Deleting sensitive information..."
rm -f /root/{.history,.viminfo}
rm -f /home/*/{.history,.viminfo}

echo "[*] Empty log files..."
for log_file in $(find /var/log -type f)
do
    echo "" > $log_file
done

echo "[*] Remove ports and src"
rm -rf /usr/{src,ports,xenocara}/*

echo "[*] Saving creation timestamp..."
date > $WDIR/etc/akanda-release

echo "[*] Saving default timezone..."
rm -f /etc/localtime
ln -s /usr/share/zoneinfo/$TZ /etc/localtime

rm -rf /vagrant

echo "[*] Clean up dhcp for vio0..."
rm /etc/hostname.vio0

echo "[*] Please support the OpenBSD project by buying official cd sets or donating some money!"
echo "[*] Enjoy Akanda!"
date
echo "[*] Done."
