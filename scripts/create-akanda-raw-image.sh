TZ=UTC                   # Time zones are in /usr/share/zoneinfo

export DEBIAN_FRONTEND=noninteractive
APT_GET="apt-get -y"
APPLIANCE_BASE_DIR="/tmp/akanda-appliance"
APPLIANCE_SCRIPT_DIR="$APPLIANCE_BASE_DIR/scripts"
PACKAGES="ntp python2.7 python-pip wget dnsmasq bird6 iptables iptables-persistent"
PACKAGES_BUILD="python-dev build-essential isc-dhcp-client"

DNS=8.8.8.8
RELEASE=`lsb_release -cs`
echo "[*] Setup APT for $RELEASE"
cat > /etc/apt/sources.list <<EOF
deb http://mirrors.dreamcompute.com/debian  $RELEASE  main
deb http://mirrors.dreamcompute.com/security.debian.org  $RELEASE/updates  main
EOF


# Need to setup bird backports for wheezy only
if [ $RELEASE = "wheezy" ]; then
        echo "[*] Setup APT sources $RELEASE backports"
        cat > /etc/apt/sources.list.d/backports.list <<EOF
deb http://mirrors.dreamcompute.com/debian  $RELEASE-backports  main
EOF

        echo "[*] Setup APT prefrences for bird/bird6 to use $RELEASE-backports"
        cat <<EOF > /etc/apt/preferences.d/bird
Package: bird
Pin: release a=$RELEASE-backports
Pin-Priority: 1000

Package: bird6
Pin: release a=$RELEASE-backports
Pin-Priority: 1000
EOF

fi


echo "[*] APT Update"
apt-get update || exit 1

echo "[*] Creating motd file..."
cat >/etc/motd <<EOF
    ___   ___                       .___
   /   \\  \\  | - L3 for OpenStack - | _/
  /  _  \\ |  | _______    ____    __| | ____
 /  /_\\  \\|  |/ /\\__  \\  /    \\  / __ |\\__  \\
/    |    \\    <  / __ \\|   |  \\/ /_/ | / __ \\_
\\____|__  /__|_ \\(____  /___|  /\\____ |(____  /
        \\/     \\/     \\/     \\/      \\/     \\/
Welcome to Akanda: Powered by Unicorns.
Default root password: akanda


EOF

echo "[*] Setting hostname..."
cat > /etc/hostname <<EOF
akanda-linux
EOF

echo "[*] Setting up DNS ($DNS)"
echo "nameserver $DNS" > /etc/resolv.conf

echo "[*] Installing additional packages..."
$APT_GET install $PACKAGES || exit 1
$APT_GET install $PACKAGES_BUILD || exit 1

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
pip install -U setuptools
pip install greenlet==0.4.0
pip install eventlet==0.12.1

cd $APPLIANCE_BASE_DIR
python setup.py install
EOF

chmod +x /tmp/akanda.sh
/tmp/akanda.sh || exit 1
rm /tmp/akanda.sh

echo "[*] Add init scripts...."
cp $APPLIANCE_SCRIPT_DIR/etc/init.d/ssh /etc/init.d/ssh
cp $APPLIANCE_SCRIPT_DIR/etc/init.d/bird6 /etc/init.d/bird6
cp $APPLIANCE_SCRIPT_DIR/etc/init.d/metadata /etc/init.d/metadata
cp $APPLIANCE_SCRIPT_DIR/etc/init.d/akanda-router-api-server /etc/init.d/akanda-router-api-server
chmod 555 /etc/init.d/ssh
chmod 555 /etc/init.d/bird6
chmod 555 /etc/init.d/metadata
chmod 555 /etc/init.d/akanda-router-api-server

echo "[*] Update rc.d"
update-rc.d akanda-router-api-server start


echo "[*] Add some stuff to sysctl.conf"
cat > /etc/sysctl.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.eth0.accept_dad=0
EOF

echo "[*] Disable fsck on boot"
touch /fastboot


echo "[*] Deleting sensitive information..."
rm -f /root/{.history,.viminfo}
rm -f /home/*/{.history,.viminfo}

if [ -e $APPLIANCE_SCRIPT_DIR/etc/key ]; then
        echo "[*] Adding ssh key..."
        mkdir /root/.ssh
        chmod 700 /root/.ssh
        cp $APPLIANCE_SCRIPT_DIR/etc/key /root/.ssh/authorized_keys
        chmod 600 /root/.ssh/authorized_keys
fi

echo "[*] Setting root password"
if [ -e $APPLIANCE_SCRIPT_DIR/etc/rootpass ]; then
        cat $APPLIANCE_SCRIPT_DIR/etc/rootpass | chpasswd -e
else
        echo 'root:$6$5HY0/7bi$axsLQiCMoSNFU2hDpv8LSM.vJNM..j4XppC.vGkELIB5/hZfss0a9c.T9ewED.qfIPlry5EZeqwzAT4ROW5nj0' |chpasswd -e
fi

echo "[*] Empty log files..."
for log_file in $(find /var/log -type f)
do
    echo "" > $log_file
done

echo "[*] Remove packages only required by install"
$APT_GET remove $PACKAGES_BUILD || exit 1
$APT_GET autoremove
$APT_GET clean


echo "[*] Saving creation timestamp..."
date > /etc/akanda-release

echo "[*] Saving default timezone..."
rm -f /etc/localtime
ln -s /usr/share/zoneinfo/$TZ /etc/localtime

echo "[*] Use bash instead of dash"
rm /bin/sh ; ln -s /bin/bash /bin/sh

echo "[*] Clean up udev rules..."
rm -f /etc/udev/rules.d/70-persistent-net.rules

echo "[*] Enjoy Akanda!"
date
echo "[*] Done."
