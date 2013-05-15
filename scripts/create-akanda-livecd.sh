#!/bin/sh
#
#     ___   ___                       .___
#    /   \  \  | - L3 for OpenStack - | _/
#   /  _  \ |  | _______    ____    __| | ____
#  /  /_\  \|  |/ /\__  \  /    \  / __ |\__  \
# /    |    \    <  / __ \|   |  \/ /_/ | / __ \_
# \____|__  /__|_ \(____  /___|  /\____ |(____  /
#         \/     \/     \/     \/      \/     \/
#
# This script creates an Akanda Live CD - powered by OpenBSD, Python, and
# Flask - and # lets you customize it.
#
# Copyright (c) 2009 Reiner Rottmann. Released under the BSD license.
# Copyright (c) 2012 New Dream Network, LLC (DreamHost).
#
# First release 2009-06-20
# Akanda release 2012-10-14
#
# Notes:
#
# * Modified 2012 by DreamHost <dev-community@dreamhost.com> for use with
#   Akanda

###############################################################################
# Defaults
###############################################################################
MAJ=5                    # Version major number
MIN=1                    # Version minor number
ARCH=amd64                # Architecture
TZ=UTC                   # Time zones are in /usr/share/zoneinfo
# The base sets that should be installed on the akanda live cd
SETS="base etc man"
# Additional packages that should be installed on the akanda live cd
PACKAGES="ntp python-2.7.1p12 py-pip wget"


WDIR=/usr/local/akanda-livecdx            # Working directory
CDBOOTDIR=$WDIR/$MAJ.$MIN/$ARCH        # CD Boot directory
OUTDIR=/tmp
HERE=`pwd`

# Mirror to use to download the OpenBSD files
#BASEURL=http://ftp-stud.fht-esslingen.de/pub/OpenBSD
#BASEURL=http://openbsd.mirrors.pair.com
BASEURL=ftp://ftp3.usa.openbsd.org/pub/OpenBSD
MIRROR=$BASEURL/$MAJ.$MIN/$ARCH
PKG_PATH=$BASEURL/$MAJ.$MIN/packages/$ARCH
DNS=8.8.8.8            # Google DNS Server to use in live cd (change accordingly)


#CLEANUP=no                    # Clean up downloaded files and workdir (disabled by default)
CLEANUP=yes

# End of user configuration
###############################################################################

# global variables

SCRIPTNAME=$(basename $0 .sh)

EXIT_SUCCESS=0
EXIT_FAILED=1
EXIT_ERROR=2
EXIT_BUG=10

VERSION="1.0.0"

# base functions

# In case of an error it is wise to show the correct usage of the script.
function usage {
    echo >&2
    echo -e "Usage: $SCRIPTNAME \t[-A <arch>] [-h] [-M <major>] [-m <minor>] [-P <packages>]" >&2
    echo -e "                   \t\t[-S <sets>] [-T <timezone>] [-V] [-W <workdir>] [-U <url>]" >&2
    echo >&2
    echo "This program creates an OpenBSD live cd and lets you customize it." >&2
    echo "The software is released under BSD license. Use it at your own risk!" >&2
    echo "Copyright (c) 2009 Reiner Rottmann. Email: reiner[AT]rottmann.it" >&2
    echo "Copyright (c) 2012 New Dream Network, LLC. Email: dev-community[AT]dreamhost.com" >&2
    echo >&2
    echo -e "  -A :\tselect architecture (default: $ARCH)" >&2
    echo -e "  -h :\tgive this help list" >&2
    echo -e "  -M :\tselect OpenBSD major version (default: $MAJ)" >&2
    echo -e "  -m :\tselect OpenBSD minor version (default: $MIN)" >&2
    echo -e "  -P :\tselect additional packages to install" >&2
    echo -e "      \t(default: $PACKAGES)" >&2
    echo -e "  -S :\tselect base sets (default: $SETS)" >&2
    echo -e "  -T :\tselect timezone (default: $TZ)" >&2
    echo -e "  -U :\tselect url of nearest OpenBSD mirror (default: $MIRROR)" >&2
    echo -e "  -u :\tselect url of nearest OpenBSD from mirror list (requires wget)" >&2
    echo -e "  -V :\tprint version" >&2
    echo -e "  -W :\tselect working directory (default: $WDIR)" >&2
    echo >&2
    echo -e "Example:" >&2
    echo -e "# $SCRIPTNAME -A amd64 -M 4 -m 5 -W /tmp/livecd" >&2
    echo >&2
    [[ $# -eq 1 ]] && exit $1 || exit $EXIT_FAILED
}

# own functions
# This function lets the user choose an OpenBSD mirror
function choosemirror {
    req="wget"
    for i in $req
    do
        if ! which $i >/dev/null; then
            echo "Missing $i. Exiting."
            exit $EXIT_ERROR
        fi
    done

    mirrorlist=$(wget -q -O - http://www.openbsd.org/ftp.html#ftp | sed -n 's#<a href=\"\(ftp://.*\)/">#\1#p'|sort)

    echo "Please select mirror from the list below:"

    mirr=""
    while [ -z "$mirr" ] ; do
            m=1
            for i in $mirrorlist
            do
                    echo $m. "$i"
                    m=$(($m+1))
            done
            echo -n "Your choice? : "
            read choice
            mirr=$(echo "$mirrorlist" | sed -n $choice,${choice}p| sed s#^\ *##g)
    done
    BASEURL=$mirr
    MIRROR=$BASEURL/$MAJ.$MIN/$ARCH
    PKG_PATH=$BASEURL/$MAJ.$MIN/packages/$ARCH
    CDBOOTDIR=$WDIR/$MAJ.$MIN/$ARCH
}

# This function may be used for cleanup before ending the program
function cleanup {
    echo
}

function makedeps {
    echo "[*] Installing dependencies for make"
    pkg_add -i bison
    pkg_add -i m4
    pkg_add -i gmake
}


# This is the main function that creates the OpenBSD livecd
function livecd {
    echo "[*] Akanda (powered by OpenBSD) LiveCD script"
    echo "[*] The software is released under BSD license. Use it at your own risk!" >&2
    echo "[*] Copyright (c) 2009 Reiner Rottmann." >&2
    echo "[*] Copyright (c) 2012 New Dream Network, LLC (DreamHost)." >&2
    echo "[*] This script is released under the BSD License."
    uname -a | grep OpenBSD || echo "[*] WARNING: This software should run on an OpenBSD System!"
    date
    echo "[*] Setting up the build environment..."
    mkdir -p $WDIR

     if [[ $CHMIRROR = y ]] ; then
        echo "[*] Selecting OpenBSD mirror..."
        choosemirror
        echo $MIRROR
    fi

    # Create CD Boot directory
    mkdir -p $CDBOOTDIR && cd $CDBOOTDIR

    echo "[*] Downloading files needed for CD Boot..."
    CDBOOTFILES="cdbr cdboot bsd"
    cd $CDBOOTDIR && for i in $CDBOOTFILES; do test -f $CDBOOTDIR/$i || ftp -o $CDBOOTDIR/$i -m $MIRROR/$i; done
    typeset missing=""
    cd $CDBOOTDIR && for i in $CDBOOTFILES; do test -f $CDBOOTDIR/$i || missing="$missing $i"; done
    if [ ! -z "$missing" ]
    then
        echo "Missing download files: $missing" 1>&2
        exit 1
    fi

    echo "[*] Downloading file sets ($SETS)..."
    cd $WDIR && for i in $SETS; do test -f $WDIR/$i$MAJ$MIN.tgz || ftp -o $WDIR/$i$MAJ$MIN.tgz -m $MIRROR/$i$MAJ$MIN.tgz; done
    typeset missing=""
    cd $WDIR && for i in $SETS; do test -f $WDIR/$i$MAJ$MIN.tgz || missing="$missing $i$MAJ$MIN.tgz"; done
    if [ ! -z "$missing" ]
    then
        echo "Missing download file sets: $missing" 1>&2
        exit 1
    fi

    echo "[*] Extracting file sets ($SETS)..."
    cd $WDIR && for i in $SETS; do tar xzpf $WDIR/$i$MAJ$MIN.tgz; done

    if [ $CLEANUP="yes" ];then
        echo "[*] Deleting file set tarballs ($SETS)..."
        cd $WDIR && for i in $SETS; do rm -f $WDIR/$i$MAJ$MIN.tgz; done
    fi

    echo "[*] Populating dynamic device directory..."
    cd $WDIR/dev && $WDIR/dev/MAKEDEV all

    echo "[*] Creating boot configuration..."
    echo "set image $MAJ.$MIN/$ARCH/bsd" > $WDIR/etc/boot.conf

    echo "[*] Creating fstab entries..."
    cat >/$WDIR/etc/fstab <<EOF
    swap /tmp mfs rw,auto,-s=120000 0 0
    swap /var mfs rw,auto,-P/mfsvar,-s=32000 0 0
    swap /etc mfs rw,auto,-P/mfsetc 0 0
    swap /root mfs rw,auto,-P/mfsroot 0 0
    swap /dev mfs rw,auto,-P/mfsdev 0 0
EOF

    echo "[*] Creating motd file..."
    cat >$WDIR/etc/motd <<EOF

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
    cat > $WDIR/etc/myname <<EOF
    akanda
EOF

echo "[*] Modifying the library path..."
cat > $WDIR/root/.cshrc << EOF
# Workaround for missing libraries:
export LD_LIBRARY_PATH=/usr/local/lib
EOF
cat > $WDIR/root/.profile << EOF
# Workaround for missing libraries:
export LD_LIBRARY_PATH=/usr/local/lib
EOF
mkdir -p $WDIR/etc/profile
cat > $WDIR/etc/profile/.cshrc << EOF
# Workaround for missing libraries:
export LD_LIBRARY_PATH=/usr/local/lib
EOF
cat > $WDIR/etc/profile/.profile << EOF
# Workaround for missing libraries:
export LD_LIBRARY_PATH=/usr/local/lib
EOF

echo "[*] Using DNS ($DNS) in livecd environment..."
echo "nameserver $DNS" > $WDIR/etc/resolv.conf

echo "[*] Disabling services...."
cat > $WDIR/etc/rc.conf.local <<EOF
spamlogd_flags=NO
inetd=NO
amd_master=NO
EOF

echo "[*] Setting default password..."
cp $HERE/etc/master.passwd $WDIR/etc/master.passwd
cp $HERE/etc/passwd $WDIR/etc/passwd
cp $HERE/etc/group $WDIR/etc/group
chroot $WDIR passwd root || exit 1

echo "[*] Installing additional packages..."
cat > $WDIR/tmp/packages.sh <<EOF
#!/bin/sh -e
export PKG_PATH=$(echo $PKG_PATH | sed 's#\ ##g')
for i in $PACKAGES
do
   pkg_add -i \$i
done
EOF

chmod +x $WDIR/tmp/packages.sh
chroot $WDIR /tmp/packages.sh || exit 1
rm $WDIR/tmp/packages.sh

echo "[*] Disabling services...."
cat > $WDIR/etc/rc.conf.local <<EOF
spamlogd_flags=NO
inetd=NO
amd_master=NO
EOF

echo "[*] Add bird and dnsmasq...."
cd $WDIR/tmp
tar -zxf $HERE/src/bird-1.3.8.tar.gz
tar -zxf $HERE/src/dnsmasq-2.65.tar.gz
cd bird-1.3.8
./configure --enable-ipv6 --prefix=
gmake
cd ../dnsmasq-2.65
make
cd $HERE
cp $WDIR/tmp/dnsmasq-2.65/src/dnsmasq $WDIR/usr/local/sbin/.
cp $WDIR/tmp/bird-1.3.8/bird $WDIR/usr/local/sbin/.
cp $WDIR/tmp/bird-1.3.8/birdc $WDIR/usr/local/sbin/.

cat > $WDIR/etc/bird6.conf <<EOF
log syslog {warning, error, info};
EOF

mkdir $WDIR/etc/dnsmasq.d
cat > $WDIR/etc/dnsmasq.conf <<EOF
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
cat > $WDIR/tmp/akanda.sh <<EOF
#!/bin/sh -e
export LD_LIBRARY_PATH=/usr/local/lib

ln -sf /usr/local/bin/python2.7 /usr/local/bin/python
ln -sf /usr/local/bin/pip-2.7 /usr/local/bin/pip

cd /tmp/greenlet-0.4.0
python setup.py install
cd /tmp/eventlet-0.9.17
python setup.py install

cd /tmp/akanda-appliance && python setup.py install

EOF

cp -r $HERE/../../akanda-appliance/ $WDIR/tmp

# build eventlet bundle so that we do not need CC on router image
cd $WDIR/tmp
tar -zxf $HERE/src/greenlet-0.4.0.tar.gz
tar -zxf $HERE/src/eventlet-0.9.17.tar.gz
cd greenlet-0.4.0
python setup.py build
cd ../eventlet-0.9.17
python setup.py build
cd $HERE


chmod +x $WDIR/tmp/akanda.sh
chroot $WDIR /tmp/akanda.sh || exit 1
rm $WDIR/tmp/akanda.sh

rm -rf $WDIR/tmp
mkdir $WDIR/tmp


echo "[*] Add rc.d scripts...."
cp $HERE/etc/rc.d/sshd $WDIR/etc/rc.d/sshd
cp $HERE/etc/rc.d/bird $WDIR/etc/rc.d/bird
cp $HERE/etc/rc.d/dnsmasq $WDIR/etc/rc.d/dnsmasq
cp $HERE/etc/rc.d/metadata $WDIR/etc/rc.d/metadata
chmod 555 $WDIR/etc/rc.d/sshd
chmod 555 $WDIR/etc/rc.d/bird
chmod 555 $WDIR/etc/rc.d/dnsmasq
chmod 555 $WDIR/etc/rc.d/metadata

echo "[*] Add rc.conf.local...."
cat > $WDIR/etc/rc.conf.local <<EOF
spamlogd_flags=NO
inetd=NO
amd_master=NO
EOF

echo "[*] Add rc.local file...."
cp $HERE/etc/rc.local $WDIR/etc/rc.local

#echo "[*] Entering Akanda livecd builder (chroot environment)."
#echo "[*] Once you have finished your modifications, type \"exit\""

#    chroot $WDIR

    echo "[*] Deleting sensitive information..."
    cd $WDIR && rm -f root/{.history,.viminfo}
    cd $WDIR && rm -f home/*/{.history,.viminfo}

    echo "[*] Empty log files..."
    for log_file in $(find $WDIR/var/log -type f)
    do
        echo "" > $log_file
    done

    echo "[*] Remove ports and src (only on live cd)..."
    rm -rf $WDIR/usr/{src,ports,xenocara}/*

    echo "[*] Removing ssh host keys..."
    rm -f $WDIR/etc/ssh/*key*

    echo "[*] Saving creation timestamp..."
    date > $WDIR/etc/livecd-release

    echo "[*] Saving default timezone..."
    rm -f $WDIR/etc/localtime
    ln -s /usr/share/zoneinfo/$TZ $WDIR/etc/localtime


    echo "[*] Creating mfs-mount directories..."
    cp -rp $WDIR/var $WDIR/mfsvar
    rm -r $WDIR/var/*
    cp -rp $WDIR/root $WDIR/mfsroot
    cp -rp $WDIR/etc $WDIR/mfsetc
    mkdir $WDIR/mfsdev
    cp -p $WDIR/dev/MAKEDEV $WDIR/mfsdev/
    cd $WDIR/mfsdev && $WDIR/mfsdev/MAKEDEV all

    echo "[*] Creating Akanda live-cd iso..."
    cd /
    mkhybrid -l -R -o $OUTDIR/livecd$MAJ$MIN-$ARCH.iso -b $MAJ.$MIN/$ARCH/cdbr -c $MAJ.$MIN/$ARCH/boot.catalog $WDIR

    echo "[*] Your modified Akanda iso is in $OUTDIR/livecd$MAJ$MIN-$ARCH.iso"
    ls -lh $OUTDIR/livecd$MAJ$MIN-$ARCH.iso

    if [ $CLEANUP="yes" ];then
        echo "[*] Cleanup"
        echo -n "Do you want to delete the working directory $WDIR? (y/N): "
        read deletewdir
        if [ ! -z $deletewdir ]
        then
            if [ $deletewdir = "y" ] || [ $deletewdir = "Y" ] || [ $deletewdir = "yes"] || [ $deletewdir = "Yes" ]
            then
                rm -rf $WDIR
               fi
        fi
    fi

    echo "[*] Please support the OpenBSD project by buying official cd sets or donating some money!"
    echo "[*] Enjoy Akanda!"
    date
    echo "[*] Done."
}

# Evaluate the command line options
while getopts 'A:hM:m:P:S:T:U:uvVW:' OPTION ; do
        case $OPTION in
        A)      ARCH=${OPTARG}
                ;;
    h)      usage $EXIT_ERFOLG
                ;;
    M)      MAJ=${OPTARG}
                ;;
    m)      MIN=${OPTARG}
                ;;
    P)      PACKAGES=${OPTARG}
                ;;
    S)      SETS=${OPTARG}
                ;;
    T)      TZ=${OPTARG}
                ;;
    U)      BASEURL=${OPTARG}
                ;;
    u)      CHMIRROR=y
                ;;
        v)      VERBOSE=y
                ;;
        V)      echo $VERSION
                exit $EXIT_ERROR
                ;;
    W)      WDIR=${OPTARG}
                ;;

        \?)     echo "Unknown option \"-$OPTARG\"." >&2
                usage $EXIT_ERROR
                ;;
        :)      echo "Option \"-$OPTARG\" needs an argument." >&2
                usage $EXIT_ERROR
                ;;
        *)      echo "" >&2
                usage $EXIT_ERROR
                ;;
        esac
done

# Skip already used arguments
shift $(( OPTIND - 1 ))

# Loop over all arguments
for ARG ; do
        if [[ $VERBOSE = y ]] ; then
                echo -n "Argument: "
        fi
        #echo $ARG
done


# Call (main-)function
makedeps
livecd

#
cleanup
exit $EXIT_SUCCESS

