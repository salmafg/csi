#!/bin/bash

source setup_env.sh
make
cd patches/bcm4339/6_37_34_43/nexmon/
make
make backup-firmware
make install-firmware
cd ../nexmon_csi/
make
make backup-firmware
make install-firmware
pkill wpa_supplicant
ifconfig wlan0 up
iw phy `iw dev wlan0 info | gawk '/wiphy/ {printf "phy" $2}'` interface add mon0 type monitor
ifconfig mon0 up
