#!/bin/bash

echo "Are the 3 deb-packages in /ramdisk?"
echo "Is only the 'main.c' in /ramdisk/compilation?"
echo "Is only the empty usb stick connected and mounted in /mnt?"
echo "Did you verify my fingerprint?"

read

cd /ramdisk

echo "Checking checksums of own files"
sha256sum -c <( cat <<EOF
2a1dc4a314c18533135c89aabc1d0dbc4f25f7dee571b38d9e3f767c28699da9  ./compilation/main.c
4ae13e84372caaa40dda23222137c5f058df9b0b800b937e24b34440c5cdf831  libssl-dev_1.0.1e-2+deb7u17_i386.deb
8e1e7c50b274fdddad39d8474207d1e4ce83932572862c635bc8080eacee5f88  libssl1.0.0_1.0.1e-2+deb7u17_i386.deb
ad8c7ffc81c9e01b56cf9c8cddf38aa0e5383e2045a85ed68e936aae642c6340  zlib1g-dev_1.2.7.dfsg-13_i386.deb
EOF
) || (echo "ERROR, checksums bad" && exit -1)

dpkg -i libssl1.0.0_1.0.1e-2+deb7u17_i386.deb libssl-dev_1.0.1e-2+deb7u17_i386.deb zlib1g-dev_1.2.7.dfsg-13_i386.deb

cd compilation

openssl genrsa 2048 > signkey.priv
openssl rsa -in signkey.priv -pubout -out signkey.pub

echo "Write down the pubkey fingerprint:"
openssl rsa -pubin -in signkey.pub -pubout -outform der | openssl dgst -sha256
read


cc -c main.c
cc main.o -lssl -o main

sha256sum main main.o main.c > checksums
openssl dgst -sha256 checksums > checksums.hash
openssl rsautl -sign -inkey signkey.priv -in checksums.hash > signature

cp checksums checksums.hash signature signkey.pub main main.c main.o /mnt
rm signkey.priv

echo "================================"
echo "things left to do:"
echo "cp typescript timelog /mnt"
echo "ls -Al /mnt"
echo "umount /mnt"
