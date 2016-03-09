#!/bin/bash

echo "Are the 3 deb-packages in /ramdisk?"
echo "Is only the 'main.c' in /ramdisk/compilation?"
echo "Is only the empty usb stick connected and mounted in /mnt?"
echo "Did you verify my fingerprint?"

read

cd /ramdisk

echo "Checking checksums of own files"
sha256sum -c <( cat <<EOF
f646a48024388bfe605a5ba2f90ee21f6385f921c9bde623cef520af6730ff30  ./compilation/main.c
dbe9f4e86f1f4a4a99acd1289a2f565fd8d3ee9c1877063b7a35ae3a704de26c  libssl1.0.0_1.0.1f-1ubuntu2.18_amd64.deb
f6c3075d116e86fe7853c73e5e177674aba038dab8d656da1064e20e14a470d7  libssl-dev_1.0.1f-1ubuntu2.18_amd64.deb
d44332327123a4fef16ededcffac98ac0425402f9c2ccc8e42193b122f8a54b8  zlib1g-dev_1.2.8.dfsg-1ubuntu1_amd64.deb
EOF
) || (echo "ERROR, checksums bad" && exit -1)

dpkg -i libssl1.0.0_1.0.1f-1ubuntu2.18_amd64.deb \
	libssl-dev_1.0.1f-1ubuntu2.18_amd64.deb \
	zlib1g-dev_1.2.8.dfsg-1ubuntu1_amd64.deb

cd compilation

openssl genrsa 2048 > signkey.priv
openssl rsa -in signkey.priv -pubout -out signkey.pub

echo "Write down the pubkey fingerprint:"
openssl rsa -pubin -in signkey.pub -pubout -outform der | openssl dgst -sha256
read


cc -c main.c
cc -o main main.o -static -lcrypto -lz -ldl

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
