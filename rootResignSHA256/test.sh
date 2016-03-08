#!/bin/bash

gcc -g main.c -lcrypto -o tool

if [[ ! -f root.crt ]] ; then
    openssl req -new -newkey rsa:1024 -keyout root.key -subj "/CN=bla" -nodes -out root.csr
    openssl x509 -in root.csr -req -signkey root.key -out root.crt -set_serial 0 -extfile <(
        echo "subjectKeyIdentifier=hash"
        echo "authorityKeyIdentifier=keyid:always,issuer:always"
    )

    openssl req -new -newkey rsa:1024 -keyout class3.key -subj "/CN=class3" -nodes -out class3.csr
    openssl x509 -in class3.csr -req -CA root.crt -CAkey root.key -out class3.crt -set_serial 3 -extfile <(
        echo "subjectKeyIdentifier=hash"
        echo "authorityKeyIdentifier=keyid:always,issuer:always"
    )
fi
#valgrind --leak-check=full --show-leak-kinds=all ./tool

./tool

diff <(openssl x509 -in root.crt -noout -text) <(openssl x509 -in root_256.crt -noout -text)
echo "diffs of Class3:"
diff <(openssl x509 -in class3.crt -noout -text) <(openssl x509 -in class3_256.crt -noout -text)
