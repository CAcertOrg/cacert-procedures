#!/bin/bash

gcc -g main.c -lcrypto -o tool

if [[ ! -f root.crt ]] ; then
    openssl req -new -newkey rsa:1024 -keyout root.key -subj "/CN=bla" -nodes -out root.csr
    openssl x509 -in root.csr -req -signkey root.key -out root.crt
fi
#valgrind --leak-check=full --show-leak-kinds=all ./tool

./tool
diff <(openssl x509 -in root.crt -noout -text) <(openssl x509 -in root_256.crt -noout -text)
