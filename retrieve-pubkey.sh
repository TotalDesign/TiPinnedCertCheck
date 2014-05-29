#!/bin/sh
#
# usage: retrieve-pubkey.sh
#
for f in *.pem
do
  openssl x509 -noout -pubkey -in "$f" > "`basename $f .pem`-pubkey.pem"
done
