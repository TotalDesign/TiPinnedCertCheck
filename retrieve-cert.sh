#!/bin/sh
#
# usage: retrieve-cert.sh remote.host.name [port]
#
REMHOST=$1
REMPORT=${2:-443}

echo |\
openssl s_client -showcerts -connect ${REMHOST}:${REMPORT} 2>&1 |\
sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' |\
awk '/BEGIN CERTIFICATE/{x="cert"++i".pem";}{print > x;}'

for f in *.pem
do
  newf=$(echo |\
    openssl x509 -noout -subject -in $f |\
    sed -ne 's/^.*CN=//p' |\
    sed -e 's/[^a-zA-Z0-9\-_ ]//g' |\
    tr ' A-Z' '-a-z')

  mv "$f" "$newf.pem"
done
