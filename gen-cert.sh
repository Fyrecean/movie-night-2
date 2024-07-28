#!/bin/sh

#Make the CA
openssl genrsa -des3 - out myCA.key 2048
openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem
#Make the website Cert
openssl genrsa -out local localhost.key 2048
openssl req -new -key localhost.key -out localhost.csr
touch localhost.ext
echo "authorityKeyIdentifier=keyid,issuer" >> localhost.ext
echo "basicConstraints=CA:FALSE" >> localhost.ext
echo "keyUsage=digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment,subjectAltName = @alt_names" >> localhost.ext

echo "[alt_names]" >> localhost.ext
echo "DNS.1 = localhost" >> localhost.ext

openssl x509 -req -in localhost.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out localhost.crt -days 1825 -sha256 -extfile localhost.ext
