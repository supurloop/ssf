#!/bin/bash
# Generates every CA, certificate and key the TLS client interop set uses into directory $1,
# fresh for each run (valid 30 days; nothing is kept in the repository).
#   Server side : ca (P-256 CA), rsaca (RSA-2048 CA); leaves for localhost: leaf (P-256),
#                 p384leaf, edleaf (Ed25519), rsaleaf (RSA-2048), rsa4kleaf (RSA-4096).
#   Client side : cca (P-256 CA); clientAuth leaves p256, p384, ed (Ed25519, ECDSA-signed),
#                 rsa2k, rsa4k; cint (intermediate CA) and p256int, with p256chain.pem
#                 (leaf then intermediate).
#   Refused      : v1leaf (X.509 v1), nosanleaf (v3, no subjectAltName).
set -e
D=$1; mkdir -p "$D"; cd "$D"
cat > ca.ext <<X
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
X
cat > srv.ext <<X
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > cli.ext <<X
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
cat > int.ext <<X
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
X
key(){ # name type
  case $2 in
    p256) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $1.key ;;
    p384) openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $1.key ;;
    ed)   openssl genpkey -algorithm ED25519 -out $1.key ;;
    rsa2k) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $1.key ;;
    rsa4k) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $1.key ;;
  esac 2>/dev/null; }
ca(){ # name type cn
  key $1 $2
  openssl req -new -x509 -key $1.key -subj "/CN=$3" -days 30 -sha256 -extensions v3 \
      -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat ca.ext) -out $1.pem; }
leaf(){ # name type cn issuer ext
  key $1 $2
  openssl req -new -key $1.key -subj "/CN=$3" -out $1.csr
  openssl x509 -req -in $1.csr -CA $4.pem -CAkey $4.key -CAcreateserial -days 30 -sha256 \
      -extfile $5 -out $1.pem 2>/dev/null; }
ca ca p256 ssf-interop-ca
ca rsaca rsa2k ssf-interop-rsa-ca
leaf leaf p256 localhost ca srv.ext
leaf p384leaf p384 localhost ca srv.ext
leaf edleaf ed localhost ca srv.ext
leaf rsaleaf rsa2k localhost rsaca srv.ext
leaf rsa4kleaf rsa4k localhost rsaca srv.ext
ca cca p256 ssf-interop-client-ca
leaf p256 p256 ssf-interop-client-p256 cca cli.ext
leaf p384 p384 ssf-interop-client-p384 cca cli.ext
leaf ed ed ssf-interop-client-ed25519 cca cli.ext
leaf rsa2k rsa2k ssf-interop-client-rsa2k cca cli.ext
leaf rsa4k rsa4k ssf-interop-client-rsa4k cca cli.ext
leaf cint p256 ssf-interop-client-int cca int.ext
leaf p256int p256 ssf-interop-client-p256int cint cli.ext
cat p256int.pem cint.pem > p256chain.pem; cp p256int.key p256chain.key
# Server certificates the client must refuse: X.509 v1 (no extensions), and v3 without a
# subjectAltName (the host only in the Common Name)
key v1leaf p256
openssl req -x509 -x509v1 -key v1leaf.key -subj "/CN=localhost" -CA ca.pem -CAkey ca.key -days 30 \
    -sha256 -out v1leaf.pem 2>/dev/null
sed '/^subjectAltName/d' srv.ext > nosan.ext
leaf nosanleaf p256 localhost ca nosan.ext
rm -f *.csr *.srl
