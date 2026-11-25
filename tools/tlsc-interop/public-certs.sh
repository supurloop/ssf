#!/bin/bash
# Fetches the test.mosquitto.org CA and requests client certificates for port 8884 into .cache
# (git-ignored): a P-256 and an RSA-2048 key, generated here, with placeholder subjects only.
# Certificates are reused until within 7 days of expiry (test.mosquitto.org issues them for 90).
set -e
HERE=$(cd "$(dirname "$0")" && pwd); C="$HERE/.cache"; mkdir -p "$C"; cd "$C"
if [ ! -s mosquitto.org.crt ]; then
  curl -sS -m 30 -o mosquitto.org.crt.new https://test.mosquitto.org/ssl/mosquitto.org.crt
  openssl x509 -in mosquitto.org.crt.new -noout -subject | grep -q "CN=mosquitto.org" || { echo "unexpected CA"; exit 1; }
  mv mosquitto.org.crt.new mosquitto.org.crt
fi
for k in p256 rsa2k; do
  if [ -s $k.crt ] && openssl x509 -in $k.crt -noout -checkend $((7 * 86400)) > /dev/null; then continue; fi
  if [ ! -s $k.key ]; then
    if [ $k = p256 ]; then openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $k.key 2>/dev/null
    else openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $k.key 2>/dev/null; fi
  fi
  openssl req -new -key $k.key -subj "/C=XX/O=SSF Test/CN=ssf-tlsc-interop-$k" -out $k.csr
  curl -sS -m 60 -o $k.crt.new --form-string "csr=$(cat $k.csr)" https://test.mosquitto.org/ssl/index.php
  openssl verify -CAfile mosquitto.org.crt $k.crt.new > /dev/null || { echo "$k: issued certificate does not verify"; exit 1; }
  [ "$(openssl x509 -in $k.crt.new -noout -pubkey)" = "$(openssl pkey -in $k.key -pubout)" ] || { echo "$k: key mismatch"; exit 1; }
  mv $k.crt.new $k.crt; rm -f $k.csr
  echo "test.mosquitto.org client certificate $k: $(openssl x509 -in $k.crt -noout -enddate)"
done
