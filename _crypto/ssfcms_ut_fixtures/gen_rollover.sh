#!/bin/sh
# Generates the CA key-rollover CMS fixtures (AUDIT CMS-4) with OpenSSL 3.x into ./rollover.
# Two intermediates share the subject "SSF Rollover CA" with different keys; the signer is issued
# by the new one. OpenSSL sorts the DER SET OF certificates, so this regenerates until the old
# intermediate is encoded first (the order that defeats a first-name-match chain builder).
set -e
cd "$(dirname "$0")"
CURVE=${SSF_CMS_FIX_CURVE:-prime256v1}
OUT=rollover${SSF_CMS_FIX_SUFFIX:-}
rm -rf "$OUT" && mkdir "$OUT" && cd "$OUT"
printf 'SSF CMS fixture content\n' > content.bin

cat > ca.cnf <<CNF
[ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[int_ext]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[int_nokid]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = none
authorityKeyIdentifier = none
[leaf_nokid]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = none
authorityKeyIdentifier = none
CNF

openssl ecparam -name "$CURVE" -genkey -noout -out root.key
openssl req -new -x509 -key root.key -days 7300 -subj "/O=SSF Test/CN=SSF Rollover Root" \
    -extensions ca_ext -config ca.cnf -sha256 -out root.pem
openssl x509 -in root.pem -outform DER -out root.der

# $1 = suffix, $2 = int extension section, $3 = leaf extension section
make_set() {
    sfx=$1; iext=$2; lext=$3
    while :; do
        for which in old new; do
            openssl ecparam -name "$CURVE" -genkey -noout -out int_${which}${sfx}.key
            openssl req -new -key int_${which}${sfx}.key -subj "/O=SSF Test/CN=SSF Rollover CA" \
                -out int_${which}${sfx}.csr
        done
        openssl x509 -req -in int_old${sfx}.csr -CA root.pem -CAkey root.key -set_serial 2 \
            -days 7300 -sha256 -extfile ca.cnf -extensions ${iext} -out int_old${sfx}.pem
        openssl x509 -req -in int_new${sfx}.csr -CA root.pem -CAkey root.key -set_serial 3 \
            -days 7300 -sha256 -extfile ca.cnf -extensions ${iext} -out int_new${sfx}.pem
        openssl ecparam -name "$CURVE" -genkey -noout -out leaf${sfx}.key
        openssl req -new -key leaf${sfx}.key -subj "/O=SSF Test/CN=SSF Rollover Signer" \
            -out leaf${sfx}.csr
        openssl x509 -req -in leaf${sfx}.csr -CA int_new${sfx}.pem -CAkey int_new${sfx}.key \
            -set_serial 4 -days 7300 -sha256 -extfile ca.cnf -extensions ${lext} \
            -out leaf${sfx}.pem
        cat int_old${sfx}.pem int_new${sfx}.pem > both${sfx}.pem
        openssl cms -sign -binary -noindef -outform DER -in content.bin -signer leaf${sfx}.pem \
            -inkey leaf${sfx}.key -certfile both${sfx}.pem -md sha256 -out both${sfx}.der
        openssl x509 -in int_old${sfx}.pem -outform DER -out int_old${sfx}.der
        openssl x509 -in int_new${sfx}.pem -outform DER -out int_new${sfx}.der
        # Old intermediate encoded before the new one in the certificates SET?
        if python3 -I - both${sfx}.der int_old${sfx}.der int_new${sfx}.der <<'PY'
import sys
m = open(sys.argv[1], 'rb').read()
o = m.find(open(sys.argv[2], 'rb').read())
n = m.find(open(sys.argv[3], 'rb').read())
sys.exit(0 if (0 <= o < n) else 1)
PY
        then break; fi
    done
    openssl cms -sign -binary -noindef -outform DER -in content.bin -signer leaf${sfx}.pem \
        -inkey leaf${sfx}.key -certfile int_old${sfx}.pem -md sha256 -out oldonly${sfx}.der
}

make_set "" int_ext leaf_ext
make_set _nokid int_nokid leaf_nokid

# Cross-check: OpenSSL itself builds the chain through the new intermediate.
openssl cms -verify -binary -inform DER -in both.der -content content.bin -CAfile root.pem \
    -purpose any -out /dev/null
ls -l *.der
