#!/bin/sh
# Generates CMS SignedData fixtures for the ssfcms unit test with OpenSSL 3.x.
# Every output is DER with definite lengths (-noindef). Content is a fixed 24-byte file.
set -e
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL="*"
cd "$(dirname "$0")"
# SSF_CMS_FIX_CURVE picks the ECDSA curve (default prime256v1), SSF_CMS_FIX_SUFFIX the output
# directory suffix (default none: ./out); toc.sh takes the same suffix.
CURVE=${SSF_CMS_FIX_CURVE:-prime256v1}
OUT=out${SSF_CMS_FIX_SUFFIX:-}
rm -rf "$OUT" && mkdir "$OUT" && cd "$OUT"

printf 'SSF CMS fixture content\n' > content.bin

cat > ca.cnf <<EOF
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

[leaf_cs_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

# ---- ECDSA P-256 three-level chain: root -> intermediate -> signer ----
openssl ecparam -name "$CURVE" -genkey -noout -out root.key
openssl req -new -x509 -key root.key -days 7300 -subj "/O=SSF Test/CN=SSF Test Root CA" \
    -extensions ca_ext -config ca.cnf -sha256 -out root.pem
openssl ecparam -name "$CURVE" -genkey -noout -out int.key
openssl req -new -key int.key -subj "/O=SSF Test/CN=SSF Test Signing CA" -out int.csr
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -set_serial 2 -days 7300 -sha256 \
    -extfile ca.cnf -extensions int_ext -out int.pem
openssl ecparam -name "$CURVE" -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj "/O=SSF Test/OU=Firmware/CN=SSF Test Signer" -out leaf.csr
openssl x509 -req -in leaf.csr -CA int.pem -CAkey int.key -set_serial 3 -days 7300 -sha256 \
    -extfile ca.cnf -extensions leaf_ext -out leaf.pem

# Detached, intermediate included, default attributes
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer leaf.pem -inkey leaf.key \
    -certfile int.pem -md sha256 -out ecdsa_chain_detached.der

# ---- RSA-2048 self-signed signer, PKCS#1 v1.5 (rsaEncryption as signatureAlgorithm) ----
openssl req -new -x509 -newkey rsa:2048 -noenc -keyout rsa.key -days 7300 \
    -subj "/O=SSF Test/CN=SSF RSA Signer" -extensions leaf_ext -config ca.cnf -sha256 -out rsa.pem
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer rsa.pem -inkey rsa.key \
    -md sha256 -out rsa_pkcs1_detached.der

# ---- RSA-PSS signature with the same key ----
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer rsa.pem -inkey rsa.key \
    -md sha256 -keyopt rsa_padding_mode:pss -out rsa_pss_detached.der

# ---- Ed25519 self-signed signer ----
openssl req -new -x509 -newkey ed25519 -noenc -keyout ed.key -days 7300 \
    -subj "/O=SSF Test/CN=SSF Ed25519 Signer" -extensions leaf_ext -config ca.cnf -out ed.pem
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer ed.pem -inkey ed.key \
    -out ed25519_detached.der || echo "ed25519 cms sign unsupported"

# ---- SKID signer identifier (SignerInfo v3) with attached content ----
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer leaf.pem -inkey leaf.key \
    -certfile int.pem -md sha256 -keyid -nodetach -out ecdsa_skid_attached.der

# ---- Two signers: ECDSA chain signer and RSA signer ----
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer leaf.pem -inkey leaf.key \
    -certfile int.pem -signer rsa.pem -inkey rsa.key -md sha256 -out two_signers_detached.der

# ---- Code-signing EKU signer with a P-384 key under the same intermediate ----
openssl ecparam -name secp384r1 -genkey -noout -out cs.key
openssl req -new -key cs.key -subj "/O=SSF Test/OU=Firmware/CN=SSF Code Signer" -out cs.csr
openssl x509 -req -in cs.csr -CA int.pem -CAkey int.key -set_serial 4 -days 7300 -sha256 \
    -extfile ca.cnf -extensions leaf_cs_ext -out cs.pem
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer cs.pem -inkey cs.key \
    -certfile int.pem -md sha384 -out ecdsa_cs_sha384_detached.der

# ---- RSA-2048 signer issued by the P-256 intermediate: an RSA leaf on an ECDSA chain ----
openssl req -new -newkey rsa:2048 -noenc -keyout rsaleaf.key \
    -subj "/O=SSF Test/OU=Firmware/CN=SSF RSA Chain Signer" -out rsaleaf.csr
openssl x509 -req -in rsaleaf.csr -CA int.pem -CAkey int.key -set_serial 5 -days 7300 -sha256 \
    -extfile ca.cnf -extensions leaf_ext -out rsaleaf.pem
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer rsaleaf.pem \
    -inkey rsaleaf.key -certfile int.pem -md sha256 -out rsa_chain_detached.der

# ---- No signed attributes (signature directly over content), attached ----
openssl cms -sign -binary -noindef -outform DER -in content.bin -signer leaf.pem -inkey leaf.key \
    -md sha256 -noattr -nodetach -out ecdsa_noattr_attached.der

# ---- BER streaming form of the first fixture, for the documented rejection ----
openssl cms -sign -binary -outform DER -in content.bin -signer leaf.pem -inkey leaf.key \
    -certfile int.pem -md sha256 -stream -out ecdsa_chain_detached_ber.der

# DER trust anchors and a wrong anchor
openssl x509 -in root.pem -outform DER -out root.der
openssl x509 -in int.pem -outform DER -out int.der
openssl x509 -in rsa.pem -outform DER -out rsa.der
openssl x509 -in ed.pem -outform DER -out ed.der
openssl ecparam -name "$CURVE" -genkey -noout -out other.key
openssl req -new -x509 -key other.key -days 7300 -subj "/O=Other/CN=Other Root CA" \
    -extensions ca_ext -config ca.cnf -sha256 -out other.pem
openssl x509 -in other.pem -outform DER -out other.der

ls -l *.der content.bin
