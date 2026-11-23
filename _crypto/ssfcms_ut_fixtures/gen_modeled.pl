#!/usr/bin/perl
# Builds a CMS detached signature modeled on a production firmware signature: a root that is not
# embedded, two CA levels with ADCS-style 19-byte serials, Certificate Policies, CRL and AIA
# pointers and GeneralizedTime expiry in 2075, a leaf with a 20-byte serial and a CN-first subject,
# signed attributes carrying CMSAlgorithmProtection, and an RFC 3161 timestamp token in the
# unsigned attributes. OpenSSL makes every key, certificate, signature and token; this script only
# assembles DER around them. Identities are SSF test names.
use strict;
use warnings;
use Digest::SHA qw(sha256);

$ENV{MSYS_NO_PATHCONV} = 1;
my $out = "modeled" . ($ENV{SSF_CMS_FIX_SUFFIX} // "");
my $curve = $ENV{SSF_CMS_FIX_CURVE} // "prime256v1";
system("rm -rf $out") == 0 or die;
mkdir $out or die; chdir $out or die;
mkdir "cadb"; mkdir "cadb/newcerts"; open(my $ix, ">", "cadb/index.txt") or die; close $ix;
mkdir "tsa";

sub run { my $c = shift; print "+ $c\n"; system($c) == 0 or die "failed: $c\n"; }
sub slurp { my $f = shift; open(my $h, "<:raw", $f) or die "$f: $!"; local $/; my $d = <$h>; close $h; $d }
sub spit { my ($f, $d) = @_; open(my $h, ">:raw", $f) or die "$f: $!"; print $h $d; close $h }

# ---- configuration for openssl ca, req and ts ----
spit("ca.cnf", <<'EOF');
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./cadb
database = $dir/index.txt
new_certs_dir = $dir/newcerts
serial = $dir/serial
default_md = sha256
policy = policy_any
unique_subject = no
email_in_dn = no
copy_extensions = none
default_days = 3650
[ policy_any ]
organizationName = optional
organizationalUnitName = optional
commonName = optional
serialNumber = optional
[ req ]
distinguished_name = dn
string_mask = pkix
[ dn ]
[ ca_ext ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ fsca_ext ]
keyUsage = critical, keyCertSign, cRLSign
certificatePolicies = 2.5.29.32.0
basicConstraints = critical, CA:TRUE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://pki.ssf.test/SSFTestRootCA.crl
authorityInfoAccess = caIssuers;URI:http://pki.ssf.test/SSFTestRootCA.cer
[ fm_ext ]
keyUsage = critical, keyCertSign, cRLSign
certificatePolicies = 2.5.29.32.0
basicConstraints = critical, CA:TRUE, pathlen:0
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
crlDistributionPoints = URI:http://pki.ssf.test/SSFFirmwareSigningCA.crl
authorityInfoAccess = caIssuers;URI:http://pki.ssf.test/SSFFirmwareSigningCA.cer
[ leaf_ext ]
basicConstraints = critical, CA:FALSE
authorityKeyIdentifier = keyid
authorityInfoAccess = caIssuers;URI:http://pki.ssf.test/SSFFirmwareMaster.cer
certificatePolicies = 1.3.6.1.4.1.99999.1.1
crlDistributionPoints = URI:http://pki.ssf.test/SSFFirmwareMaster.crl
subjectKeyIdentifier = hash
keyUsage = critical, digitalSignature
[ tsa_ext ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, nonRepudiation
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
spit("req_utf8.cnf", "[ req ]\ndistinguished_name = dn\nstring_mask = utf8only\n[ dn ]\n");
spit("tsa.cnf", <<'EOF');
[ tsa ]
default_tsa = tsa_config1
[ tsa_config1 ]
dir = ./tsa
serial = $dir/tsaserial
signer_cert = $dir/tsa.pem
certs = $dir/tsa.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.2.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
EOF

# ---- the signing chain: root (not embedded) -> Firmware Signing CA -> Firmware Master -> leaf ----
run("openssl ecparam -name $curve -genkey -noout -out root.key");
run("openssl req -new -x509 -key root.key -days 20000 -subj \"/O=SSF Test/CN=SSF Test Root CA\" " .
    "-set_serial 0x3300000001 -extensions ca_ext -config ca.cnf -sha256 -out root.pem");

run("openssl ecparam -name $curve -genkey -noout -out fsca.key");
run("openssl req -new -key fsca.key -subj \"/O=SSF Test/CN=SSF Firmware Signing CA\" -config ca.cnf -out fsca.csr");
spit("cadb/serial", "3300000003A1B2C3D4E5F60718293A4B5C0003\n");
run("openssl ca -config ca.cnf -cert root.pem -keyfile root.key -in fsca.csr -out fsca.pem -extensions fsca_ext " .
    "-startdate 20150519093553Z -enddate 20750519091650Z -batch -notext -preserveDN");

run("openssl ecparam -name $curve -genkey -noout -out fm.key");
run("openssl req -new -key fm.key -subj \"/O=SSF Test/OU=Firmware Master/CN=SSF Firmware Master\" -config ca.cnf -out fm.csr");
spit("cadb/serial", "3300000010B1C2D3E4F506172839404B5C0010\n");
run("openssl ca -config ca.cnf -cert fsca.pem -keyfile fsca.key -in fm.csr -out fm.pem -extensions fm_ext " .
    "-startdate 20180228090904Z -enddate 20750519091650Z -batch -notext -preserveDN");

run("openssl ecparam -name $curve -genkey -noout -out leaf.key");
run("openssl req -new -key leaf.key -subj \"/CN=SSF Firmware Signature/serialNumber=1/OU=Firmware Signature/O=SSF Test\" " .
    "-config req_utf8.cnf -out leaf.csr");
spit("cadb/serial", "4A1F014CBC7A6862FC4CB46897FB27C1DA599028\n");
run("openssl ca -config ca.cnf -cert fm.pem -keyfile fm.key -in leaf.csr -out leaf.pem -extensions leaf_ext " .
    "-startdate 20261015073703Z -enddate 20561007073702Z -batch -notext -preserveDN");

# ---- a separate timestamp authority ----
run("openssl ecparam -name $curve -genkey -noout -out tsaroot.key");
run("openssl req -new -x509 -key tsaroot.key -days 20000 -subj \"/O=SSF Test/CN=SSF Test Timestamp CA\" " .
    "-set_serial 0x3300000002 -extensions ca_ext -config ca.cnf -sha256 -out tsaroot.pem");
run("openssl ecparam -name $curve -genkey -noout -out tsa/tsa.key");
run("openssl req -new -key tsa/tsa.key -subj \"/O=SSF Test/OU=Timestamping/CN=SSF Test TSA\" -config ca.cnf -out tsa.csr");
spit("cadb/serial", "3300000003AD0A076D2BC0B24C00000000000A\n");
run("openssl ca -config ca.cnf -cert tsaroot.pem -keyfile tsaroot.key -in tsa.csr -out tsa/tsa.pem -extensions tsa_ext " .
    "-startdate 20150519110156Z -enddate 20450519110156Z -batch -notext -preserveDN");
spit("tsa/tsaserial", "01\n");

for my $n (qw(root fsca fm leaf)) { run("openssl x509 -in $n.pem -outform DER -out $n.der"); }

# ---- content: a 1 KB pseudo-random firmware image ----
run("openssl rand -out fw.bin 1024");
my $fw = slurp("fw.bin");
my $md = sha256($fw);

# ---- DER helpers ----
sub tlv { my ($tag, $c) = @_; my $l = length $c;
    my $len = $l < 128 ? chr($l) : $l < 256 ? "\x81" . chr($l) : "\x82" . pack("n", $l);
    return chr($tag) . $len . $c }
sub oid { tlv(0x06, pack("H*", shift)) }
my $OID_SHA256   = "608648016503040201";
my $OID_ECDSA256 = "2A8648CE3D040302";
my $OID_DATA     = "2A864886F70D010701";
my $OID_SIGNED   = "2A864886F70D010702";
my $OID_CT       = "2A864886F70D010903";
my $OID_MD       = "2A864886F70D010904";
my $OID_ST       = "2A864886F70D010905";
my $OID_AP       = "2A864886F70D010934";
my $OID_TST      = "2A864886F70D010910020E";

# Minimal DER reader for pulling the issuer Name and serial out of the leaf certificate
sub rd { my ($d, $p) = @_; my $tag = ord(substr($d, $p, 1)); my $l = ord(substr($d, $p + 1, 1)); my $h = 2;
    if ($l >= 0x80) { my $n = $l & 0x7F; $l = 0; $l = ($l << 8) | ord(substr($d, $p + 1 + $_, 1)) for 1 .. $n; $h = 2 + $n }
    return ($tag, $h, $l) }
my $leaf = slurp("leaf.der");
my ($t, $h, $l) = rd($leaf, 0);            my $p = $h;              # Certificate SEQUENCE
($t, $h, $l) = rd($leaf, $p);              $p += $h;                # TBSCertificate
($t, $h, $l) = rd($leaf, $p);              $p += $h + $l;           # [0] version
($t, $h, $l) = rd($leaf, $p);              my $serialTlv = substr($leaf, $p, $h + $l); $p += $h + $l;
($t, $h, $l) = rd($leaf, $p);              $p += $h + $l;           # signature AlgorithmIdentifier
($t, $h, $l) = rd($leaf, $p);              my $issuerTlv = substr($leaf, $p, $h + $l);

# ---- signed attributes in DER SET OF order ----
my @attrs = (
    tlv(0x30, oid($OID_CT) . tlv(0x31, oid($OID_DATA))),
    tlv(0x30, oid($OID_ST) . tlv(0x31, tlv(0x17, "261117094351Z"))),
    tlv(0x30, oid($OID_AP) . tlv(0x31, tlv(0x30, tlv(0x30, oid($OID_SHA256) . "\x05\x00") .
                                                   tlv(0xA1, oid($OID_ECDSA256))))),
    tlv(0x30, oid($OID_MD) . tlv(0x31, tlv(0x04, $md))),
);
my $attrsContent = join("", sort @attrs);
spit("attrs_set.der", tlv(0x31, $attrsContent));

# ---- signature over the SET form, then a timestamp token over the signature ----
run("openssl pkeyutl -sign -inkey leaf.key -rawin -digest sha256 -in attrs_set.der -out sig.der");
my $sig = slurp("sig.der");
run("openssl ts -query -data sig.der -sha256 -no_nonce -cert -out sig.tsq");
run("openssl ts -reply -config tsa.cnf -queryfile sig.tsq -token_out -out token.der");
my $token = slurp("token.der");

# ---- SignerInfo, SignedData, ContentInfo ----
my $si = tlv(0x30,
    tlv(0x02, "\x01") .
    tlv(0x30, $issuerTlv . $serialTlv) .
    tlv(0x30, oid($OID_SHA256) . "\x05\x00") .
    tlv(0xA0, $attrsContent) .
    tlv(0x30, oid($OID_ECDSA256)) .
    tlv(0x04, $sig) .
    tlv(0xA1, tlv(0x30, oid($OID_TST) . tlv(0x31, $token))));
my $sd = tlv(0x30,
    tlv(0x02, "\x01") .
    tlv(0x31, tlv(0x30, oid($OID_SHA256))) .
    tlv(0x30, oid($OID_DATA)) .
    tlv(0xA0, slurp("fsca.der") . slurp("fm.der") . $leaf) .
    tlv(0x31, $si));
my $ci = tlv(0x30, oid($OID_SIGNED) . tlv(0xA0, $sd));
spit("modeled.der", $ci);
printf "modeled.der: %d bytes, token %d bytes, sig %d bytes\n", length $ci, length $token, length $sig;

# ---- independent check: OpenSSL verifies the assembled message against the root ----
run("openssl cms -verify -inform DER -in modeled.der -content fw.bin -binary -CAfile root.pem -purpose any -out verified.bin");
slurp("verified.bin") eq $fw or die "verified content differs from fw.bin\n";
print "openssl cms -verify: OK\n";
