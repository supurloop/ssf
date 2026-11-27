#!/bin/sh
# Crypto configuration matrix on Linux / macOS: build the tree under each configuration below
# and confirm it builds warning-free and that the RSA/EC-dependent unit tests pass.
#
# One feature option off at a time (switches run.sh in this directory does not cover):
#
#   pkcs1off     SSF_RSA_CONFIG_ENABLE_PKCS1_V15 0
#   pssoff       SSF_RSA_CONFIG_ENABLE_PSS 0
#   keygenoff    SSF_RSA_CONFIG_ENABLE_KEYGEN 0
#   p256off      SSF_EC_CONFIG_ENABLE_P256 0
#   p384off      SSF_EC_CONFIG_ENABLE_P384 0
#   signoff      SSF_ECDSA_CONFIG_ENABLE_SIGN 0
#   fb256off     SSF_EC_CONFIG_FIXED_BASE_P256 0
#   fb384off     SSF_EC_CONFIG_FIXED_BASE_P384 0
#
# JSON parser limits (ssfjson), raised from their defaults:
#
#   json4k       SSF_JSON_CONFIG_MAX_IN_LEN 4095 (what ssfawsprov needs)
#   jsonbig      SSF_JSON_CONFIG_MAX_IN_LEN 65534
#   jsondepth8   SSF_JSON_CONFIG_MAX_IN_DEPTH 8
#
# MQTT client string limits (ssfmqttc), these rows also run the ssfmqttc / ssfmqttpkt tests:
#
#   mqttcsmall   the pre-AWSPROV-G05 defaults: client id, host, user name, password 64; topic 128
#   mqttcbig     client id, topic, user name 65536; password 65535 (the protocol maximums;
#                no inbound topic is too long, so the too-long-topic tests are skipped)
#   mqttctopic64k topic 65535, the largest at which an inbound topic can still be too long
#
# The curve / RSA-size combinations and crypto profiles of run.sh (which needs MSBuild on
# Windows and runs the full suite), here with the targeted tests:
#
#   ecc-both     RSA 2048 / 3072 / 4096 all off
#   ecc-p256     RSA all off, P-384 off
#   ecc-p384     RSA all off, P-256 off
#   rsa2048      RSA 3072 and 4096 off          rsa3072   2048 and 4096 off
#   rsa4096      RSA 2048 and 3072 off          embmin    RSA-2048 and P-256 only
#   prof-min     SSF_CRYPT_CONFIG_PROFILE SSF_CRYPT_PROFILE_MIN_MEMORY
#   prof-max     SSF_CRYPT_CONFIG_PROFILE SSF_CRYPT_PROFILE_MAX_PERF
#
# Each variant is exported from the working tree (including uncommitted edits and new
# untracked files) into its own directory under build-cov/variants/, so the working tree is
# never modified. Only the RSA/EC-dependent and JSON unit tests run (and the MQTT tests in the
# mqttc rows), one process each, so a full sweep takes a few minutes on a multi-core host.
#
# Usage:  ./tools/config-matrix/features.sh [variant ...]   (default: all)
#
# Exit:   0 if every selected variant builds with no errors or warnings and every test
#         passes; 1 otherwise. Per-variant logs: build-cov/variants/<variant>/.

set -u

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
R=$(cd -- "$script_dir/../.." && pwd)
V=$R/build-cov/variants
TESTS="SSFRSAUnitTest SSFECUnitTest SSFECDSAUnitTest SSFX509UnitTest SSFCMSUnitTest SSFTLSUnitTest SSFPKeyUnitTest SSFTLSCUnitTest SSFJsonUnitTest SSFGObjUnitTest"
MQTTC_TESTS="SSFMQTTPktUnitTest SSFMQTTCUnitTest"

case "$(uname -s)" in
    Linux)  ninja_file=build-linux.ninja ;;
    Darwin) ninja_file=build.ninja ;;
    *)      echo "[features] unsupported host: $(uname -s)" >&2; exit 65 ;;
esac

# name|MACRO=value ... (each MACRO's #define in its _opt header is rewritten to the value)
RSA_OFF="SSF_RSA_CONFIG_ENABLE_2048=0 SSF_RSA_CONFIG_ENABLE_3072=0 SSF_RSA_CONFIG_ENABLE_4096=0"
VARIANTS="
pkcs1off|SSF_RSA_CONFIG_ENABLE_PKCS1_V15=0
pssoff|SSF_RSA_CONFIG_ENABLE_PSS=0
keygenoff|SSF_RSA_CONFIG_ENABLE_KEYGEN=0
p256off|SSF_EC_CONFIG_ENABLE_P256=0
p384off|SSF_EC_CONFIG_ENABLE_P384=0
signoff|SSF_ECDSA_CONFIG_ENABLE_SIGN=0
fb256off|SSF_EC_CONFIG_FIXED_BASE_P256=0
fb384off|SSF_EC_CONFIG_FIXED_BASE_P384=0
json4k|SSF_JSON_CONFIG_MAX_IN_LEN=4095
jsonbig|SSF_JSON_CONFIG_MAX_IN_LEN=65534
jsondepth8|SSF_JSON_CONFIG_MAX_IN_DEPTH=8
mqttcsmall|SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE=64 SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE=128 SSF_MQTTC_CONFIG_MAX_HOST_SIZE=64 SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE=64 SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN=64
mqttctopic64k|SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE=65535
mqttcbig|SSF_MQTTC_CONFIG_MAX_CLIENT_ID_SIZE=65536 SSF_MQTTC_CONFIG_MAX_TOPIC_SIZE=65536 SSF_MQTTC_CONFIG_MAX_USERNAME_SIZE=65536 SSF_MQTTC_CONFIG_MAX_PASSWORD_LEN=65535
ecc-both|$RSA_OFF
ecc-p256|$RSA_OFF SSF_EC_CONFIG_ENABLE_P384=0
ecc-p384|$RSA_OFF SSF_EC_CONFIG_ENABLE_P256=0
rsa2048|SSF_RSA_CONFIG_ENABLE_3072=0 SSF_RSA_CONFIG_ENABLE_4096=0
rsa3072|SSF_RSA_CONFIG_ENABLE_2048=0 SSF_RSA_CONFIG_ENABLE_4096=0
rsa4096|SSF_RSA_CONFIG_ENABLE_2048=0 SSF_RSA_CONFIG_ENABLE_3072=0
embmin|SSF_RSA_CONFIG_ENABLE_3072=0 SSF_RSA_CONFIG_ENABLE_4096=0 SSF_EC_CONFIG_ENABLE_P384=0
prof-min|SSF_CRYPT_CONFIG_PROFILE=SSF_CRYPT_PROFILE_MIN_MEMORY
prof-max|SSF_CRYPT_CONFIG_PROFILE=SSF_CRYPT_PROFILE_MAX_PERF
"

# Header that holds a macro's #define, from its prefix
_opt_header() {
    case "$1" in
        SSF_RSA_CONFIG_*)   echo _opt/ssfrsa_opt.h ;;
        SSF_ECDSA_CONFIG_*) echo _opt/ssfecdsa_opt.h ;;
        SSF_EC_CONFIG_*)    echo _opt/ssfec_opt.h ;;
        SSF_CRYPT_CONFIG_*) echo _opt/ssfcrypt_opt.h ;;
        SSF_JSON_CONFIG_*)  echo _opt/ssfjson_opt.h ;;
        SSF_MQTTC_CONFIG_*) echo _opt/ssfmqttc_opt.h ;;
        *)                  echo "" ;;
    esac
}

want="$*"
fail=0
# Working tree as a commit object, without touching the index or stash list (HEAD if clean)
tree=$(cd "$R" && git stash create)
[ -n "$tree" ] || tree=HEAD

for name in $(echo "$VARIANTS" | cut -d'|' -f1); do
    edits=$(echo "$VARIANTS" | grep "^$name|" | cut -d'|' -f2-)
    if [ -n "$want" ]; then case " $want " in *" $name "*) ;; *) continue ;; esac; fi
    d=$V/$name
    rm -rf -- "$d"
    mkdir -p "$d"
    (cd "$R" && git archive "$tree") | tar -x -C "$d"
    (cd "$R" && git ls-files --others --exclude-standard -z | xargs -0 -r cp --parents -t "$d")
    bad=""
    for kv in $edits; do
        mac=${kv%%=*}; val=${kv#*=}
        case "$val" in [0-9]*) val="(${val}u)" ;; esac
        hdr=$(_opt_header "$mac")
        if [ -z "$hdr" ] || ! grep -q "^#define $mac " "$d/$hdr"; then bad="$bad $mac"; continue; fi
        sed -i.bak "s/^#define $mac .*/#define $mac $val/" "$d/$hdr" && rm -f "$d/$hdr.bak"
        grep -q "^#define $mac $val\$" "$d/$hdr" || bad="$bad $mac"
    done
    if [ -n "$bad" ]; then
        echo "[$name] option edit did not apply:$bad"; fail=1; continue
    fi
    (cd "$d" && ninja -f "$ninja_file" -k 0 > build.log 2>&1)
    errs=$(grep -c ' error: ' "$d/build.log")
    warns=$(grep -c ' warning: ' "$d/build.log")
    if [ "$errs" -ne 0 ] || [ ! -x "$d/ssf" ]; then
        echo "[$name] BUILD FAILED: $errs errors, $warns warnings (see $d/build.log)"
        fail=1; continue
    fi
    [ "$warns" -ne 0 ] && fail=1
    vt=$TESTS
    case "$name" in mqttc*) vt="$TESTS $MQTTC_TESTS" ;; esac
    # One-test-per-process harness linked against the variant's own objects
    {
        echo '#include <stdio.h>'
        echo '#include <string.h>'
        for t in $vt; do echo "void $t(void);"; done
        echo 'int main(int c, char **v){'
        for t in $vt; do echo "    if ((c == 2) && (strcmp(v[1], \"$t\") == 0)) { $t(); return 0; }"; done
        echo '    return 2; }'
    } > "$d/h.c"
    if ! (cd "$d" && gcc -O1 -c h.c -o h.o && \
          gcc -o h h.o $(find build -name '*.o' ! -name main.o) -lm -lpthread -lcrypto) \
          >> "$d/build.log" 2>&1; then
        echo "[$name] harness link failed (see $d/build.log)"; fail=1; continue
    fi
    res=""
    for t in $vt; do
        if (cd "$d" && ./h "$t" > "$t.log" 2>&1); then
            res="$res ${t%UnitTest}=ok"
        else
            res="$res ${t%UnitTest}=FAIL"; fail=1
        fi
    done
    echo "[$name] build ok ($warns warnings):$res"
done
exit $fail
