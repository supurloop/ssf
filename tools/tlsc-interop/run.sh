#!/bin/bash
# TLS client (ssftlsc) interop regression set. Linux; needs openssl, gnutls-serv (gnutls-utils),
# python3, gcc, ninja. Not part of the unit tests: it talks to real TLS servers.
#
#   tools/tlsc-interop/run.sh               local rows (s_server, gnutls-serv over loopback)
#   tools/tlsc-interop/run.sh --public      also test.mosquitto.org (needs the internet; requests
#                                           and caches its client certificates, see README.md)
#   tools/tlsc-interop/run.sh --self-test   builds a client with AES-128-CCM broken and checks that
#                                           exactly the CCM rows fail (the harness can see failures)
#   tools/tlsc-interop/run.sh --asan        build the drivers against the ASan / UBSan objects
#   tools/tlsc-interop/run.sh --only TEXT   only the rows whose name contains TEXT
set -e
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd); cd "$ROOT"
PUBLIC=""; SELF=""; ASAN=""; ONLY=()
while [ $# -gt 0 ]; do
  case $1 in
    --public) PUBLIC=--public ;; --self-test) SELF=1 ;; --asan) ASAN=1 ;;
    --only) ONLY=(--only "$2"); shift ;;
    *) echo "usage: $0 [--public] [--self-test] [--asan] [--only TEXT]"; exit 2 ;;
  esac; shift
done
for c in openssl gnutls-serv python3 gcc ninja; do command -v $c > /dev/null || { echo "missing: $c"; exit 2; }; done
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
if [ -n "$ASAN" ]; then NJ=build-asan.ninja; OBJ=build-asan; F="-fsanitize=address,undefined"; else NJ=build.ninja; OBJ=build; F=""; fi
ninja -f $NJ > /dev/null
INC="-I. -I_net -I_opt -I_codec -I_fsm -I_struct -I_osal -I_debug -I_time -I_crypto -I_ecc -I_edc -I_storage -I_ui"
OBJS=$(find $OBJ -name '*.o' ! -name main.o ! -name ssftlsc.o ! -name '*_ut.o')
build(){ # name ssftlsc.c-source extra-defines
  gcc -O1 $F $INC $3 -c "$2" -o "$WORK/$1_tlsc.o"
  gcc -O1 $F $INC "$HERE/tlsc_interop.c" "$WORK/$1_tlsc.o" $OBJS $F -o "$WORK/$1" -lm -lpthread; }
build tlsc_interop _net/ssftlsc.c ""
build tlsc_interop_ku3 _net/ssftlsc.c "-DSSF_TLSC_CONFIG_KEY_UPDATE_RECORDS=3"
"$HERE/gen-certs.sh" "$WORK/certs"
if [ -n "$PUBLIC" ]; then "$HERE/public-certs.sh"; fi
if [ -n "$SELF" ]; then
  # A client whose AES-128-CCM key is the wrong length: every CCM row must fail, nothing else
  sed 's|    case SSF_TLS_CS_AES_128_CCM_SHA256:        /\* Record layer: ssftls / ssfaesccm, 16-byte tag \*/|&\n        s->hash = SSF_HMAC_HASH_SHA256; s->hashLen = 32; s->keyLen = 32; break;|' \
      _net/ssftlsc.c > "$WORK/ssftlsc_ccm_broken.c"
  ! cmp -s _net/ssftlsc.c "$WORK/ssftlsc_ccm_broken.c" || { echo "self-test: could not break CCM"; exit 1; }
  build tlsc_interop "$WORK/ssftlsc_ccm_broken.c" "-I_net"
  exec python3 "$HERE/interop.py" "$WORK" "$WORK/certs" --only matrix --expect-fail 0x1304
fi
python3 "$HERE/interop.py" "$WORK" "$WORK/certs" $PUBLIC "${ONLY[@]}"
