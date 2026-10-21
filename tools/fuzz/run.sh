#!/bin/sh
# Build + run libFuzzer differential-fuzz harnesses for AES-CTR and ECDSA verify.
# Each harness compares SSF against OpenSSL on the same input; any divergence
# (one accepts, the other rejects, or outputs differ) aborts. ASan + UBSan also
# instrument both sides, so memory bugs and UB on adversarial inputs surface.
#
# Usage:  ./tools/fuzz/run.sh [<harness>] [<seconds>]
#         <harness> ∈ aes_ctr | ecdsa_verify | all   (default: all)
#         <seconds> — wall-clock budget per harness  (default: 60)
#
# Runs inside a gcc:latest Docker container with clang + libssl-dev installed
# on the fly. macOS-arm64 host can't run libFuzzer natively (same dyld init
# race that affects ASan there), so Docker is the supported path.
#
# Output: seed-corpus dirs under tools/fuzz/seed_*; per-run output under
# build/fuzz/<harness>/. A divergence aborts immediately and writes the
# triggering input to build/fuzz/<harness>/crash-* per libFuzzer convention.

set -eu

harness=${1:-all}
seconds=${2:-60}

if [ "$harness" != "all" ] && [ "$harness" != "aes_ctr" ] && [ "$harness" != "ecdsa_verify" ]; then
    echo "usage: $0 [aes_ctr | ecdsa_verify | all] [seconds]" >&2
    exit 64
fi

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

mkdir -p build/fuzz/aes_ctr build/fuzz/ecdsa_verify
mkdir -p tools/fuzz/seed_aes_ctr tools/fuzz/seed_ecdsa_verify

# Seed corpus: a single representative input per harness is enough to start —
# libFuzzer's mutator finds new coverage from there. (More seeds would speed
# the campaign but aren't required.)
if [ ! -f tools/fuzz/seed_aes_ctr/seed1 ]; then
    # AES-CTR: selector(0=128) + key(16 zeros) + IV(16 zeros) + 32 bytes plaintext.
    printf '\x00' > tools/fuzz/seed_aes_ctr/seed1
    head -c 64 /dev/zero >> tools/fuzz/seed_aes_ctr/seed1
fi
if [ ! -f tools/fuzz/seed_ecdsa_verify/seed1 ]; then
    # ECDSA: pubkey(65) + hash(32) + sig(70) all zeros — gives the harness
    # something to mutate. Almost certainly rejects on both sides initially.
    head -c 167 /dev/zero > tools/fuzz/seed_ecdsa_verify/seed1
fi

run_one() {
    name=$1
    docker run --rm -v "$repo_root":/work -w /work gcc:latest bash -c '
set -e
apt-get update -qq > /dev/null 2>&1
apt-get install -y -qq clang libssl-dev > /dev/null 2>&1

INCS="-I. -I_time -I_codec -I_crypto -I_ecc -I_edc -I_fsm -I_debug -I_storage -I_struct -I_ui -I_osal -I_opt"
DEFS="-DSSF_CONFIG_HAVE_OPENSSL=1"
SAN="-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer"

# Compile every SSF .c (excluding _ut.c and main.c) into the harness binary.
SRCS=$(find _crypto _codec _struct _debug _osal _edc _ecc _fsm _storage _time _ui ssfport.c -name "*.c" 2>/dev/null | grep -v "_ut\.c$")

clang -O1 -g $INCS $DEFS $SAN $SRCS tools/fuzz/fuzz_'"$name"'.c \
      -lssl -lcrypto -o build/fuzz/'"$name"'/fuzz_'"$name"' 2>&1 | tail -5

cd build/fuzz/'"$name"'
mkdir -p corpus
echo === fuzzing '"$name"' for '"$seconds"'s ===
# First positional arg = writable corpus (libFuzzer accumulates discoveries here).
# Subsequent args = read-only seed dirs (libFuzzer mutates from these but does not modify).
ASAN_OPTIONS="halt_on_error=1:abort_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    ./fuzz_'"$name"' -max_total_time='"$seconds"' \
                     -timeout=10 \
                     -print_final_stats=1 \
                     corpus \
                     /work/tools/fuzz/seed_'"$name"' 2>&1 | tail -20
'
}

if [ "$harness" = "all" ] || [ "$harness" = "aes_ctr" ]; then
    run_one aes_ctr
fi
if [ "$harness" = "all" ] || [ "$harness" = "ecdsa_verify" ]; then
    run_one ecdsa_verify
fi
