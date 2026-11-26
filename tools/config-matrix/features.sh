#!/bin/sh
# Feature-option matrix: turn off one crypto feature option at a time and confirm the whole
# tree still builds warning-free and the unit tests that depend on that option still pass.
# Complements run.sh in this directory, which sweeps curve and RSA-size combinations through
# the full suite; this script covers the feature switches it does not:
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
# Each variant is exported from the working tree (including uncommitted edits and new
# untracked files) into its own directory under build-cov/variants/, so the working tree is
# never modified. Only the RSA/EC-dependent unit tests run, one process each, so a full sweep
# takes well under a minute on a multi-core host.
#
# Usage:  ./tools/config-matrix/features.sh [variant ...]   (default: all)
#
# Exit:   0 if every selected variant builds with no errors or warnings and every test
#         passes; 1 otherwise. Per-variant logs: build-cov/variants/<variant>/.

set -u

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
R=$(cd -- "$script_dir/../.." && pwd)
V=$R/build-cov/variants
TESTS="SSFRSAUnitTest SSFECUnitTest SSFECDSAUnitTest SSFX509UnitTest SSFCMSUnitTest SSFTLSUnitTest SSFPKeyUnitTest SSFTLSCUnitTest"

case "$(uname -s)" in
    Linux)  ninja_file=build-linux.ninja ;;
    Darwin) ninja_file=build.ninja ;;
    *)      echo "[features] unsupported host: $(uname -s)" >&2; exit 65 ;;
esac

# name|header|sed expression
VARIANTS='
pkcs1off|_opt/ssfrsa_opt.h|s/^#define SSF_RSA_CONFIG_ENABLE_PKCS1_V15 .*/#define SSF_RSA_CONFIG_ENABLE_PKCS1_V15      (0u)/
pssoff|_opt/ssfrsa_opt.h|s/^#define SSF_RSA_CONFIG_ENABLE_PSS .*/#define SSF_RSA_CONFIG_ENABLE_PSS            (0u)/
keygenoff|_opt/ssfrsa_opt.h|s/^#define SSF_RSA_CONFIG_ENABLE_KEYGEN .*/#define SSF_RSA_CONFIG_ENABLE_KEYGEN         (0u)/
p256off|_opt/ssfec_opt.h|s/^#define SSF_EC_CONFIG_ENABLE_P256 .*/#define SSF_EC_CONFIG_ENABLE_P256            (0u)/
p384off|_opt/ssfec_opt.h|s/^#define SSF_EC_CONFIG_ENABLE_P384 .*/#define SSF_EC_CONFIG_ENABLE_P384            (0u)/
signoff|_opt/ssfecdsa_opt.h|s/^#define SSF_ECDSA_CONFIG_ENABLE_SIGN .*/#define SSF_ECDSA_CONFIG_ENABLE_SIGN         (0u)/
fb256off|_opt/ssfec_opt.h|s/^#define SSF_EC_CONFIG_FIXED_BASE_P256 .*/#define SSF_EC_CONFIG_FIXED_BASE_P256        (0u)/
fb384off|_opt/ssfec_opt.h|s/^#define SSF_EC_CONFIG_FIXED_BASE_P384 .*/#define SSF_EC_CONFIG_FIXED_BASE_P384        (0u)/
'
want="$*"
fail=0
# Working tree as a commit object, without touching the index or stash list (HEAD if clean)
tree=$(cd "$R" && git stash create)
[ -n "$tree" ] || tree=HEAD

for name in $(echo "$VARIANTS" | cut -d'|' -f1); do
    line=$(echo "$VARIANTS" | grep "^$name|")
    hdr=$(echo "$line" | cut -d'|' -f2)
    expr=$(echo "$line" | cut -d'|' -f3-)
    if [ -n "$want" ]; then case " $want " in *" $name "*) ;; *) continue ;; esac; fi
    d=$V/$name
    rm -rf -- "$d"
    mkdir -p "$d"
    (cd "$R" && git archive "$tree") | tar -x -C "$d"
    (cd "$R" && git ls-files --others --exclude-standard -z | xargs -0 -r cp --parents -t "$d")
    sed -i.bak "$expr" "$d/$hdr" && rm -f "$d/$hdr.bak"
    if cmp -s "$R/$hdr" "$d/$hdr"; then
        echo "[$name] option edit did not apply to $hdr"; fail=1; continue
    fi
    (cd "$d" && ninja -f "$ninja_file" -k 0 > build.log 2>&1)
    errs=$(grep -c ' error: ' "$d/build.log")
    warns=$(grep -c ' warning: ' "$d/build.log")
    if [ "$errs" -ne 0 ] || [ ! -x "$d/ssf" ]; then
        echo "[$name] BUILD FAILED: $errs errors, $warns warnings (see $d/build.log)"
        fail=1; continue
    fi
    [ "$warns" -ne 0 ] && fail=1
    # One-test-per-process harness linked against the variant's own objects
    {
        echo '#include <stdio.h>'
        echo '#include <string.h>'
        for t in $TESTS; do echo "void $t(void);"; done
        echo 'int main(int c, char **v){'
        for t in $TESTS; do echo "    if ((c == 2) && (strcmp(v[1], \"$t\") == 0)) { $t(); return 0; }"; done
        echo '    return 2; }'
    } > "$d/h.c"
    if ! (cd "$d" && gcc -O1 -c h.c -o h.o && \
          gcc -o h h.o $(find build -name '*.o' ! -name main.o) -lm -lpthread -lcrypto) \
          >> "$d/build.log" 2>&1; then
        echo "[$name] harness link failed (see $d/build.log)"; fail=1; continue
    fi
    res=""
    for t in $TESTS; do
        if (cd "$d" && ./h "$t" > "$t.log" 2>&1); then
            res="$res ${t%UnitTest}=ok"
        else
            res="$res ${t%UnitTest}=FAIL"; fail=1
        fi
    done
    echo "[$name] build ok ($warns warnings):$res"
done
exit $fail
