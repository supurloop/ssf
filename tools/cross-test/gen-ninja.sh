#!/bin/sh
# Render build-cross.ninja.in for a given target descriptor.
#
# Usage:  gen-ninja.sh <arch>
#         where targets/<arch>.env exists and supplies ARCH, TRIPLE, QEMU,
#         CFLAGS, LDFLAGS (see targets/mipsel.env).
#
# Output: build/cross/<arch>/build.ninja, plus the build directory tree.
# Stdout: the path to the generated ninja file (consumed by run.sh).

set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <arch>" >&2
    exit 64
fi

arch=$1
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
target_env="$script_dir/targets/$arch.env"
template="$script_dir/build-cross.ninja.in"

if [ ! -f "$target_env" ]; then
    echo "$0: no descriptor at $target_env" >&2
    exit 66
fi

# shellcheck disable=SC1090
. "$target_env"

# Validate that every placeholder the template references is non-empty.
: "${ARCH:?ARCH not set in $target_env}"
: "${TRIPLE:?TRIPLE not set in $target_env}"
: "${QEMU:?QEMU not set in $target_env}"
: "${CFLAGS:?CFLAGS not set in $target_env}"
: "${LDFLAGS:?LDFLAGS not set in $target_env}"

builddir="build/cross/$ARCH"
outbin="ssf-$ARCH"
mkdir -p "$repo_root/$builddir"

ninja_path="$repo_root/$builddir/build.ninja"

# Substitute @VARS@ in the template. sed pipeline picked over envsubst because
# envsubst would expand any $foo in the template (we use $builddir as a Ninja
# variable inside the template — $-substitution would mangle it).
sed \
    -e "s|@CC@|${TRIPLE}-gcc|g" \
    -e "s|@CFLAGS@|${CFLAGS}|g" \
    -e "s|@LDFLAGS@|${LDFLAGS}|g" \
    -e "s|@BUILDDIR@|${builddir}|g" \
    -e "s|@OUTBIN@|${outbin}|g" \
    "$template" > "$ninja_path"

echo "$ninja_path"
