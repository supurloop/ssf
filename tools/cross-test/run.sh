#!/bin/sh
# Cross-build SSF for <arch> and run the unit suite under qemu-user.
#
# Usage:  ./tools/cross-test/run.sh <arch>           # native (Linux host w/ tools)
#         ./tools/cross-test/run.sh --docker <arch>  # via the cross-test image
#         ./tools/cross-test/run.sh [--docker] all   # iterate every targets/*.env (parallel)
#
# Exit:   matches the unit suite's exit code (0 on success, non-zero on any failure).
#         In `all` mode, exits 0 only if every target passes.
#
# Env:    SSF_NINJA_JOBS   per-arch ninja parallelism. Defaults to 2 in `all`
#                          mode (so 7 arches × 2 jobs ~= 14 simultaneous compile
#                          processes, fine on a typical 8-core dev VM). Unset
#                          for single-arch invocations (ninja default).

set -eu

use_docker=0
if [ $# -ge 1 ] && [ "$1" = "--docker" ]; then
    use_docker=1
    shift
fi

if [ $# -ne 1 ]; then
    echo "usage: $0 [--docker] <arch|all>" >&2
    exit 64
fi

arch=$1
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)

if [ "$use_docker" = "1" ]; then
    image="ssf-cross:latest"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        echo "[run.sh] building image $image (one-time)..."
        docker build -t "$image" "$script_dir/docker"
    fi
    # Re-enter ourselves inside the container with the same arch arg.
    exec docker run --rm \
        -v "$repo_root":/work -w /work \
        "$image" \
        sh tools/cross-test/run.sh "$arch"
fi

# --- inside the build environment from here on ---

# `all` mode: spawn every targets/*.env in parallel, capture per-arch logs,
# wait on every PID, print a pass/fail matrix. Wall time is dominated by the
# slowest arch (~5–10 min) instead of the sum of all arches.
if [ "$arch" = "all" ]; then
    cd "$repo_root"
    mkdir -p build/cross/logs
    : "${SSF_NINJA_JOBS:=2}"
    export SSF_NINJA_JOBS
    pids=""
    for env in "$script_dir"/targets/*.env; do
        a=$(basename "$env" .env)
        log="build/cross/logs/$a.log"
        ( "$0" "$a" >"$log" 2>&1 ) &
        pid=$!
        printf '[run.sh] === %s spawned (pid %d) -> %s ===\n' "$a" "$pid" "$log"
        pids="$pids $a:$pid"
    done
    overall=0
    summary=""
    for entry in $pids; do
        a=${entry%:*}
        pid=${entry#*:}
        if wait "$pid"; then
            printf '[run.sh] === %s PASS ===\n' "$a"
            summary="$summary
  $a  PASS"
        else
            printf '[run.sh] === %s FAIL (see build/cross/logs/%s.log) ===\n' "$a" "$a"
            summary="$summary
  $a  FAIL  (see build/cross/logs/$a.log)"
            overall=1
        fi
    done
    printf '\n=== cross-test matrix summary ===%s\n' "$summary"
    exit $overall
fi

target_env="$script_dir/targets/$arch.env"
if [ ! -f "$target_env" ]; then
    echo "[run.sh] no descriptor at $target_env" >&2
    exit 66
fi
# shellcheck disable=SC1090
. "$target_env"

ninja_file=$("$script_dir/gen-ninja.sh" "$arch")
echo "[run.sh] generated $ninja_file"

cd "$repo_root"
ninja ${SSF_NINJA_JOBS:+-j "$SSF_NINJA_JOBS"} -f "$ninja_file"

binary="$repo_root/ssf-$ARCH"
if [ ! -x "$binary" ]; then
    echo "[run.sh] expected binary at $binary, not found" >&2
    exit 70
fi

echo "[run.sh] running: $QEMU $binary"
exec "$QEMU" "$binary"
