#!/bin/sh
# Measure unit-test code coverage of an SSF module subtree using gcov.
#
# Builds a coverage-instrumented variant of the full SSF binary in build-cov/
# (everything compiled with --coverage -O0 -g -fprofile-update=atomic), runs
# the unit suite, then reports gcov line and branch coverage for every
# production source file (.c, excluding *_ut.c) under the chosen module.
#
# Usage:  ./tools/coverage/run.sh [<module>]
#         ./tools/coverage/run.sh --clean
#
#         <module>  one of _crypto _codec _ecc _edc _fsm _storage _struct
#                   _time _ui _osal _debug   (default: _crypto)
#
# Exit:   0 on successful build + run; non-zero if the build failed or the
#         instrumented binary aborted before any .gcda was written.
#         Test failures during the run do NOT fail the script — coverage is
#         a measurement, not a gate.
#
# Requirements:
#   * gcc (resolves to clang on macOS, real gcc on Linux — both fine).
#   * gcov in PATH (Apple's llvm-cov gcov shim works against clang's .gcno).
#   * fprofile-update=atomic so the test harness's parallel forks do not race
#     on the shared .gcda files.

set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

cov_dir=build-cov
cov_bin=ssf-cov

if [ "${1:-}" = "--clean" ]; then
    rm -rf "$cov_dir" "$cov_bin"
    echo "[coverage] removed $cov_dir/ and $cov_bin"
    exit 0
fi

module=${1:-_crypto}
case "$module" in
    _codec|_crypto|_debug|_ecc|_edc|_fsm|_osal|_storage|_struct|_time|_ui) ;;
    *) echo "[coverage] unknown module: $module" >&2; exit 64 ;;
esac

case "$(uname -s)" in
    Darwin) base_ninja=build.ninja ;;
    Linux)  base_ninja=build-linux.ninja ;;
    *)      echo "[coverage] unsupported host: $(uname -s)" >&2; exit 65 ;;
esac

if [ ! -f "$base_ninja" ]; then
    echo "[coverage] missing $base_ninja in $repo_root" >&2
    exit 66
fi

mkdir -p "$cov_dir"
cov_ninja="$cov_dir/build.ninja"

# Derive the coverage ninja from the host's normal ninja by patching only the
# four lines that need to differ: cflags (drop -O3, add coverage flags), ldflags
# (link in libgcov), builddir (parallel tree), and the final binary name.
#
# Keeping the rest byte-for-byte identical means the source list stays in sync
# automatically when sources are added or removed from the canonical ninja.
sed \
    -e 's|^cflags = \$cflags_common -O3$|cflags = $cflags_common -O0 -g --coverage -fprofile-update=atomic -DSSF_COVERAGE=1|' \
    -e 's|^ldflags = \(.*\)$|ldflags = \1 --coverage|' \
    -e "s|^builddir = build$|builddir = $cov_dir|" \
    -e "s|^build ssf: link |build $cov_bin: link |" \
    -e "s|^default ssf$|default $cov_bin|" \
    "$base_ninja" > "$cov_ninja"

# Sanity-check that the substitutions actually fired. If the upstream ninja's
# cflags / ldflags / builddir / target lines change form, the sed above will
# silently produce a non-instrumented build — fail loudly instead.
for marker in '^cflags = .*--coverage' '^ldflags = .*--coverage' "^builddir = $cov_dir\$" "^build $cov_bin: link " "^default $cov_bin\$"; do
    if ! grep -q "$marker" "$cov_ninja"; then
        echo "[coverage] sed substitution did not fire for: $marker" >&2
        echo "[coverage] $base_ninja format may have drifted; update tools/coverage/run.sh" >&2
        exit 70
    fi
done

# Wipe stale .gcda counters from a previous run; .gcno (compile-time graph)
# is rebuilt by ninja whenever the source changes, so we leave it alone.
find "$cov_dir" -name '*.gcda' -delete 2>/dev/null || true

echo "[coverage] building $cov_bin via $cov_ninja"
ninja -f "$cov_ninja"

echo "[coverage] running ./$cov_bin (suite output suppressed; coverage only)"
# The unit suite forks per-module and runs in parallel — atomic .gcda updates
# (set at compile time above) keep the counters consistent.
# Test failures are not fatal here; we only need the .gcda files to land.
./"$cov_bin" >"$cov_dir/run.log" 2>&1 || true

if ! find "$cov_dir/$module" -name '*.gcda' -print -quit | grep -q .; then
    echo "[coverage] no .gcda files written under $cov_dir/$module — binary aborted before exit?" >&2
    echo "[coverage] see $cov_dir/run.log" >&2
    exit 71
fi

# Run gcov per-source and collect the summary lines. gcov -b adds branch stats;
# -o points it at the directory containing the matching .gcno/.gcda. Output
# .gcov files land in cwd by default — stash them in $cov_dir/gcov/<module>/
# so a subsequent run does not pile them up at the repo root.
gcov_outdir="$cov_dir/gcov/$module"
mkdir -p "$gcov_outdir"

# Pick gcov binary: on macOS allow homebrew gcc-14's gcov-14 if present (it
# tracks gcc's data format more precisely than Apple's llvm-cov gcov shim);
# otherwise fall back to whatever 'gcov' resolves to.
gcov_bin=gcov
if command -v gcov-14 >/dev/null 2>&1 && [ "$(uname -s)" = Darwin ]; then
    : # leave as 'gcov' — Apple gcov reads clang's .gcno fine, and gcov-14
      # would mismatch against clang-produced data.
fi

summary_tsv="$cov_dir/gcov/$module/summary.tsv"
: > "$summary_tsv"

# Iterate the production sources only (drop *_ut.c — that is test code, not
# the code under test). Sorted output keeps the table stable across runs.
srcs=$(find "$module" -maxdepth 1 -name 'ssf*.c' ! -name '*_ut.c' | sort)
if [ -z "$srcs" ]; then
    echo "[coverage] no production sources found under $module/" >&2
    exit 72
fi

(
    cd "$gcov_outdir"
    for src in $srcs; do
        # repo-root-relative path from the gcov_outdir vantage point.
        rel_src="../../../$src"
        # Object dir holds the .gcno/.gcda for this source.
        obj_dir="../../../$cov_dir/$(dirname "$src")"
        "$gcov_bin" -b -o "$obj_dir" "$rel_src" 2>/dev/null
    done
) > "$cov_dir/gcov/$module/raw.txt"

# Parse the gcov stdout into per-file rows. Lines look like:
#   File '_crypto/ssfaes.c'
#   Lines executed:95.23% of 168
#   Branches executed:100.00% of 50
#   Taken at least once:80.00% of 50
# Branch lines may be absent if the file has no branch points — emit "—".
awk '
function flush() {
    if (file != "") {
        printf "%s\t%s\t%d\t%s\t%d\n", file, lines_pct, lines_n, taken_pct, branches_n
    }
    file=""; lines_pct="—"; lines_n=0; taken_pct="—"; branches_n=0
}
/^File / {
    flush()
    file = $0
    sub(/^File [`'\'']/, "", file)
    sub(/[`'\'']$/, "", file)
}
/^Lines executed:/ {
    s=$0; sub(/^Lines executed:/, "", s)
    split(s, a, "%"); lines_pct=a[1]
    n=split(s, b, " "); lines_n=b[n]
}
/^Taken at least once:/ {
    s=$0; sub(/^Taken at least once:/, "", s)
    split(s, a, "%"); taken_pct=a[1]
    n=split(s, b, " "); branches_n=b[n]
}
END { flush() }
' "$cov_dir/gcov/$module/raw.txt" > "$summary_tsv"

# Pretty-print the table + a totals row. Width tuned for ssf*.c paths.
awk -F'\t' -v module="$module" '
BEGIN {
    printf "\nCoverage report for %s/\n", module
    printf "%-44s  %8s  %12s  %8s  %12s\n", "file", "lines%", "exec/total", "branch%", "taken/total"
    printf "%-44s  %8s  %12s  %8s  %12s\n", "----", "------", "----------", "-------", "-----------"
}
{
    file=$1; lp=$2; ln=$3; tp=$4; tn=$5
    if (lp != "—") {
        exec = int(ln * lp / 100 + 0.5)
        sum_exec += exec; sum_lines += ln
        lines_cell = sprintf("%d/%d", exec, ln)
    } else { lines_cell = "—" }
    if (tp != "—" && tn > 0) {
        taken = int(tn * tp / 100 + 0.5)
        sum_taken += taken; sum_branches += tn
        branch_cell = sprintf("%d/%d", taken, tn)
    } else { branch_cell = "—"; tp = "—" }
    printf "%-44s  %7s%%  %12s  %7s%%  %12s\n", file, lp, lines_cell, tp, branch_cell
}
END {
    if (sum_lines > 0) {
        agg_lines = sum_exec * 100.0 / sum_lines
        agg_lines_cell = sprintf("%d/%d", sum_exec, sum_lines)
    } else { agg_lines = 0; agg_lines_cell = "0/0" }
    if (sum_branches > 0) {
        agg_branches = sum_taken * 100.0 / sum_branches
        agg_branch_cell = sprintf("%d/%d", sum_taken, sum_branches)
    } else { agg_branches = 0; agg_branch_cell = "0/0" }
    printf "%-44s  %7s%%  %12s  %7s%%  %12s\n", "----", "------", "----------", "-------", "-----------"
    printf "%-44s  %7.2f%%  %12s  %7.2f%%  %12s\n", "TOTAL", agg_lines, agg_lines_cell, agg_branches, agg_branch_cell
}
' "$summary_tsv"

echo
echo "[coverage] gcov files: $cov_dir/gcov/$module/"
echo "[coverage] suite log:  $cov_dir/run.log"
