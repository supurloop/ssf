#!/bin/sh
# Compile every C code block of SSF markdown files, so the documentation can't drift from the API.
#
# Each block that opens with a line of exactly ```c is written to its own .c file under
# build-cov/doccheck/ and compiled (no link) with the warning flags and include paths of
# build-linux.ninja plus -Werror. Each file starts with:
#
#   #include "ssfport.h"
#   #include "ssf.h"
#   #include "<header>"  for each header a  <!-- doccheck: include a.h b.h -->  line names
#
# Markers, on the line just before a block's ```c line:
#
#   <!-- doccheck: skip <reason> -->   not compiled (a fragment, a placeholder); give the reason
#   <!-- doccheck: body -->            statements: wrapped in  void _doccheck_N(void) { ... }
#
# Usage:  ./tools/doccheck/run.sh <file.md> [file.md ...]
#
# Exit:   0 if every block compiles warning-free; 1 if any fails (its compiler output is shown);
#         2 on a usage or setup error. Run from anywhere; paths are relative to the repo root.

set -u

repo_root=$(cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root" || exit 2

if [ $# -lt 1 ]; then
    echo "usage: $0 <file.md> [file.md ...]" >&2
    exit 2
fi

# Flags from build-linux.ninja (joined across its "$" line continuations).
ninja_var() {
    awk -v name="$1" '
        $0 ~ "^" name " *=" { on = 1; sub("^" name " *= *", "") }
        on { line = $0; cont = sub(/ *\$$/, "", line); out = out " " line; if (!cont) { on = 0 } }
        END { print out }' build-linux.ninja
}
cflags="$(ninja_var cflags_common) -Werror -std=gnu11 -DSSF_CONFIG_HAVE_OPENSSL=0"
includes=$(ninja_var includes)
cc=${CC:-gcc}

out_dir=build-cov/doccheck
mkdir -p "$out_dir" || exit 2

status=0
total=0
skipped=0
for md in "$@"; do
    if [ ! -f "$md" ]; then
        echo "$0: $md: no such file" >&2
        exit 2
    fi
    base=$(basename "$md" .md)
    rm -f "$out_dir/$base"_*.c

    # Split the blocks into files; print "<file> <line>" for each compiled block, "skip" lines.
    list=$(awk -v dir="$out_dir" -v base="$base" '
        BEGIN { n = 0; inblk = 0; prev = "" }
        /^<!-- doccheck: include / {
            s = $0; sub(/^<!-- doccheck: include /, "", s); sub(/ *-->.*$/, "", s)
            incs = incs " " s
        }
        inblk && /^```/ {
            if (wrap) print "}" > f
            close(f); inblk = 0; prev = ""; next
        }
        inblk { print > f; next }
        /^```c[ \t]*$/ {
            n++
            if (prev ~ /^<!-- doccheck: skip /) { print "skip " FILENAME ":" NR; inblk = 2; f = "/dev/null"; wrap = 0; next }
            f = dir "/" base "_" n ".c"
            print "#include \"ssfport.h\"" > f
            print "#include \"ssf.h\"" > f
            k = split(incs, h, " ")
            for (i = 1; i <= k; i++) print "#include \"" h[i] "\"" > f
            print "#line " (NR + 1) " \"" FILENAME "\"" > f
            wrap = (prev ~ /^<!-- doccheck: body *-->/)
            if (wrap) print "void _doccheck_" n "(void) {" > f
            print f " " FILENAME ":" NR
            inblk = 1; next
        }
        { if ($0 !~ /^[ \t]*$/) prev = $0 }
        END { if (inblk == 1) { print "unterminated " FILENAME ":" NR } }' "$md")

    echo "$list" | while read -r a b; do
        [ -z "$a" ] && continue
        case $a in
            skip) echo "[doccheck] skipped $b" ;;
            unterminated) echo "[doccheck] FAIL: unterminated block at $b"; exit 1 ;;
            *)
                if "$cc" $cflags $includes -c "$a" -o /dev/null 2> "$a.log"; then
                    echo "[doccheck] ok      $b"
                else
                    echo "[doccheck] FAIL    $b"
                    cat "$a.log"
                    exit 1
                fi ;;
        esac
    done || status=1
    total=$((total + $(echo "$list" | grep -c '^[^su]')))
    skipped=$((skipped + $(echo "$list" | grep -c '^skip')))
done

echo "[doccheck] $total compiled, $skipped skipped: $( [ $status -eq 0 ] && echo pass || echo FAIL )"
exit $status
