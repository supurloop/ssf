#!/bin/sh
# Bare-metal ARM compile-only warning check (no link, no run).
#
# Compiles every library and unit-test source listed in build-linux.ninja with arm-none-eabi-gcc
# against newlib, the way an STM32CubeIDE (or similar) port builds SSF. Catches what host builds
# cannot: uint32_t/int32_t are long on newlib (printf format mismatches), enums are short by
# default on arm-none-eabi, and POSIX APIs (pthreads, clock_gettime, poll) are absent.
#
# Thread support is forced off (-DSSF_CONFIG_ENABLE_THREAD_SUPPORT=0), as on a bare-metal port.
# main.c and ssfport.c are skipped: they are the host test runner and host port layer, which a
# target port replaces.
#
# Usage:  ./build-arm.sh [core ...]       default cores: cortex-m4 cortex-m0plus
# Env:    ARM_CC   compiler to use (default: arm-none-eabi-gcc on PATH, else STM32CubeIDE's)
#         JOBS     parallel compiles (default: nproc)
# Output: build/arm/<core>/ objects and warnings.log; exit 1 if any warning or error.

set -u

repo_root=$(cd -- "$(dirname -- "$0")" && pwd)
cd "$repo_root" || exit 1

# Pick the compiler: ARM_CC, then PATH, then the newest STM32CubeIDE install.
cc=${ARM_CC:-}
if [ -z "$cc" ]; then
    cc=$(command -v arm-none-eabi-gcc 2>/dev/null || true)
fi
if [ -z "$cc" ]; then
    cc=$(ls -d /opt/st/stm32cubeide_*/plugins/*gnu-tools-for-stm32*/tools/bin/arm-none-eabi-gcc \
         2>/dev/null | sort -V | tail -n 1)
fi
if [ -z "$cc" ] || [ ! -x "$(command -v "$cc")" ]; then
    echo "$0: arm-none-eabi-gcc not found; set ARM_CC" >&2
    exit 2
fi
jobs=${JOBS:-$(nproc 2>/dev/null || echo 4)}

cores=${*:-cortex-m4 cortex-m0plus}

# Same warning set as build-linux.ninja minus -Wno-unused (CubeIDE's -Wall reports unused code).
warn="-Wall -Wextra -pedantic -Wcast-align -Wno-parentheses -Wdisabled-optimization \
-fdiagnostics-show-option -Wstrict-overflow=5 -Wformat=2 -Wlogical-op"
includes="-I. -I_time -I_codec -I_crypto -I_ecc -I_edc -I_fsm -I_debug -I_storage -I_struct \
-I_ui -I_osal -I_opt"
defs="-DSSF_CONFIG_HAVE_OPENSSL=0 -DSSF_CONFIG_ENABLE_THREAD_SUPPORT=0"

# Source list comes from build-linux.ninja so the two builds never drift apart.
srcs=$(sed -n 's/.*cc_obj[[:space:]]\{1,\}\([^[:space:]]*\.c\).*/\1/p' build-linux.ninja | \
       grep -v -e '^main\.c$' -e '^ssfport\.c$')

echo "Compiler: $cc ($("$cc" -dumpversion))"
status=0
for core in $cores; do
    case $core in
        cortex-m4)                      fp="-mfpu=fpv4-sp-d16 -mfloat-abi=hard" ;;
        *)                              fp="-mfloat-abi=soft" ;;
    esac
    out="build/arm/$core"
    rm -rf "$out"
    mkdir -p "$out"
    log="$out/warnings.log"

    # One compile per source; each writes its diagnostics to its own .log, merged afterwards.
    echo "$srcs" | xargs -P "$jobs" -I{} sh -c '
        o="$1/$(echo "$2" | tr / _)"
        $3 -c "$2" -o "${o%.c}.o" > "${o%.c}.log" 2>&1 || echo "COMPILE FAILED: $2" >> "${o%.c}.log"
    ' sh "$out" {} "$cc -mcpu=$core -mthumb $fp -std=gnu11 -Os -ffunction-sections \
-fdata-sections --specs=nano.specs $warn $includes $defs"
    cat "$out"/*.log > "$log" 2>/dev/null

    nwarn=$(grep -c 'warning:' "$log")
    nerr=$(grep -c 'COMPILE FAILED' "$log")
    echo "$core: $nwarn warnings, $nerr failed files (see $log)"
    if [ "$nwarn" -ne 0 ] || [ "$nerr" -ne 0 ]; then status=1; fi
done
exit $status
