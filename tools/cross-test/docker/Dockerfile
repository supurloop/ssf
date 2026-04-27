# SSF cross-build environment.
#
# Single image carries all cross toolchains + qemu-user-static. To add a new
# target, add the matching gcc-<triple> package to the apt-get line below
# (and verify the qemu-user-static package ships a runner for that machine
# type — Debian's bundle covers all the usual suspects).
#
# Build:  docker build -t ssf-cross:latest tools/cross-test/docker
#         (the run.sh --docker driver does this automatically on first use)
#
# Use:    docker run --rm -v <repo>:/work -w /work ssf-cross:latest \
#             sh tools/cross-test/run.sh mipsel
FROM debian:stable-slim

# Avoid tzdata / debconf prompts during apt-get install.
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates \
        ninja-build \
        make \
        binutils \
        gcc-mipsel-linux-gnu        binutils-mipsel-linux-gnu        libc6-dev-mipsel-cross \
        gcc-mips-linux-gnu          binutils-mips-linux-gnu          libc6-dev-mips-cross \
        gcc-mips64el-linux-gnuabi64 binutils-mips64el-linux-gnuabi64 libc6-dev-mips64el-cross \
        gcc-mips64-linux-gnuabi64   binutils-mips64-linux-gnuabi64   libc6-dev-mips64-cross \
        gcc-arm-linux-gnueabihf     binutils-arm-linux-gnueabihf     libc6-dev-armhf-cross \
        gcc-aarch64-linux-gnu       binutils-aarch64-linux-gnu       libc6-dev-arm64-cross \
        gcc-riscv64-linux-gnu       binutils-riscv64-linux-gnu       libc6-dev-riscv64-cross \
        gcc-i686-linux-gnu          binutils-i686-linux-gnu          libc6-dev-i386-cross \
        gcc-m68k-linux-gnu          binutils-m68k-linux-gnu          libc6-dev-m68k-cross \
        qemu-user-static \
 && rm -rf /var/lib/apt/lists/*

# Each cross toolchain needs both the runtime libc (pulled in transitively by
# gcc-<triple>) and the headers (the libc6-dev-<arch>-cross package). -static
# linkage means we never touch the runtime at execution, but cc1 still needs
# the headers at build time.
#
# `binutils` (native, unprefixed) is for the case where target == host: on an
# arm64 build host, `gcc-aarch64-linux-gnu` is the native compiler and looks
# for an unprefixed `as`/`ld` from the native binutils package, not the
# `aarch64-linux-gnu-as` shipped by `binutils-aarch64-linux-gnu`. Installing
# both is harmless on cross-arch hosts.

WORKDIR /work
