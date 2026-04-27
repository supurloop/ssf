# Cross-architecture unit tests under QEMU

Runs the SSF unit suite on architectures the dev host can't natively compile
for, by cross-building inside Docker and executing the resulting binary under
QEMU user-mode emulation.

The primary motivation is **portability coverage for the `_crypto` modules** —
endianness, alignment, 32-bit word size, integer-promotion footguns. The
Wycheproof and RFC 6979 KAT corpora are the load-bearing correctness tests;
running them on a non-host arch is what catches the platform bugs.

## Prerequisites

- **Docker** (or compatible: OrbStack, Colima, Podman with `docker` shim).
  All cross compilation and emulation happens inside the image. macOS dev
  hosts don't have a usable mipsel toolchain, so Docker is the path.
- The first invocation of `run.sh --docker <arch>` builds the image
  (`ssf-cross:latest`); subsequent runs reuse it.

## One-shot usage

```sh
./tools/cross-test/run.sh --docker mipsel
```

Drops you into `qemu-mipsel-static ./ssf-mipsel`. Exit code matches the unit
suite (`0` = green, non-zero = a `SSF_ASSERT` fired).

To skip Docker (e.g. on a Linux host that already has the toolchain + qemu
installed):

```sh
./tools/cross-test/run.sh mipsel
```

To run the full matrix (every `targets/*.env`) and get a pass/fail summary:

```sh
./tools/cross-test/run.sh --docker all
```

Targets are spawned in parallel inside a single container — wall time is
roughly the slowest arch (~5–10 min) rather than the sum. Per-target logs
land under `build/cross/logs/<arch>.log`. Exit code is `0` only if every
target passes.

In `all` mode each arch's ninja is invoked with `-j 2` by default to avoid
oversubscribing CPUs (override via `SSF_NINJA_JOBS=N`). Single-arch
invocations still use ninja's default (host CPU count).

## Layout

```
tools/cross-test/
├── README.md                  # this file
├── run.sh                     # one-command driver
├── gen-ninja.sh               # renders build-cross.ninja.in -> build/cross/<arch>/build.ninja
├── build-cross.ninja.in       # parametric ninja (CC / CFLAGS / LDFLAGS / BUILDDIR / OUTBIN)
├── targets/
│   └── mipsel.env             # one descriptor per target arch
└── docker/
    └── Dockerfile             # debian:stable-slim + cross gccs + qemu-user-static
```

## Adding a target

A new platform is two changes:

1. **Drop a descriptor** at `targets/<arch>.env`. Mirror `mipsel.env`:
   ```sh
   ARCH=<short-tag>
   TRIPLE=<gcc-triple>            # e.g. mips-linux-gnu, arm-linux-gnueabihf
   QEMU=<qemu-user-bin>           # e.g. qemu-mips-static, qemu-arm-static
   CFLAGS="-O2 -DSSF_CONFIG_HAVE_OPENSSL=0"
   LDFLAGS="-lm -lpthread -static"
   ```

2. **Add the toolchain** to `docker/Dockerfile`:
   ```
   gcc-<triple>
   ```
   (`qemu-user-static` already bundles runners for every common machine type.)

Then `docker build -t ssf-cross:latest tools/cross-test/docker` and
`./tools/cross-test/run.sh --docker <arch>`.

## Currently wired targets

| Target     | Triple                       | Bits | Endian | Notes |
|------------|------------------------------|------|--------|-------|
| `mipsel`   | `mipsel-linux-gnu`           | 32   | LE     | |
| `mips`     | `mips-linux-gnu`             | 32   | BE     | |
| `mips64el` | `mips64el-linux-gnuabi64`    | 64   | LE     | n64 ABI |
| `mips64`   | `mips64-linux-gnuabi64`      | 64   | BE     | n64 ABI |
| `armhf`    | `arm-linux-gnueabihf`        | 32   | LE     | hard-float EABI |
| `aarch64`  | `aarch64-linux-gnu`          | 64   | LE     | |
| `riscv64`  | `riscv64-linux-gnu`          | 64   | LE     | Debian doesn't ship riscv32 |
| `i686`     | `i686-linux-gnu`             | 32   | LE     | x86-32; qemu binary is `qemu-i386-static` |
| `m68k`     | `m68k-linux-gnu`             | 32   | BE     | Motorola 68k; BE-only, no 64-bit variant |

The `--docker all` mode iterates every descriptor in `targets/`. Coverage
spans every (32/64) × (BE/LE) cell that Debian stable's cross toolchains
support; soft-float ARM (`armel`) and big-endian aarch64 are out of the
box (no Debian package).

## OpenSSL gating

Native macOS / Linux builds run the OpenSSL cross-validation paths in
`ssfbn_ut.c`, `ssfec_ut.c`, and `ssfecdsa_ut.c`. Cross builds disable them
by setting `-DSSF_CONFIG_HAVE_OPENSSL=0` (see `targets/mipsel.env`'s
`CFLAGS`). The Wycheproof corpus and the RFC 6979 KATs that ship with the
unit suite are the load-bearing correctness coverage in that mode.

If you want libcrypto on a cross build, you'd need to either:
- cross-compile OpenSSL (heavy), or
- install `libssl-dev:<arch>` for that arch in the Docker image and adjust
  `LDFLAGS` to add `-lcrypto` (works for some targets via Debian multi-arch
  but adds a meaningful image build cost).

Neither is in scope today.

## Performance

QEMU user-mode is roughly 5×–10× slower than native. The full unit suite is
~60 s on host, so expect ~5–10 minutes per cross run. The dominant time goes
to `ssfrsa` and `ssfecdsa`'s Wycheproof loops; if you only want a quick
smoke pass, comment out those tests in `main.c` or run a focused subset.

## Known caveats

- The static-link strategy assumes the cross toolchain ships a static libc
  (Debian's `gcc-<triple>` packages all do).
- `qemu-user-static` translates Linux syscalls only; any code path that
  pokes platform-specific files outside `/dev/urandom` will need attention.
- `_osal/ssflptask` and `_storage/ssfcfg` use generic POSIX file IO and
  work fine under QEMU. If a future port references hardware-specific
  paths, that test will skip or fail under emulation — handle by gating
  the test on a config flag.
