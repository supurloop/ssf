# ssfbn — Multi-Precision Big Number Arithmetic

[SSF](../README.md) | [Cryptography](README.md)

Fixed-capacity multi-precision integer arithmetic over a 32-bit limb (4096-bit default).
Provides the primitives that [`ssfrsa`](ssfrsa.h), [`ssfec`](ssfec.h),
[`ssfecdsa`](ssfecdsa.h), and related public-key modules are built on: unsigned add / subtract
/ multiply / square (with Karatsuba dispatch above 32 limbs), modular reduction and arithmetic,
modular inverse, extended Euclidean GCD, full division (`SSFBNDivMod`), a constant-time
fixed-window `ModExp`, the Montgomery multiplication / conversion / square primitives that make
large-modulus exponentiation affordable on a microcontroller, and primality / random-prime
generation for RSA key creation.

Numbers are stored as a struct ([`SSFBN_t`](#ssfbn-t)) carrying a *pointer* to caller-supplied
limb storage plus `len` (active limb count) and `cap` (storage capacity in limbs). The
[`SSFBN_DEFINE`](#ssfbn-define) macro is the normal way to declare a local: it pairs a
zero-initialised limb array with the struct in one expansion, sized exactly for the working
width. There is no dynamic allocation.

This module is intended as a back-end — most callers will use it indirectly through the
higher-level modules. Direct use is appropriate when implementing a protocol not already
covered by SSF (e.g., a custom Diffie-Hellman group) or when porting algorithms out of
other big-integer libraries.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfprng.h`](ssfprng.h) — for [`SSFBNRandom`](#ssfbnrandom), [`SSFBNRandomBelow`](#ssfbnrandombelow), [`SSFBNIsProbablePrime`](#ssfbnisprobableprime), [`SSFBNGenPrime`](#ssfbngenprime)

<a id="notes"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Notes

- **`SSFBN_t` carries a pointer, not an embedded limb array.** Each `SSFBN_t` holds
  `{ SSFBNLimb_t *limbs; uint16_t len; uint16_t cap; }` — `limbs` points at a caller-owned
  limb buffer, `len` is the working limb count for the current operation, and `cap` is the
  size of the buffer. Use the [`SSFBN_DEFINE`](#ssfbn-define) macro (or
  [`SSFBNMONT_DEFINE`](#ssfbnmont-define) for a Montgomery context) to declare a local
  paired with its zero-initialised storage in one step. Static constants (the NIST primes,
  curve parameters) declare a separate `SSFBNLimb_t[]` array and point at it from the
  struct initialiser.
- **`len`-matching is mandatory for two-operand arithmetic.** Every same-length
  two-operand function (`Add`, `Sub`, `Cmp`, `ModAdd`, `ModSub`, `ModMul`, `ModSquare`,
  `ModInv*`, `CondSwap`, `CondCopy`, `Gcd`) requires `a->len == b->len` — and, for modular
  operations, equal to `m->len` as well. The caller is responsible for zero-padding shorter
  inputs up to the working limb count before calling. Passing mismatched `len` values
  produces silently-wrong results, not a `SSF_REQUIRE` failure. The `*Uint32` variants
  (`AddUint32`, `SubUint32`, `MulUint32`, `CmpUint32`, `ModUint32`) take a single 32-bit
  scalar and have no corresponding constraint.
- **`ModAdd` / `ModSub` require pre-reduced operands.** Both expect `a, b < m` on input —
  their post-correction is a single conditional subtract (Add) or add (Sub) of `m`, so
  operands further out of range produce silently-wrong results. If operands may exceed
  the modulus, reduce them first with [`SSFBNMod()`](#ssfbnmod). `ModMul` and `ModSquare`
  are not constrained this way; they reduce the full unreduced product internally via
  `SSFBNMod`.
- **Not all functions are constant time.** Callers who handle secret data (private keys,
  nonces, ephemeral scalars) must restrict themselves to the constant-time primitives:

  | Status | Functions |
  |---|---|
  | **Constant-time** (safe on secrets) | [`SSFBNCmp`](#ssfbncmp), [`SSFBNModExp`/`SSFBNModExpMont`](#modexp), [`SSFBNMontMul`](#montmul), [`SSFBNMontSquare`](#montsquare), [`SSFBNMontConvertIn`/`Out`](#montconv), [`SSFBNCondSwap`](#condswap), [`SSFBNCondCopy`](#condswap), [`SSFBNAdd`](#ssfbnadd), [`SSFBNSub`](#ssfbnsub), [`SSFBNModAdd`](#modaddsub), [`SSFBNModSub`](#modaddsub), [`SSFBNModMulCT`](#ssfbnmodmulct), [`SSFBNMul`](#ssfbnmul), [`SSFBNSquare`](#ssfbnsquare), [`SSFBNIsEven`/`SSFBNIsOdd`](#predicates) |
  | **Variable-time** (do not use on secrets) | [`SSFBNMod`](#ssfbnmod), [`SSFBNDivMod`](#ssfbndivmod), [`SSFBNModMul`](#ssfbnmodmul), [`SSFBNModSquare`](#ssfbnmodsquare), [`SSFBNGcd`](#ssfbngcd), [`SSFBNModInvExt`](#modinv), [`SSFBNModMulNIST`](#modmulnist), [`SSFBNModExpPub`/`SSFBNModExpMontPub`](#modexppub), [`SSFBNBitLen`](#bitlen), [`SSFBNTrailingZeros`](#trailingzeros), [`SSFBNIsZero`/`IsOne`](#predicates), [`SSFBNShiftLeft1`/`Right1`](#shift), [`SSFBNShiftLeft`/`Right`](#shift-multi), [`SSFBNIsProbablePrime`](#ssfbnisprobableprime), [`SSFBNGenPrime`](#ssfbngenprime) |
  | **Constant-time only when `m` is prime** | [`SSFBNModInv`](#modinv) — uses Fermat's little theorem (`a^(m-2) mod m`), which is constant-time but yields the correct answer only for prime `m`. After computing it, the function verifies `a · r ≡ 1 (mod m)` and returns `false` if it does not hold, so non-prime moduli are rejected (even when an inverse exists). |
- **Secret scalars go through `SSFBNModInv` (with prime `m`) or the ModExp path, never
  `SSFBNModInvExt` or `SSFBNModExpPub`.** ECDSA signing, for instance, computes `s⁻¹ mod n`
  where `n` is the curve order (prime); use `SSFBNModInv` there. Reserve `SSFBNModInvExt`
  for cases where the modulus is known non-prime *and* none of the inputs are secret.
  Reserve `SSFBNModExpPub` / `SSFBNModExpMontPub` for public-exponent operations such as
  RSA verify (`e = 65537`).
- **`SSFBNMul` and `SSFBNSquare` expand; the caller must size the destination.** For
  `SSFBNMul`, `r->len` is set to `a->len + b->len`, which must satisfy
  `r->len ≤ r->cap` and `r->len ≤ SSF_BN_MAX_LIMBS`. `SSFBNSquare` sets `r->len = 2 *
  a->len`. Both require `r` to not alias either operand. All other two-operand functions
  permit `r == a` or `r == b`. `SSFBNMul` dispatches to a one-level Karatsuba implementation
  for same-size, even-length operands at or above
  [`SSF_BN_KARATSUBA_THRESHOLD`](#functions) (32 limbs) and falls back to schoolbook
  otherwise; the inner schoolbook loop deliberately performs no zero-limb skipping so
  timing is independent of operand bit pattern on secret-data paths.
- **`SSFBNDivMod` is the full division.** `SSFBNMod` is the right primitive when only the
  remainder is wanted; `SSFBNDivMod` produces both quotient and remainder via shift-and-
  subtract long division. Both are variable-time.
- **`SSFBNModExp` uses a constant-time fixed-window (k=4) algorithm**, not a Montgomery
  ladder. It precomputes a 16-entry table of Montgomery powers, then for each 4-bit window
  of the exponent: squares the running result four times, decodes the window, scans the
  full 16-entry table with constant-time masked copies to fetch the matching power, and
  multiplies. The table-scan address pattern and per-window timing are independent of the
  secret exponent value. Window count is fixed at `max(e->len, ctx->len) * 32 / 4` so
  total iterations depend only on public lengths. Cost is ~1.25 multiplications per bit
  (4 squares + 1 multiply per 4 bits) versus 2 per bit for a bit-by-bit ladder, after
  amortising the 14-MontMul precompute.
- **Montgomery context reuse is an important optimisation.** Initializing a `SSFBNMont_t`
  with [`SSFBNMontInit()`](#montinit) is relatively expensive (it computes `R² mod m`). For
  repeated operations against the same modulus — RSA sign/verify loops, DH key rotation,
  Miller-Rabin witness rounds — initialise once and reuse the context across
  [`SSFBNModExpMont()`](#modexp) / [`SSFBNMontMul()`](#montmul) /
  [`SSFBNMontSquare()`](#montsquare) calls.
- **Modulus parity — Montgomery requires odd `m`.** `SSFBNMontInit` will not produce a
  correct context for even `m` (the `-m⁻¹ mod 2³²` precomputation assumes odd `m`). Every
  cryptographic modulus used with this module (RSA modulus, ECC curve prime, DH prime) is
  odd, so this is not a practical limitation — but it is a silent correctness hazard if
  you reach for this module outside those contexts.
- **Byte serialization is available in both endiannesses.** [`SSFBNFromBytes()` /
  `SSFBNToBytes()`](#serialization) read/write big-endian buffers, matching the wire format
  of ASN.1 `INTEGER`, X.509, PKCS#1, and SEC1. [`SSFBNFromBytesLE()` /
  `SSFBNToBytesLE()`](#serialization-le) are the little-endian counterparts used by
  RFC 8032 / X25519 / Ed25519 scalar encoding.
- **NIST-specific fast reduction** is available via [`SSFBNModMulNIST()`](#modmulnist) for
  the P-256 and P-384 primes (exposed as [`SSF_BN_NIST_P256`](#nist-constants) and
  [`SSF_BN_NIST_P384`](#nist-constants)). Replaces the general Barrett-style reduction with
  a few add/sub steps using the sparse structure of those primes. Falls back to the
  general `SSFBNModMul` if the modulus is neither. **Variable-time** — do not use on
  secret inputs.
- **Primality testing and random-prime generation are first-class.**
  [`SSFBNIsProbablePrime()`](#ssfbnisprobableprime) is a Miller-Rabin test (fast paths
  for `n ≤ 3` and even `n`); [`SSFBNGenPrime()`](#ssfbngenprime) draws random
  candidates with the top two bits forced (so `p · q` reaches the full `2 · bitLen`
  width) and the low bit forced (odd), screens against a 256-entry small-prime table via
  [`SSFBNModUint32()`](#ssfbnmoduint32), then confirms with Miller-Rabin. Both are
  variable-time and require an [`ssfprng`](ssfprng.md) context. Used by
  [`ssfrsa`](ssfrsa.md) key generation.
- **`SSFBNZeroize` clears limb storage but preserves the descriptor.** It writes through a
  `volatile` pointer so the compiler cannot elide the clear via dead-store elimination,
  zeros all `cap` limbs (not just `len`) plus the `len` field, but leaves `limbs` and
  `cap` intact — the `SSFBN_t` remains usable for subsequent operations. Use before any
  bignum that held secret material goes out of scope (private-key scalar, DH exponent, RSA
  decryption intermediate).

<a id="configuration"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Configuration

Options live in [`_opt/ssfbn_opt.h`](../_opt/ssfbn_opt.h). The single knob caps the limb
storage callers can request; pick the smallest width that accommodates the largest modulus
you will operate on.

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="ssf-bn-config-max-bits"></a>`SSF_BN_CONFIG_MAX_BITS` | auto | Maximum big-number width in bits. **Auto-derived in `ssfbn.h`** as `2 × largest enabled operand` from [`SSF_EC_CONFIG_ENABLE_P256/P384`](ssfec.md#configuration) and [`SSF_RSA_CONFIG_ENABLE_2048/3072/4096`](ssfrsa.md#configuration). The doubling is mandatory: multiplication produces a `2N`-limb intermediate, and `SSFBNMul` / `SSFBNModMul` / `SSFBNModMulNIST` / `SSFBNModInvExt` all gate on `2N <= MAX_LIMBS`. Resulting values: `512` for P-256-only, `768` for P-256+P-384, `4096` for RSA-2048, `6144` for RSA-3072, `8192` for RSA-4096 — the maximum across all enabled algorithms wins. Override in [`_opt/ssfbn_opt.h`](../_opt/ssfbn_opt.h) only when an out-of-tree consumer needs a wider cap; the in-tree consumers self-size correctly. |
| <a id="ssf-bn-max-mod-limbs"></a>`SSF_BN_MAX_MOD_LIMBS` | `(SSF_BN_MAX_LIMBS + 1) / 2` | Upper bound on `SSFBNMont_t::len` — the cap needed to hold a Montgomery residue (mod `m`). The `2N` derivation of `SSF_BN_CONFIG_MAX_BITS` makes `MAX_LIMBS / 2` exactly the largest possible modulus for any enabled algorithm; per-algo static asserts in `ssfbn.h` enforce this. [`SSFBNModExpMont`](#modexpmont) sizes its 16-entry window table and residue locals at this width — sticking to `SSF_BN_MAX_LIMBS` would inflate the function's stack frame by ~10 KB without ever using the extra capacity. Override in [`_opt/ssfbn_opt.h`](../_opt/ssfbn_opt.h) only when pinning `SSF_BN_CONFIG_MAX_BITS` to a non-`2N` value (no algorithm flags enabled, or an out-of-tree modulus wider than `MAX_LIMBS / 2`). |

The `SSFBN_t` struct itself is small (a pointer plus two `uint16_t` fields); the actual
limb storage lives in whatever array the caller supplies. Dropping `SSF_BN_CONFIG_MAX_BITS`
from `8192` to `768` cuts the per-array storage that `SSFBN_DEFINE(name, SSF_BN_MAX_LIMBS)`
allocates from 1024 bytes to 96 bytes, which directly reduces every caller's stack frame.
The `ssfrsa` and `ssfbn` modules sanity-check against this macro at compile time
(`SSF_BN_MAX_LIMBS <= 32767` so `a->len + b->len` cannot wrap `uint16_t` in `SSFBNMul` /
`SSFBNSquare`).

<a id="api-summary"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-bn-limb-bits"></a>`SSF_BN_LIMB_BITS` | Constant | `32` — width of one limb in bits. |
| `SSF_BN_LIMB_MAX` | Constant | `0xFFFFFFFF` — largest single-limb value. |
| `SSF_BN_BITS_TO_LIMBS(bits)` | Macro | Number of limbs needed to represent `bits` bits (rounded up). |
| <a id="ssf-bn-max-limbs"></a>`SSF_BN_MAX_LIMBS` | Constant | `SSF_BN_BITS_TO_LIMBS(SSF_BN_CONFIG_MAX_BITS)` — the maximum limb count any `SSFBN_t` may hold. |
| <a id="ssf-bn-max-mod-limbs"></a>`SSF_BN_MAX_MOD_LIMBS` | Constant | Upper bound on `SSFBNMont_t::len` — the cap needed to hold a Montgomery residue mod `m`. See [Configuration](#configuration). |
| `SSF_BN_MAX_BYTES` | Constant | `(SSF_BN_CONFIG_MAX_BITS + 7) / 8` — the maximum byte width for [serialization](#serialization). |
| `SSF_BN_KARATSUBA_THRESHOLD` | Constant | `32` — limb count at or above which `SSFBNMul` dispatches to Karatsuba (same-size, even-length operands only); schoolbook is used below. |
| `SSFBNLimb_t` | Typedef | `uint32_t` — the single-limb integer type. |
| `SSFBNDLimb_t` | Typedef | `uint64_t` — the double-wide type used internally for carry propagation. |
| <a id="ssfbn-t"></a>`SSFBN_t` | Struct | `{ SSFBNLimb_t *limbs; uint16_t len; uint16_t cap; }`. `limbs` points at caller-supplied limb storage in little-endian order (`limbs[0]` is least significant); `len` is the working limb count for the current operation (`1 ≤ len ≤ cap`); `cap` is the size of the storage in limbs. |
| <a id="ssfbnmont-t"></a>`SSFBNMont_t` | Struct | Precomputed Montgomery reduction context for a given modulus: holds the modulus `mod` (an `SSFBN_t`), `rr` (`R² mod m`, an `SSFBN_t`), `mp` (`-m⁻¹ mod 2³²`), and `len`. Treat members as opaque; declare via [`SSFBNMONT_DEFINE`](#ssfbnmont-define) and initialise via [`SSFBNMontInit()`](#montinit). |
| <a id="ssfbn-define"></a>`SSFBN_DEFINE(name, nlimbs)` | Macro | Declare an `SSFBN_t` named `name` backed by a fresh zero-initialised `SSFBNLimb_t[nlimbs]` array. Expands to two declarations (storage + struct), so it must appear in a scope that admits multiple declarations (function body or block — not an initialiser expression). Pick `nlimbs` to fit the widest operand the code path will see (`SSF_EC_MAX_LIMBS` (12) for P-384-capable ECC, `SSF_BN_BITS_TO_LIMBS(256)` (8) for P-256-only, `SSF_BN_MAX_LIMBS` for generic / RSA code). |
| <a id="ssfbnmont-define"></a>`SSFBNMONT_DEFINE(name, nlimbs)` | Macro | Declare an `SSFBNMont_t` named `name` with fresh zero-initialised limb storage for both `mod` and `rr` (each of capacity `nlimbs`). Same scope restrictions as `SSFBN_DEFINE`. |
| <a id="nist-constants"></a>`SSF_BN_NIST_P256`, `SSF_BN_NIST_P384` | `extern const SSFBN_t` | The NIST P-256 and P-384 curve primes (8 / 12 limbs respectively), ready to pass as a modulus to [`SSFBNModMulNIST()`](#modmulnist). Defined when `SSF_BN_CONFIG_MAX_BITS` is at least 512 / 768 — the cap must hold the 2N-limb intermediate product from [`SSFBNMul()`](#mul). |

<a id="functions"></a>

### Functions

**[Initialization and conversion](#init-conversion)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFBNSetZero(a, numLimbs)`](#ssfbnsetzero) | Set `a` to `0` with working limb count `numLimbs` |
| [e.g.](#ex-init) | [`void SSFBNSetUint32(a, val, numLimbs)`](#ssfbnsetuint32) | Set `a` to a small integer value |
| [e.g.](#ex-init) | [`void SSFBNSetOne(a, numLimbs)`](#ssfbnsetone) | Set `a` to `1` (shortcut for `SetUint32(a, 1, …)`) |
| [e.g.](#ex-init) | [`void SSFBNCopy(dst, src)`](#ssfbncopy) | Copy `src` into `dst` (including `len`) |
| [e.g.](#ex-serialization) | [`bool SSFBNFromBytes(a, data, dataLen, numLimbs)`](#serialization) | Import from big-endian byte array |
| [e.g.](#ex-serialization) | [`bool SSFBNToBytes(a, out, outSize)`](#serialization) | Export to big-endian byte array |
| | [`bool SSFBNFromBytesLE(a, data, dataLen, numLimbs)`](#serialization-le) | Import from little-endian byte array |
| | [`bool SSFBNToBytesLE(a, out, outSize)`](#serialization-le) | Export to little-endian byte array |

**[Comparison and predicates](#predicates)**

| | Function | Description |
|---|----------|-------------|
| | [`bool SSFBNIsZero(a)`](#predicates) | Returns `true` iff `a == 0` |
| | [`bool SSFBNIsOne(a)`](#predicates) | Returns `true` iff `a == 1` |
| | [`SSFBNIsEven(a)`](#predicates) | Macro: nonzero iff the low bit of `a` is zero |
| | [`SSFBNIsOdd(a)`](#predicates) | Macro: nonzero iff the low bit of `a` is one |
| | [`int8_t SSFBNCmp(a, b)`](#ssfbncmp) | Constant-time three-way compare |
| | [`int8_t SSFBNCmpUint32(a, val)`](#ssfbncmpuint32) | Three-way compare against a 32-bit scalar |

**[Bit-level operations](#bit-ops)**

| | Function | Description |
|---|----------|-------------|
| | [`uint32_t SSFBNBitLen(a)`](#bitlen) | Position of the most-significant set bit + 1 |
| | [`uint32_t SSFBNTrailingZeros(a)`](#trailingzeros) | Index of the lowest set bit (0-based); `a` must be nonzero |
| | [`SSFBNGetBit(a, pos)`](#getbit) | Macro: value of bit `pos` (0 = LSB); returns 0 past the limb count |
| | [`SSFBNSetBit(a, pos)`](#setbit) | Macro: set bit `pos` to 1 |
| | [`SSFBNClearBit(a, pos)`](#setbit) | Macro: clear bit `pos` to 0 |
| | [`void SSFBNShiftLeft1(a)`](#shift) | In-place left shift by 1 bit |
| | [`void SSFBNShiftRight1(a)`](#shift) | In-place right shift by 1 bit |
| | [`void SSFBNShiftLeft(a, nBits)`](#shift-multi) | In-place left shift by `nBits` |
| | [`void SSFBNShiftRight(a, nBits)`](#shift-multi) | In-place right shift by `nBits` |

**[Unsigned arithmetic](#arith)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-arith) | [`SSFBNLimb_t SSFBNAdd(r, a, b)`](#ssfbnadd) | `r = a + b`; returns carry-out |
| [e.g.](#ex-arith) | [`SSFBNLimb_t SSFBNSub(r, a, b)`](#ssfbnsub) | `r = a − b`; returns borrow-out (1 iff `a < b`) |
| | [`SSFBNLimb_t SSFBNAddUint32(r, a, b)`](#ssfbnaddsubuint32) | `r = a + b` for a single 32-bit `b`; returns carry-out |
| | [`SSFBNLimb_t SSFBNSubUint32(r, a, b)`](#ssfbnaddsubuint32) | `r = a − b` for a single 32-bit `b`; returns borrow-out |
| [e.g.](#ex-arith) | [`void SSFBNMul(r, a, b)`](#ssfbnmul) | `r = a × b`; `r->len` set to `a->len + b->len`; `r` must not alias `a` or `b` |
| | [`void SSFBNMulUint32(r, a, b)`](#ssfbnmuluint32) | `r = a × b` for a single 32-bit `b`; `r->len` = `a->len + 1` |
| | [`void SSFBNSquare(r, a)`](#ssfbnsquare) | `r = a²`; `r->len = 2 × a->len`; faster than `SSFBNMul(r, a, a)` |

**[Modular arithmetic](#modarith)**

| | Function | Description |
|---|----------|-------------|
| | [`void SSFBNMod(r, a, m)`](#ssfbnmod) | `r = a mod m`; `a->len` may be up to `2 × m->len` |
| | [`void SSFBNDivMod(q, rem, a, b)`](#ssfbndivmod) | `q = a / b`, `rem = a mod b` via shift-and-subtract long division |
| | [`void SSFBNModAdd(r, a, b, m)`](#modaddsub) | `r = (a + b) mod m`; requires `a, b < m` |
| | [`void SSFBNModSub(r, a, b, m)`](#modaddsub) | `r = (a − b) mod m`; requires `a, b < m` |
| [e.g.](#ex-modmul) | [`void SSFBNModMul(r, a, b, m)`](#ssfbnmodmul) | `r = (a × b) mod m`; general-purpose |
| | [`void SSFBNModMulCT(r, a, b, m)`](#ssfbnmodmulct) | `r = (a × b) mod m`, constant-time; for secret `a` or `b` |
| | [`void SSFBNModSquare(r, a, m)`](#ssfbnmodsquare) | `r = (a²) mod m`; `Square` then `Mod` (variable-time) |
| | [`void SSFBNModMulNIST(r, a, b, m)`](#modmulnist) | `r = (a × b) mod m` using NIST fast reduction for P-256 / P-384 |
| | [`bool SSFBNModInv(r, a, m)`](#modinv) | `r = a⁻¹ mod m` via Fermat's little theorem (prime `m`) |
| | [`bool SSFBNModInvExt(r, a, m)`](#modinv) | `r = a⁻¹ mod m` via binary extended GCD (any coprime `m`) |
| | [`void SSFBNGcd(r, a, b)`](#ssfbngcd) | `r = gcd(a, b)` via binary GCD |

**[Montgomery multiplication](#mont)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-mont) | [`void SSFBNMontInit(ctx, m)`](#montinit) | Precompute Montgomery context for odd modulus `m` |
| [e.g.](#ex-mont) | [`void SSFBNMontMul(r, a, b, ctx)`](#montmul) | `r = a × b × R⁻¹ mod m` (operands in Montgomery form) |
| [e.g.](#ex-mont) | [`void SSFBNMontSquare(r, a, ctx)`](#montsquare) | `r = a² × R⁻¹ mod m`; semantically `MontMul(r, a, a, ctx)` |
| [e.g.](#ex-mont) | [`void SSFBNMontConvertIn(aR, a, ctx)`](#montconv) | Convert normal → Montgomery form |
| [e.g.](#ex-mont) | [`void SSFBNMontConvertOut(a, aR, ctx)`](#montconv) | Convert Montgomery → normal form |

**[Modular exponentiation](#modexp)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-modexp) | [`void SSFBNModExp(r, a, e, m)`](#modexp) | `r = aᵉ mod m`; constant-time fixed-window (k=4) |
| [e.g.](#ex-modexp) | [`void SSFBNModExpMont(r, a, e, ctx)`](#modexp) | Same, using a precomputed `SSFBNMont_t` |
| | [`void SSFBNModExpPub(r, a, e, m)`](#modexppub) | Variable-time `r = aᵉ mod m`; **public exponents only** |
| | [`void SSFBNModExpMontPub(r, a, e, ctx)`](#modexppub) | Variable-time, with precomputed `SSFBNMont_t` |

**[Primality and randomness](#prime-rand)**

| | Function | Description |
|---|----------|-------------|
| | [`uint32_t SSFBNModUint32(a, d)`](#ssfbnmoduint32) | `a mod d` for a 32-bit divisor; trial-division helper |
| | [`void SSFBNRandom(a, numLimbs, prng)`](#ssfbnrandom) | Fill `numLimbs` of `a` with PRNG bytes |
| | [`bool SSFBNRandomBelow(a, bound, prng)`](#ssfbnrandombelow) | Uniform random in `[0, bound)` via rejection sampling |
| | [`bool SSFBNIsProbablePrime(n, rounds, prng)`](#ssfbnisprobableprime) | Miller-Rabin primality test with `rounds` random witnesses |
| | [`bool SSFBNGenPrime(p, bitLen, rounds, prng)`](#ssfbngenprime) | Generate a random `bitLen`-bit prime |

**[Utility](#utility)**

| | Function | Description |
|---|----------|-------------|
| | [`void SSFBNCondSwap(a, b, swap)`](#condswap) | Constant-time swap if `swap != 0` |
| | [`void SSFBNCondCopy(dst, src, sel)`](#condswap) | Constant-time copy if `sel != 0` |
| | [`void SSFBNZeroize(a)`](#ssfbnzeroize) | Compiler-opaque zero of the limb storage and `len` |

<a id="function-reference"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Function Reference

<a id="init-conversion"></a>

### [↑](#functions) Initialization and Conversion

<a id="ssfbnsetzero"></a>
```c
void SSFBNSetZero(SSFBN_t *a, uint16_t numLimbs);
```
Sets `a` to zero with working limb count `numLimbs`. `numLimbs` must satisfy
`1 ≤ numLimbs ≤ a->cap`.

<a id="ssfbnsetuint32"></a>
```c
void SSFBNSetUint32(SSFBN_t *a, uint32_t val, uint16_t numLimbs);
```
Sets `a` to the small integer `val` (placed in `limbs[0]`; remaining limbs zeroed) with
working limb count `numLimbs`. Useful for loading scalars like `1`, `2`, or a small public
exponent.

<a id="ssfbnsetone"></a>
```c
void SSFBNSetOne(SSFBN_t *a, uint16_t numLimbs);
```
Shortcut for `SSFBNSetUint32(a, 1u, numLimbs)`. Used wherever the multiplicative identity
is needed (e.g., the seed for ModExp's running result before window iteration).

<a id="ssfbncopy"></a>
```c
void SSFBNCopy(SSFBN_t *dst, const SSFBN_t *src);
```
Copies `src` to `dst`. `dst->len` is set to `src->len`. Works for any source length;
`src->len ≤ dst->cap` is required.

<a id="serialization"></a>
```c
bool SSFBNFromBytes(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs);
bool SSFBNToBytes(const SSFBN_t *a, uint8_t *out, size_t outSize);
```
Big-endian byte-buffer conversion, matching the wire format of PKCS#1, SEC1, ASN.1 INTEGER,
and X.509 subjects. `SSFBNFromBytes` zero-pads `data` (if shorter than `numLimbs × 4` bytes)
and sets `a->len` to `numLimbs`; returns `false` if `data` cannot fit in `numLimbs`.
`SSFBNToBytes` writes exactly `outSize` bytes, zero-padding the leading positions; returns
`false` if `outSize` is too small to represent the value.

<a id="serialization-le"></a>
```c
bool SSFBNFromBytesLE(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs);
bool SSFBNToBytesLE(const SSFBN_t *a, uint8_t *out, size_t outSize);
```
Little-endian counterparts of the BE pair. `data[0]` is the lowest byte of `limbs[0]`. Used
by RFC 8032 (Ed25519) and RFC 7748 (X25519) scalar / point encodings, and by any
LE-native algorithm being ported in. Same zero-pad / too-large semantics as the BE
versions.

<a id="ex-init"></a>

**Example:**

```c
/* Working in 256-bit (8-limb) space — enough for ECC-P-256 operations. */
SSFBN_DEFINE(a, SSF_BN_BITS_TO_LIMBS(256));
SSFBN_DEFINE(b, SSF_BN_BITS_TO_LIMBS(256));
const uint16_t nLimbs = SSF_BN_BITS_TO_LIMBS(256);

SSFBNSetZero(&a, nLimbs);            /* a = 0 */
SSFBNSetUint32(&b, 65537u, nLimbs);  /* b = 0x00010001 (RSA "F4" exponent) */

SSFBNCopy(&a, &b);                   /* a = b */
```

<a id="ex-serialization"></a>

**Example:**

```c
/* Import a 256-bit value from a 32-byte BE array (e.g., an ECC private key
   received over the wire). */
uint8_t  wire[32] = { /* ... big-endian octets ... */ };
SSFBN_DEFINE(x, SSF_BN_BITS_TO_LIMBS(256));
bool     ok = SSFBNFromBytes(&x, wire, sizeof(wire), SSF_BN_BITS_TO_LIMBS(256));
/* ok == true on success; x.len == 8 and x.limbs[] holds the little-endian
   limb representation of the BE wire integer. */

/* Export back out to a fixed-width byte array (for signing, KDF input, etc.) */
uint8_t out[32];
SSFBNToBytes(&x, out, sizeof(out));   /* round-trips exactly for a well-sized buffer */
```

---

<a id="predicates"></a>

### [↑](#functions) Predicates and Comparison

<a id="ssfbncmp"></a>
```c
bool   SSFBNIsZero(const SSFBN_t *a);
bool   SSFBNIsOne (const SSFBN_t *a);
#define SSFBNIsEven(a)  /* nonzero iff (a)->limbs[0] & 1 == 0 */
#define SSFBNIsOdd(a)   /* nonzero iff (a)->limbs[0] & 1 != 0 */
int8_t SSFBNCmp  (const SSFBN_t *a, const SSFBN_t *b);
```

`SSFBNIsZero` / `SSFBNIsOne` are the obvious value checks; they short-circuit on the first
non-matching limb and are **not** constant-time — do not use them to branch on secret values.

`SSFBNIsEven` and `SSFBNIsOdd` are macros that inspect only the low bit of `limbs[0]`, so
they are constant-time (no per-limb scan) and have no call overhead — important for the hot
paths in binary-GCD and Miller-Rabin. The argument must be a non-NULL pointer to an
`SSFBN_t` with `len ≥ 1`; debug-build assertions in the function form are dropped.

`SSFBNCmp` returns `0` if `a == b`, `-1` if `a < b`, and `+1` if `a > b`. It walks every limb
without early exit and is the correct primitive for comparing secret values (e.g., checking
whether `S < n` in ECDSA verification). Both operands must have the same `len`.

<a id="ssfbncmpuint32"></a>
```c
int8_t SSFBNCmpUint32(const SSFBN_t *a, uint32_t val);
```
Three-way compare against a 32-bit scalar (`0`, `-1`, `+1` semantics). Avoids constructing
a throw-away `SSFBN_t` for small-integer comparisons against `0`, `1`, `2`, `3`, etc. — the
fast paths inside `SSFBNIsProbablePrime` use it before entering Miller-Rabin proper.

---

<a id="bit-ops"></a>

### [↑](#functions) Bit-level Operations

<a id="bitlen"></a>
```c
uint32_t SSFBNBitLen(const SSFBN_t *a);
```
Returns `⌊log₂(a)⌋ + 1` — the position of the most significant set bit plus one, i.e., the
number of bits needed to represent `a`. Returns `0` if `a == 0`. Variable-time — public
input only. Used to size a public exponent before encoding as ASN.1 and to drive the
window count in `SSFBNModExp`.

<a id="trailingzeros"></a>
```c
uint32_t SSFBNTrailingZeros(const SSFBN_t *a);
```
Returns the index of the lowest set bit (0-based). `a` must be nonzero (asserted via
`SSF_REQUIRE`). Used by Miller-Rabin to factor `n − 1 = 2ˢ · d` and by binary-GCD-style
algorithms that strip factors of 2. Variable-time — public input only.

<a id="getbit"></a>
```c
#define SSFBNGetBit(a, pos)  /* value of bit pos (0 = LSB), 0 if pos beyond the limb count */
```
Macro form to eliminate call overhead in `SSFBNModExp` window-decode loops and in
`ssfec`'s scalar-multiplication ladder. Both `a` and `pos` are evaluated more than once —
callers must avoid side-effecting expressions for either argument.

<a id="setbit"></a>
```c
#define SSFBNSetBit(a, pos)    /* set bit pos to 1 */
#define SSFBNClearBit(a, pos)  /* set bit pos to 0 */
```
Macro pair; each is wrapped in a `do { … } while (0)` so it can be used as a statement.
`pos` must satisfy `pos < a->len * SSF_BN_LIMB_BITS`. Same multi-evaluation caveat as
`SSFBNGetBit`.

<a id="shift"></a>
```c
void SSFBNShiftLeft1(SSFBN_t *a);
void SSFBNShiftRight1(SSFBN_t *a);
```
In-place 1-bit shifts. `ShiftLeft1` discards the top bit if it overflows the active limb
count; `ShiftRight1` discards the LSB. These are the building blocks for the binary-GCD
and binary-extended-GCD paths elsewhere in the module.

<a id="shift-multi"></a>
```c
void SSFBNShiftLeft (SSFBN_t *a, uint32_t nBits);
void SSFBNShiftRight(SSFBN_t *a, uint32_t nBits);
```
Multi-bit shifts in place: at most one limb-shift pass plus one bit-shift pass, so total
work is `O(a->len)` regardless of `nBits`. Bits shifted past the active limb count are
discarded. If `nBits ≥ a->len * SSF_BN_LIMB_BITS` the result is zero. Used by Miller-Rabin
to compute `d` from `n − 1` and by general-purpose shift-by-`s` operations.

---

<a id="arith"></a>

### [↑](#functions) Unsigned Arithmetic

Unless otherwise stated, all two-operand functions require `a->len == b->len`; `r->len`
takes the same value.

<a id="ssfbnadd"></a>
```c
SSFBNLimb_t SSFBNAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
```
Computes `r = a + b` and returns the final carry-out (`0` or `1`). `r` may alias `a` or `b`.
The carry return is useful when doing multi-precision sums that need to grow by a limb —
e.g., when implementing a higher-level Barrett reduction.

<a id="ssfbnsub"></a>
```c
SSFBNLimb_t SSFBNSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
```
Computes `r = a − b` and returns the final borrow (`0` if `a ≥ b`, `1` if `a < b`). `r` may
alias `a` or `b`. Callers wanting a signed result can inspect the borrow and conditionally
negate.

<a id="ssfbnaddsubuint32"></a>
```c
SSFBNLimb_t SSFBNAddUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b);
SSFBNLimb_t SSFBNSubUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b);
```
Add / subtract a single 32-bit value to / from a multi-precision `a`. `r->len` is set to
`a->len`; `r` may alias `a`. Carry / borrow propagates through every limb, so the cost is
`O(a->len)`. Convenient for `n − 1` / `n − 2` / `n − 3` constructions used inside
`SSFBNModInv` (Fermat exponent) and `SSFBNIsProbablePrime` (witness range).

<a id="ssfbnmul"></a>
```c
void SSFBNMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
```
Unsigned multi-precision multiply. `r->len` is set to `a->len + b->len`; that sum must be
`≤ SSF_BN_MAX_LIMBS` and `≤ r->cap`. **`r` must not alias `a` or `b`.** Same-size,
even-length operands at or above `SSF_BN_KARATSUBA_THRESHOLD` (32 limbs) take a one-level
Karatsuba path (~0.75 · n² single-limb multiplies); everything else uses schoolbook (n²).
The schoolbook inner loop deliberately performs no zero-limb skipping, so timing depends
only on `a->len` and `b->len`, not on operand values.

For modular multiplication, prefer [`SSFBNModMul`](#ssfbnmodmul) (no expansion) or
[`SSFBNMontMul`](#montmul) (Montgomery-form inputs).

<a id="ssfbnmuluint32"></a>
```c
void SSFBNMulUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b);
```
Multiply a multi-precision `a` by a single 32-bit `b`. `r->len` is set to `a->len + 1`
(the product can grow by at most one limb). `r` must not alias `a`.

<a id="ssfbnsquare"></a>
```c
void SSFBNSquare(SSFBN_t *r, const SSFBN_t *a);
```
Computes `r = a²`. Faster than `SSFBNMul(r, a, a)` because the off-diagonal partial products
are computed once and doubled rather than computed twice. `r->len` is set to `2 × a->len`;
that must be `≤ SSF_BN_MAX_LIMBS` and `≤ r->cap`. `r` must not alias `a`.

<a id="ex-arith"></a>

**Example:**

```c
SSFBN_DEFINE(a, 8);
SSFBN_DEFINE(b, 8);
SSFBN_DEFINE(r, 8);
SSFBN_DEFINE(product, 16);  /* needs 2 × operand width */
const uint16_t nLimbs = 8;  /* 256-bit working width */

SSFBNSetUint32(&a, 100u, nLimbs);
SSFBNSetUint32(&b,  50u, nLimbs);

SSFBNLimb_t carry  = SSFBNAdd(&r, &a, &b);   /* r = 150, carry = 0 */
SSFBNLimb_t borrow = SSFBNSub(&r, &a, &b);   /* r = 50,  borrow = 0 */
                                             /* If b > a, borrow = 1 and r holds
                                                the wrapped two's-complement value. */

SSFBNMul(&product, &a, &b);                  /* product = 5000, product.len = 16 */
```

---

<a id="modarith"></a>

### [↑](#functions) Modular Arithmetic

`ModAdd` / `ModSub` require operands already reduced (`a, b < m`); use
[`SSFBNMod`](#ssfbnmod) first if that is not guaranteed. `ModMul` / `ModSquare` reduce the
unreduced product internally and tolerate any same-length input. The result is always
strictly less than `m`.

<a id="ssfbnmod"></a>
```c
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
```
`r = a mod m`. `a->len` may be as large as `2 × m->len` (supports reducing the output of
`SSFBNMul` / `SSFBNSquare`). `r->len` is set to `m->len`. **Variable-time** — shift-and-
subtract long division branches on the bit pattern of `a`; do not call on secret `a` or
`m`.

<a id="ssfbndivmod"></a>
```c
void SSFBNDivMod(SSFBN_t *q, SSFBN_t *rem, const SSFBN_t *a, const SSFBN_t *b);
```
Full shift-and-subtract long division: `q = a / b`, `rem = a mod b`. Both `q` and `rem`
are sized to `max(a->len, b->len)`. `q` must not alias `a`, `b`, or `rem`; `rem` must not
alias `a`, `b`, or `q`. `b` must be nonzero (asserted). Variable-time — public input only.

<a id="modaddsub"></a>
```c
void SSFBNModAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
void SSFBNModSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
```
`r = (a ± b) mod m`. Both operands must be reduced (`a, b < m`). `r` may alias `a` or `b`.

<a id="ssfbnmodmul"></a>
```c
void SSFBNModMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
```
`r = (a × b) mod m` using `SSFBNMul` (which itself dispatches to Karatsuba when applicable)
followed by `SSFBNMod`. General-purpose; works for any modulus. **Variable-time** —
inherits the bit-pattern-dependent timing of `SSFBNMod`, so do not call on secret operands.
For modular multiplications on secret data — and for many multiplications against the same
modulus (the RSA / DH case) — go through the Montgomery path
([`SSFBNMontMul`](#montmul) / [`SSFBNMontSquare`](#montsquare)).

<a id="ssfbnmodmulct"></a>
```c
void SSFBNModMulCT(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
```
`r = (a × b) mod m`. Mathematically equivalent to [`SSFBNModMul`](#ssfbnmodmul) but the
iteration count and per-iteration work do not depend on the values of `a`, `b`, or
intermediate state — only on the limb count of `m`. **Constant-time** — use this when `a`
or `b` are secret (e.g., ECDSA signing's `k⁻¹` and `d`-derived operands modulo the curve
order). Cost: ~2–3× slower than `SSFBNModMul` for typical inputs because it always does
worst-case work. Algorithm: schoolbook multiply (already CT) followed by fixed-iteration
shift-and-subtract reduction with branchless mask-conditional commits.

<a id="ssfbnmodsquare"></a>
```c
void SSFBNModSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
```
`r = a² mod m` using `SSFBNSquare` followed by `SSFBNMod`. `r` may alias `a`. Inherits the
**variable-time** behaviour of `SSFBNMod` — public input only. Used by
`SSFBNIsProbablePrime` for the witness inner squaring loop.

<a id="ex-modmul"></a>

**Example:**

```c
SSFBN_DEFINE(a, SSF_BN_BITS_TO_LIMBS(256));
SSFBN_DEFINE(b, SSF_BN_BITS_TO_LIMBS(256));
SSFBN_DEFINE(m, SSF_BN_BITS_TO_LIMBS(256));
SSFBN_DEFINE(r, SSF_BN_BITS_TO_LIMBS(256));
const uint16_t nLimbs = SSF_BN_BITS_TO_LIMBS(256);

/* Assume a, b, m already loaded from somewhere, with a < m and b < m. */

SSFBNModMul(&r, &a, &b, &m);  /* r = (a * b) mod m, in r->len = m->len limbs */
```

<a id="modmulnist"></a>
```c
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m);
```
Specialised modular multiplication for the NIST P-256 and P-384 primes (passed as
[`SSF_BN_NIST_P256`](#nist-constants) or [`SSF_BN_NIST_P384`](#nist-constants)). Uses the
sparse structure of those primes to replace a general Barrett reduction with a short
sequence of adds and subtracts — significantly faster on a microcontroller. Falls back to
[`SSFBNModMul()`](#ssfbnmodmul) for any other modulus. **Variable-time** (branches on the
reduction result) — this is fine for the public curve arithmetic in ECDH and ECDSA
verification, but inappropriate for secret scalars.

<a id="modinv"></a>
```c
bool SSFBNModInv   (SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
```
`r = a⁻¹ mod m`. Both return `false` if the inverse does not exist (`gcd(a, m) ≠ 1`).

- [`SSFBNModInv`](#modinv) computes `a^(m-2) mod m` via the constant-time
  [`SSFBNModExp`](#modexp), then verifies the result satisfies `a · r ≡ 1 (mod m)` and
  returns `false` if not. **Constant-time on the success path** for prime `m`. For non-
  prime `m` (or when `gcd(a, m) ≠ 1`) the verification check fails and the function
  returns `false` — the post-Fermat verify makes the function safe to call on any modulus,
  but it is only *useful* (yields a result) when `m` is prime. Use this on secret `a`
  whenever `m` is a curve order, a field prime, or a Diffie-Hellman group order.
- [`SSFBNModInvExt`](#modinv) uses the binary extended Euclidean algorithm. Works for any
  coprime `a` and `m`. **Variable-time** — do not use on secret inputs. Use this only when
  the modulus is known non-prime (e.g., RSA's `phi(n)` or CRT helpers) and the inputs are
  not secret.

<a id="ssfbngcd"></a>
```c
void SSFBNGcd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
```
Binary-GCD (Stein's algorithm) producing `r = gcd(a, b)`. Variable-time. `a` and `b` must
have the same `len`.

---

<a id="mont"></a>

### [↑](#functions) Montgomery Multiplication

Montgomery form replaces `a` with `aR mod m` (where `R = 2^(len·32)`), replacing the
expensive mod-`m` reduction after each multiply with a much cheaper mod-`R` reduction. The
setup (`SSFBNMontInit`) amortises over however many multiplies are then done under that
modulus. Best used as the backing path for [modular exponentiation](#modexp); also useful
when a protocol performs many multiplications against a single modulus (e.g., RSA private
operation, DH exponent computation).

<a id="montinit"></a>
```c
void SSFBNMontInit(SSFBNMont_t *ctx, const SSFBN_t *m);
```
Initialise `ctx` for modulus `m`. Precomputes `rr = R² mod m` and `mp = -m⁻¹ mod 2³²`. `m`
must be odd (every cryptographic modulus used with this module is). `ctx->len` and the
embedded `mod`/`rr` lengths are set from `m->len`.

<a id="montmul"></a>
```c
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx);
```
`r = a × b × R⁻¹ mod m`. Both `a` and `b` must already be in Montgomery form; the result is
also in Montgomery form. Constant-time. `r` may alias `a` or `b`.

<a id="montsquare"></a>
```c
void SSFBNMontSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBNMont_t *ctx);
```
Semantically equivalent to `SSFBNMontMul(r, a, a, ctx)`; exposed as a dedicated entry point
so the squaring sites inside `SSFBNModExpMont` and the like can be accelerated by a future
square-optimised CIOS loop without changing the caller. `r` may alias `a`.

<a id="montconv"></a>
```c
void SSFBNMontConvertIn (SSFBN_t *aR, const SSFBN_t *a,  const SSFBNMont_t *ctx);
void SSFBNMontConvertOut(SSFBN_t *a,  const SSFBN_t *aR, const SSFBNMont_t *ctx);
```
Convert between normal and Montgomery representations. `ConvertIn` computes
`aR = a × R mod m` by multiplying `a` by the precomputed `R²`. `ConvertOut` multiplies by
`1` in Montgomery form to strip the factor, producing `a`.

<a id="ex-mont"></a>

**Example:**

```c
SSFBNMONT_DEFINE(ctx, SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(m,        SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(base,     SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(baseMont, SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(accMont,  SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(result,   SSF_BN_MAX_LIMBS);

/* Load modulus and base ... */

SSFBNMontInit(&ctx, &m);                /* Amortised once */

SSFBNMontConvertIn(&baseMont, &base, &ctx);

/* Perform many multiplies cheaply, e.g. squaring-chain. */
SSFBNCopy(&accMont, &baseMont);
for (int i = 0; i < 16; i++)
{
    SSFBNMontSquare(&accMont, &accMont, &ctx);  /* acc <- acc^2 */
}

SSFBNMontConvertOut(&result, &accMont, &ctx);   /* result = base^(2^16) mod m */
```

---

<a id="modexp"></a>

### [↑](#functions) Modular Exponentiation

```c
void SSFBNModExp    (SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx);
```

`r = aᵉ mod m`. Uses a **constant-time fixed-window** algorithm with window width `k = 4`:

1. Convert `a` into Montgomery form (`aM`).
2. Build a 16-entry table of Montgomery powers — `table[0] = Mont(1)`, `table[1] = aM`,
   `table[i] = table[i-1] · aM` for `i = 2..15`.
3. For each 4-bit window of `e` from MSB to LSB: square the running result four times,
   decode the window value `w`, fetch `table[w]` via a constant-time scan that walks all
   16 entries with `SSFBNCondCopy`, and multiply.
4. Convert out of Montgomery form.

The table-scan address pattern and per-window timing are independent of the secret
exponent value, and the window count is fixed at `max(e->len, ctx->len) · 32 / 4` — which
depends only on public storage lengths. Cost is ~1.25 multiplications per bit (4 squares
+ 1 multiply per 4-bit window) versus 2 per bit for a bit-by-bit ladder, after
amortising the 14-MontMul precompute. This is the primitive that RSA private operations,
DH key exchange, and `SSFBNModInv` (via Fermat) rely on for side-channel resistance.

- [`SSFBNModExp`](#modexp) allocates an `SSFBNMont_t` on the stack, initialises it, and
  tears it down for each call. Convenient for a single operation.
- [`SSFBNModExpMont`](#modexp) takes a caller-owned `ctx`, skipping the init / teardown.
  Use when multiple exponentiations share a modulus (RSA signing with repeated messages,
  DH key refresh, the Miller-Rabin witness rounds).

`a` should satisfy `a < m`. `e` is processed window-by-window up to the fixed window
count; `e == 0` produces a result of `1` because every window is zero and `table[0] =
Mont(1)`.

<a id="modexppub"></a>
```c
void SSFBNModExpPub    (SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);
void SSFBNModExpMontPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx);
```
Variable-time `r = aᵉ mod m` via left-to-right binary square-and-multiply: every iteration
squares; the multiply step runs only when the current bit of `e` is `1`. Typical 2–3×
faster than `SSFBNModExp` for low-Hamming-weight exponents (e.g., RSA's `e = 65537 =
0x10001` has only two set bits out of 17).

**Public-input only.** Timing and memory access pattern depend on the bit pattern of `e`.
Use only when `e` is public — RSA verify, signature verification, public-key operations.
For secret exponents (RSA private key operations, DH with secret scalars), use
`SSFBNModExp` instead.

<a id="ex-modexp"></a>

**Example:**

```c
/* Single RSA verify-style exponentiation: s = c^e mod n (e = 65537). The exponent is
   public, so the variable-time path is faster. */
SSFBN_DEFINE(c, SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
/* ... load c, e, n from PKCS#1 data ... */
SSFBNModExpPub(&s, &c, &e, &n);

/* Repeated operations against the same modulus (e.g. DH with a secret exponent) — cache
   the context and use the constant-time path. */
SSFBNMONT_DEFINE(ctx, SSF_BN_MAX_LIMBS);
SSFBNMontInit(&ctx, &n);

SSFBN_DEFINE(d,  SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(y1, SSF_BN_MAX_LIMBS);
SSFBN_DEFINE(y2, SSF_BN_MAX_LIMBS);
SSFBNModExpMont(&y1, &c, &d, &ctx);
SSFBNModExpMont(&y2, &c, &d, &ctx);
/* ... etc. No redundant R^2 computation. */
```

---

<a id="prime-rand"></a>

### [↑](#functions) Primality and Randomness

These entry points exist primarily to support [`ssfrsa`](ssfrsa.md) key generation. All
require an [`ssfprng`](ssfprng.md) context and are variable-time.

<a id="ssfbnmoduint32"></a>
```c
uint32_t SSFBNModUint32(const SSFBN_t *a, uint32_t d);
```
Returns `a mod d` for a 32-bit divisor `d`. Implemented as a single MSB-to-LSB pass over
the limbs using 64-bit modular arithmetic. Used by `SSFBNGenPrime` to trial-divide
candidates against a 256-entry small-prime table (up to 1613) before invoking the
relatively expensive Miller-Rabin test. `d` must be nonzero (asserted).

<a id="ssfbnrandom"></a>
```c
void SSFBNRandom(SSFBN_t *a, uint16_t numLimbs, SSFPRNGContext_t *prng);
```
Fills the low `numLimbs` of `a` with raw bytes from `prng`, chunked at
`SSF_PRNG_RANDOM_MAX_SIZE`. Sets `a->len = numLimbs`; limbs above `numLimbs` are not
modified. Caller must ensure `numLimbs ≤ a->cap`.

<a id="ssfbnrandombelow"></a>
```c
bool SSFBNRandomBelow(SSFBN_t *a, const SSFBN_t *bound, SSFPRNGContext_t *prng);
```
Draws a uniform random value in `[0, bound)` via rejection sampling: draw `bitLen(bound)`
random bits, accept if `< bound`, otherwise re-draw. `a->len` is set to `bound->len`.
Returns `false` if an internal retry cap (100 attempts) is exceeded — vanishingly unlikely
for any cryptographic bound, where the rejection probability per draw is `≤ 1/2`. `bound`
must be nonzero.

<a id="ssfbnisprobableprime"></a>
```c
bool SSFBNIsProbablePrime(const SSFBN_t *n, uint16_t rounds, SSFPRNGContext_t *prng);
```
Miller-Rabin primality test. Returns `true` if `n` is probably prime after `rounds` random-
witness trials (each round bounds the false-positive probability at ~1/4). Fast paths
return immediately for `n ≤ 1` (false), `n ∈ {2, 3}` (true), and even `n > 3` (false).
Suitable rounds for cryptographic use: `≥ 5`. RSA key generation typically uses 5–40
depending on modulus size.

Internally writes `n − 1 = 2ˢ · d` (using `SSFBNTrailingZeros` and `SSFBNShiftRight`),
then for each round picks a random witness `a ∈ [2, n − 2]` (via `SSFBNRandom` with
post-mask), computes `x = aᵈ mod n` via `SSFBNModExpMont` (the precomputed Montgomery
context is reused across rounds), and applies the standard Miller-Rabin inner loop.

<a id="ssfbngenprime"></a>
```c
bool SSFBNGenPrime(SSFBN_t *p, uint16_t bitLen, uint16_t rounds, SSFPRNGContext_t *prng);
```
Generate a random prime of exactly `bitLen` bits. The two top bits are forced high (so the
product of two such primes has the full `2 · bitLen` bit length), the low bit is forced to
make the candidate odd, the candidate is trial-divided against the 256-entry small-prime
table, and survivors go through `rounds` Miller-Rabin rounds. Returns `false` if no prime
is found within an internal attempt cap (50000).

`bitLen` must be `≥ 8` and `≤ SSF_BN_CONFIG_MAX_BITS`.

---

<a id="utility"></a>

### [↑](#functions) Utility

<a id="condswap"></a>
```c
void SSFBNCondSwap(SSFBN_t *a, SSFBN_t *b, SSFBNLimb_t swap);
void SSFBNCondCopy(SSFBN_t *dst, const SSFBN_t *src, SSFBNLimb_t sel);
```
Constant-time conditional primitives. **Every limb** of both operands is touched regardless
of the control input, so the branch direction does not leak via cache or timing. `swap` and
`sel` are treated as "nonzero → perform the operation". `SSFBNCondCopy` is the workhorse
behind the constant-time table scan inside [`SSFBNModExp`](#modexp), and is available for
callers building their own constant-time point / scalar selection logic (ECDH, scalar
multiplication). Both operands must have the same `len`.

<a id="ssfbnzeroize"></a>
```c
void SSFBNZeroize(SSFBN_t *a);
```
Zero every limb of the storage that `a->limbs` points at — all `cap` limbs, not just the
active `len` — and clear `a->len` to `0`. Performed via a `volatile`-qualified pointer so
the compiler cannot remove the writes via dead-store elimination. The `limbs` and `cap`
fields are left intact, so the `SSFBN_t` remains a valid descriptor for subsequent
operations. Use before any bignum that held secret material goes out of scope — a
private-key scalar, a DH exponent, an RSA decryption intermediate.
