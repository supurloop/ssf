# ssfbn — Multi-Precision Big Number Arithmetic

[SSF](../README.md) | [Cryptography](README.md)

Fixed-capacity multi-precision integer arithmetic over a 32-bit limb (4096-bit default).
Provides the primitives that [`ssfrsa`](ssfrsa.h), [`ssfec`](ssfec.h),
[`ssfecdsa`](ssfecdsa.h), and related public-key modules are built on: unsigned add / subtract
/ multiply, modular reduction and arithmetic, modular inverse, extended Euclidean GCD, a
constant-time Montgomery-ladder `ModExp`, and the Montgomery multiplication / conversion
primitives that make large-modulus exponentiation affordable on a microcontroller.

Numbers are stored as a struct ([`SSFBN_t`](#ssfbn-t)) that embeds a fixed-size limb array
plus a `len` field indicating how many of those limbs are in use for the current operation.
Callers pick the working `len` at initialisation (usually the key / curve / modulus size in
limbs) and pass that struct to the arithmetic functions. There is no dynamic allocation.

This module is intended as a back-end — most callers will use it indirectly through the
higher-level modules. Direct use is appropriate when implementing a protocol not already
covered by SSF (e.g., a custom Diffie-Hellman group) or when porting algorithms out of
other big-integer libraries.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Notes

- **`len`-matching is mandatory.** Every two-operand function (`Add`, `Sub`, `Cmp`, `ModAdd`,
  `ModSub`, `ModMul`, `ModInv*`, `ModExp`, `CondSwap`, `CondCopy`, `Gcd`) requires
  `a->len == b->len` — and, for modular operations, equal to `m->len` as well. The caller is
  responsible for zero-padding shorter inputs up to the working limb count before calling.
  Passing mismatched `len` values produces silently-wrong results, not a `SSF_REQUIRE`
  failure.
- **Modular operands must already be reduced.** `SSFBNModAdd`, `SSFBNModSub`, and
  `SSFBNModMul` require `a, b < m` on input. If operands may exceed the modulus, reduce them
  first with [`SSFBNMod()`](#ssfbnmod).
- **Not all functions are constant time.** Callers who handle secret data (private keys,
  nonces, ephemeral scalars) must restrict themselves to the constant-time primitives:

  | Status | Functions |
  |---|---|
  | **Constant-time** (safe on secrets) | [`SSFBNCmp`](#ssfbncmp), [`SSFBNModExp`](#modexp), [`SSFBNModExpMont`](#modexp), [`SSFBNMontMul`](#montmul), [`SSFBNMontConvertIn`/`Out`](#montconv), [`SSFBNCondSwap`](#condswap), [`SSFBNCondCopy`](#condswap), [`SSFBNAdd`](#ssfbnadd), [`SSFBNSub`](#ssfbnsub), [`SSFBNModAdd`](#modaddsub), [`SSFBNModSub`](#modaddsub), [`SSFBNModMul`](#ssfbnmodmul) |
  | **Variable-time** (do not use on secrets) | [`SSFBNMod`](#ssfbnmod), [`SSFBNGcd`](#ssfbngcd), [`SSFBNModInvExt`](#modinv), [`SSFBNModMulNIST`](#modmulnist), [`SSFBNBitLen`](#bitlen), [`SSFBNIsZero`/`IsOne`/`IsEven`](#predicates), [`SSFBNShiftLeft1`/`Right1`](#shift) |
  | **Constant-time only when `m` is prime** | [`SSFBNModInv`](#modinv) — uses Fermat's little theorem (`a^(m-2) mod m`), which is constant-time but yields the correct answer only for prime `m`. Returns `false` for non-prime moduli that have an inverse. |
- **Secret scalars go through `SSFBNModInv` (with prime `m`) or the ModExp path, never
  `SSFBNModInvExt`.** ECDSA signing, for instance, computes `s⁻¹ mod n` where `n` is the
  curve order (prime); use `SSFBNModInv` there. Reserve `SSFBNModInvExt` for cases where the
  modulus is known non-prime *and* none of the inputs are secret.
- **`SSFBNMul` expands; the caller must make room.** `r->len` is set to `a->len + b->len`,
  which must not exceed [`SSF_BN_MAX_LIMBS`](#ssf-bn-max-limbs). `r` must not alias either
  operand. This is the only public function with that aliasing restriction; all other
  two-operand functions permit `r == a` or `r == b`.
- **Montgomery context reuse is an important optimisation.** Initializing a `SSFBNMont_t`
  with [`SSFBNMontInit()`](#montinit) is relatively expensive (it computes `R² mod m`). For
  repeated operations against the same modulus — RSA sign/verify loops, DH key rotation —
  initialise once and reuse the context across
  [`SSFBNModExpMont()`](#modexp) / [`SSFBNMontMul()`](#montmul) calls.
- **Modulus parity — Montgomery requires odd `m`.** `SSFBNMontInit` will not produce a
  correct context for even `m` (the `-m⁻¹ mod 2³²` precomputation assumes odd `m`). Every
  cryptographic modulus used with this module (RSA modulus, ECC curve prime, DH prime) is
  odd, so this is not a practical limitation — but it is a silent correctness hazard if you
  reach for this module outside those contexts.
- **Byte serialization is big-endian.** [`SSFBNFromBytes()`](#serialization) reads a BE byte
  buffer (matching the wire format of ASN.1 `INTEGER`, X.509, PKCS#1, SEC1); 
  [`SSFBNToBytes()`](#serialization) writes a zero-padded BE buffer of the requested size.
- **NIST-specific fast reduction** is available via [`SSFBNModMulNIST()`](#modmulnist) for
  the P-256 and P-384 primes (exposed as [`SSF_BN_NIST_P256`](#nist-constants) and
  [`SSF_BN_NIST_P384`](#nist-constants)). Replaces the general Barrett reduction with a few
  add/sub steps using the sparse structure of those primes. Falls back to the general
  `SSFBNModMul` if the modulus is neither. **Variable-time** — do not use on secret inputs.
- **`SSFBNZeroize` prevents dead-store elimination.** Regular `memset(0)` on a local
  `SSFBN_t` just before return may be optimized away by the compiler. Use `SSFBNZeroize()`
  for any bignum that held secret material.

<a id="configuration"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Configuration

Options live in [`_opt/ssfbn_opt.h`](../_opt/ssfbn_opt.h). The single knob sizes every
`SSFBN_t` struct in the whole build, so pick the smallest width that accommodates the
largest modulus you will operate on.

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="ssf-bn-config-max-bits"></a>`SSF_BN_CONFIG_MAX_BITS` | `4096` | Maximum big-number width in bits. Sizes the fixed-capacity limb array inside every `SSFBN_t` and `SSFBNMont_t`, and therefore every stack frame that holds one. Set to `384` for ECC-P-256/P-384 only, `2048` for RSA-2048 / DH Group 14, `4096` for RSA-4096 / DH Group 16. Multiplication needs `2 × key-bits`, so RSA-2048 still fits in a 4096-bit configuration, but RSA-4096 does not fit in a 2048-bit one. |

Dropping `SSF_BN_CONFIG_MAX_BITS` from `4096` to `2048` halves the static size of every
`SSFBN_t` (from `516` to `260` bytes), which directly reduces every caller's stack frame.
The `ssfrsa` and `ssfbn` modules both sanity-check against this macro at compile time.

<a id="api-summary"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-bn-limb-bits"></a>`SSF_BN_LIMB_BITS` | Constant | `32` — width of one limb in bits. |
| `SSF_BN_LIMB_MAX` | Constant | `0xFFFFFFFF` — largest single-limb value. |
| `SSF_BN_BITS_TO_LIMBS(bits)` | Macro | Number of limbs needed to represent `bits` bits (rounded up). |
| <a id="ssf-bn-max-limbs"></a>`SSF_BN_MAX_LIMBS` | Constant | `SSF_BN_BITS_TO_LIMBS(SSF_BN_CONFIG_MAX_BITS)` — the fixed-capacity limb count of every `SSFBN_t`. |
| `SSF_BN_MAX_BYTES` | Constant | `(SSF_BN_CONFIG_MAX_BITS + 7) / 8` — the maximum byte width for [serialization](#serialization). |
| `SSFBNLimb_t` | Typedef | `uint32_t` — the single-limb integer type. |
| `SSFBNDLimb_t` | Typedef | `uint64_t` — the double-wide type used internally for carry propagation. |
| <a id="ssfbn-t"></a>`SSFBN_t` | Struct | `{ SSFBNLimb_t limbs[SSF_BN_MAX_LIMBS]; uint16_t len; }`. `limbs` is little-endian (`limbs[0]` is least significant); `len` is the working limb count for the current operation (`1 ≤ len ≤ SSF_BN_MAX_LIMBS`). |
| <a id="ssfbnmont-t"></a>`SSFBNMont_t` | Struct | Precomputed Montgomery reduction context for a given modulus: holds `mod`, `rr = R² mod m`, `mp = -m⁻¹ mod 2³²`, and `len`. Treat members as opaque; initialise via [`SSFBNMontInit()`](#montinit). |
| <a id="nist-constants"></a>`SSF_BN_NIST_P256`, `SSF_BN_NIST_P384` | `extern const SSFBN_t` | The NIST P-256 and P-384 curve primes, ready to pass as a modulus to [`SSFBNModMulNIST()`](#modmulnist). |

<a id="functions"></a>

### Functions

**[Initialization and conversion](#init-conversion)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-init) | [`void SSFBNSetZero(a, numLimbs)`](#ssfbnsetzero) | Set `a` to `0` with working limb count `numLimbs` |
| [e.g.](#ex-init) | [`void SSFBNSetUint32(a, val, numLimbs)`](#ssfbnsetuint32) | Set `a` to a small integer value |
| [e.g.](#ex-init) | [`void SSFBNCopy(dst, src)`](#ssfbncopy) | Copy `src` into `dst` (including `len`) |
| [e.g.](#ex-serialization) | [`bool SSFBNFromBytes(a, data, dataLen, numLimbs)`](#serialization) | Import from big-endian byte array |
| [e.g.](#ex-serialization) | [`bool SSFBNToBytes(a, out, outSize)`](#serialization) | Export to big-endian byte array |

**[Comparison and predicates](#predicates)**

| | Function | Description |
|---|----------|-------------|
| | [`bool SSFBNIsZero(a)`](#predicates) | Returns `true` iff `a == 0` |
| | [`bool SSFBNIsOne(a)`](#predicates) | Returns `true` iff `a == 1` |
| | [`bool SSFBNIsEven(a)`](#predicates) | Returns `true` iff the low bit of `a` is zero |
| | [`int8_t SSFBNCmp(a, b)`](#ssfbncmp) | Constant-time three-way compare |

**[Bit-level operations](#bit-ops)**

| | Function | Description |
|---|----------|-------------|
| | [`uint32_t SSFBNBitLen(a)`](#bitlen) | Position of the most-significant set bit + 1 |
| | [`uint8_t SSFBNGetBit(a, pos)`](#getbit) | Value of bit `pos` (0 = LSB) |
| | [`void SSFBNShiftLeft1(a)`](#shift) | In-place left shift by 1 bit |
| | [`void SSFBNShiftRight1(a)`](#shift) | In-place right shift by 1 bit |

**[Unsigned arithmetic](#arith)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-arith) | [`SSFBNLimb_t SSFBNAdd(r, a, b)`](#ssfbnadd) | `r = a + b`; returns carry-out |
| [e.g.](#ex-arith) | [`SSFBNLimb_t SSFBNSub(r, a, b)`](#ssfbnsub) | `r = a − b`; returns borrow-out (1 iff `a < b`) |
| [e.g.](#ex-arith) | [`void SSFBNMul(r, a, b)`](#ssfbnmul) | `r = a × b`; `r->len` set to `a->len + b->len`; `r` must not alias `a` or `b` |

**[Modular arithmetic](#modarith)**

| | Function | Description |
|---|----------|-------------|
| | [`void SSFBNMod(r, a, m)`](#ssfbnmod) | `r = a mod m`; `a->len` may be up to `2 × m->len` |
| | [`void SSFBNModAdd(r, a, b, m)`](#modaddsub) | `r = (a + b) mod m`; requires `a, b < m` |
| | [`void SSFBNModSub(r, a, b, m)`](#modaddsub) | `r = (a − b) mod m`; requires `a, b < m` |
| [e.g.](#ex-modmul) | [`void SSFBNModMul(r, a, b, m)`](#ssfbnmodmul) | `r = (a × b) mod m`; general-purpose |
| | [`void SSFBNModMulNIST(r, a, b, m)`](#modmulnist) | `r = (a × b) mod m` using NIST fast reduction for P-256 / P-384 |
| | [`bool SSFBNModInv(r, a, m)`](#modinv) | `r = a⁻¹ mod m` via Fermat's little theorem (prime `m`) |
| | [`bool SSFBNModInvExt(r, a, m)`](#modinv) | `r = a⁻¹ mod m` via binary extended GCD (any coprime `m`) |
| | [`void SSFBNGcd(r, a, b)`](#ssfbngcd) | `r = gcd(a, b)` via binary GCD |

**[Montgomery multiplication](#mont)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-mont) | [`void SSFBNMontInit(ctx, m)`](#montinit) | Precompute Montgomery context for odd modulus `m` |
| [e.g.](#ex-mont) | [`void SSFBNMontMul(r, a, b, ctx)`](#montmul) | `r = a × b × R⁻¹ mod m` (operands in Montgomery form) |
| [e.g.](#ex-mont) | [`void SSFBNMontConvertIn(aR, a, ctx)`](#montconv) | Convert normal → Montgomery form |
| [e.g.](#ex-mont) | [`void SSFBNMontConvertOut(a, aR, ctx)`](#montconv) | Convert Montgomery → normal form |

**[Modular exponentiation](#modexp)**

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-modexp) | [`void SSFBNModExp(r, a, e, m)`](#modexp) | `r = aᵉ mod m`; constant-time Montgomery ladder |
| [e.g.](#ex-modexp) | [`void SSFBNModExpMont(r, a, e, ctx)`](#modexp) | Same, using a precomputed `SSFBNMont_t` |

**[Utility](#utility)**

| | Function | Description |
|---|----------|-------------|
| | [`void SSFBNCondSwap(a, b, swap)`](#condswap) | Constant-time swap if `swap != 0` |
| | [`void SSFBNCondCopy(dst, src, sel)`](#condswap) | Constant-time copy if `sel != 0` |
| | [`void SSFBNZeroize(a)`](#ssfbnzeroize) | Compiler-opaque zero of the limb array |

<a id="function-reference"></a>

## [↑](#ssfbn--multi-precision-big-number-arithmetic) Function Reference

<a id="init-conversion"></a>

### [↑](#functions) Initialization and Conversion

<a id="ssfbnsetzero"></a>
```c
void SSFBNSetZero(SSFBN_t *a, uint16_t numLimbs);
```
Sets `a` to zero with working limb count `numLimbs`. `numLimbs` must satisfy
`1 ≤ numLimbs ≤ SSF_BN_MAX_LIMBS`.

<a id="ssfbnsetuint32"></a>
```c
void SSFBNSetUint32(SSFBN_t *a, uint32_t val, uint16_t numLimbs);
```
Sets `a` to the small integer `val` (placed in `limbs[0]`; remaining limbs zeroed) with
working limb count `numLimbs`. Useful for loading scalars like `1`, `2`, or a small public
exponent.

<a id="ssfbncopy"></a>
```c
void SSFBNCopy(SSFBN_t *dst, const SSFBN_t *src);
```
Copies `src` to `dst`. `dst->len` is set to `src->len`. Works for any source length.

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

<a id="ex-init"></a>

**Example:**

```c
SSFBN_t a;
SSFBN_t b;

/* Working in 256-bit (8-limb) space — enough for ECC-P-256 operations. */
const uint16_t nLimbs = SSF_BN_BITS_TO_LIMBS(256);

SSFBNSetZero(&a, nLimbs);    /* a = 0 */
SSFBNSetUint32(&b, 65537u, nLimbs);  /* b = 0x00010001 (RSA "F4" exponent) */

SSFBNCopy(&a, &b);           /* a = b */
```

<a id="ex-serialization"></a>

**Example:**

```c
/* Import a 256-bit value from a 32-byte BE array (e.g., an ECC private key
   received over the wire). */
uint8_t  wire[32] = { /* ... big-endian octets ... */ };
SSFBN_t  x;
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
bool  SSFBNIsZero(const SSFBN_t *a);
bool  SSFBNIsOne (const SSFBN_t *a);
bool  SSFBNIsEven(const SSFBN_t *a);
int8_t SSFBNCmp  (const SSFBN_t *a, const SSFBN_t *b);
```

`SSFBNIsZero` / `SSFBNIsOne` are the obvious value checks; they short-circuit on the first
non-matching limb and are **not** constant-time — do not use them to branch on secret values.
`SSFBNIsEven` inspects only the low bit of `limbs[0]` and is constant-time.

`SSFBNCmp` returns `0` if `a == b`, `-1` if `a < b`, and `+1` if `a > b`. It walks every limb
without early exit and is the correct primitive for comparing secret values (e.g., checking
whether `S < n` in ECDSA verification). Both operands must have the same `len`.

---

<a id="bit-ops"></a>

### [↑](#functions) Bit-level Operations

<a id="bitlen"></a>
```c
uint32_t SSFBNBitLen(const SSFBN_t *a);
```
Returns `⌊log₂(a)⌋ + 1` — the position of the most significant set bit plus one, i.e., the
number of bits needed to represent `a`. Returns `0` if `a == 0`. Useful for sizing a public
exponent before encoding as ASN.1, or for driving a bit-by-bit exponentiation loop.

<a id="getbit"></a>
```c
uint8_t SSFBNGetBit(const SSFBN_t *a, uint32_t pos);
```
Returns the value of bit `pos` (`0 = LSB`). Returns `0` for positions past `len × 32`.

<a id="shift"></a>
```c
void SSFBNShiftLeft1(SSFBN_t *a);
void SSFBNShiftRight1(SSFBN_t *a);
```
In-place 1-bit shifts. `ShiftLeft1` discards the top bit if it overflows the fixed limb
count; `ShiftRight1` discards the LSB. These are the building blocks for the binary-GCD and
binary-extended-GCD paths elsewhere in the module.

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

<a id="ssfbnmul"></a>
```c
void SSFBNMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b);
```
Unsigned multi-precision multiply. `r->len` is set to `a->len + b->len`; that sum must be
`≤ SSF_BN_MAX_LIMBS`. **`r` must not alias `a` or `b`.** For modular multiplication, prefer
[`SSFBNModMul`](#ssfbnmodmul) (no expansion) or [`SSFBNMontMul`](#montmul) (Montgomery-form
inputs).

<a id="ex-arith"></a>

**Example:**

```c
SSFBN_t a, b, r;
const uint16_t nLimbs = 8;  /* 256-bit working width */

SSFBNSetUint32(&a, 100u, nLimbs);
SSFBNSetUint32(&b,  50u, nLimbs);

SSFBNLimb_t carry = SSFBNAdd(&r, &a, &b);     /* r = 150, carry = 0 */
SSFBNLimb_t borrow = SSFBNSub(&r, &a, &b);    /* r = 50,  borrow = 0 */
                                              /* If b > a, borrow = 1 and r holds
                                                 the wrapped two's-complement value. */

/* Multiplication doubles the working width. */
SSFBN_t product;  /* holds 512 bits — 16 limbs */
SSFBNMul(&product, &a, &b);                   /* product = 5000, product.len = 16 */
```

---

<a id="modarith"></a>

### [↑](#functions) Modular Arithmetic

All modular functions require operands `a, b < m`. Use [`SSFBNMod`](#ssfbnmod) to reduce
first if that is not already guaranteed. The result is always strictly less than `m`.

<a id="ssfbnmod"></a>
```c
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m);
```
`r = a mod m`. `a->len` may be as large as `2 × m->len` (supports reducing the output of
`SSFBNMul`). `r->len` is set to `m->len`. **Variable-time** — do not call on secret `a`.

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
`r = (a × b) mod m` using schoolbook multiplication followed by Barrett-style reduction.
General-purpose; works for any modulus. For many modular multiplications against the same
modulus (the RSA / DH case), prefer the Montgomery path.

<a id="ex-modmul"></a>

**Example:**

```c
SSFBN_t a, b, m, r;
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

- [`SSFBNModInv`](#modinv) uses Fermat's little theorem — `a^(m-2) mod m` via the
  constant-time [`SSFBNModExp`](#modexp). **Constant-time** but only correct when `m` is
  prime. Returns `false` for non-prime moduli (including when the inverse actually exists).
  Use this on secret `a` whenever `m` is a curve order, a field prime, or a Diffie-Hellman
  group order.
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
must be odd (every cryptographic modulus used with this module is). `ctx->len` is set from
`m->len`.

<a id="montmul"></a>
```c
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx);
```
`r = a × b × R⁻¹ mod m`. Both `a` and `b` must already be in Montgomery form; the result is
also in Montgomery form. Constant-time. `r` may alias `a` or `b`.

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
SSFBNMont_t ctx;
SSFBN_t     m;
SSFBN_t     base, baseMont, accMont, resMont, result;

/* Load modulus and base ... */

SSFBNMontInit(&ctx, &m);                /* Amortised once */

SSFBNMontConvertIn(&baseMont, &base, &ctx);

/* Perform many multiplies cheaply, e.g. squaring-chain. */
SSFBNCopy(&accMont, &baseMont);
for (int i = 0; i < 16; i++)
{
    SSFBNMontMul(&accMont, &accMont, &accMont, &ctx);  /* acc ← acc² */
}

SSFBNMontConvertOut(&result, &accMont, &ctx);           /* result = base^(2^16) mod m */
```

---

<a id="modexp"></a>

### [↑](#functions) Modular Exponentiation

```c
void SSFBNModExp    (SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m);
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx);
```

`r = aᵉ mod m`. Uses the **constant-time Montgomery ladder** — every bit of `e` triggers
exactly one `SSFBNMontMul` and one swap, and the swap is a constant-time `SSFBNCondSwap`.
Total time depends only on the bit length of `e`, not its value, so the exponent's Hamming
weight or individual bit values do not leak. This is the primitive that RSA and DH private
operations rely on for side-channel resistance.

- [`SSFBNModExp`](#modexp) allocates an `SSFBNMont_t` on the stack, initialises it, and
  tears it down for each call. Convenient for a single operation.
- [`SSFBNModExpMont`](#modexp) takes a caller-owned `ctx`, skipping the init / teardown.
  Use when multiple exponentiations share a modulus (RSA signing with repeated messages, DH
  key refresh).

`a` must satisfy `a < m`. `e` is treated bit-by-bit up to `SSFBNBitLen(e)`; the bit-length
itself is observable through the loop count, but individual bit values are not.

<a id="ex-modexp"></a>

**Example:**

```c
/* Single RSA verify-style exponentiation: s = cᵉ mod n (e = 65537 for typical keys). */
SSFBN_t c, e, n, s;
/* ... load c, e, n from PKCS#1 data ... */
SSFBNModExp(&s, &c, &e, &n);

/* Repeated operations against the same modulus (e.g. DH) — cache the context. */
SSFBNMont_t ctx;
SSFBNMontInit(&ctx, &n);

SSFBN_t y1, y2;
SSFBNModExpMont(&y1, &c, &e1, &ctx);
SSFBNModExpMont(&y2, &c, &e2, &ctx);
/* ... etc. No redundant R² computation. */
```

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
`sel` are treated as "nonzero → perform the operation". Used inside
[`SSFBNModExp`](#modexp) for the ladder step and available for callers building their own
constant-time point / scalar selection logic (ECDH, scalar multiplication). Both operands
must have the same `len`.

<a id="ssfbnzeroize"></a>
```c
void SSFBNZeroize(SSFBN_t *a);
```
Zero every limb (and `len`) in a way the compiler cannot optimise away. Use before the
bignum goes out of scope if it held secret material — a private-key scalar, a DH exponent,
an RSA decryption intermediate. Plain `memset(a, 0, sizeof(*a))` on a local whose address
is not taken afterwards is a candidate for dead-store elimination under aggressive
optimisation; `SSFBNZeroize` is guaranteed not to be.
