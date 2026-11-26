# ssfcrypt — Cryptographic Helpers

[SSF](../README.md) | [Cryptography](README.md)

High-level cryptographic helpers shared across the cryptographic modules: constant-time
byte-buffer equality and secure zeroization of sensitive memory.

These primitives are intended for security-sensitive code paths where the standard library
analogues (`memcmp()`, `memset()`) are unsafe — `memcmp()` short-circuits on the first
differing byte and leaks timing information, and `memset()` may be elided by an optimizing
compiler when the target buffer is never read again.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfcrypt--cryptographic-helpers) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfcrypt--cryptographic-helpers) Notes

- Use `SSFCryptCTMemEq()` in preference to `memcmp()` for any comparison whose result depends
  on a secret (MAC tags, authentication codes, signatures, password or token equality).
  `memcmp()` short-circuits on the first differing byte and leaks, through its runtime, how
  many leading bytes matched.
- `SSFCryptCTMemEq()` runtime is independent of the position of the first differing byte:
  every byte of the input is inspected regardless of where — or whether — a mismatch occurs.
  The runtime still scales linearly with `n`, which is typically a public, fixed-size quantity
  (e.g., 16 for GCM or Poly1305 tags, 32 for SHA-256-based MACs).
- The implementation folds all byte differences into a single accumulator using XOR and bitwise
  OR; do not rewrite the loop to exit early.
- `SSFCryptCTMemEq()` with `n == 0` returns `true` regardless of the pointer values, matching
  the mathematical convention that two empty sequences are equal. Both pointers must still be
  non-`NULL`; both are validated with `SSF_REQUIRE`.
- Both `SSFCryptCTMemEq()` parameters are `const void *`, so callers can pass `uint8_t *`,
  `char *`, or any other byte-granular pointer without a cast at the call site.
- Use `SSFCryptSecureZero()` to clear secret keying material, intermediate scalars, hash
  contexts, and any other sensitive buffer that is about to leave scope. The implementation
  writes through a `volatile` pointer so the compiler cannot eliminate the clear via
  dead-store elimination, even when the buffer is never read again before going out of scope.
- `SSFCryptSecureZero()` clears byte by byte up to the first `uintptr_t`-aligned address, then
  one aligned `volatile uintptr_t` store per word, then the remaining tail bytes. Word stores
  are never misaligned, so the function is safe on strict-alignment targets, and any `p` and
  `n` are accepted. Compared with a byte loop it is several times faster on large buffers,
  which matters because the hash, AEAD and stream-cipher modules call it per block to wipe
  their working state (SHA message schedules, ChaCha20 working state, GHASH temporaries).
  The word store writes through a different type than the caller's buffer; with `volatile`
  the compiler must emit it, but a port that wants strictly portable C may replace the body
  with its platform's `explicit_bzero` / `memset_s`.
- These primitives are used internally wherever the framework compares a computed tag or
  signature against a caller-supplied expected value (the AEAD decryption paths in
  [`ssfaesgcm`](ssfaesgcm.md), `ssfaesccm`, and `ssfchacha20poly1305`; the signature
  verification path in `ssfed25519`; and the RSA encoded-message comparison in `ssfrsa`),
  and wherever a module needs to scrub keying material from stack or heap buffers before
  returning.

<a id="configuration"></a>

## [↑](#ssfcrypt--cryptographic-helpers) Configuration

This module's own helpers (`SSFCryptCTMemEq`, `SSFCryptSecureZero`) have no
compile-time options. The same opt file
([`_opt/ssfcrypt_opt.h`](../_opt/ssfcrypt_opt.h)) hosts the **`_crypto`-wide
profile selector** that sets defaults for the cross-module performance / memory
knobs in [`ssfbn`](ssfbn.md#configuration) and [`ssfec`](ssfec.md#configuration):

| Macro | Default | Description |
|-------|---------|-------------|
| `SSF_CRYPT_CONFIG_PROFILE` | `SSF_CRYPT_PROFILE_CUSTOM` | One of `MIN_MEMORY` / `CUSTOM` / `MAX_PERF`. |

**`SSF_CRYPT_PROFILE_MIN_MEMORY`** sets `SSF_EC_CONFIG_FIXED_BASE_P256` and
`SSF_EC_CONFIG_FIXED_BASE_P384` to `0`, dropping the Lim-Lee comb tables (~12 KB
rodata at the default `COMB_H = 6`); `[k]G` runs ~3-4× slower (Montgomery
ladder fallback) and `SSFECScalarMulDualBase` auto-falls-back to the
Shamir's-trick path. Also sets `SSF_ECDSA_CONFIG_ENABLE_SIGN` to `0`, dropping
`SSFECDSASign()` and the DER-encode helper; the verify-only path is
`ssfasn1`-free, so a MIN_MEMORY build with this default can omit the entire
`ssfasn1` module; targets that need on-device signing override it back to `1`.
Also sets `SSF_BN_MODEXP_WIN_K` to `3` (8-entry ModExp window table instead of
16: RSA keygen peak -4.2 KB and sign peak -1.1 KB at the RSA-4096 cap, RSA
private ops ~5 % slower). Suited to verify-only signers on Cortex-M0/M3-class
targets.

**`SSF_CRYPT_PROFILE_CUSTOM`** is today's defaults — both fixed-base tables on,
both curves enabled, RSA-2048/3072/4096 all on. Intended for networked 32-bit
MCUs in the ~512 KB-RAM range. Sets no defaults of its own; each per-module
opt file picks its own (`COMB_H = 6`, 4-bit ModExp window).

**`SSF_CRYPT_PROFILE_MAX_PERF`** sets `SSF_BN_KARATSUBA_THRESHOLD = 16` so
RSA-2048+ multiplies enter Karatsuba sooner, and `SSF_BN_MODEXP_WIN_K = 5`
(32-entry table: RSA private ops 0 to -3 %, RSA keygen peak +8.3 KB and sign
peak +4.2 KB at the RSA-4096 cap). Suited to host / server builds where RAM and
flash are not the constraint.

The compiler's dead-code elimination handles the rest: unreferenced KeyGen,
PSS, larger RSA sizes, or unused curve code paths are stripped at link without
needing per-profile flag gating, so the profile only touches knobs DCE cannot
reach (lookup-table sizes, dispatch thresholds). Each knob is `#ifndef`-guarded
in its per-module opt file, so individual overrides still win after the
profile sets its defaults.

<a id="api-summary"></a>

## [↑](#ssfcrypt--cryptographic-helpers) API Summary

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-memeq) | [`bool SSFCryptCTMemEq(a, b, n)`](#ssfcryptctmemeq) | Constant-time byte-buffer equality; returns `true` iff the first `n` bytes at `a` and `b` are equal |
| [e.g.](#ex-securezero) | [`void SSFCryptSecureZero(p, n)`](#ssfcryptsecurezero) | Securely zero `n` bytes at `p`; defeats compiler dead-store elimination |

<a id="function-reference"></a>

## [↑](#ssfcrypt--cryptographic-helpers) Function Reference

<a id="ssfcryptctmemeq"></a>

### [↑](#functions) [`bool SSFCryptCTMemEq()`](#functions)

```c
bool SSFCryptCTMemEq(const void *a, const void *b, size_t n);
```

Returns `true` if the first `n` bytes at `a` and `b` are equal, `false` otherwise. Every byte
is inspected regardless of where a mismatch occurs, so the runtime does not leak the position
of the first differing byte. Use this in place of `memcmp()` whenever the equality result
depends on a secret value (MAC tags, signatures, authentication codes, secret tokens).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `a` | in | `const void *` | Pointer to the first buffer. Must not be `NULL`, even when `n` is `0`. |
| `b` | in | `const void *` | Pointer to the second buffer. Must not be `NULL`, even when `n` is `0`. |
| `n` | in | `size_t` | Number of bytes to compare. `0` returns `true`. |

**Returns:** `true` if all `n` bytes are equal (including the `n == 0` case); `false` if any
byte differs.

<a id="ex-memeq"></a>

**Example:**

```c
/* Verify a 16-byte authentication tag without leaking where the first
   mismatching byte is via the comparison's runtime. */
uint8_t computedTag[16];
uint8_t receivedTag[16];

/* ... compute MAC over message into computedTag ... */
/* ... receive the expected tag from the untrusted source into receivedTag ... */

if (SSFCryptCTMemEq(computedTag, receivedTag, sizeof(computedTag)))
{
    /* Tag matches — accept the message. */
}
else
{
    /* Tag mismatch — reject the message. */
}

/* void * ergonomics: pass char * or uint8_t * without casts. */
const char *expected = "session-token-abc";
const char *supplied = "session-token-xyz";
bool tokenOk = SSFCryptCTMemEq(expected, supplied, 17u);  /* false */

/* n == 0 is defined and returns true. */
bool emptyEq = SSFCryptCTMemEq(expected, supplied, 0u);   /* true */
```

<a id="ssfcryptsecurezero"></a>

### [↑](#functions) [`void SSFCryptSecureZero()`](#functions)

```c
void SSFCryptSecureZero(void *p, size_t n);
```

Securely writes `n` zero bytes at `p` (byte stores to a word boundary, aligned word stores,
then tail bytes; see [Notes](#notes)). Uses `volatile` pointer writes so the compiler cannot
eliminate the clear via dead-store elimination, even when the buffer is never read again
before going out of scope. Use this for clearing secret keying material, intermediate
scalars, hash contexts, and any other sensitive buffer that is about to leave scope.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `p` | in/out | `void *` | Pointer to the buffer to zero. Must not be `NULL` even when `n` is `0`. |
| `n` | in | `size_t` | Number of bytes to clear. `0` is a no-op (the loop body never executes). |

<a id="ex-securezero"></a>

**Example:**

```c
/* Scrub a derived-key buffer before it leaves scope so it cannot leak
   through stack reuse or a later memory dump. */
uint8_t prk[32];

/* ... derive PRK with HKDF-Extract ... */
/* ... use PRK to expand into the session keys ... */

SSFCryptSecureZero(prk, sizeof(prk));
```
