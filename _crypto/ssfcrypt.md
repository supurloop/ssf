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
- These primitives are used internally wherever the framework compares a computed tag or
  signature against a caller-supplied expected value (the AEAD decryption paths in
  [`ssfaesgcm`](ssfaesgcm.md), `ssfaesccm`, and `ssfchacha20poly1305`; the signature
  verification path in `ssfed25519`; and the RSA encoded-message comparison in `ssfrsa`),
  and wherever a module needs to scrub keying material from stack or heap buffers before
  returning.

<a id="configuration"></a>

## [↑](#ssfcrypt--cryptographic-helpers) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

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

Securely writes `n` zero bytes at `p`. Uses a `volatile` pointer write so the compiler cannot
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
