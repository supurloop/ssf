# ssfct — Constant-Time Primitives

[SSF](../README.md) | [Cryptography](README.md)

Constant-time primitives for security-sensitive byte-buffer comparisons.

The module currently provides a single primitive, `SSFCTMemEq()`, whose runtime does not depend
on the position of the first differing byte. It is intended for equality checks whose result
depends on a secret — most commonly MAC tag and signature verification — where `memcmp()`'s
early-return behaviour would let an attacker incrementally guess the expected value by
measuring response times.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfct--constant-time-primitives) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfct--constant-time-primitives) Notes

- Use `SSFCTMemEq()` in preference to `memcmp()` for any comparison whose result depends on a
  secret (MAC tags, authentication codes, signatures, password or token equality). `memcmp()`
  short-circuits on the first differing byte and leaks, through its runtime, how many leading
  bytes matched.
- Runtime is independent of the position of the first differing byte: every byte of the input
  is inspected regardless of where — or whether — a mismatch occurs. The runtime still scales
  linearly with `n`, which is typically a public, fixed-size quantity (e.g., 16 for GCM or
  Poly1305 tags, 32 for SHA-256-based MACs).
- The implementation folds all byte differences into a single accumulator using XOR and bitwise
  OR; do not rewrite the loop to exit early.
- `n == 0` returns `true` regardless of the pointer values, matching the mathematical
  convention that two empty sequences are equal.
- `a` and `b` must not be `NULL` even when `n` is `0`; both pointers are validated with
  `SSF_REQUIRE`.
- Both parameters are `const void *`, so callers can pass `uint8_t *`, `char *`, or any other
  byte-granular pointer without a cast at the call site.
- This module is used internally wherever the framework compares a computed tag or signature
  against a caller-supplied expected value: the AEAD decryption paths in
  [`ssfaesgcm`](ssfaesgcm.md), `ssfaesccm`, and `ssfchacha20poly1305`; the signature
  verification path in `ssfed25519`; and the RSA encoded-message comparison in `ssfrsa`.

<a id="configuration"></a>

## [↑](#ssfct--constant-time-primitives) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfct--constant-time-primitives) API Summary

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-memeq) | [`bool SSFCTMemEq(a, b, n)`](#ssfctmemeq) | Constant-time byte-buffer equality; returns `true` iff the first `n` bytes at `a` and `b` are equal |

<a id="function-reference"></a>

## [↑](#ssfct--constant-time-primitives) Function Reference

<a id="ssfctmemeq"></a>

### [↑](#functions) [`bool SSFCTMemEq()`](#functions)

```c
bool SSFCTMemEq(const void *a, const void *b, size_t n);
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

if (SSFCTMemEq(computedTag, receivedTag, sizeof(computedTag)))
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
bool tokenOk = SSFCTMemEq(expected, supplied, 17u);  /* false */

/* n == 0 is defined and returns true. */
bool emptyEq = SSFCTMemEq(expected, supplied, 0u);   /* true */
```
