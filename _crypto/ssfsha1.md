# ssfsha1 — SHA-1 Hash

[SSF](../README.md) | [Cryptography](README.md)

SHA-1 (RFC 3174) hash function with both one-shot and incremental (Begin / Update / End)
interfaces.

SHA-1 is included in SSF only to satisfy protocols that mandate it — most notably the
`Sec-WebSocket-Accept` computation in [RFC 6455](https://datatracker.ietf.org/doc/html/rfc6455)
§4.2.2. **Do not use SHA-1 for new cryptographic purposes.** Use [`ssfsha2`](ssfsha2.md) instead
whenever the protocol you are implementing allows a choice of hash.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfsha1--sha-1-hash) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfsha1--sha-1-hash) Notes

- **SHA-1 is cryptographically deprecated for collision resistance.** Practical collision
  attacks exist (Google/CWI 2017 "SHAttered"); SHA-1 must not be used for digital signatures,
  certificate issuance, or any new construction whose security depends on collision resistance.
  Use [`ssfsha2`](ssfsha2.md) (SHA-256 or SHA-512) for those cases. SHA-1 remains acceptable
  only in legacy protocol contexts that explicitly require it (e.g., RFC 6455 WebSocket
  handshake, legacy HMAC-SHA-1 where the surrounding protocol does not rely on collision
  resistance).
- Output is always exactly [`SSF_SHA1_HASH_SIZE`](#ssf-sha1-hash-size) (20) bytes. The output
  buffer must be at least that large.
- The incremental interface (Begin / Update / End) allows hashing data that arrives in chunks
  without buffering the entire input; the result is identical to the one-shot interface.
- After `SSFSHA1End()` the context is invalid; call `SSFSHA1Begin()` again before reuse.
- `SSFSHA1Context_t` should be treated as opaque; do not access its members directly.
- The one-shot `SSFSHA1()` function and `SSFSHA1Update()` accept `in == NULL` only when
  `inLen == 0`. All other pointer parameters must be non-`NULL`.

<a id="configuration"></a>

## [↑](#ssfsha1--sha-1-hash) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfsha1--sha-1-hash) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-sha1-hash-size"></a>`SSF_SHA1_HASH_SIZE` | Constant | `20` — SHA-1 output size in bytes (160 bits) |
| <a id="ssf-sha1-block-size"></a>`SSF_SHA1_BLOCK_SIZE` | Constant | `64` — SHA-1 internal block size in bytes (512 bits); relevant when building HMAC-SHA-1 or similar constructions |
| <a id="ssfsha1context-t"></a>`SSFSHA1Context_t` | Struct | Incremental hash context. Treat as opaque; pass by pointer to all API functions. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-sha1) | [`void SSFSHA1(in, inLen, out)`](#ssfsha1) | One-shot SHA-1 hash |
| [e.g.](#ex-sha1-inc) | [`void SSFSHA1Begin` / `void SSFSHA1Update` / `void SSFSHA1End`](#ssfsha1-inc) | Incremental SHA-1: initialize context, feed data chunks, finalize hash |

<a id="function-reference"></a>

## [↑](#ssfsha1--sha-1-hash) Function Reference

<a id="ssfsha1"></a>

### [↑](#functions) [`void SSFSHA1()`](#functions)

```c
void SSFSHA1(const uint8_t *in, uint32_t inLen, uint8_t out[SSF_SHA1_HASH_SIZE]);
```

One-shot SHA-1 hash. Computes the SHA-1 digest over `inLen` bytes from `in` in a single call
and writes the 20-byte result to `out`. Equivalent to `SSFSHA1Begin()` + a single
`SSFSHA1Update()` + `SSFSHA1End()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the data to hash. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes to hash. |
| `out` | out | `uint8_t[SSF_SHA1_HASH_SIZE]` | Buffer receiving the 20-byte hash. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-sha1"></a>

**Example:**

```c
uint8_t hash[SSF_SHA1_HASH_SIZE];

/* RFC 3174 test vector */
SSFSHA1((const uint8_t *)"abc", 3, hash);
/* hash == a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d */

/* RFC 6455 Sec-WebSocket-Accept:
   SHA-1(client-key || "258EAFA5-E914-47DA-95CA-C5AB0DC85B11") */
const char *wsInput =
    "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
SSFSHA1((const uint8_t *)wsInput, (uint32_t)strlen(wsInput), hash);
/* hash == b37a4f2c c0624f16 90f64606 cf385945 b2bec4ea
   then Base64-encode hash to produce the Sec-WebSocket-Accept header value. */

/* Empty input is valid; in may be NULL when inLen is 0. */
SSFSHA1(NULL, 0, hash);
/* hash == da39a3ee 5e6b4b0d 3255bfef 95601890 afd80709 */
```

---

<a id="ssfsha1-inc"></a>

### [↑](#functions) [`void SSFSHA1Begin() / void SSFSHA1Update() / void SSFSHA1End()`](#functions)

```c
void SSFSHA1Begin(SSFSHA1Context_t *ctx);
void SSFSHA1Update(SSFSHA1Context_t *ctx, const uint8_t *in, uint32_t inLen);
void SSFSHA1End(SSFSHA1Context_t *ctx, uint8_t out[SSF_SHA1_HASH_SIZE]);
```

Incremental SHA-1 interface. Call `SSFSHA1Begin()` once to initialize the context,
`SSFSHA1Update()` zero or more times to feed data chunks, then `SSFSHA1End()` once to finalize
and write the 20-byte hash. The result is identical to the one-shot
[`SSFSHA1()`](#ssfsha1) interface. After `SSFSHA1End()` the context is invalid — call
`SSFSHA1Begin()` again before reusing it.

**`SSFSHA1Begin()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | out | `SSFSHA1Context_t *` | Pointer to the context to initialize. Must not be `NULL`. |

**`SSFSHA1Update()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in-out | `SSFSHA1Context_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Pointer to the next data chunk. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes in this chunk. |

**`SSFSHA1End()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in-out | `SSFSHA1Context_t *` | Pointer to the context to finalize. Invalidated after this call. Must not be `NULL`. |
| `out` | out | `uint8_t[SSF_SHA1_HASH_SIZE]` | Buffer receiving the 20-byte final hash. Must not be `NULL`. |

All three functions **return:** Nothing.

<a id="ex-sha1-inc"></a>

**Example:**

```c
SSFSHA1Context_t ctx;
uint8_t hash[SSF_SHA1_HASH_SIZE];

/* Incremental hash — identical result to SSFSHA1((uint8_t *)"abc", 3, hash). */
SSFSHA1Begin(&ctx);
SSFSHA1Update(&ctx, (const uint8_t *)"a", 1);
SSFSHA1Update(&ctx, (const uint8_t *)"b", 1);
SSFSHA1Update(&ctx, (const uint8_t *)"c", 1);
SSFSHA1End(&ctx, hash);
/* hash == a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d */

/* Context is invalid after End(); Begin() again to reuse. */
SSFSHA1Begin(&ctx);
SSFSHA1Update(&ctx, buffer, bufferLen);
SSFSHA1End(&ctx, hash);
```
