# ssfsha2 — SHA-2 Hash

[SSF](../README.md) | [Cryptography](README.md)

SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256 hash functions.

All six variants are implemented by two base functions — `SSFSHA2_32` (32-bit, 512-bit block
engine for SHA-256 and SHA-224) and `SSFSHA2_64` (64-bit, 1024-bit block engine for the SHA-512
family). Convenience macros select the variant without exposing the `hashBitSize` and
`truncationBitSize` parameters. Both one-shot and incremental (Begin / Update / End) interfaces
are provided.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfsha2--sha-2-hash) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfsha2--sha-2-hash) Notes

- Use the named macros (`SSFSHA256`, `SSFSHA512`, etc.) in preference to calling `SSFSHA2_32`
  or `SSFSHA2_64` directly; the macros select the correct `hashBitSize` and `truncationBitSize`
  automatically.
- The output buffer must be at least as large as the hash output for the chosen variant; use the
  `SSF_SHA2_*_BYTE_SIZE` constants for sizing.
- The incremental interface (Begin / Update / End) allows hashing data that arrives in chunks
  without buffering the entire input; the result is identical to the one-shot interface.
- After `SSFSHA2_32End()` or `SSFSHA2_64End()` the context is invalid; call the corresponding
  `Begin` function again before reuse.
- `SSFSHA2_32Context_t` and `SSFSHA2_64Context_t` should be treated as opaque; do not access
  their members directly.

<a id="configuration"></a>

## [↑](#ssfsha2--sha-2-hash) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfsha2--sha-2-hash) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-sha2-224-byte-size"></a>`SSF_SHA2_224_BYTE_SIZE` | Constant | `28` — SHA-224 output size in bytes |
| <a id="ssf-sha2-256-byte-size"></a>`SSF_SHA2_256_BYTE_SIZE` | Constant | `32` — SHA-256 output size in bytes |
| <a id="ssf-sha2-384-byte-size"></a>`SSF_SHA2_384_BYTE_SIZE` | Constant | `48` — SHA-384 output size in bytes |
| <a id="ssf-sha2-512-byte-size"></a>`SSF_SHA2_512_BYTE_SIZE` | Constant | `64` — SHA-512 output size in bytes |
| <a id="ssf-sha2-512-224-byte-size"></a>`SSF_SHA2_512_224_BYTE_SIZE` | Constant | `28` — SHA-512/224 output size in bytes |
| <a id="ssf-sha2-512-256-byte-size"></a>`SSF_SHA2_512_256_BYTE_SIZE` | Constant | `32` — SHA-512/256 output size in bytes |
| <a id="ssfsha2-32context-t"></a>`SSFSHA2_32Context_t` | Struct | Incremental hash context for the 32-bit engine (SHA-256 and SHA-224). Treat as opaque; pass by pointer to all API functions. |
| <a id="ssfsha2-64context-t"></a>`SSFSHA2_64Context_t` | Struct | Incremental hash context for the 64-bit engine (SHA-512, SHA-384, SHA-512/256, SHA-512/224). Treat as opaque; pass by pointer to all API functions. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-sha2-32) | [`void SSFSHA2_32(in, inLen, out, outSize, hashBitSize)`](#ssfsha2-32) | One-shot hash using the 32-bit engine; selects SHA-256 or SHA-224 via `hashBitSize` |
| [e.g.](#ex-sha256) | [`void SSFSHA256(in, inLen, out, outSize)`](#ssfsha256) | One-shot SHA-256 |
| [e.g.](#ex-sha224) | [`void SSFSHA224(in, inLen, out, outSize)`](#ssfsha224) | One-shot SHA-224 |
| [e.g.](#ex-sha2-64) | [`void SSFSHA2_64(in, inLen, out, outSize, hashBitSize, truncationBitSize)`](#ssfsha2-64) | One-shot hash using the 64-bit engine; selects SHA-512, SHA-384, SHA-512/256, or SHA-512/224 |
| [e.g.](#ex-sha512) | [`void SSFSHA512(in, inLen, out, outSize)`](#ssfsha512) | One-shot SHA-512 |
| [e.g.](#ex-sha384) | [`void SSFSHA384(in, inLen, out, outSize)`](#ssfsha384) | One-shot SHA-384 |
| [e.g.](#ex-sha512-256) | [`void SSFSHA512_256(in, inLen, out, outSize)`](#ssfsha512-256) | One-shot SHA-512/256 |
| [e.g.](#ex-sha512-224) | [`void SSFSHA512_224(in, inLen, out, outSize)`](#ssfsha512-224) | One-shot SHA-512/224 |
| [e.g.](#ex-sha2-32-inc) | [`void SSFSHA2_32Begin` / `void SSFSHA2_32Update` / `void SSFSHA2_32End`](#ssfsha2-32-inc) | Incremental 32-bit engine: initialize context, feed data chunks, finalize hash |
| [e.g.](#ex-sha256-inc) | [`void SSFSHA256Begin` / `void SSFSHA256Update` / `void SSFSHA256End`](#sha256-inc-macros) | Incremental SHA-256 |
| [e.g.](#ex-sha224-inc) | [`void SSFSHA224Begin` / `void SSFSHA224Update` / `void SSFSHA224End`](#sha224-inc-macros) | Incremental SHA-224 |
| [e.g.](#ex-sha2-64-inc) | [`void SSFSHA2_64Begin` / `void SSFSHA2_64Update` / `void SSFSHA2_64End`](#ssfsha2-64-inc) | Incremental 64-bit engine: initialize context, feed data chunks, finalize hash |
| [e.g.](#ex-sha512-inc) | [`void SSFSHA512Begin` / `void SSFSHA512Update` / `void SSFSHA512End`](#sha512-inc-macros) | Incremental SHA-512 |
| [e.g.](#ex-sha384-inc) | [`void SSFSHA384Begin` / `void SSFSHA384Update` / `void SSFSHA384End`](#sha384-inc-macros) | Incremental SHA-384 |
| [e.g.](#ex-sha512-256-inc) | [`void SSFSHA512_256Begin` / `void SSFSHA512_256Update` / `void SSFSHA512_256End`](#sha512-256-inc-macros) | Incremental SHA-512/256 |
| [e.g.](#ex-sha512-224-inc) | [`void SSFSHA512_224Begin` / `void SSFSHA512_224Update` / `void SSFSHA512_224End`](#sha512-224-inc-macros) | Incremental SHA-512/224 |

<a id="function-reference"></a>

## [↑](#ssfsha2--sha-2-hash) Function Reference

<a id="ssfsha2-32"></a>

### [↑](#functions) [`void SSFSHA2_32()`](#functions)

```c
void SSFSHA2_32(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize);
```

One-shot SHA-2 hash using the 32-bit (512-bit block) engine. Computes SHA-256 or SHA-224 over
`inLen` bytes from `in` in a single call. Prefer [`SSFSHA256()`](#ssfsha256) or
[`SSFSHA224()`](#ssfsha224) over calling this function directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the data to hash. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes to hash. |
| `out` | out | `uint8_t *` | Buffer receiving the hash. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Size of `out`. Must be at least [`SSF_SHA2_256_BYTE_SIZE`](#ssf-sha2-256-byte-size) (32) for SHA-256 or [`SSF_SHA2_224_BYTE_SIZE`](#ssf-sha2-224-byte-size) (28) for SHA-224. |
| `hashBitSize` | in | `uint16_t` | Hash variant: `256` for SHA-256, `224` for SHA-224. |

**Returns:** Nothing.

<a id="ex-sha2-32"></a>

**Example:**

```c
uint8_t out256[SSF_SHA2_256_BYTE_SIZE];
uint8_t out224[SSF_SHA2_224_BYTE_SIZE];

/* SHA-256 via base function */
SSFSHA2_32((uint8_t *)"abc", 3, out256, sizeof(out256), 256);
/* out256 == SHA-256("abc") */

/* SHA-224 via base function */
SSFSHA2_32((uint8_t *)"abc", 3, out224, sizeof(out224), 224);
/* out224 == SHA-224("abc") */
```

---

<a id="oneshot-32-macros"></a>

### [↑](#functions) One-Shot 32-bit Engine Macros

Convenience macros that call [`SSFSHA2_32()`](#ssfsha2-32) with `hashBitSize` pre-set. All
other parameters are identical to [`SSFSHA2_32()`](#ssfsha2-32).

<a id="ssfsha256"></a>

#### [↑](#functions) [`void SSFSHA256()`](#functions)

```c
SSFSHA256(in, inLen, out, outSize)
```

Expands to `SSFSHA2_32(in, inLen, out, outSize, 256)`. `outSize` must be at least
[`SSF_SHA2_256_BYTE_SIZE`](#ssf-sha2-256-byte-size) (32).

<a id="ex-sha256"></a>

**Example:**

```c
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

SSFSHA256((uint8_t *)"abc", 3, out, sizeof(out));
/* out == SHA-256("abc")
        == ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469348423f656ab5a6f3 */
```

<a id="ssfsha224"></a>

#### [↑](#functions) [`void SSFSHA224()`](#functions)

```c
SSFSHA224(in, inLen, out, outSize)
```

Expands to `SSFSHA2_32(in, inLen, out, outSize, 224)`. `outSize` must be at least
[`SSF_SHA2_224_BYTE_SIZE`](#ssf-sha2-224-byte-size) (28).

<a id="ex-sha224"></a>

**Example:**

```c
uint8_t out[SSF_SHA2_224_BYTE_SIZE];

SSFSHA224((uint8_t *)"abc", 3, out, sizeof(out));
/* out == SHA-224("abc")
        == 23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7 */
```

---

<a id="ssfsha2-32-inc"></a>

### [↑](#functions) [`void SSFSHA2_32Begin() / void SSFSHA2_32Update() / void SSFSHA2_32End()`](#functions)

```c
void SSFSHA2_32Begin(SSFSHA2_32Context_t *context, uint16_t hashBitSize);
void SSFSHA2_32Update(SSFSHA2_32Context_t *context, const uint8_t *in, uint32_t inLen);
void SSFSHA2_32End(SSFSHA2_32Context_t *context, uint8_t *out, uint32_t outSize);
```

Incremental interface for SHA-256 and SHA-224 using the 32-bit engine. Call
`SSFSHA2_32Begin()` once to initialize the context, `SSFSHA2_32Update()` one or more times to
feed data chunks, then `SSFSHA2_32End()` once to finalize and write the hash. The result is
identical to the one-shot interface. After `SSFSHA2_32End()` the context is invalid. Prefer the
[`SSFSHA256Begin`](#sha256-inc-macros) or [`SSFSHA224Begin`](#sha224-inc-macros) macro families
over calling these directly.

**`SSFSHA2_32Begin()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | out | `SSFSHA2_32Context_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `hashBitSize` | in | `uint16_t` | Hash variant: `256` for SHA-256, `224` for SHA-224. |

**`SSFSHA2_32Update()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFSHA2_32Context_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Pointer to the next data chunk. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes in this chunk. |

**`SSFSHA2_32End()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFSHA2_32Context_t *` | Pointer to the context to finalize. Invalidated after this call. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the final hash. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Size of `out`. Must be at least [`SSF_SHA2_256_BYTE_SIZE`](#ssf-sha2-256-byte-size) (32) for SHA-256 or [`SSF_SHA2_224_BYTE_SIZE`](#ssf-sha2-224-byte-size) (28) for SHA-224. |

All three functions **return:** Nothing.

<a id="ex-sha2-32-inc"></a>

**Example:**

```c
SSFSHA2_32Context_t ctx;
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

/* Incremental SHA-256 via base functions — same result as one-shot SSFSHA256 */
SSFSHA2_32Begin(&ctx, 256);
SSFSHA2_32Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA2_32Update(&ctx, (uint8_t *)"c",  1);
SSFSHA2_32End(&ctx, out, sizeof(out));
/* out == SHA-256("abc") */
```

---

<a id="sha256-inc-macros"></a>

### [↑](#functions) [SHA-256 Incremental Macros](#ex-sha256-inc)

```c
#define SSFSHA256Begin(context)             SSFSHA2_32Begin(context, 256)
#define SSFSHA256Update(context, in, inLen) SSFSHA2_32Update(context, in, inLen)
#define SSFSHA256End(context, out, outSize) SSFSHA2_32End(context, out, outSize)
```

Convenience macros for the incremental SHA-256 interface. Parameters and return values are
identical to [`SSFSHA2_32Begin() / SSFSHA2_32Update() / SSFSHA2_32End()`](#ssfsha2-32-inc);
`outSize` must be at least [`SSF_SHA2_256_BYTE_SIZE`](#ssf-sha2-256-byte-size) (32).

<a id="ex-sha256-inc"></a>

**Example:**

```c
SSFSHA2_32Context_t ctx;
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

SSFSHA256Begin(&ctx);
SSFSHA256Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA256Update(&ctx, (uint8_t *)"c",  1);
SSFSHA256End(&ctx, out, sizeof(out));
/* out == SHA-256("abc") */
```

---

<a id="sha224-inc-macros"></a>

### [↑](#functions) [SHA-224 Incremental Macros](#ex-sha224-inc)

```c
#define SSFSHA224Begin(context)             SSFSHA2_32Begin(context, 224)
#define SSFSHA224Update(context, in, inLen) SSFSHA2_32Update(context, in, inLen)
#define SSFSHA224End(context, out, outSize) SSFSHA2_32End(context, out, outSize)
```

Convenience macros for the incremental SHA-224 interface. Parameters and return values are
identical to [`SSFSHA2_32Begin() / SSFSHA2_32Update() / SSFSHA2_32End()`](#ssfsha2-32-inc);
`outSize` must be at least [`SSF_SHA2_224_BYTE_SIZE`](#ssf-sha2-224-byte-size) (28).

<a id="ex-sha224-inc"></a>

**Example:**

```c
SSFSHA2_32Context_t ctx;
uint8_t out[SSF_SHA2_224_BYTE_SIZE];

SSFSHA224Begin(&ctx);
SSFSHA224Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA224Update(&ctx, (uint8_t *)"c",  1);
SSFSHA224End(&ctx, out, sizeof(out));
/* out == SHA-224("abc") */
```

---

<a id="ssfsha2-64"></a>

### [↑](#functions) [`void SSFSHA2_64()`](#functions)

```c
void SSFSHA2_64(const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outSize,
                uint16_t hashBitSize, uint16_t truncationBitSize);
```

One-shot SHA-2 hash using the 64-bit (1024-bit block) engine. Computes SHA-512, SHA-384,
SHA-512/256, or SHA-512/224 over `inLen` bytes from `in` in a single call. Prefer the named
macros ([`SSFSHA512`](#ssfsha512), [`SSFSHA384`](#ssfsha384), [`SSFSHA512_256`](#ssfsha512-256),
[`SSFSHA512_224`](#ssfsha512-224)) over calling this function directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the data to hash. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes to hash. |
| `out` | out | `uint8_t *` | Buffer receiving the hash. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Size of `out`. Must be at least the output size of the chosen variant (see `SSF_SHA2_*_BYTE_SIZE` constants). |
| `hashBitSize` | in | `uint16_t` | Engine selector: `512` for SHA-512 and its truncated variants; `384` for SHA-384. |
| `truncationBitSize` | in | `uint16_t` | Truncation: `0` for full output (SHA-512 or SHA-384), `256` for SHA-512/256, `224` for SHA-512/224. |

**Returns:** Nothing.

<a id="ex-sha2-64"></a>

**Example:**

```c
uint8_t out512[SSF_SHA2_512_BYTE_SIZE];
uint8_t out384[SSF_SHA2_384_BYTE_SIZE];
uint8_t out512_256[SSF_SHA2_512_256_BYTE_SIZE];
uint8_t out512_224[SSF_SHA2_512_224_BYTE_SIZE];

SSFSHA2_64((uint8_t *)"abc", 3, out512,     sizeof(out512),     512, 0);
SSFSHA2_64((uint8_t *)"abc", 3, out384,     sizeof(out384),     384, 0);
SSFSHA2_64((uint8_t *)"abc", 3, out512_256, sizeof(out512_256), 512, 256);
SSFSHA2_64((uint8_t *)"abc", 3, out512_224, sizeof(out512_224), 512, 224);
```

---

<a id="oneshot-64-macros"></a>

### [↑](#functions) One-Shot 64-bit Engine Macros

Convenience macros that call [`SSFSHA2_64()`](#ssfsha2-64) with `hashBitSize` and
`truncationBitSize` pre-set. All other parameters are identical to
[`SSFSHA2_64()`](#ssfsha2-64).

<a id="ssfsha512"></a>

#### [↑](#functions) [`void SSFSHA512()`](#functions)

```c
SSFSHA512(in, inLen, out, outSize)
```

Expands to `SSFSHA2_64(in, inLen, out, outSize, 512, 0)`. `outSize` must be at least
[`SSF_SHA2_512_BYTE_SIZE`](#ssf-sha2-512-byte-size) (64).

<a id="ex-sha512"></a>

**Example:**

```c
uint8_t out[SSF_SHA2_512_BYTE_SIZE];

SSFSHA512((uint8_t *)"abc", 3, out, sizeof(out));
/* out == SHA-512("abc") */
```

<a id="ssfsha384"></a>

#### [↑](#functions) [`void SSFSHA384()`](#functions)

```c
SSFSHA384(in, inLen, out, outSize)
```

Expands to `SSFSHA2_64(in, inLen, out, outSize, 384, 0)`. `outSize` must be at least
[`SSF_SHA2_384_BYTE_SIZE`](#ssf-sha2-384-byte-size) (48).

<a id="ex-sha384"></a>

**Example:**

```c
uint8_t out[SSF_SHA2_384_BYTE_SIZE];

SSFSHA384((uint8_t *)"abc", 3, out, sizeof(out));
/* out == SHA-384("abc") */
```

<a id="ssfsha512-256"></a>

#### [↑](#functions) [`void SSFSHA512_256()`](#functions)

```c
SSFSHA512_256(in, inLen, out, outSize)
```

Expands to `SSFSHA2_64(in, inLen, out, outSize, 512, 256)`. `outSize` must be at least
[`SSF_SHA2_512_256_BYTE_SIZE`](#ssf-sha2-512-256-byte-size) (32).

<a id="ex-sha512-256"></a>

**Example:**

```c
uint8_t out[SSF_SHA2_512_256_BYTE_SIZE];

SSFSHA512_256((uint8_t *)"abc", 3, out, sizeof(out));
/* out == SHA-512/256("abc") */
```

<a id="ssfsha512-224"></a>

#### [↑](#functions) [`void SSFSHA512_224()`](#functions)

```c
SSFSHA512_224(in, inLen, out, outSize)
```

Expands to `SSFSHA2_64(in, inLen, out, outSize, 512, 224)`. `outSize` must be at least
[`SSF_SHA2_512_224_BYTE_SIZE`](#ssf-sha2-512-224-byte-size) (28).

<a id="ex-sha512-224"></a>

**Example:**

```c
uint8_t out[SSF_SHA2_512_224_BYTE_SIZE];

SSFSHA512_224((uint8_t *)"abc", 3, out, sizeof(out));
/* out == SHA-512/224("abc") */
```

---

<a id="ssfsha2-64-inc"></a>

### [↑](#functions) [`void SSFSHA2_64Begin() / void SSFSHA2_64Update() / void SSFSHA2_64End()`](#functions)

```c
void SSFSHA2_64Begin(SSFSHA2_64Context_t *context, uint16_t hashBitSize,
                     uint16_t truncationBitSize);
void SSFSHA2_64Update(SSFSHA2_64Context_t *context, const uint8_t *in, uint32_t inLen);
void SSFSHA2_64End(SSFSHA2_64Context_t *context, uint8_t *out, uint32_t outSize);
```

Incremental interface for SHA-512, SHA-384, SHA-512/256, and SHA-512/224 using the 64-bit
engine. Call `SSFSHA2_64Begin()` once to initialize the context, `SSFSHA2_64Update()` one or
more times to feed data chunks, then `SSFSHA2_64End()` once to finalize and write the hash.
After `SSFSHA2_64End()` the context is invalid. Prefer the named incremental macro families
over calling these directly.

**`SSFSHA2_64Begin()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | out | `SSFSHA2_64Context_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `hashBitSize` | in | `uint16_t` | Engine selector: `512` for SHA-512 and truncated variants; `384` for SHA-384. |
| `truncationBitSize` | in | `uint16_t` | Truncation: `0` for full output, `256` for SHA-512/256, `224` for SHA-512/224. |

**`SSFSHA2_64Update()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFSHA2_64Context_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Pointer to the next data chunk. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `uint32_t` | Number of bytes in this chunk. |

**`SSFSHA2_64End()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `context` | in-out | `SSFSHA2_64Context_t *` | Pointer to the context to finalize. Invalidated after this call. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the final hash. Must not be `NULL`. |
| `outSize` | in | `uint32_t` | Size of `out`. Must be at least the output size for the chosen variant (see `SSF_SHA2_*_BYTE_SIZE` constants). |

All three functions **return:** Nothing.

<a id="ex-sha2-64-inc"></a>

**Example:**

```c
SSFSHA2_64Context_t ctx;
uint8_t out[SSF_SHA2_512_BYTE_SIZE];

/* Incremental SHA-512 via base functions — same result as one-shot SSFSHA512 */
SSFSHA2_64Begin(&ctx, 512, 0);
SSFSHA2_64Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA2_64Update(&ctx, (uint8_t *)"c",  1);
SSFSHA2_64End(&ctx, out, sizeof(out));
/* out == SHA-512("abc") */
```

---

<a id="sha512-inc-macros"></a>

### [↑](#functions) [SHA-512 Incremental Macros](#ex-sha512-inc)

```c
#define SSFSHA512Begin(context)             SSFSHA2_64Begin(context, 512, 0)
#define SSFSHA512Update(context, in, inLen) SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512End(context, out, outSize) SSFSHA2_64End(context, out, outSize)
```

Convenience macros for the incremental SHA-512 interface. Parameters and return values are
identical to [`SSFSHA2_64Begin() / SSFSHA2_64Update() / SSFSHA2_64End()`](#ssfsha2-64-inc);
`outSize` must be at least [`SSF_SHA2_512_BYTE_SIZE`](#ssf-sha2-512-byte-size) (64).

<a id="ex-sha512-inc"></a>

**Example:**

```c
SSFSHA2_64Context_t ctx;
uint8_t out[SSF_SHA2_512_BYTE_SIZE];

SSFSHA512Begin(&ctx);
SSFSHA512Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA512Update(&ctx, (uint8_t *)"c",  1);
SSFSHA512End(&ctx, out, sizeof(out));
/* out == SHA-512("abc") */
```

---

<a id="sha384-inc-macros"></a>

### [↑](#functions) [SHA-384 Incremental Macros](#ex-sha384-inc)

```c
#define SSFSHA384Begin(context)             SSFSHA2_64Begin(context, 384, 0)
#define SSFSHA384Update(context, in, inLen) SSFSHA2_64Update(context, in, inLen)
#define SSFSHA384End(context, out, outSize) SSFSHA2_64End(context, out, outSize)
```

Convenience macros for the incremental SHA-384 interface. Parameters and return values are
identical to [`SSFSHA2_64Begin() / SSFSHA2_64Update() / SSFSHA2_64End()`](#ssfsha2-64-inc);
`outSize` must be at least [`SSF_SHA2_384_BYTE_SIZE`](#ssf-sha2-384-byte-size) (48).

<a id="ex-sha384-inc"></a>

**Example:**

```c
SSFSHA2_64Context_t ctx;
uint8_t out[SSF_SHA2_384_BYTE_SIZE];

SSFSHA384Begin(&ctx);
SSFSHA384Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA384Update(&ctx, (uint8_t *)"c",  1);
SSFSHA384End(&ctx, out, sizeof(out));
/* out == SHA-384("abc") */
```

---

<a id="sha512-256-inc-macros"></a>

### [↑](#functions) [SHA-512/256 Incremental Macros](#ex-sha512-256-inc)

```c
#define SSFSHA512_256Begin(context)             SSFSHA2_64Begin(context, 512, 256)
#define SSFSHA512_256Update(context, in, inLen) SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512_256End(context, out, outSize) SSFSHA2_64End(context, out, outSize)
```

Convenience macros for the incremental SHA-512/256 interface. Parameters and return values are
identical to [`SSFSHA2_64Begin() / SSFSHA2_64Update() / SSFSHA2_64End()`](#ssfsha2-64-inc);
`outSize` must be at least [`SSF_SHA2_512_256_BYTE_SIZE`](#ssf-sha2-512-256-byte-size) (32).

<a id="ex-sha512-256-inc"></a>

**Example:**

```c
SSFSHA2_64Context_t ctx;
uint8_t out[SSF_SHA2_512_256_BYTE_SIZE];

SSFSHA512_256Begin(&ctx);
SSFSHA512_256Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA512_256Update(&ctx, (uint8_t *)"c",  1);
SSFSHA512_256End(&ctx, out, sizeof(out));
/* out == SHA-512/256("abc") */
```

---

<a id="sha512-224-inc-macros"></a>

### [↑](#functions) [SHA-512/224 Incremental Macros](#ex-sha512-224-inc)

```c
#define SSFSHA512_224Begin(context)             SSFSHA2_64Begin(context, 512, 224)
#define SSFSHA512_224Update(context, in, inLen) SSFSHA2_64Update(context, in, inLen)
#define SSFSHA512_224End(context, out, outSize) SSFSHA2_64End(context, out, outSize)
```

Convenience macros for the incremental SHA-512/224 interface. Parameters and return values are
identical to [`SSFSHA2_64Begin() / SSFSHA2_64Update() / SSFSHA2_64End()`](#ssfsha2-64-inc);
`outSize` must be at least [`SSF_SHA2_512_224_BYTE_SIZE`](#ssf-sha2-512-224-byte-size) (28).

<a id="ex-sha512-224-inc"></a>

**Example:**

```c
SSFSHA2_64Context_t ctx;
uint8_t out[SSF_SHA2_512_224_BYTE_SIZE];

SSFSHA512_224Begin(&ctx);
SSFSHA512_224Update(&ctx, (uint8_t *)"ab", 2);
SSFSHA512_224Update(&ctx, (uint8_t *)"c",  1);
SSFSHA512_224End(&ctx, out, sizeof(out));
/* out == SHA-512/224("abc") */
```
