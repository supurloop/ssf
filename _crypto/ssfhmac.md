# ssfhmac — HMAC Keyed-Hash MAC

[SSF](../README.md) | [Cryptography](README.md)

HMAC (RFC 2104) keyed-hash message authentication code with SHA-1, SHA-256, SHA-384, and
SHA-512 backends.

Both one-shot (`SSFHMAC`) and incremental (`SSFHMACBegin` / `SSFHMACUpdate` / `SSFHMACEnd`)
interfaces are provided. The hash algorithm is selected at runtime via the
[`SSFHMACHash_t`](#ssfhmachash-t) enumeration; a single context type
([`SSFHMACContext_t`](#ssfhmaccontext-t)) covers every variant. Helper
[`SSFHMACGetHashSize()`](#ssfhmacgethashsize) returns the MAC output length for a given hash
so callers can size their MAC buffer without hard-coding a constant.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfhmac--hmac-keyed-hash-mac) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfsha1`](ssfsha1.md) — hash backend for `SSF_HMAC_HASH_SHA1`
- [`ssfsha2`](ssfsha2.md) — hash backend for `SSF_HMAC_HASH_SHA256`, `SHA384`, `SHA512`

<a id="notes"></a>

## [↑](#ssfhmac--hmac-keyed-hash-mac) Notes

- **Prefer SHA-256 or stronger.** `SSF_HMAC_HASH_SHA1` is provided for interop with legacy
  protocols only (see [`ssfsha1`](ssfsha1.md)). HMAC-SHA-1 itself is not directly broken by
  the SHA-1 collision attacks, but there is no reason to pick it for new designs.
- **Verify MACs with [`ssfcrypt`](ssfcrypt.md), not `memcmp()`.** `SSFHMAC()` computes a tag; callers
  must then compare the computed tag to the expected tag using `SSFCryptCTMemEq()` to avoid a
  timing side channel that would let an attacker forge MACs byte-by-byte.
- `macOut` must be at least [`SSFHMACGetHashSize(hash)`](#ssfhmacgethashsize) bytes; the full
  hash output is always written (HMAC truncation is not performed by this module — if your
  protocol requires HMAC-SHA-256-128 or similar, truncate the output at the call site).
- Key-length handling follows RFC 2104 §2:
  - `keyLen > blockSize` → the key is pre-hashed with the selected hash and the hash output
    is used as the effective key.
  - `keyLen ≤ blockSize` → the key is zero-padded to the block size.
  - Block sizes: 64 bytes for SHA-1 / SHA-256; 128 bytes for SHA-384 / SHA-512.
  - For security, the key should be at least as long as the selected hash's output size.
    Short or low-entropy keys weaken the MAC regardless of the underlying hash strength.
- `SSFHMAC()` returns `bool` for consistency with the SSF API style; in practice it always
  returns `true`. All argument-validity failures are caught by `SSF_REQUIRE` design-by-contract
  asserts, not by a `false` return.
- **Zero the context before the first `Begin`.** `SSFHMACContext_t` carries a magic-number
  validity marker that must be zero on entry to `SSFHMACBegin()` — use
  `SSFHMACContext_t ctx = {0};` (or equivalent) at declaration. `SSFHMACDeInit()` wipes the
  context, so a subsequent `Begin` on the same storage is valid without a re-zero.
  `SSFHMACEnd()` does **not** wipe the context: to reuse a context for a second MAC you must
  call `SSFHMACDeInit()` between the End of the first and the Begin of the second. `Update`,
  `End`, and `DeInit` all assert that the context is currently initialised, so calling them
  on a zeroed, finalised, or DeInit'd context fires a `SSF_REQUIRE` rather than silently
  operating on stale state.
- After `SSFHMACEnd()` the context is finalised but still holds the outer-hash padding and
  inner-hash state — treat it as secret. Call `SSFHMACDeInit()` to scrub it before the
  storage goes out of scope or is reused.
- `SSFHMACContext_t` should be treated as opaque; do not access its members directly.
- `hash` must be one of the four defined variants in [`SSFHMACHash_t`](#ssfhmachash-t); the
  `MIN`/`MAX` sentinels are bounds only and must not be passed as a valid selector.
- `key` must be non-`NULL`. `msg` / `data` may be `NULL` when the corresponding length is `0`.

<a id="configuration"></a>

## [↑](#ssfhmac--hmac-keyed-hash-mac) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfhmac--hmac-keyed-hash-mac) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-hmac-max-hash-size"></a>`SSF_HMAC_MAX_HASH_SIZE` | Constant | `64` — maximum HMAC output size in bytes across all supported hashes (SHA-512) |
| <a id="ssf-hmac-max-block-size"></a>`SSF_HMAC_MAX_BLOCK_SIZE` | Constant | `128` — maximum hash block size in bytes across all supported hashes (SHA-384/512) |
| <a id="ssfhmachash-t"></a>`SSFHMACHash_t` | Enum | Hash-algorithm selector: `SSF_HMAC_HASH_SHA1`, `SSF_HMAC_HASH_SHA256`, `SSF_HMAC_HASH_SHA384`, `SSF_HMAC_HASH_SHA512` (plus `MIN` / `MAX` sentinels). |
| <a id="ssfhmaccontext-t"></a>`SSFHMACContext_t` | Struct | Incremental HMAC context. Treat as opaque; pass by pointer to all API functions. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-hmac) | [`bool SSFHMAC(hash, key, keyLen, msg, msgLen, macOut, macOutSize)`](#ssfhmac) | One-shot HMAC over `msg` with `key` using the selected hash |
| [e.g.](#ex-hmac-inc) | [`void SSFHMACBegin` / `void SSFHMACUpdate` / `void SSFHMACEnd`](#ssfhmac-inc) | Incremental HMAC: initialize context with key, feed message chunks, finalize MAC |
| [e.g.](#ex-hashsize) | [`size_t SSFHMACGetHashSize(hash)`](#ssfhmacgethashsize) | Output size in bytes for the selected hash; useful for sizing the MAC buffer |

<a id="function-reference"></a>

## [↑](#ssfhmac--hmac-keyed-hash-mac) Function Reference

<a id="ssfhmac"></a>

### [↑](#functions) [`bool SSFHMAC()`](#functions)

```c
bool SSFHMAC(SSFHMACHash_t hash, const uint8_t *key, size_t keyLen,
             const uint8_t *msg, size_t msgLen,
             uint8_t *macOut, size_t macOutSize);
```

One-shot HMAC. Computes HMAC over `msgLen` bytes from `msg` using `keyLen`-byte `key` and the
hash algorithm selected by `hash`, writing the MAC to `macOut`. Equivalent to
`SSFHMACBegin()` + a single `SSFHMACUpdate()` + `SSFHMACEnd()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hash` | in | `SSFHMACHash_t` | Hash algorithm. Must be one of `SSF_HMAC_HASH_SHA1`, `SHA256`, `SHA384`, `SHA512`. |
| `key` | in | `const uint8_t *` | Pointer to the HMAC key. Must not be `NULL`. Keys shorter than the hash's block size are zero-padded; keys longer than the block size are pre-hashed per RFC 2104 §2. |
| `keyLen` | in | `size_t` | Number of key bytes. |
| `msg` | in | `const uint8_t *` | Pointer to the message. May be `NULL` when `msgLen` is `0`. |
| `msgLen` | in | `size_t` | Number of message bytes. |
| `macOut` | out | `uint8_t *` | Buffer receiving the MAC. Must not be `NULL`. |
| `macOutSize` | in | `size_t` | Size of `macOut`. Must be at least [`SSFHMACGetHashSize(hash)`](#ssfhmacgethashsize); the full hash-sized MAC is always written. |

**Returns:** `true`. The function always succeeds when it returns; all argument-validity
failures are caught by `SSF_REQUIRE` before return. The `bool` result preserves the SSF API
convention and leaves room for future failure modes without a signature change.

<a id="ex-hmac"></a>

**Example:**

```c
/* RFC 4231 Test Case 1: HMAC-SHA-256 */
const uint8_t key[20] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b
};
uint8_t mac[SSF_HMAC_MAX_HASH_SIZE];

SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
        (const uint8_t *)"Hi There", 8, mac, sizeof(mac));
/* mac[0..31] ==
   b0 34 4c 61 d8 db 38 53  5c a8 af ce af 0b f1 2b
   88 1d c2 00 c9 83 3d a7  26 e9 37 6c 2e 32 cf f7  */

/* MAC verification must use constant-time comparison, not memcmp(). */
const uint8_t expected[32] = { 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
                               0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
                               0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
                               0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7 };
bool ok = SSFCryptCTMemEq(mac, expected, SSFHMACGetHashSize(SSF_HMAC_HASH_SHA256));
```

---

<a id="ssfhmac-inc"></a>

### [↑](#functions) [`void SSFHMACBegin() / void SSFHMACUpdate() / void SSFHMACEnd()`](#functions)

```c
void SSFHMACBegin(SSFHMACContext_t *ctx, SSFHMACHash_t hash,
                  const uint8_t *key, size_t keyLen);
void SSFHMACUpdate(SSFHMACContext_t *ctx, const uint8_t *data, size_t dataLen);
void SSFHMACEnd(SSFHMACContext_t *ctx, uint8_t *macOut, size_t macOutSize);
```

Incremental HMAC interface. Call `SSFHMACBegin()` once to bind a hash algorithm and key to the
context, `SSFHMACUpdate()` zero or more times to feed message chunks, then `SSFHMACEnd()` once
to finalize and write the MAC. The result is identical to the one-shot
[`SSFHMAC()`](#ssfhmac) interface. After `SSFHMACEnd()` the context is invalid — call
`SSFHMACBegin()` again before reusing it.

**`SSFHMACBegin()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | out | `SSFHMACContext_t *` | Pointer to the context to initialize. Must not be `NULL`. |
| `hash` | in | `SSFHMACHash_t` | Hash algorithm; one of the four defined variants. |
| `key` | in | `const uint8_t *` | HMAC key. Must not be `NULL`. Pre-hashed when `keyLen` exceeds the hash's block size; otherwise zero-padded to the block size. |
| `keyLen` | in | `size_t` | Number of key bytes. |

**`SSFHMACUpdate()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in-out | `SSFHMACContext_t *` | Pointer to an initialized context. Must not be `NULL`. |
| `data` | in | `const uint8_t *` | Pointer to the next message chunk. May be `NULL` when `dataLen` is `0`. |
| `dataLen` | in | `size_t` | Number of bytes in this chunk. |

**`SSFHMACEnd()` parameters:**

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in-out | `SSFHMACContext_t *` | Pointer to the context to finalize. Invalidated after this call. Must not be `NULL`. |
| `macOut` | out | `uint8_t *` | Buffer receiving the MAC. Must not be `NULL`. |
| `macOutSize` | in | `size_t` | Size of `macOut`. Must be at least [`SSFHMACGetHashSize(ctx->hash)`](#ssfhmacgethashsize). |

All three functions **return:** Nothing.

<a id="ex-hmac-inc"></a>

**Example:**

```c
SSFHMACContext_t ctx;
uint8_t          mac[SSF_HMAC_MAX_HASH_SIZE];
const uint8_t    key[] = "shared-secret-key";

/* Stream a large message (e.g., a file) through HMAC-SHA-256 without
   loading the whole thing into memory. Result matches the one-shot call. */
SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key) - 1);
SSFHMACUpdate(&ctx, header, headerLen);
SSFHMACUpdate(&ctx, body,   bodyLen);
SSFHMACUpdate(&ctx, footer, footerLen);
SSFHMACEnd(&ctx, mac, sizeof(mac));

/* Context is invalid after End(); Begin() again to reuse. */
SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA512, key, sizeof(key) - 1);
/* ... */
```

---

<a id="ssfhmacgethashsize"></a>

### [↑](#functions) [`size_t SSFHMACGetHashSize()`](#functions)

```c
size_t SSFHMACGetHashSize(SSFHMACHash_t hash);
```

Returns the output (MAC) size in bytes for the selected hash: `20` for SHA-1, `32` for
SHA-256, `48` for SHA-384, `64` for SHA-512. Useful for sizing a MAC buffer and for feeding
`macOutSize` when you don't want to hard-code a per-hash constant.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hash` | in | `SSFHMACHash_t` | Hash algorithm; one of the four defined variants. |

**Returns:** Output size in bytes for the selected hash (`20`, `32`, `48`, or `64`).

<a id="ex-hashsize"></a>

**Example:**

```c
/* Size a MAC buffer for the hash actually selected at runtime — no per-hash
   branching at the call site. */
SSFHMACHash_t hash   = SSF_HMAC_HASH_SHA384;
size_t        macLen = SSFHMACGetHashSize(hash);   /* 48 */
uint8_t       mac[SSF_HMAC_MAX_HASH_SIZE];

SSFHMAC(hash, key, keyLen, msg, msgLen, mac, sizeof(mac));
/* Only the first macLen bytes of mac are meaningful. */
```
