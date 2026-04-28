# ssfaesctr — AES-CTR Stream Cipher

[SSF](../README.md) | [Cryptography](README.md)

AES counter mode (CTR) per NIST SP 800-38A §6.5. **Confidentiality only — no authentication.**
The caller is responsible for integrity protection by some independent mechanism (a separate
MAC over the ciphertext, an envelope ECDSA / Ed25519 signature, or by switching to an AEAD
mode like [`ssfaesgcm`](ssfaesgcm.md) or [`ssfaesccm`](ssfaesccm.md) when integrity is needed).

CTR turns AES into a stream cipher: the keystream is `AES(key, counter) ‖ AES(key, counter+1) ‖ …`,
XORed against the plaintext. Encryption and decryption are the same operation.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfaesctr--aes-ctr-stream-cipher) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfaes`](ssfaes.md) — single-block AES encryption used to generate each keystream block
- [`ssfcrypt`](ssfcrypt.md) — `SSFCryptSecureZero` for `SSFAESCTRDeInit`

<a id="notes"></a>

## [↑](#ssfaesctr--aes-ctr-stream-cipher) Notes

- **CTR provides confidentiality only.** A bit flip in the ciphertext flips the corresponding
  plaintext bit on decryption, undetected. **Do not use CTR ciphertext without an external
  integrity check.** Acceptable patterns: an envelope signature (ECDSA / Ed25519) over the
  ciphertext; a separate HMAC over the ciphertext; a higher-level container (signed firmware
  manifest, signed certificate). If you don't have an out-of-band integrity check, use
  [`ssfaesgcm`](ssfaesgcm.md) or [`ssfaesccm`](ssfaesccm.md) instead — those build authentication
  into the mode.
- **The IV is a 16-byte initial counter.** The counter is treated as a 128-bit big-endian
  integer and incremented by 1 per block (NIST SP 800-38A §B.1 standard counter function;
  matches WolfSSL's `wc_AesCtrEncrypt` convention). This module does **not** use the
  "12-byte nonce + 4-byte counter" convention (the AES-GCM `J0` layout).
- **Never reuse a `(key, IV)` pair for two different plaintexts.** CTR-mode nonce reuse is
  catastrophic: XOR the two ciphertexts and the keystream cancels, leaving `pt1 ⊕ pt2`. From
  there, any plaintext-recovery attack against unauthenticated XOR ciphertext applies. Either
  derive a fresh IV per message (random or counter), or use a session key per message.
- **Encryption and decryption are the same operation.** There is one `SSFAESCTRCrypt` function;
  it XORs the input against the keystream regardless of whether the input is plaintext or
  ciphertext. This is what makes CTR symmetric.
- **In-place is supported.** `in` and `out` may point to the same buffer; the implementation
  reads each input byte before writing the corresponding output byte.
- **No padding.** CTR is a stream cipher — `len` may be any non-negative size_t and is not
  required to be a multiple of 16. The implementation buffers the leftover keystream from the
  last block across `Crypt` calls so that consecutive incremental calls produce a byte stream
  identical to a single one-shot call.
- **Counter overflow.** The 128-bit counter wraps at `2^128` blocks (i.e., `2^132` bytes —
  unreachable in practice). Wrap is not detected; if you need a hard limit, enforce it at the
  call site.
- **Strict zero-init contract on `Begin`.** `SSFAESCTRBegin` requires `ctx->magic !=
  SSF_AESCTR_CONTEXT_MAGIC`, so the caller must zero-initialize a stack-allocated context
  before first use, or call `SSFAESCTRDeInit` between successive `Begin` calls on the same
  context. Zero-init via `SSFAESCTRContext_t ctx = {0};` is the canonical pattern.
- **Migration from WolfSSL's CTR API.** `wc_AesSetKeyDirect(&ctx, key, len, iv, AES_ENCRYPTION)`
  + `wc_AesCtrEncrypt(&ctx, ct, pt, len)` maps to `SSFAESCTRBegin(&ctx, key, len, iv)` +
  `SSFAESCTRCrypt(&ctx, pt, ct, len)`. Byte-for-byte compatible because both libraries use the
  full-16-byte big-endian counter convention.

<a id="configuration"></a>

## [↑](#ssfaesctr--aes-ctr-stream-cipher) Configuration

This module has no compile-time configuration options in `ssfoptions.h`. Unit-test inclusion is
gated by `SSF_CONFIG_AESCTR_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfaesctr--aes-ctr-stream-cipher) API Summary

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-oneshot)   | [`void SSFAESCTR(key, keyLen, iv, in, out, len)`](#ssfaesctr) | Single-call encrypt/decrypt |
| [e.g.](#ex-incremental) | [`void SSFAESCTRBegin(ctx, key, keyLen, iv)`](#ssfaesctrbegin) | Initialize incremental context |
| [e.g.](#ex-incremental) | [`void SSFAESCTRCrypt(ctx, in, out, len)`](#ssfaesctrcrypt) | Encrypt or decrypt a chunk |
| [e.g.](#ex-incremental) | [`void SSFAESCTRDeInit(ctx)`](#ssfaesctrdeinit) | Securely zero the context |

<a id="function-reference"></a>

## [↑](#ssfaesctr--aes-ctr-stream-cipher) Function Reference

<a id="ssfaesctrbegin"></a>

### [↑](#functions) [`void SSFAESCTRBegin()`](#functions)

```c
void SSFAESCTRBegin(SSFAESCTRContext_t *ctx, const uint8_t *key, size_t keyLen,
                    const uint8_t *iv);
```

Initializes an incremental AES-CTR context with the given key and initial 16-byte counter.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in/out | `SSFAESCTRContext_t *` | Context to initialize. `ctx->magic` must not equal the live magic value — caller must zero-init or DeInit between Begins. |
| `key` | in | `const uint8_t *` | AES key bytes. Must be non-NULL. |
| `keyLen` | in | `size_t` | Key length in bytes. Must be exactly 16, 24, or 32. |
| `iv` | in | `const uint8_t *` | 16-byte initial counter. Must be non-NULL. |

<a id="ssfaesctrcrypt"></a>

### [↑](#functions) [`void SSFAESCTRCrypt()`](#functions)

```c
void SSFAESCTRCrypt(SSFAESCTRContext_t *ctx, const uint8_t *in, uint8_t *out, size_t len);
```

Encrypt or decrypt `len` bytes from `in` into `out`. CTR is symmetric — the same call performs
both directions. `in` and `out` may alias.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in/out | `SSFAESCTRContext_t *` | Context, must have been initialized by `SSFAESCTRBegin`. |
| `in` | in | `const uint8_t *` | Input buffer. May be `NULL` if `len == 0`. |
| `out` | out | `uint8_t *` | Output buffer (at least `len` bytes). May be `NULL` if `len == 0`. |
| `len` | in | `size_t` | Number of bytes to process. May be `0`. |

<a id="ssfaesctrdeinit"></a>

### [↑](#functions) [`void SSFAESCTRDeInit()`](#functions)

```c
void SSFAESCTRDeInit(SSFAESCTRContext_t *ctx);
```

Securely zeroes the entire context, clearing the key, counter, and any buffered keystream.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in/out | `SSFAESCTRContext_t *` | Live context (must have valid magic). |

<a id="ex-incremental"></a>

**Incremental example:**

```c
SSFAESCTRContext_t ctx = {0};

SSFAESCTRBegin(&ctx, key, sizeof(key), iv);
while (haveMoreInput()) {
    size_t got = readNextChunk(buf, sizeof(buf));
    SSFAESCTRCrypt(&ctx, buf, buf, got);  /* in-place */
    consume(buf, got);
}
SSFAESCTRDeInit(&ctx);
```

<a id="ssfaesctr"></a>

### [↑](#functions) [`void SSFAESCTR()`](#functions)

```c
void SSFAESCTR(const uint8_t *key, size_t keyLen, const uint8_t *iv,
               const uint8_t *in, uint8_t *out, size_t len);
```

Single-call encrypt/decrypt. Equivalent to `Begin` / `Crypt` / `DeInit` on an internal context.

<a id="ex-oneshot"></a>

**One-shot example:**

```c
/* Decrypt a firmware payload that was encrypted with AES-256-CTR. The payload's integrity is
   verified separately via an envelope ECDSA signature; the CTR step here is confidentiality
   only. */
uint8_t key[32];   /* derived earlier */
uint8_t iv[16];    /* shipped alongside the encrypted payload */
uint8_t pt[FW_SIZE];

SSFAESCTR(key, sizeof(key), iv, ct, pt, FW_SIZE);

if (!SSFECDSAVerify(...,  pt, FW_SIZE, sig, sigLen)) {
    /* signature failed — reject the firmware. */
}
```
