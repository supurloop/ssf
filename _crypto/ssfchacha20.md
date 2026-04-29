# ssfchacha20 — ChaCha20 Stream Cipher

[SSF](../README.md) | [Cryptography](README.md)

ChaCha20 stream cipher (RFC 7539 / RFC 8439). Encrypts or decrypts data of any length using a
256-bit key, a 96-bit nonce, and an explicit 32-bit block counter.

Because ChaCha20 is a stream cipher — output is plaintext XOR keystream — the same function
is used for encryption and decryption. A single entry point [`SSFChaCha20Encrypt()`](#ssfchacha20encrypt)
is exposed; [`SSFChaCha20Decrypt`](#ssfchacha20decrypt) is a convenience alias. For
authenticated encryption, pair this module with [`ssfpoly1305`](ssfpoly1305.md) via the
`ssfchacha20poly1305` AEAD wrapper rather than rolling your own authentication.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfchacha20--chacha20-stream-cipher) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfchacha20--chacha20-stream-cipher) Notes

- **Never reuse a `(key, nonce)` pair.** Reusing the same nonce with the same key under
  ChaCha20 is catastrophic: the two ciphertexts XOR together reveal the XOR of the two
  plaintexts, and any known-plaintext on one side recovers the other in full. Use a fresh
  nonce per message. Typical strategies: a per-session random nonce, a monotonic counter
  packed into the nonce, or the AEAD construction below which manages nonces for you.
- **ChaCha20 on its own is NOT authenticated.** An attacker who can tamper with ciphertext
  can flip arbitrary plaintext bits at known offsets. Every real-world use should combine
  ChaCha20 with a MAC or use the `ssfchacha20poly1305` AEAD (which pairs this module with
  [`ssfpoly1305`](ssfpoly1305.md)). Do not ship ChaCha20 ciphertext without integrity.
- **Constant-time by design.** The cipher uses only 32-bit add, XOR, and rotate operations;
  there are no S-boxes or data-dependent memory accesses, so the implementation does not
  leak key or plaintext via timing or cache side channels the way [`ssfaes`](ssfaes.md) can.
- `key` must be exactly [`SSF_CHACHA20_KEY_SIZE`](#ssf-chacha20-key-size) (32) bytes.
- `nonce` must be exactly [`SSF_CHACHA20_NONCE_SIZE`](#ssf-chacha20-nonce-size) (12) bytes
  — this is the IETF variant. The original 8-byte DJB "XChaCha" and "chacha20-djb" nonce
  variants are not supported by this API.
- `counter` is the 32-bit block counter (RFC 7539 §2.4). Start at `0` when encrypting raw
  data; start at `1` when producing the body ciphertext in ChaCha20-Poly1305, reserving
  block 0 for the Poly1305 key derivation. Whatever value you pass here will be used for the
  first 64-byte block; subsequent blocks increment from there.
- `ptLen` is bounded at `512 MiB` (2²⁹ bytes) per call.
- **The counter must not wrap past 2³² blocks.** A `SSF_REQUIRE` enforces
  `counter + ⌈ptLen / 64⌉ ≤ 2³²` — i.e., the highest block index used must fit in 32 bits.
  RFC 8439 leaves wrap behavior undefined and SSF was empirically observed to diverge from
  OpenSSL's `EVP_chacha20` past the boundary, so producing output that wraps would be
  non-interoperable; the contract refuses the call rather than silently risking that. Within
  a single `(key, nonce)` pair the contract still allows up to `2³² × 64 B = 256 GiB` of
  ciphertext, possibly produced via several calls that manually carry the counter — once you
  approach that limit you should be splitting across multiple `(key, nonce)` pairs anyway,
  because the security bounds for ChaCha20 also degrade past the 2³² block mark.
- `ct` may alias `pt` for in-place encryption; both buffers are traversed in ascending order
  64 bytes at a time, and each keystream byte is consumed before the corresponding output
  byte is written, so overwriting the input as it is read is safe. Partial overlap is not
  supported.
- `ctSize` must be `≥ ptLen`; the output has the same length as the input. Extra bytes in
  `ct` beyond `ptLen` are not touched.
- `ptLen == 0` is a no-op. When `ptLen > 0`, `pt` and `ct` must be non-`NULL`.

<a id="configuration"></a>

## [↑](#ssfchacha20--chacha20-stream-cipher) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfchacha20--chacha20-stream-cipher) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-chacha20-key-size"></a>`SSF_CHACHA20_KEY_SIZE` | Constant | `32` — ChaCha20 key size in bytes (256 bits). |
| <a id="ssf-chacha20-nonce-size"></a>`SSF_CHACHA20_NONCE_SIZE` | Constant | `12` — ChaCha20 nonce size in bytes (IETF variant, 96 bits). |
| <a id="ssf-chacha20-block-size"></a>`SSF_CHACHA20_BLOCK_SIZE` | Constant | `64` — ChaCha20 keystream block size in bytes. Relevant for counter-advance calculations; not a plaintext-length constraint. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-encrypt) | [`void SSFChaCha20Encrypt(pt, ptLen, key, keyLen, nonce, nonceLen, counter, ct, ctSize)`](#ssfchacha20encrypt) | Encrypt `ptLen` bytes of plaintext to ciphertext under the given `(key, nonce, counter)` |
| [e.g.](#ex-decrypt) | [`SSFChaCha20Decrypt(...)`](#ssfchacha20decrypt) | Alias for `SSFChaCha20Encrypt`; decryption is the same operation |

<a id="function-reference"></a>

## [↑](#ssfchacha20--chacha20-stream-cipher) Function Reference

<a id="ssfchacha20encrypt"></a>

### [↑](#functions) [`void SSFChaCha20Encrypt()`](#functions)

```c
void SSFChaCha20Encrypt(const uint8_t *pt, size_t ptLen,
                        const uint8_t *key, size_t keyLen,
                        const uint8_t *nonce, size_t nonceLen,
                        uint32_t counter,
                        uint8_t *ct, size_t ctSize);
```

Encrypts `ptLen` bytes of plaintext at `pt` into `ct` using ChaCha20 with the given key,
12-byte nonce, and starting block counter. The ciphertext is the plaintext XOR'd with the
keystream generated from `(key, nonce, counter, counter+1, ...)`. In-place operation (`ct ==
pt`) is supported; partial overlap is not.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Pointer to plaintext. May be `NULL` when `ptLen` is `0`. |
| `ptLen` | in | `size_t` | Number of bytes to encrypt. Must be `< 512 MiB` (2²⁹). |
| `key` | in | `const uint8_t *` | Pointer to the 32-byte key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Must equal [`SSF_CHACHA20_KEY_SIZE`](#ssf-chacha20-key-size) (32). |
| `nonce` | in | `const uint8_t *` | Pointer to the 12-byte nonce. Must not be `NULL`. **Must be unique per key.** |
| `nonceLen` | in | `size_t` | Must equal [`SSF_CHACHA20_NONCE_SIZE`](#ssf-chacha20-nonce-size) (12). |
| `counter` | in | `uint32_t` | Starting block counter. Use `0` for raw ChaCha20 encryption; use `1` for the body ciphertext inside a ChaCha20-Poly1305 AEAD (block `0` is reserved for Poly1305 key derivation). |
| `ct` | out | `uint8_t *` | Ciphertext output buffer. May alias `pt`. May be `NULL` when `ptLen` is `0`. |
| `ctSize` | in | `size_t` | Size of `ct`. Must be `≥ ptLen`. Bytes beyond `ptLen` are not written. |

**Returns:** Nothing.

<a id="ex-encrypt"></a>

**Example:**

```c
/* RFC 7539 §2.4.2 test vector: encrypt "Ladies and Gentlemen of the class of '99..." */
const uint8_t key[SSF_CHACHA20_KEY_SIZE] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
const uint8_t nonce[SSF_CHACHA20_NONCE_SIZE] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
};
const uint8_t pt[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only"
    " one tip for the future, sunscreen would be it.";
uint8_t ct[sizeof(pt) - 1];   /* exclude trailing NUL */

SSFChaCha20Encrypt(pt, sizeof(pt) - 1,
                   key, sizeof(key),
                   nonce, sizeof(nonce),
                   1u,                       /* counter starts at 1 per RFC 7539 §2.4.2 */
                   ct, sizeof(ct));
/* ct[0..13] ==
   6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d  ...  */

/* In-place encryption is also supported. */
uint8_t buf[128];
/* ... fill buf with plaintext ... */
SSFChaCha20Encrypt(buf, plaintextLen,
                   key, sizeof(key),
                   nonce, sizeof(nonce),
                   0u,
                   buf, sizeof(buf));
/* buf now holds the ciphertext; the plaintext has been overwritten. */
```

---

<a id="ssfchacha20decrypt"></a>

### [↑](#functions) [`SSFChaCha20Decrypt`](#functions)

```c
#define SSFChaCha20Decrypt SSFChaCha20Encrypt
```

Convenience alias for [`SSFChaCha20Encrypt()`](#ssfchacha20encrypt). ChaCha20 is a stream
cipher — decryption is exactly the same operation as encryption (plaintext XOR keystream).
The alias exists only to make call sites self-documenting. Parameters and return value are
identical.

<a id="ex-decrypt"></a>

**Example:**

```c
/* Decrypt the ciphertext from the encryption example. Same key, nonce, and
   counter; pt now receives the original plaintext. */
uint8_t recovered[sizeof(pt) - 1];

SSFChaCha20Decrypt(ct, sizeof(ct),
                   key, sizeof(key),
                   nonce, sizeof(nonce),
                   1u,
                   recovered, sizeof(recovered));
/* memcmp(recovered, pt, sizeof(pt) - 1) == 0 */
```
