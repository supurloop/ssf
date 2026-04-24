# ssfchacha20poly1305 — ChaCha20-Poly1305 AEAD

[SSF](../README.md) | [Cryptography](README.md)

ChaCha20-Poly1305 authenticated encryption with associated data (AEAD), per RFC 7539 / RFC
8439 §2.8. Combines the [`ssfchacha20`](ssfchacha20.md) stream cipher with the
[`ssfpoly1305`](ssfpoly1305.md) one-time MAC into a single authenticated primitive:

- **Encrypt** takes plaintext + associated data (AAD) + key + nonce, produces ciphertext
  (same length as plaintext) + a 16-byte authentication tag.
- **Decrypt** takes ciphertext + AAD + tag + key + nonce, verifies the tag, and either
  produces the plaintext (tag valid) or refuses (tag invalid) — never returns unauthenticated
  plaintext.

The construction derives a fresh per-message Poly1305 one-time key by running ChaCha20 with
block counter `0` on an all-zero plaintext under the given `(key, nonce)`; the body ciphertext
starts at block counter `1`. Callers of this module should not need to invoke the underlying
ChaCha20 or Poly1305 primitives directly.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfchacha20poly1305--chacha20-poly1305-aead) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfchacha20`](ssfchacha20.md) — stream cipher
- [`ssfpoly1305`](ssfpoly1305.md) — one-time MAC

<a id="notes"></a>

## [↑](#ssfchacha20poly1305--chacha20-poly1305-aead) Notes

- **Nonce uniqueness is mandatory.** A `(key, nonce)` pair must never be reused across two
  encryptions. Reuse breaks both confidentiality and integrity simultaneously: identical
  keystream leaks plaintext XOR, and the resulting two Poly1305 tags let an attacker recover
  the one-time key and forge arbitrary MACs. Common safe patterns: a random 96-bit nonce from
  [`ssfprng`](ssfprng.md) per message (with a strong PRNG), a monotonic 64-bit counter
  left-padded to 12 bytes, or a `(random prefix, counter)` split.
- **Decrypt is all-or-nothing.** [`SSFChaCha20Poly1305Decrypt()`](#ssfchacha20poly1305decrypt)
  computes the expected tag *before* writing plaintext and returns `false` if it does not
  match the supplied tag. On `false` the `pt` buffer is left unwritten — callers must
  discard the ciphertext and abort the operation; do not retry, do not emit a distinguishing
  error message, and do not use any bytes from `pt`.
- The 12-byte parameter is called `iv` in the function signatures but is the RFC 7539 nonce.
  The API accepts only the IETF 96-bit-nonce variant; the 8-byte DJB / "XChaCha20" variants
  are not supported.
- The tag is always exactly [`SSF_CCP_TAG_SIZE`](#ssf-ccp-tag-size) (16) bytes. Tag
  truncation is not supported — if your protocol uses a shorter tag, compute the full 16-byte
  tag and truncate at the protocol layer.
- AAD (`auth`, `authLen`) is protected for integrity but not encrypted. Both sides must
  supply the exact same AAD bytes for decryption to succeed. `auth` may be `NULL` when
  `authLen` is `0`.
- The AEAD construction buffers `auth || pad16 || ct || pad16 || le64(authLen) || le64(ctLen)`
  on the stack before running Poly1305 over it, so the total MAC input — not just the
  plaintext — is capped by [`SSF_CCP_POLY1305_MAX_INPUT`](#ssf-ccp-poly1305-max-input)
  (default `17408` bytes). Exceeding that cap trips an `SSF_ASSERT`. To raise it, `#define`
  the macro before including `ssfchacha20poly1305.h`; to lower it for RAM-constrained ports,
  do the same with a smaller value large enough for your expected worst-case record.
- `ptLen` (encrypt) and `ctLen` (decrypt) are also capped at `512 MiB` (2²⁹) per call,
  inherited from [`ssfchacha20`](ssfchacha20.md). Typical AEAD records — TLS, QUIC, SSH —
  are well below any of these limits.
- In-place operation (`ct == pt`) is supported for both encrypt and decrypt: the tag is
  computed over the ciphertext bytes at the point they exist in the shared buffer, which is
  "after encryption" on encrypt and "before decryption" on decrypt.
- `ctSize` (encrypt) must be `≥ ptLen`; `ptSize` (decrypt) must be `≥ ctLen`. Ciphertext is
  the same length as plaintext; the 16-byte tag is returned separately via the `tag`
  parameter (encrypt) or supplied separately via the `tag` parameter (decrypt) — it is not
  appended to the ciphertext buffer.

<a id="configuration"></a>

## [↑](#ssfchacha20poly1305--chacha20-poly1305-aead) Configuration

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="ssf-ccp-poly1305-max-input"></a>`SSF_CCP_POLY1305_MAX_INPUT` | `17408` | Upper bound on the Poly1305 construction buffer that the encrypt and decrypt functions allocate on the stack. Must be at least `authLen + pad16 + ctLen + pad16 + 16` for the largest record the caller intends to process. Override by `#define`-ing before including `ssfchacha20poly1305.h`. |

<a id="api-summary"></a>

## [↑](#ssfchacha20poly1305--chacha20-poly1305-aead) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-ccp-key-size"></a>`SSF_CCP_KEY_SIZE` | Constant | `32` — key size in bytes (256 bits). Same as `SSF_CHACHA20_KEY_SIZE`. |
| <a id="ssf-ccp-nonce-size"></a>`SSF_CCP_NONCE_SIZE` | Constant | `12` — nonce size in bytes (96 bits, IETF variant). Same as `SSF_CHACHA20_NONCE_SIZE`. |
| <a id="ssf-ccp-tag-size"></a>`SSF_CCP_TAG_SIZE` | Constant | `16` — Poly1305 tag size in bytes. Same as `SSF_POLY1305_TAG_SIZE`. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-encrypt) | [`void SSFChaCha20Poly1305Encrypt(pt, ptLen, iv, ivLen, auth, authLen, key, keyLen, tag, tagSize, ct, ctSize)`](#ssfchacha20poly1305encrypt) | Authenticated encrypt; writes ciphertext to `ct` and tag to `tag` |
| [e.g.](#ex-decrypt) | [`bool SSFChaCha20Poly1305Decrypt(ct, ctLen, iv, ivLen, auth, authLen, key, keyLen, tag, tagLen, pt, ptSize)`](#ssfchacha20poly1305decrypt) | Verify tag and decrypt; returns `false` (plaintext unwritten) if the tag does not match |

<a id="function-reference"></a>

## [↑](#ssfchacha20poly1305--chacha20-poly1305-aead) Function Reference

<a id="ssfchacha20poly1305encrypt"></a>

### [↑](#functions) [`void SSFChaCha20Poly1305Encrypt()`](#functions)

```c
void SSFChaCha20Poly1305Encrypt(const uint8_t *pt,  size_t ptLen,
                                const uint8_t *iv,  size_t ivLen,
                                const uint8_t *auth, size_t authLen,
                                const uint8_t *key, size_t keyLen,
                                uint8_t *tag, size_t tagSize,
                                uint8_t *ct,  size_t ctSize);
```

Encrypts `ptLen` bytes of plaintext under `(key, iv)` and computes a 16-byte Poly1305
authentication tag covering both the AAD (`auth`) and the resulting ciphertext. The tag is
written to `tag`; the ciphertext is written to `ct` and is the same length as the plaintext.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Plaintext. May be `NULL` when `ptLen` is `0`. |
| `ptLen` | in | `size_t` | Number of plaintext bytes. Must be `< 512 MiB`; together with `authLen`, must satisfy [`SSF_CCP_POLY1305_MAX_INPUT`](#ssf-ccp-poly1305-max-input). |
| `iv` | in | `const uint8_t *` | 12-byte nonce. Must not be `NULL`. **Must be unique per key.** |
| `ivLen` | in | `size_t` | Must equal [`SSF_CCP_NONCE_SIZE`](#ssf-ccp-nonce-size) (12). |
| `auth` | in | `const uint8_t *` | Associated data (integrity-protected, not encrypted). May be `NULL` when `authLen` is `0`. |
| `authLen` | in | `size_t` | Number of AAD bytes. |
| `key` | in | `const uint8_t *` | 32-byte key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Must equal [`SSF_CCP_KEY_SIZE`](#ssf-ccp-key-size) (32). |
| `tag` | out | `uint8_t *` | Buffer receiving the 16-byte tag. Must not be `NULL`. |
| `tagSize` | in | `size_t` | Size of `tag`. Must be `≥` [`SSF_CCP_TAG_SIZE`](#ssf-ccp-tag-size) (16); exactly 16 bytes are written. |
| `ct` | out | `uint8_t *` | Ciphertext buffer. May alias `pt`. May be `NULL` when `ptLen` is `0`. |
| `ctSize` | in | `size_t` | Size of `ct`. Must be `≥ ptLen`. |

**Returns:** Nothing.

<a id="ex-encrypt"></a>

**Example:**

```c
/* RFC 7539 §2.8.2 test vector. */
const uint8_t key[SSF_CCP_KEY_SIZE] = {
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
};
const uint8_t iv[SSF_CCP_NONCE_SIZE] = {
    0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
};
const uint8_t aad[] = { 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
                        0xc4,0xc5,0xc6,0xc7 };
const uint8_t pt[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you only"
    " one tip for the future, sunscreen would be it.";

uint8_t ct[sizeof(pt) - 1];
uint8_t tag[SSF_CCP_TAG_SIZE];

SSFChaCha20Poly1305Encrypt(pt, sizeof(pt) - 1,
                           iv, sizeof(iv),
                           aad, sizeof(aad),
                           key, sizeof(key),
                           tag, sizeof(tag),
                           ct, sizeof(ct));
/* tag ==
   1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91 */

/* The tag is returned separately — not appended to ct. If your wire
   format needs contiguous (ciphertext || tag), concatenate at the call site. */
```

---

<a id="ssfchacha20poly1305decrypt"></a>

### [↑](#functions) [`bool SSFChaCha20Poly1305Decrypt()`](#functions)

```c
bool SSFChaCha20Poly1305Decrypt(const uint8_t *ct,  size_t ctLen,
                                const uint8_t *iv,  size_t ivLen,
                                const uint8_t *auth, size_t authLen,
                                const uint8_t *key, size_t keyLen,
                                const uint8_t *tag, size_t tagLen,
                                uint8_t *pt, size_t ptSize);
```

Verifies the 16-byte tag and, if it matches, decrypts `ctLen` bytes of ciphertext to `pt`.
The expected tag is computed over `auth || pad16 || ct || pad16 || le64(authLen) ||
le64(ctLen)` using the Poly1305 one-time key derived from `(key, iv)` and compared to the
supplied `tag` before any plaintext is written.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ct` | in | `const uint8_t *` | Ciphertext. May be `NULL` when `ctLen` is `0`. |
| `ctLen` | in | `size_t` | Number of ciphertext bytes. Must be `< 512 MiB`; together with `authLen`, must satisfy [`SSF_CCP_POLY1305_MAX_INPUT`](#ssf-ccp-poly1305-max-input). |
| `iv` | in | `const uint8_t *` | 12-byte nonce. Must not be `NULL`. Must match the nonce used during encryption. |
| `ivLen` | in | `size_t` | Must equal [`SSF_CCP_NONCE_SIZE`](#ssf-ccp-nonce-size) (12). |
| `auth` | in | `const uint8_t *` | Associated data. May be `NULL` when `authLen` is `0`. Must bitwise match the AAD supplied to encrypt. |
| `authLen` | in | `size_t` | Number of AAD bytes. |
| `key` | in | `const uint8_t *` | 32-byte key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Must equal [`SSF_CCP_KEY_SIZE`](#ssf-ccp-key-size) (32). |
| `tag` | in | `const uint8_t *` | 16-byte tag from the sender. Must not be `NULL`. |
| `tagLen` | in | `size_t` | Must equal [`SSF_CCP_TAG_SIZE`](#ssf-ccp-tag-size) (16). |
| `pt` | out | `uint8_t *` | Plaintext output buffer. May alias `ct`. May be `NULL` when `ctLen` is `0`. Left unwritten on tag-verify failure. |
| `ptSize` | in | `size_t` | Size of `pt`. Must be `≥ ctLen`. |

**Returns:** `true` if the tag is valid and the plaintext has been written to `pt`; `false`
if the tag is invalid — in which case `pt` is left unwritten and the caller must discard the
message. Do not use `pt` bytes when `false` is returned.

<a id="ex-decrypt"></a>

**Example:**

```c
/* Decrypt the ciphertext from the encryption example. */
uint8_t recovered[sizeof(pt) - 1];

bool ok = SSFChaCha20Poly1305Decrypt(ct,  sizeof(ct),
                                     iv,  sizeof(iv),
                                     aad, sizeof(aad),
                                     key, sizeof(key),
                                     tag, sizeof(tag),
                                     recovered, sizeof(recovered));
if (!ok)
{
    /* Tag verification failed — the message was tampered with, the wrong
       key/nonce/AAD was supplied, or the sender and receiver disagree.
       Discard everything. Do not inspect `recovered`. */
    return;
}
/* ok == true: recovered[] now holds the original plaintext. */

/* In-place decrypt: reuse the ciphertext buffer for the plaintext. */
uint8_t buf[512];
/* ... fill buf[0..recvLen-1] with received ciphertext ... */
bool ok2 = SSFChaCha20Poly1305Decrypt(buf, recvLen,
                                      iv, sizeof(iv),
                                      aad, sizeof(aad),
                                      key, sizeof(key),
                                      recvTag, SSF_CCP_TAG_SIZE,
                                      buf, sizeof(buf));
/* On success, buf[0..recvLen-1] now holds plaintext; on failure, buf is
   left unchanged from its post-receive state (the decrypt is skipped). */
```
