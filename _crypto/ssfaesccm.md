# ssfaesccm — AES-CCM AEAD

[SSF](../README.md) | [Cryptography](README.md)

AES-CCM (Counter with CBC-MAC) authenticated encryption with associated data, per
RFC 3610 and NIST SP 800-38C. Pairs [`ssfaes`](ssfaes.md) (for the AES block cipher) with a
CBC-MAC-based authentication step to produce a single AEAD primitive.

- **Encrypt** takes plaintext + associated data (AAD) + key + nonce + tag length, produces
  ciphertext (same length as plaintext) + an authentication tag of the requested size.
- **Decrypt** takes ciphertext + AAD + tag + key + nonce, verifies the tag, and either
  produces the plaintext (tag valid) or refuses and wipes the output buffer (tag invalid).

AES-CCM is the AEAD required by IEEE 802.15.4 (Zigbee, Thread, Matter), Bluetooth Low Energy,
WPA2 (CCMP), and much of the "classic" secure-IoT stack. It is a good choice when interop
with those standards is required and/or when a tag length shorter than 16 bytes is needed
(see below); for new designs without a protocol mandate, prefer
[`ssfaesgcm`](ssfaesgcm.md) or [`ssfchacha20poly1305`](ssfchacha20poly1305.md).

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfaesccm--aes-ccm-aead) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfaes`](ssfaes.md) — AES block cipher
- [`ssfct`](ssfct.md) — constant-time tag comparison inside
  [`SSFAESCCMDecrypt()`](#ssfaesccmdecrypt)

<a id="notes"></a>

## [↑](#ssfaesccm--aes-ccm-aead) Notes

- **Nonce uniqueness is mandatory.** A `(key, nonce)` pair must never be reused across two
  encryptions. Reuse breaks both confidentiality (identical CTR keystream leaks plaintext
  XOR) and integrity (identical CBC-MAC state allows forgery). Typical safe patterns for the
  7–13 byte nonce: a monotonic counter left-padded to `nonceLen` bytes, or a
  `(sender-id, counter)` split.
- **Decrypt is all-or-nothing — and hardened.** On tag-verify failure,
  [`SSFAESCCMDecrypt()`](#ssfaesccmdecrypt) returns `false` **and memsets** the entire `pt`
  buffer to zero before returning, so even buggy callers that forget to check the return
  value can't ship unauthenticated plaintext. Do not retry, do not emit a distinguishing
  error, and do not use `pt` on `false`. (The zeroing is stricter than what
  [`ssfaesgcm`](ssfaesgcm.md) does; callers porting between the two should not rely on the
  zeroing behaviour.)
- **Tag length is a protocol-visible parameter.** Valid tag sizes are `4, 6, 8, 10, 12, 14,
  or 16` bytes (even, 4–16). Shorter tags shrink per-message overhead but raise the forgery
  probability: an attacker guessing a tag succeeds with probability `2^-(8·tagLen)`, so a
  4-byte tag (1 in ~4 billion) is acceptable only when each key is used for a small number
  of messages and a successful forgery has low impact. Use 16 bytes when you can.
- **Nonce length implies the L parameter.** CCM splits the 16-byte block between the nonce
  (`nonceLen` bytes, 7–13) and a big-endian length / counter field (`L = 15 - nonceLen`
  bytes, so `L` ranges from 2 to 8). Longer nonces mean shorter `L`, which caps the maximum
  message length at `2^(8·L) - 1` bytes:

  | `nonceLen` | `L` | Max plaintext |
  |---|---|---|
  | 7  | 8 | 2⁶⁴ − 1 (effectively unlimited) |
  | 11 | 4 | 4 GiB − 1 |
  | 12 | 3 | 16 MiB − 1 |
  | 13 | 2 | 65 535 bytes (IEEE 802.15.4 default) |

  Exceeding the per-L length cap is **not** rejected by a `SSF_REQUIRE`; the high bits of the
  length field silently truncate and decryption will then fail with a tag mismatch. Enforce
  the cap at the call site if your upper layer does not already bound record size.
- **AAD length cap.** This implementation uses the 2-byte AAD length encoding from RFC 3610
  §2.2, which limits `aadLen` to `< 65 280` bytes (`0xFF00`). The 6-byte encoding for larger
  AAD is not supported, and the cap is not enforced by `SSF_REQUIRE` — oversized AAD will
  silently produce an incorrect tag. In practice every CCM-using protocol keeps AAD well
  under this limit.
- Key length must be exactly `16` (AES-128), `24` (AES-192), or `32` (AES-256) bytes.
- In-place operation (`ct == pt`) is supported for both encrypt and decrypt.
- `pt` / `ct` may be `NULL` when the corresponding length is `0`; `aad` may be `NULL` when
  `aadLen` is `0`. All other pointers must be non-`NULL`.
- **Timing-side-channel inherited from AES.** [`ssfaes`](ssfaes.md) is not hardened against
  timing attacks on its S-box lookups. Do not deploy AES-CCM in environments where an
  attacker can measure per-block encryption time with ciphertext granularity (networked
  servers, shared hosts). This is a property of the block cipher, not of CCM itself.
- The ciphertext output is exactly `ptLen` bytes; the tag is returned separately through the
  `tag` parameter rather than appended. Serialize them in whatever order your wire format
  requires at the call site.

<a id="configuration"></a>

## [↑](#ssfaesccm--aes-ccm-aead) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfaesccm--aes-ccm-aead) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-aesccm-block-size"></a>`SSF_AESCCM_BLOCK_SIZE` | Constant | `16` — AES block size in bytes. The CBC-MAC and CTR stages both operate on 16-byte blocks; this constant exists mainly for internal alignment and caller-side buffer sizing. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-encrypt) | [`void SSFAESCCMEncrypt(pt, ptLen, nonce, nonceLen, aad, aadLen, key, keyLen, tag, tagSize, ct, ctSize)`](#ssfaesccmencrypt) | Authenticated encrypt; writes ciphertext and tag |
| [e.g.](#ex-decrypt) | [`bool SSFAESCCMDecrypt(ct, ctLen, nonce, nonceLen, aad, aadLen, key, keyLen, tag, tagLen, pt, ptSize)`](#ssfaesccmdecrypt) | Verify tag and decrypt; returns `false` (plaintext zeroed) on mismatch |

<a id="function-reference"></a>

## [↑](#ssfaesccm--aes-ccm-aead) Function Reference

<a id="ssfaesccmencrypt"></a>

### [↑](#functions) [`void SSFAESCCMEncrypt()`](#functions)

```c
void SSFAESCCMEncrypt(const uint8_t *pt,    size_t ptLen,
                      const uint8_t *nonce, size_t nonceLen,
                      const uint8_t *aad,   size_t aadLen,
                      const uint8_t *key,   size_t keyLen,
                      uint8_t *tag,         size_t tagSize,
                      uint8_t *ct,          size_t ctSize);
```

Encrypts `ptLen` bytes of plaintext under `(key, nonce)` and computes a `tagSize`-byte
authentication tag covering both the AAD and the plaintext. Ciphertext is written to `ct`
(same length as plaintext); tag is written to `tag`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Plaintext. May be `NULL` when `ptLen` is `0`. |
| `ptLen` | in | `size_t` | Number of plaintext bytes. Must be `< 2^(8·L)` where `L = 15 - nonceLen`; the cap is **not** enforced — see [Notes](#notes). |
| `nonce` | in | `const uint8_t *` | Nonce. Must not be `NULL`. **Must be unique per key.** |
| `nonceLen` | in | `size_t` | Number of nonce bytes. Must be in `[7, 13]`. |
| `aad` | in | `const uint8_t *` | Associated data (integrity-protected, not encrypted). May be `NULL` when `aadLen` is `0`. |
| `aadLen` | in | `size_t` | Number of AAD bytes. Must be `< 0xFF00` (65 280); the cap is **not** enforced — see [Notes](#notes). |
| `key` | in | `const uint8_t *` | AES key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Must be `16`, `24`, or `32`. |
| `tag` | out | `uint8_t *` | Buffer receiving the tag. Must not be `NULL`. |
| `tagSize` | in | `size_t` | Tag length in bytes. Must be one of `4, 6, 8, 10, 12, 14, 16`. Exactly `tagSize` bytes are written. |
| `ct` | out | `uint8_t *` | Ciphertext buffer. May alias `pt`. May be `NULL` when `ptLen` is `0`. |
| `ctSize` | in | `size_t` | Size of `ct`. Must be `≥ ptLen`. |

**Returns:** Nothing.

<a id="ex-encrypt"></a>

**Example:**

```c
/* RFC 3610 Packet Vector #1 (AES-128-CCM, 13-byte nonce, 8-byte tag). */
const uint8_t key[16] = {
    0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,
    0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf
};
const uint8_t nonce[13] = {
    0x00,0x00,0x00,0x03,0x02,0x01,0x00,0xa0,
    0xa1,0xa2,0xa3,0xa4,0xa5
};
const uint8_t aad[8] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };
const uint8_t pt[23] = {
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e
};

uint8_t ct[sizeof(pt)];
uint8_t tag[8];

SSFAESCCMEncrypt(pt,    sizeof(pt),
                 nonce, sizeof(nonce),
                 aad,   sizeof(aad),
                 key,   sizeof(key),
                 tag,   sizeof(tag),
                 ct,    sizeof(ct));
/* tag ==  17 e8 d1 2c fd f9 26 e0 */
```

---

<a id="ssfaesccmdecrypt"></a>

### [↑](#functions) [`bool SSFAESCCMDecrypt()`](#functions)

```c
bool SSFAESCCMDecrypt(const uint8_t *ct,    size_t ctLen,
                      const uint8_t *nonce, size_t nonceLen,
                      const uint8_t *aad,   size_t aadLen,
                      const uint8_t *key,   size_t keyLen,
                      const uint8_t *tag,   size_t tagLen,
                      uint8_t *pt,          size_t ptSize);
```

Verifies the `tagLen`-byte tag and, if it matches, decrypts `ctLen` bytes of ciphertext
into `pt`. On tag-verify failure the entire `pt` buffer is memset to zero before return.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ct` | in | `const uint8_t *` | Ciphertext. May be `NULL` when `ctLen` is `0`. |
| `ctLen` | in | `size_t` | Number of ciphertext bytes. Must satisfy the same per-L cap as [`SSFAESCCMEncrypt()`](#ssfaesccmencrypt). |
| `nonce` | in | `const uint8_t *` | Nonce. Must not be `NULL`. Must match the nonce used to encrypt. |
| `nonceLen` | in | `size_t` | Number of nonce bytes. Must be in `[7, 13]` and match the encrypt-side value. |
| `aad` | in | `const uint8_t *` | Associated data. May be `NULL` when `aadLen` is `0`. Must bitwise match the AAD supplied to encrypt. |
| `aadLen` | in | `size_t` | Number of AAD bytes. |
| `key` | in | `const uint8_t *` | AES key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Must be `16`, `24`, or `32`. |
| `tag` | in | `const uint8_t *` | Tag from the sender. Must not be `NULL`. |
| `tagLen` | in | `size_t` | Tag length in bytes. Must be one of `4, 6, 8, 10, 12, 14, 16`. |
| `pt` | out | `uint8_t *` | Plaintext output. May alias `ct`. May be `NULL` when `ctLen` is `0`. Zeroed on tag-verify failure. |
| `ptSize` | in | `size_t` | Size of `pt`. Must be `≥ ctLen`. |

**Returns:** `true` if the tag is valid and `pt` holds the plaintext; `false` if the tag
does not match, in which case `pt[0..ctLen-1]` has been zeroed. The comparison is constant
time via [`SSFCTMemEq()`](ssfct.md).

<a id="ex-decrypt"></a>

**Example:**

```c
/* Decrypt the ciphertext from the encryption example. */
uint8_t recovered[sizeof(pt)];

bool ok = SSFAESCCMDecrypt(ct,    sizeof(ct),
                           nonce, sizeof(nonce),
                           aad,   sizeof(aad),
                           key,   sizeof(key),
                           tag,   sizeof(tag),
                           recovered, sizeof(recovered));
if (!ok)
{
    /* Tag verification failed — message was tampered with, the wrong
       key/nonce/AAD was supplied, or sender and receiver disagree. The
       `recovered` buffer has already been zeroed; do not inspect it. */
    return;
}
/* ok == true: recovered[] now holds the original plaintext. */

/* In-place decrypt: reuse the ciphertext buffer for the plaintext. */
uint8_t buf[128];
/* ... receive ciphertext into buf[0..recvLen-1], and tag into recvTag ... */
bool ok2 = SSFAESCCMDecrypt(buf, recvLen,
                            nonce, sizeof(nonce),
                            aad,   sizeof(aad),
                            key,   sizeof(key),
                            recvTag, tagLen,
                            buf, sizeof(buf));
/* On success buf[0..recvLen-1] is plaintext. On failure it is zeroed. */
```
