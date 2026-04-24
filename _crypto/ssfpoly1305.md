# ssfpoly1305 — Poly1305 One-Time MAC

[SSF](../README.md) | [Cryptography](README.md)

Poly1305 message authentication code (RFC 7539 / RFC 8439 §2.5). Produces a 16-byte
authentication tag over an arbitrary-length message using a 32-byte one-time key.

The 32-byte key is the pair `(r, s)`: `r` is the first 16 bytes (clamped per RFC 7539 §2.5)
and `s` is the last 16 bytes (added to the final tag). This module performs the clamping
internally — callers pass the raw 32-byte key.

Poly1305 is almost always used as part of the ChaCha20-Poly1305 AEAD construction
([`ssfchacha20poly1305`](ssfchacha20poly1305.h)), which derives a fresh per-message Poly1305
key from a long-term key and a nonce. Use this module directly only when you are building a
construction that supplies its own per-message one-time key.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfpoly1305--poly1305-one-time-mac) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfpoly1305--poly1305-one-time-mac) Notes

- **Poly1305 is a ONE-TIME MAC. The key must NEVER be reused across two messages.** Using the
  same 32-byte key to authenticate two different messages lets an attacker recover `r` (half
  the key) from the two tags and forge MACs on further messages. This is not a side-channel
  concern — it is a direct algebraic attack. For general-purpose keyed MACing with a
  reusable key, use [`ssfhmac`](ssfhmac.md) instead. For authenticated encryption, use the
  `ssfchacha20poly1305` AEAD, which handles fresh-key derivation for you.
- **Verify tags with [`ssfct`](ssfct.md), not `memcmp()`.** Compare a computed tag to an
  expected tag using `SSFCTMemEq()` to avoid a timing side channel that would let an attacker
  forge MACs byte-by-byte.
- The key must be exactly [`SSF_POLY1305_KEY_SIZE`](#ssf-poly1305-key-size) (32) bytes — this
  is enforced by a `SSF_REQUIRE`. The clamping of the low half (`r`) defined in RFC 7539
  §2.5 is performed inside the function; callers supply the raw 32-byte key.
- The tag buffer must be at least [`SSF_POLY1305_TAG_SIZE`](#ssf-poly1305-tag-size) (16)
  bytes; exactly 16 bytes are written. Oversized buffers are not padded — byte 16 onward is
  left untouched.
- The message may be any length. `msg` may be `NULL` when `msgLen` is `0`; the tag over an
  empty message is `s` itself.
- The implementation uses 32-bit "Donna" limb arithmetic (5 × 26-bit limbs for the 130-bit
  accumulator) and is not constant-time. For pure MAC computation over attacker-visible
  messages this is acceptable — the secret (`r`, `s`) is mixed only into the final output —
  but do not use this module in constructions where the attacker can observe timing of the
  MAC computation on secret message bytes.
- Interface is one-shot only: the entire message is processed in a single
  [`SSFPoly1305Mac()`](#ssfpoly1305mac) call. There is no incremental Begin/Update/End
  interface — fold chunked message assembly into the caller if needed, or use
  `ssfchacha20poly1305` which streams naturally under its AEAD interface.

<a id="configuration"></a>

## [↑](#ssfpoly1305--poly1305-one-time-mac) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfpoly1305--poly1305-one-time-mac) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-poly1305-key-size"></a>`SSF_POLY1305_KEY_SIZE` | Constant | `32` — Poly1305 key size in bytes. The key is the pair `(r, s)` occupying bytes `[0..15]` and `[16..31]` respectively. |
| <a id="ssf-poly1305-tag-size"></a>`SSF_POLY1305_TAG_SIZE` | Constant | `16` — Poly1305 tag (output) size in bytes. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-mac) | [`void SSFPoly1305Mac(msg, msgLen, key, keyLen, tag, tagSize)`](#ssfpoly1305mac) | Compute a 16-byte Poly1305 tag over `msg` using a 32-byte one-time key |

<a id="function-reference"></a>

## [↑](#ssfpoly1305--poly1305-one-time-mac) Function Reference

<a id="ssfpoly1305mac"></a>

### [↑](#functions) [`void SSFPoly1305Mac()`](#functions)

```c
void SSFPoly1305Mac(const uint8_t *msg, size_t msgLen,
                    const uint8_t *key, size_t keyLen,
                    uint8_t *tag, size_t tagSize);
```

Computes the Poly1305 tag over `msgLen` bytes from `msg` using the 32-byte one-time key at
`key`, writing the 16-byte tag to `tag`. The key's low half is clamped per RFC 7539 §2.5
internally.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `msg` | in | `const uint8_t *` | Pointer to the message to authenticate. May be `NULL` when `msgLen` is `0`. |
| `msgLen` | in | `size_t` | Number of message bytes. |
| `key` | in | `const uint8_t *` | Pointer to the 32-byte one-time key. Must not be `NULL`. **Must never be reused across two different messages.** |
| `keyLen` | in | `size_t` | Must equal [`SSF_POLY1305_KEY_SIZE`](#ssf-poly1305-key-size) (32). |
| `tag` | out | `uint8_t *` | Buffer receiving the 16-byte tag. Must not be `NULL`. |
| `tagSize` | in | `size_t` | Size of `tag`. Must be `≥` [`SSF_POLY1305_TAG_SIZE`](#ssf-poly1305-tag-size) (16). Exactly 16 bytes are written; remaining bytes are left untouched. |

**Returns:** Nothing.

<a id="ex-mac"></a>

**Example:**

```c
/* RFC 7539 / 8439 §2.5.2 test vector. */
const uint8_t key[SSF_POLY1305_KEY_SIZE] = {
    0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
    0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
    0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
    0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
};
const uint8_t msg[] = "Cryptographic Forum Research Group";
uint8_t tag[SSF_POLY1305_TAG_SIZE];

SSFPoly1305Mac(msg, sizeof(msg) - 1,     /* exclude trailing NUL */
               key, sizeof(key),
               tag, sizeof(tag));
/* tag ==
   a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9 */

/* Tag verification must be constant-time. */
const uint8_t expected[SSF_POLY1305_TAG_SIZE] = {
    0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
    0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
};
bool ok = SSFCTMemEq(tag, expected, SSF_POLY1305_TAG_SIZE);
```
