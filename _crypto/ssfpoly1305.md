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
- Two interfaces are provided: a one-shot [`SSFPoly1305Mac()`](#ssfpoly1305mac) for
  callers who have the full message in a single buffer, and an incremental
  [`SSFPoly1305Begin()`](#ssfpoly1305begin) / [`SSFPoly1305Update()`](#ssfpoly1305update) /
  [`SSFPoly1305End()`](#ssfpoly1305end) interface for callers who need to feed data in
  chunks. Both produce bit-identical tags; the one-shot is a thin wrapper over the three
  incremental primitives. The incremental interface is what `ssfchacha20poly1305` uses
  internally to build the RFC 7539 AEAD authenticated-message stream without allocating a
  record-sized concatenation buffer.
- The context used by the incremental interface is ~100 bytes. The primitive has
  essentially no stack cost beyond that, so both the one-shot and the streaming path are
  safe to use on tightly-constrained targets.

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
| <a id="ssfpoly1305context-t"></a>`SSFPoly1305Context_t` | Struct | Incremental MAC context. Treat as opaque; pass by pointer to [`Begin`](#ssfpoly1305begin) / [`Update`](#ssfpoly1305update) / [`End`](#ssfpoly1305end). Size is ~100 bytes. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-mac) | [`void SSFPoly1305Mac(msg, msgLen, key, keyLen, tag, tagSize)`](#ssfpoly1305mac) | One-shot: compute a 16-byte Poly1305 tag over `msg` using a 32-byte one-time key |
| [e.g.](#ex-stream) | [`void SSFPoly1305Begin(ctx, key, keyLen)`](#ssfpoly1305begin) | Incremental: initialise context with the 32-byte key |
| [e.g.](#ex-stream) | [`void SSFPoly1305Update(ctx, msg, msgLen)`](#ssfpoly1305update) | Incremental: feed a chunk of the message |
| [e.g.](#ex-stream) | [`void SSFPoly1305End(ctx, tag, tagSize)`](#ssfpoly1305end) | Incremental: finalise, emit tag, zeroise context |

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

---

<a id="ssfpoly1305begin"></a>

### [↑](#functions) [`void SSFPoly1305Begin()`](#functions)

```c
void SSFPoly1305Begin(SSFPoly1305Context_t *ctx,
                      const uint8_t *key, size_t keyLen);
```

Initialise `ctx` for a new Poly1305 MAC computation using the 32-byte one-time key at
`key`. Internally: clamps the low half of the key as `r` per RFC 7539 §2.5, takes the
high half verbatim as `s`, precomputes `r[1..4] * 5` for the reduction loop, and zeroes
the accumulator.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | out | `SSFPoly1305Context_t *` | Context to initialise. Must not be `NULL`. |
| `key` | in | `const uint8_t *` | The 32-byte one-time key. **Must never be reused across two different messages.** |
| `keyLen` | in | `size_t` | Must equal [`SSF_POLY1305_KEY_SIZE`](#ssf-poly1305-key-size) (32). |

**Returns:** Nothing.

---

<a id="ssfpoly1305update"></a>

### [↑](#functions) [`void SSFPoly1305Update()`](#functions)

```c
void SSFPoly1305Update(SSFPoly1305Context_t *ctx,
                       const uint8_t *msg, size_t msgLen);
```

Feed `msgLen` bytes of message into the MAC. May be called any number of times with any
chunk sizes; the final tag is identical to what a single call with the concatenation of
all chunks would produce. Complete 16-byte blocks are processed immediately; a shorter
tail is held in the context for the next call (or final processing by
[`SSFPoly1305End()`](#ssfpoly1305end)).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in-out | `SSFPoly1305Context_t *` | Context previously initialised by [`SSFPoly1305Begin()`](#ssfpoly1305begin). Must not be `NULL`. |
| `msg` | in | `const uint8_t *` | Message bytes. May be `NULL` when `msgLen` is `0`. |
| `msgLen` | in | `size_t` | Number of bytes to feed. May be `0` (no-op). |

**Returns:** Nothing.

---

<a id="ssfpoly1305end"></a>

### [↑](#functions) [`void SSFPoly1305End()`](#functions)

```c
void SSFPoly1305End(SSFPoly1305Context_t *ctx,
                    uint8_t *tag, size_t tagSize);
```

Finalise the MAC. Processes any remaining partial block with the RFC 7539 `0x01`
high-bit marker, runs the final modular reduction, adds `s`, and writes the 16-byte tag.
On return the context is memset to zero — it must be re-initialised via
[`SSFPoly1305Begin()`](#ssfpoly1305begin) before reuse.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ctx` | in-out | `SSFPoly1305Context_t *` | Context to finalise. Zeroised on return. Must not be `NULL`. |
| `tag` | out | `uint8_t *` | Buffer receiving the 16-byte tag. Must not be `NULL`. |
| `tagSize` | in | `size_t` | Size of `tag`. Must be `≥` [`SSF_POLY1305_TAG_SIZE`](#ssf-poly1305-tag-size) (16). Exactly 16 bytes are written. |

**Returns:** Nothing.

<a id="ex-stream"></a>

**Example:**

```c
/* Streaming equivalent of the RFC 7539 §2.5.2 test vector — produces the exact same tag
   as the SSFPoly1305Mac call above, with no intermediate concatenation buffer. Useful
   when the message is assembled from several sources (AEAD construction, on-the-fly
   protocol framing, etc.). */
SSFPoly1305Context_t ctx;
uint8_t tag[SSF_POLY1305_TAG_SIZE];

SSFPoly1305Begin(&ctx, key, sizeof(key));
SSFPoly1305Update(&ctx, (const uint8_t *)"Cryptographic ", 14u);
SSFPoly1305Update(&ctx, (const uint8_t *)"Forum Research Group", 20u);
SSFPoly1305End(&ctx, tag, sizeof(tag));
/* tag == a8 06 1d c1 30 51 36 c6 c2 2b 8b af 0c 01 27 a9, same as the one-shot path. */

/* The ChaCha20-Poly1305 AEAD uses this exact pattern: feed the AAD, a zero-pad, the
   ciphertext, another zero-pad, and the le64 lengths — each as a separate Update — and
   let Poly1305 authenticate the construction without ever materialising it in memory. */
```
