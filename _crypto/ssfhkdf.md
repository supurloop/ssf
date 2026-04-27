# ssfhkdf — HKDF Key Derivation

[SSF](../README.md) | [Cryptography](README.md)

HKDF (RFC 5869) HMAC-based extract-and-expand key derivation function over SHA-1, SHA-256,
SHA-384, and SHA-512.

HKDF turns potentially-low-entropy input keying material (IKM) — for example, the shared
secret from a Diffie-Hellman exchange — into one or more cryptographically strong,
uniformly-distributed output keys of arbitrary length. The construction is formally defined
as two separate operations:

- **Extract** — `PRK = HMAC-Hash(salt, IKM)`. Concentrates the entropy of the IKM into a
  `HashLen`-byte pseudorandom key (PRK).
- **Expand** — `OKM = T(1) || T(2) || ... || T(N)`, where each `T(i) = HMAC-Hash(PRK,
  T(i-1) || info || i)`. Stretches the PRK into `L` bytes of output keying material (OKM).

This module exposes both steps individually ([`SSFHKDFExtract`](#ssfhkdfextract),
[`SSFHKDFExpand`](#ssfhkdfexpand)) and a combined one-shot entry point
([`SSFHKDF`](#ssfhkdf)) that performs Extract-then-Expand in a single call.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfhkdf--hkdf-key-derivation) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfhmac`](ssfhmac.md) — underlying HMAC primitive (which in turn depends on
  [`ssfsha1`](ssfsha1.md) and [`ssfsha2`](ssfsha2.md))

<a id="notes"></a>

## [↑](#ssfhkdf--hkdf-key-derivation) Notes

- Use **Extract + Expand together** (or the combined [`SSFHKDF()`](#ssfhkdf)) when your IKM
  is a raw shared secret (e.g., an ECDH or X25519 output) that may not be uniformly
  distributed. Use **Expand alone** only when you already have a uniformly-distributed PRK of
  at least `HashLen` bytes (e.g., a previous HKDF output or an already-uniform master key).
- **Salt vs. info vs. IKM:**
  - `ikm` is the **secret** input keying material. Required (non-`NULL`).
  - `salt` is a **non-secret, ideally random, public** value that strengthens Extract. When
    omitted (`salt == NULL` or `saltLen == 0`), Extract substitutes a `HashLen`-byte all-zero
    salt per RFC 5869 §2.2 — this is defined behaviour, not an error, and matches the RFC
    test vectors that omit salt. A non-zero salt is recommended when one is available.
  - `info` is a **non-secret** application- and context-binding string passed to Expand. It is
    how you domain-separate multiple keys derived from the same PRK (e.g., "HTTPS client
    write key", "HTTPS server write key"). May be empty / `NULL` when context-binding is not
    required, but providing one is strongly recommended.
- **Output-length limit:** `okmLen ≤ 255 × HashLen` (RFC 5869 §2.3). That is 5100 bytes for
  HKDF-SHA-1, 8160 for HKDF-SHA-256, 12240 for HKDF-SHA-384, and 16320 for HKDF-SHA-512.
  Requests larger than this limit fail the `SSF_REQUIRE` check in
  [`SSFHKDFExpand()`](#ssfhkdfexpand). `okmLen == 0` is accepted and is a no-op.
- `prkLen` passed to [`SSFHKDFExpand()`](#ssfhkdfexpand) must be at least `HashLen`; supplying
  a PRK that is too short violates the security proof and is rejected by a `SSF_REQUIRE`.
- `prkOutSize` passed to [`SSFHKDFExtract()`](#ssfhkdfextract) must be at least `HashLen`.
  The full `HashLen`-byte PRK is always written; oversized buffers are not padded.
- The derived OKM is secret material — store, wipe, and compare it with the same care as any
  other long-term key. Use [`SSFCryptCTMemEq()`](ssfcrypt.md) when any equality check on derived-key
  bytes affects a security decision.
- All three entry points return `bool` for consistency with the SSF API style; in practice
  they always return `true`. Argument-validity failures are caught by `SSF_REQUIRE`
  design-by-contract asserts, not signalled by a `false` return. The bool is retained to
  leave room for future failure modes without a signature change.
- Hash-algorithm selection uses the same [`SSFHMACHash_t`](ssfhmac.md#ssfhmachash-t) enum as
  `ssfhmac`; prefer `SSF_HMAC_HASH_SHA256` or stronger. HKDF-SHA-1 is permitted for interop
  with legacy protocols but should not be chosen for new designs.

<a id="configuration"></a>

## [↑](#ssfhkdf--hkdf-key-derivation) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfhkdf--hkdf-key-derivation) API Summary

This module defines no constants or types of its own; it reuses
[`SSFHMACHash_t`](ssfhmac.md#ssfhmachash-t) and
[`SSF_HMAC_MAX_HASH_SIZE`](ssfhmac.md#ssf-hmac-max-hash-size) from [`ssfhmac`](ssfhmac.md).

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-hkdf) | [`bool SSFHKDF(hash, salt, saltLen, ikm, ikmLen, info, infoLen, okmOut, okmLen)`](#ssfhkdf) | One-shot Extract-then-Expand |
| [e.g.](#ex-extract) | [`bool SSFHKDFExtract(hash, salt, saltLen, ikm, ikmLen, prkOut, prkOutSize)`](#ssfhkdfextract) | Extract: concentrate IKM entropy into a `HashLen`-byte PRK |
| [e.g.](#ex-expand) | [`bool SSFHKDFExpand(hash, prk, prkLen, info, infoLen, okmOut, okmLen)`](#ssfhkdfexpand) | Expand: stretch a PRK into `okmLen` bytes of output keying material |

<a id="function-reference"></a>

## [↑](#ssfhkdf--hkdf-key-derivation) Function Reference

<a id="ssfhkdf"></a>

### [↑](#functions) [`bool SSFHKDF()`](#functions)

```c
bool SSFHKDF(SSFHMACHash_t hash,
             const uint8_t *salt, size_t saltLen,
             const uint8_t *ikm,  size_t ikmLen,
             const uint8_t *info, size_t infoLen,
             uint8_t *okmOut, size_t okmLen);
```

One-shot HKDF. Performs Extract followed by Expand in a single call, writing `okmLen` bytes of
output keying material to `okmOut`. Equivalent to calling
[`SSFHKDFExtract()`](#ssfhkdfextract) into a local `HashLen`-byte PRK buffer and then
[`SSFHKDFExpand()`](#ssfhkdfexpand) from that PRK; use this entry point unless you need to
hold on to the intermediate PRK.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hash` | in | `SSFHMACHash_t` | Hash algorithm; one of the four variants defined by [`ssfhmac`](ssfhmac.md). |
| `salt` | in | `const uint8_t *` | Optional non-secret salt. May be `NULL` when `saltLen` is `0`, in which case a `HashLen`-byte zero salt is used per RFC 5869 §2.2. |
| `saltLen` | in | `size_t` | Number of salt bytes. |
| `ikm` | in | `const uint8_t *` | Input keying material (the secret). Must not be `NULL`. |
| `ikmLen` | in | `size_t` | Number of IKM bytes. |
| `info` | in | `const uint8_t *` | Optional context / application binding. May be `NULL` when `infoLen` is `0`. |
| `infoLen` | in | `size_t` | Number of info bytes. |
| `okmOut` | out | `uint8_t *` | Buffer receiving the output keying material. Must not be `NULL`. |
| `okmLen` | in | `size_t` | Number of OKM bytes to produce. Must be `≤ 255 × HashLen`. `0` is a no-op. |

**Returns:** `true`. The function always succeeds when it returns; argument-validity
violations are caught by `SSF_REQUIRE` before return.

<a id="ex-hkdf"></a>

**Example:**

```c
/* RFC 5869 Test Case 1: HKDF-SHA-256, 42-byte OKM. */
const uint8_t ikm[22]  = { 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                           0x0b,0x0b,0x0b,0x0b,0x0b,0x0b };
const uint8_t salt[13] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                           0x08,0x09,0x0a,0x0b,0x0c };
const uint8_t info[10] = { 0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,
                           0xf8,0xf9 };
uint8_t okm[42];

SSFHKDF(SSF_HMAC_HASH_SHA256,
        salt, sizeof(salt),
        ikm,  sizeof(ikm),
        info, sizeof(info),
        okm,  sizeof(okm));
/* okm ==
   3c b2 5f 25 fa ac d5 7a 90 43 4f 64 d0 36 2f 2a
   2d 2d 0a 90 cf 1a 5a 4c 5d b0 2d 56 ec c4 c5 bf
   34 00 72 08 d5 b8 87 18 58 65                    */

/* Typical TLS-style key-schedule pattern: derive multiple keys from
   the same IKM by varying the info string. */
uint8_t clientWriteKey[16];
uint8_t serverWriteKey[16];
SSFHKDF(SSF_HMAC_HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
        (const uint8_t *)"client write key", 16,
        clientWriteKey, sizeof(clientWriteKey));
SSFHKDF(SSF_HMAC_HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
        (const uint8_t *)"server write key", 16,
        serverWriteKey, sizeof(serverWriteKey));
```

---

<a id="ssfhkdfextract"></a>

### [↑](#functions) [`bool SSFHKDFExtract()`](#functions)

```c
bool SSFHKDFExtract(SSFHMACHash_t hash,
                    const uint8_t *salt, size_t saltLen,
                    const uint8_t *ikm,  size_t ikmLen,
                    uint8_t *prkOut, size_t prkOutSize);
```

HKDF Extract step (RFC 5869 §2.2): `PRK = HMAC-Hash(salt, IKM)`. Writes a `HashLen`-byte
pseudorandom key to `prkOut`. Use this when you need to retain the PRK — for example, when
later Expand calls will reuse the same PRK to derive several keys without re-running the
(possibly expensive) Extract over a large IKM.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hash` | in | `SSFHMACHash_t` | Hash algorithm. |
| `salt` | in | `const uint8_t *` | Optional salt. May be `NULL` when `saltLen` is `0`, in which case a `HashLen`-byte zero salt is used. |
| `saltLen` | in | `size_t` | Number of salt bytes. |
| `ikm` | in | `const uint8_t *` | Input keying material (secret). Must not be `NULL`. |
| `ikmLen` | in | `size_t` | Number of IKM bytes. |
| `prkOut` | out | `uint8_t *` | Buffer receiving the PRK. Must not be `NULL`. The first [`SSFHMACGetHashSize(hash)`](ssfhmac.md#ssfhmacgethashsize) bytes are always written. |
| `prkOutSize` | in | `size_t` | Size of `prkOut`. Must be `≥ SSFHMACGetHashSize(hash)`. |

**Returns:** `true`. Always succeeds when it returns.

<a id="ex-extract"></a>

**Example:**

```c
/* Reuse a single Extract across multiple Expand calls. */
uint8_t prk[SSF_HMAC_MAX_HASH_SIZE];

SSFHKDFExtract(SSF_HMAC_HASH_SHA256,
               salt, saltLen, sharedSecret, secretLen,
               prk, sizeof(prk));
/* prk[0..31] is the PRK; subsequent Expand calls only need prk + info. */
```

---

<a id="ssfhkdfexpand"></a>

### [↑](#functions) [`bool SSFHKDFExpand()`](#functions)

```c
bool SSFHKDFExpand(SSFHMACHash_t hash,
                   const uint8_t *prk, size_t prkLen,
                   const uint8_t *info, size_t infoLen,
                   uint8_t *okmOut, size_t okmLen);
```

HKDF Expand step (RFC 5869 §2.3). Given a pseudorandom key `prk`, produces `okmLen` bytes of
output keying material in `okmOut` using the construction
`T(i) = HMAC-Hash(prk, T(i-1) || info || i)` with `T(0) = empty` and `OKM` being the first
`okmLen` bytes of `T(1) || T(2) || ...`. Use this when you already hold a uniformly-random
PRK of at least `HashLen` bytes.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hash` | in | `SSFHMACHash_t` | Hash algorithm. |
| `prk` | in | `const uint8_t *` | Pseudorandom key. Must not be `NULL`. |
| `prkLen` | in | `size_t` | Number of PRK bytes. Must be `≥ SSFHMACGetHashSize(hash)`. |
| `info` | in | `const uint8_t *` | Optional context / application binding. May be `NULL` when `infoLen` is `0`. |
| `infoLen` | in | `size_t` | Number of info bytes. |
| `okmOut` | out | `uint8_t *` | Buffer receiving the OKM. Must not be `NULL`. |
| `okmLen` | in | `size_t` | Number of OKM bytes to produce. Must be `≤ 255 × HashLen`. `0` is a no-op. |

**Returns:** `true`. Always succeeds when it returns.

<a id="ex-expand"></a>

**Example:**

```c
/* Derive several independently-bound keys from the same PRK. */
uint8_t prk[32];            /* HashLen for SHA-256 */
uint8_t encKey[32];
uint8_t macKey[32];
uint8_t ivSeed[16];

/* Assume prk was produced by an earlier SSFHKDFExtract call. */

SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk),
              (const uint8_t *)"enc key", 7, encKey, sizeof(encKey));
SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk),
              (const uint8_t *)"mac key", 7, macKey, sizeof(macKey));
SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk),
              (const uint8_t *)"iv seed", 7, ivSeed, sizeof(ivSeed));
/* Each info string domain-separates the output: even with identical PRK,
   encKey, macKey, and ivSeed are cryptographically independent. */
```
