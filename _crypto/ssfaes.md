# ssfaes — AES Block Cipher

[SSF](../README.md) | [Cryptography](README.md)

AES-128, AES-192, and AES-256 single-block encryption and decryption.

Each function or macro processes exactly one [`SSF_AES_BLOCK_SIZE`](#ssf-aes-block-size)-byte
block at a time. The base functions accept explicit round-count (`nr`) and key-word-count (`nk`)
parameters; the fixed-key macros pre-set those parameters for a specific key length; and the
`SSFAESXXX` macros derive both from `keyLen` at compile time.

A reusable key-schedule API ([`SSFAESKeySchedule_t`](#ssf-aes-key-schedule) with
[`SSFAESKeyScheduleInit()`](#ssfaeskeyscheduleinit), [`SSFAESKeyScheduleDeInit()`](#ssfaeskeyscheduledeinit),
[`SSFAESKSBlockEncrypt()`](#ssfaesksblockencrypt), and [`SSFAESKSBlockDecrypt()`](#ssfaesksblockdecrypt))
expands the round keys once so that many blocks can be processed without re-deriving the schedule
on every call — useful for callers that chain many blocks, such as counter or authenticated-encryption
modes. The one-shot block functions and macros above are thin wrappers that expand a schedule,
process the single block, then securely wipe the schedule.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfaes--aes-block-cipher) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfaes--aes-block-cipher) Notes

- **Timing attack warning:** This implementation is not hardened against timing side-channel
  attacks. Do not use in production environments where an attacker can observe precise execution
  times (e.g., network servers, shared systems). Use a constant-time AES library for those cases.
- Operates on exactly one 16-byte block per call; chain block operations at the application
  layer to implement modes such as CBC or CTR.
- `ptLen` / `ctLen` and `ctSize` / `ptSize` must all equal
  [`SSF_AES_BLOCK_SIZE`](#ssf-aes-block-size) (16) — strict equality on both length and
  buffer-size parameters, enforced by `SSF_REQUIRE`.
- The `SSFAESXXX` macros derive `nr` and `nk` from `keyLen` at compile time; `keyLen` must be a
  compile-time constant of 16, 24, or 32. Any other value produces incorrect round counts without
  a compile-time diagnostic.
- **No key material left on the stack:** the one-shot block functions and macros route through the
  reusable key schedule internally and securely wipe both the expanded round-key schedule and the
  per-block working state (via `SSFCryptSecureZero`) before returning.
- A [`SSFAESKeySchedule_t`](#ssf-aes-key-schedule) holds the expanded round keys and is secret.
  Zero it before its first [`SSFAESKeyScheduleInit()`](#ssfaeskeyscheduleinit) (e.g. `= {0}`), and
  call [`SSFAESKeyScheduleDeInit()`](#ssfaeskeyscheduledeinit) to securely wipe it when finished.
- This module is used internally by [`ssfaesgcm`](ssfaesgcm.md).

<a id="configuration"></a>

## [↑](#ssfaes--aes-block-cipher) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfaes--aes-block-cipher) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-aes-block-size"></a>`SSF_AES_BLOCK_SIZE` | Constant | `16` — size in bytes of one AES block; all encrypt/decrypt calls operate on exactly this many bytes |
| <a id="ssf-aes-max-round-key-words"></a>`SSF_AES_MAX_ROUND_KEY_WORDS` | Constant | `60` — number of 32-bit expanded round-key words for the largest key (AES-256: `(Nr + 1) * Nb`); sizes the schedule's key store |
| <a id="ssf-aes-key-schedule"></a>`SSFAESKeySchedule_t` | Type | Holds the expanded (secret) round keys and round count for a reusable key schedule; zero before first init and wipe with `SSFAESKeyScheduleDeInit()` |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-ks) | [`void SSFAESKeyScheduleInit(ks, key, keyLen)`](#ssfaeskeyscheduleinit) | Expand an AES key into a reusable round-key schedule (expand once, use for many blocks) |
| [e.g.](#ex-ks) | [`void SSFAESKeyScheduleDeInit(ks)`](#ssfaeskeyscheduledeinit) | Securely wipe a round-key schedule |
| [e.g.](#ex-ks) | [`void SSFAESKSBlockEncrypt(ks, pt, ptLen, ct, ctSize)`](#ssfaesksblockencrypt) | Encrypt a 16-byte block using a precomputed schedule |
| [e.g.](#ex-ks) | [`void SSFAESKSBlockDecrypt(ks, ct, ctLen, pt, ptSize)`](#ssfaesksblockdecrypt) | Decrypt a 16-byte block using a precomputed schedule |
| [e.g.](#ex-base) | [`void SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, nr, nk)`](#ssfaesblockencrypt) | Encrypt a 16-byte block using AES with explicit round and key-word counts |
| [e.g.](#ex-base) | [`void SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, nr, nk)`](#ssfaesblockdecrypt) | Decrypt a 16-byte block using AES with explicit round and key-word counts |
| [e.g.](#ex-128) | [`void SSFAES128BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)`](#ssfaes128blockencrypt) | Encrypt with AES-128 (nr=10, nk=4); `keyLen` must be 16 |
| [e.g.](#ex-128) | [`void SSFAES128BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)`](#ssfaes128blockdecrypt) | Decrypt with AES-128 (nr=10, nk=4); `keyLen` must be 16 |
| [e.g.](#ex-192) | [`void SSFAES192BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)`](#ssfaes192blockencrypt) | Encrypt with AES-192 (nr=12, nk=6); `keyLen` must be 24 |
| [e.g.](#ex-192) | [`void SSFAES192BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)`](#ssfaes192blockdecrypt) | Decrypt with AES-192 (nr=12, nk=6); `keyLen` must be 24 |
| [e.g.](#ex-256) | [`void SSFAES256BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)`](#ssfaes256blockencrypt) | Encrypt with AES-256 (nr=14, nk=8); `keyLen` must be 32 |
| [e.g.](#ex-256) | [`void SSFAES256BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)`](#ssfaes256blockdecrypt) | Decrypt with AES-256 (nr=14, nk=8); `keyLen` must be 32 |
| [e.g.](#ex-xxx) | [`void SSFAESXXXBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)`](#ssfaesxxxblockencrypt) | Encrypt with key size inferred from `keyLen` (16, 24, or 32) at compile time |
| [e.g.](#ex-xxx) | [`void SSFAESXXXBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)`](#ssfaesxxxblockdecrypt) | Decrypt with key size inferred from `keyLen` (16, 24, or 32) at compile time |

<a id="function-reference"></a>

## [↑](#ssfaes--aes-block-cipher) Function Reference

<a id="ssfaeskeyscheduleinit"></a>

### [↑](#functions) [`void SSFAESKeyScheduleInit()`](#functions)

```c
void SSFAESKeyScheduleInit(SSFAESKeySchedule_t *ks, const uint8_t *key, size_t keyLen);
```

Expands the `keyLen`-byte AES key at `key` into the reusable round-key schedule `ks`, so that the
same expanded key can encrypt or decrypt many blocks without re-deriving it per call. The schedule
must be zeroed before its first init (e.g. declared as `SSFAESKeySchedule_t ks = {0};`): the
function `SSF_REQUIRE`s that `ks` is not already an active schedule, rejecting re-initialization of
a live schedule. Call [`SSFAESKeyScheduleDeInit()`](#ssfaeskeyscheduledeinit) to wipe the schedule
when finished with it.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ks` | out | `SSFAESKeySchedule_t *` | Schedule to initialize. Must not be `NULL` and must not already be an active (initialized) schedule. |
| `key` | in | `const uint8_t *` | Pointer to the AES key bytes. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Number of key bytes. Must be 16 (AES-128), 24 (AES-192), or 32 (AES-256). |

**Returns:** Nothing.

---

<a id="ssfaeskeyscheduledeinit"></a>

### [↑](#functions) [`void SSFAESKeyScheduleDeInit()`](#functions)

```c
void SSFAESKeyScheduleDeInit(SSFAESKeySchedule_t *ks);
```

Securely wipes the round-key schedule `ks` (via `SSFCryptSecureZero`), erasing the expanded secret
round keys and clearing its active state so the storage can be re-initialized or discarded. `ks`
must be an active schedule initialized by [`SSFAESKeyScheduleInit()`](#ssfaeskeyscheduleinit).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ks` | in,out | `SSFAESKeySchedule_t *` | Active schedule to wipe. Must not be `NULL`. |

**Returns:** Nothing.

---

<a id="ssfaesksblockencrypt"></a>

### [↑](#functions) [`void SSFAESKSBlockEncrypt()`](#functions)

```c
void SSFAESKSBlockEncrypt(const SSFAESKeySchedule_t *ks, const uint8_t *pt, size_t ptLen,
                          uint8_t *ct, size_t ctSize);
```

Encrypts the `ptLen`-byte plaintext block at `pt` into the `ctSize`-byte output buffer `ct` using
the precomputed schedule `ks`. Both `ptLen` and `ctSize` must equal
[`SSF_AES_BLOCK_SIZE`](#ssf-aes-block-size). The per-block working state is securely wiped before
returning; the schedule `ks` is left intact for reuse.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ks` | in | `const SSFAESKeySchedule_t *` | Active schedule from [`SSFAESKeyScheduleInit()`](#ssfaeskeyscheduleinit). Must not be `NULL`. |
| `pt` | in | `const uint8_t *` | Pointer to the plaintext block. Must not be `NULL`. |
| `ptLen` | in | `size_t` | Number of plaintext bytes. Must equal `SSF_AES_BLOCK_SIZE` (16). |
| `ct` | out | `uint8_t *` | Buffer to receive the ciphertext block. Must not be `NULL`. |
| `ctSize` | in | `size_t` | Size of `ct`. Must equal `SSF_AES_BLOCK_SIZE` (16) — strict equality. |

**Returns:** Nothing.

---

<a id="ssfaesksblockdecrypt"></a>

### [↑](#functions) [`void SSFAESKSBlockDecrypt()`](#functions)

```c
void SSFAESKSBlockDecrypt(const SSFAESKeySchedule_t *ks, const uint8_t *ct, size_t ctLen,
                          uint8_t *pt, size_t ptSize);
```

Decrypts the `ctLen`-byte ciphertext block at `ct` into the `ptSize`-byte output buffer `pt` using
the precomputed schedule `ks`. Both `ctLen` and `ptSize` must equal
[`SSF_AES_BLOCK_SIZE`](#ssf-aes-block-size). The per-block working state is securely wiped before
returning; the schedule `ks` is left intact for reuse.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ks` | in | `const SSFAESKeySchedule_t *` | Active schedule from [`SSFAESKeyScheduleInit()`](#ssfaeskeyscheduleinit). Must not be `NULL`. |
| `ct` | in | `const uint8_t *` | Pointer to the ciphertext block. Must not be `NULL`. |
| `ctLen` | in | `size_t` | Number of ciphertext bytes. Must equal `SSF_AES_BLOCK_SIZE` (16). |
| `pt` | out | `uint8_t *` | Buffer to receive the decrypted plaintext. Must not be `NULL`. |
| `ptSize` | in | `size_t` | Size of `pt`. Must equal `SSF_AES_BLOCK_SIZE` (16) — strict equality. |

**Returns:** Nothing.

<a id="ex-ks"></a>

**Example:**

```c
/* Expand the key once, then encrypt/decrypt many blocks with it. */
uint8_t key[16] = {
    0x2bu, 0x7eu, 0x15u, 0x16u, 0x28u, 0xaeu, 0xd2u, 0xa6u,
    0xabu, 0xf7u, 0x15u, 0x88u, 0x09u, 0xcfu, 0x4fu, 0x3cu
};
uint8_t pt[SSF_AES_BLOCK_SIZE] = {
    0x32u, 0x43u, 0xf6u, 0xa8u, 0x88u, 0x5au, 0x30u, 0x8du,
    0x31u, 0x31u, 0x98u, 0xa2u, 0xe0u, 0x37u, 0x07u, 0x34u
};
uint8_t ct[SSF_AES_BLOCK_SIZE];
uint8_t dt[SSF_AES_BLOCK_SIZE];
SSFAESKeySchedule_t ks = {0};  /* must be zeroed before the first init */

SSFAESKeyScheduleInit(&ks, key, sizeof(key));   /* expand round keys once */
SSFAESKSBlockEncrypt(&ks, pt, sizeof(pt), ct, sizeof(ct));
SSFAESKSBlockDecrypt(&ks, ct, sizeof(ct), dt, sizeof(dt));
/* memcmp(dt, pt, SSF_AES_BLOCK_SIZE) == 0 */
SSFAESKeyScheduleDeInit(&ks);                   /* securely wipe the schedule */
```

---

<a id="ssfaesblockencrypt"></a>

### [↑](#functions) [`void SSFAESBlockEncrypt()`](#functions)

```c
void SSFAESBlockEncrypt(const uint8_t *pt, size_t ptLen, uint8_t *ct, size_t ctSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk);
```

Encrypts the `ptLen`-byte plaintext block at `pt` into the `ctSize`-byte output buffer `ct`
using AES with `nr` rounds and `nk` 32-bit key words. Both `ptLen` and `ctSize` must equal
[`SSF_AES_BLOCK_SIZE`](#ssf-aes-block-size). Prefer the fixed-key or `SSFAESXXX` macros over
calling this function directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Pointer to the plaintext block. Must not be `NULL`. |
| `ptLen` | in | `size_t` | Number of plaintext bytes. Must equal `SSF_AES_BLOCK_SIZE` (16). |
| `ct` | out | `uint8_t *` | Buffer to receive the ciphertext block. Must not be `NULL` and must not overlap `pt`. |
| `ctSize` | in | `size_t` | Size of `ct`. Must equal `SSF_AES_BLOCK_SIZE` (16) — strict equality. |
| `key` | in | `const uint8_t *` | Pointer to the AES key bytes. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Number of key bytes. Must be 16, 24, or 32, consistent with `nr` and `nk`. |
| `nr` | in | `uint8_t` | Number of AES rounds: 10 for AES-128, 12 for AES-192, 14 for AES-256. |
| `nk` | in | `uint8_t` | Number of 32-bit words in the key: 4 for AES-128, 6 for AES-192, 8 for AES-256. |

**Returns:** Nothing.

---

<a id="ssfaesblockdecrypt"></a>

### [↑](#functions) [`void SSFAESBlockDecrypt()`](#functions)

```c
void SSFAESBlockDecrypt(const uint8_t *ct, size_t ctLen, uint8_t *pt, size_t ptSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk);
```

Decrypts the `ctLen`-byte ciphertext block at `ct` into the `ptSize`-byte output buffer `pt`
using AES with `nr` rounds and `nk` 32-bit key words. Both `ctLen` and `ptSize` must equal
[`SSF_AES_BLOCK_SIZE`](#ssf-aes-block-size). Prefer the fixed-key or `SSFAESXXX` macros over
calling this function directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ct` | in | `const uint8_t *` | Pointer to the ciphertext block. Must not be `NULL`. |
| `ctLen` | in | `size_t` | Number of ciphertext bytes. Must equal `SSF_AES_BLOCK_SIZE` (16). |
| `pt` | out | `uint8_t *` | Buffer to receive the decrypted plaintext. Must not be `NULL` and must not overlap `ct`. |
| `ptSize` | in | `size_t` | Size of `pt`. Must equal `SSF_AES_BLOCK_SIZE` (16) — strict equality. |
| `key` | in | `const uint8_t *` | Pointer to the AES key bytes. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Number of key bytes. Must be 16, 24, or 32, consistent with `nr` and `nk`. |
| `nr` | in | `uint8_t` | Number of AES rounds: 10 for AES-128, 12 for AES-192, 14 for AES-256. |
| `nk` | in | `uint8_t` | Number of 32-bit words in the key: 4 for AES-128, 6 for AES-192, 8 for AES-256. |

**Returns:** Nothing.

<a id="ex-base"></a>

**Example:**

```c
/* FIPS-197 Appendix B test vector (AES-128) */
uint8_t key[16] = {
    0x2bu, 0x7eu, 0x15u, 0x16u, 0x28u, 0xaeu, 0xd2u, 0xa6u,
    0xabu, 0xf7u, 0x15u, 0x88u, 0x09u, 0xcfu, 0x4fu, 0x3cu
};
uint8_t pt[SSF_AES_BLOCK_SIZE] = {
    0x32u, 0x43u, 0xf6u, 0xa8u, 0x88u, 0x5au, 0x30u, 0x8du,
    0x31u, 0x31u, 0x98u, 0xa2u, 0xe0u, 0x37u, 0x07u, 0x34u
};
uint8_t ct[SSF_AES_BLOCK_SIZE];
uint8_t dt[SSF_AES_BLOCK_SIZE];

/* Encrypt — AES-128: nr=10, nk=4 */
SSFAESBlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key), 10, 4);
/* ct == { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
           0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 } */

/* Decrypt recovers the original plaintext */
SSFAESBlockDecrypt(ct, sizeof(ct), dt, sizeof(dt), key, sizeof(key), 10, 4);
/* memcmp(dt, pt, SSF_AES_BLOCK_SIZE) == 0 */
```

---

<a id="fixed-key-encrypt-macros"></a>

### [↑](#functions) Fixed-Key Encrypt Macros

Convenience macros that expand to [`SSFAESBlockEncrypt()`](#ssfaesblockencrypt) with `nr` and
`nk` pre-set for a specific key size. All parameters are forwarded unchanged; `keyLen` must
match the fixed size for the chosen variant.

<a id="ssfaes128blockencrypt"></a>

#### [↑](#functions) [`void SSFAES128BlockEncrypt()`](#functions)

```c
SSFAES128BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)
```

Expands to `SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 10, 4)`. `keyLen` must be 16.

<a id="ssfaes192blockencrypt"></a>

#### [↑](#functions) [`void SSFAES192BlockEncrypt()`](#functions)

```c
SSFAES192BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)
```

Expands to `SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 12, 6)`. `keyLen` must be 24.

<a id="ssfaes256blockencrypt"></a>

#### [↑](#functions) [`void SSFAES256BlockEncrypt()`](#functions)

```c
SSFAES256BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)
```

Expands to `SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 14, 8)`. `keyLen` must be 32.

---

<a id="fixed-key-decrypt-macros"></a>

### [↑](#functions) Fixed-Key Decrypt Macros

Convenience macros that expand to [`SSFAESBlockDecrypt()`](#ssfaesblockdecrypt) with `nr` and
`nk` pre-set for a specific key size. All parameters are forwarded unchanged; `keyLen` must
match the fixed size for the chosen variant.

<a id="ssfaes128blockdecrypt"></a>

#### [↑](#functions) [`void SSFAES128BlockDecrypt()`](#functions)

```c
SSFAES128BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)
```

Expands to `SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 10, 4)`. `keyLen` must be 16.

<a id="ex-128"></a>

**Example:**

```c
uint8_t key128[16] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu
};
uint8_t pt[SSF_AES_BLOCK_SIZE] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
};
uint8_t ct[SSF_AES_BLOCK_SIZE];
uint8_t dt[SSF_AES_BLOCK_SIZE];

SSFAES128BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key128, sizeof(key128));
SSFAES128BlockDecrypt(ct, sizeof(ct), dt, sizeof(dt), key128, sizeof(key128));
/* memcmp(dt, pt, SSF_AES_BLOCK_SIZE) == 0 */
```

<a id="ssfaes192blockdecrypt"></a>

#### [↑](#functions) [`void SSFAES192BlockDecrypt()`](#functions)

```c
SSFAES192BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)
```

Expands to `SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 12, 6)`. `keyLen` must be 24.

<a id="ex-192"></a>

**Example:**

```c
uint8_t key192[24] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u
};
uint8_t pt[SSF_AES_BLOCK_SIZE] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
};
uint8_t ct[SSF_AES_BLOCK_SIZE];
uint8_t dt[SSF_AES_BLOCK_SIZE];

SSFAES192BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key192, sizeof(key192));
SSFAES192BlockDecrypt(ct, sizeof(ct), dt, sizeof(dt), key192, sizeof(key192));
/* memcmp(dt, pt, SSF_AES_BLOCK_SIZE) == 0 */
```

<a id="ssfaes256blockdecrypt"></a>

#### [↑](#functions) [`void SSFAES256BlockDecrypt()`](#functions)

```c
SSFAES256BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)
```

Expands to `SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 14, 8)`. `keyLen` must be 32.

<a id="ex-256"></a>

**Example:**

```c
uint8_t key256[32] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
};
uint8_t pt[SSF_AES_BLOCK_SIZE] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
};
uint8_t ct[SSF_AES_BLOCK_SIZE];
uint8_t dt[SSF_AES_BLOCK_SIZE];

SSFAES256BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key256, sizeof(key256));
SSFAES256BlockDecrypt(ct, sizeof(ct), dt, sizeof(dt), key256, sizeof(key256));
/* memcmp(dt, pt, SSF_AES_BLOCK_SIZE) == 0 */
```

---

<a id="ssfaesxxxblockencrypt"></a>

### [↑](#functions) [`void SSFAESXXXBlockEncrypt()`](#functions)

```c
SSFAESXXXBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)
```

Convenience macro that derives `nr` and `nk` from `keyLen` at compile time:
`nr = 6 + (keyLen >> 2)`, `nk = keyLen >> 2` (low byte of `keyLen` only). `keyLen` must be a
compile-time constant of 16, 24, or 32; any other value produces incorrect round counts without
a compile-time diagnostic. Expands to [`SSFAESBlockEncrypt()`](#ssfaesblockencrypt).

**Returns:** Nothing (expands to a `void` function call).

---

<a id="ssfaesxxxblockdecrypt"></a>

### [↑](#functions) [`void SSFAESXXXBlockDecrypt()`](#functions)

```c
SSFAESXXXBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)
```

Convenience macro that derives `nr` and `nk` from `keyLen` at compile time, identical in
behaviour to [`SSFAESXXXBlockEncrypt()`](#ssfaesxxxblockencrypt) but expands to
[`SSFAESBlockDecrypt()`](#ssfaesblockdecrypt). `keyLen` must be a compile-time constant of 16,
24, or 32.

**Returns:** Nothing (expands to a `void` function call).

<a id="ex-xxx"></a>

**Example:**

```c
/* keyLen must be a compile-time constant: 16, 24, or 32 */
uint8_t key[32] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu,
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
};
uint8_t pt[SSF_AES_BLOCK_SIZE] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
};
uint8_t ct[SSF_AES_BLOCK_SIZE];
uint8_t dt[SSF_AES_BLOCK_SIZE];

/* nr and nk derived at compile time from sizeof(key) == 32 → AES-256 (nr=14, nk=8) */
SSFAESXXXBlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));
SSFAESXXXBlockDecrypt(ct, sizeof(ct), dt, sizeof(dt), key, sizeof(key));
/* memcmp(dt, pt, SSF_AES_BLOCK_SIZE) == 0 */
```
