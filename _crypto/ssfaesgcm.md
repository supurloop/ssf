# ssfaesgcm — AES-GCM Authenticated Encryption

[SSF](../README.md) | [Cryptography](README.md)

AES-128-GCM, AES-192-GCM, and AES-256-GCM authenticated encryption and decryption for
arbitrary-length data.

The interface supports four operating modes selected by which parameters are non-`NULL`: tag
generation over an empty message, tag generation over additional authenticated data (AAD) only,
authenticated encryption without AAD, and authenticated encryption with AAD. Pass `NULL` and `0`
for any unused field.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfaes`](ssfaes.md) — AES block cipher used internally

<a id="notes"></a>

## [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) Notes

- **Timing attack warning:** This implementation relies on the timing-attack-vulnerable
  [`ssfaes`](ssfaes.md) block cipher. Do not use in production environments where an attacker
  can observe precise execution times.
- The IV must be unique for every encryption performed with the same key. Reusing an IV with
  the same key completely breaks GCM confidentiality and authenticity.
- A 96-bit (12-byte) IV is recommended per the GCM specification and is slightly more efficient
  than other IV lengths; any length is accepted.
- Supported key sizes: 16 bytes (AES-128-GCM), 24 bytes (AES-192-GCM), 32 bytes (AES-256-GCM).
- `SSFAESGCMDecrypt()` verifies the authentication tag before decrypting. Always check the
  return value; treat the output plaintext buffer as invalid when `false` is returned.
- A common embedded IV strategy is to concatenate an 8-byte device EUI-64 with a 4-byte
  big-endian frame counter that increments monotonically.

<a id="configuration"></a>

## [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) API Summary

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-encrypt) | [`SSFAESGCMEncrypt(pt, ptLen, iv, ivLen, auth, authLen, key, keyLen, tag, tagSize, ct, ctSize)`](#ssfaesgcmencrypt) | Encrypt and/or authenticate data; produce an authentication tag |
| [e.g.](#ex-decrypt) | [`SSFAESGCMDecrypt(ct, ctLen, iv, ivLen, auth, authLen, key, keyLen, tag, tagLen, pt, ptSize)`](#ssfaesgcmdecrypt) | Verify authentication tag and decrypt data |

<a id="function-reference"></a>

## [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) Function Reference

<a id="ssfaesgcmencrypt"></a>

### [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) [`SSFAESGCMEncrypt()`](#ex-encrypt)

```c
void SSFAESGCMEncrypt(const uint8_t *pt, size_t ptLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *auth, size_t authLen, const uint8_t *key, size_t keyLen,
                      uint8_t *tag, size_t tagSize, uint8_t *ct, size_t ctSize);
```

Performs AES-GCM authenticated encryption. Encrypts `ptLen` bytes from `pt` into `ct` and
produces a 16-byte authentication tag over the ciphertext and any additional authenticated data
(`auth`). The operating mode is determined by which data fields are non-`NULL`:

| `pt` / `ct` | `auth` | Mode |
|:-----------:|:------:|------|
| `NULL` | `NULL` | Tag over empty message only |
| `NULL` | non-`NULL` | Tag over AAD only; no encryption |
| non-`NULL` | `NULL` | Authenticated encryption; no AAD |
| non-`NULL` | non-`NULL` | Authenticated encryption with AAD |

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Plaintext to encrypt. Pass `NULL` for auth-only modes. |
| `ptLen` | in | `size_t` | Number of plaintext bytes. Must be `0` when `pt` is `NULL`. |
| `iv` | in | `const uint8_t *` | Initialization vector. Must not be `NULL`. Must be unique per encryption with the same key. |
| `ivLen` | in | `size_t` | Length of `iv` in bytes. Any length is accepted; 12 is recommended. |
| `auth` | in | `const uint8_t *` | Additional authenticated data (AAD) to authenticate but not encrypt. Pass `NULL` when not used. |
| `authLen` | in | `size_t` | Number of AAD bytes. Must be `0` when `auth` is `NULL`. |
| `key` | in | `const uint8_t *` | AES key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Length of `key`: 16 (AES-128-GCM), 24 (AES-192-GCM), or 32 (AES-256-GCM). |
| `tag` | out | `uint8_t *` | Buffer receiving the 16-byte authentication tag. Must not be `NULL`. |
| `tagSize` | in | `size_t` | Size of `tag`. Must be at least 16 bytes. |
| `ct` | out | `uint8_t *` | Buffer receiving the ciphertext. Pass `NULL` when `pt` is `NULL`. When non-`NULL`, must be at least `ptLen` bytes. |
| `ctSize` | in | `size_t` | Size of `ct`. Must be at least `ptLen` when `ct` is non-`NULL`. |

**Returns:** Nothing.

---

<a id="ssfaesgcmdecrypt"></a>

### [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) [`SSFAESGCMDecrypt()`](#ex-decrypt)

```c
bool SSFAESGCMDecrypt(const uint8_t *ct, size_t ctLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *auth, size_t authLen, const uint8_t *key, size_t keyLen,
                      const uint8_t *tag, size_t tagLen, uint8_t *pt, size_t ptSize);
```

Performs AES-GCM authenticated decryption. Verifies the authentication tag produced by
[`SSFAESGCMEncrypt()`](#ssfaesgcmencrypt) before decrypting. If verification fails, `false` is
returned and the contents of `pt` must be treated as invalid. All parameters (`iv`, `auth`,
`key`, `tag`) must exactly match those used during encryption.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ct` | in | `const uint8_t *` | Ciphertext to decrypt. Pass `NULL` for auth-only verification. |
| `ctLen` | in | `size_t` | Number of ciphertext bytes. Must be `0` when `ct` is `NULL`. |
| `iv` | in | `const uint8_t *` | Initialization vector used during encryption. Must not be `NULL`. |
| `ivLen` | in | `size_t` | Length of `iv` in bytes. Must match the value used during encryption. |
| `auth` | in | `const uint8_t *` | Additional authenticated data. Pass `NULL` when not used. Must match the value used during encryption. |
| `authLen` | in | `size_t` | Number of AAD bytes. Must be `0` when `auth` is `NULL`. |
| `key` | in | `const uint8_t *` | AES key. Must not be `NULL`. Must match the key used during encryption. |
| `keyLen` | in | `size_t` | Length of `key`: 16, 24, or 32. Must match the value used during encryption. |
| `tag` | in | `const uint8_t *` | Authentication tag produced by `SSFAESGCMEncrypt()`. Must not be `NULL`. |
| `tagLen` | in | `size_t` | Length of `tag` in bytes. Must match the tag length produced during encryption. |
| `pt` | out | `uint8_t *` | Buffer receiving the decrypted plaintext. Pass `NULL` when `ct` is `NULL`. When non-`NULL`, must be at least `ctLen` bytes. |
| `ptSize` | in | `size_t` | Size of `pt`. Must be at least `ctLen` when `pt` is non-`NULL`. |

**Returns:** `true` if the authentication tag verified and decryption succeeded; `false` if the
tag did not match or an argument is invalid. Always check the return value before using `pt`.

<a id="examples"></a>

## [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) Examples

The examples below share this key and IV:

```c
uint8_t key[16] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu
};
/* 96-bit IV — must be unique for every encryption with this key */
uint8_t iv[12] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu
};
uint8_t tag[16];
```

<a id="ex-encrypt"></a>

### [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) [SSFAESGCMEncrypt()](#ssfaesgcmencrypt)

```c
uint8_t pt[]   = { 0x48u, 0x65u, 0x6cu, 0x6cu, 0x6fu }; /* "Hello" */
uint8_t auth[] = { 0x68u, 0x64u, 0x72u };                /* "hdr"   */
uint8_t ct[sizeof(pt)];

/* Mode 1: tag over empty message — no plaintext, no AAD */
SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), NULL, 0,
                 key, sizeof(key), tag, sizeof(tag), NULL, 0);

/* Mode 2: tag over AAD only — authenticate header without encrypting anything */
SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), auth, sizeof(auth),
                 key, sizeof(key), tag, sizeof(tag), NULL, 0);

/* Mode 3: authenticated encryption without AAD */
SSFAESGCMEncrypt(pt, sizeof(pt), iv, sizeof(iv), NULL, 0,
                 key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));

/* Mode 4: authenticated encryption with AAD */
SSFAESGCMEncrypt(pt, sizeof(pt), iv, sizeof(iv), auth, sizeof(auth),
                 key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));
```

<a id="ex-decrypt"></a>

### [↑](#ssfaesgcm--aes-gcm-authenticated-encryption) [SSFAESGCMDecrypt()](#ssfaesgcmdecrypt)

```c
uint8_t dpt[sizeof(pt)];

/* Verify tag and decrypt the output produced by Mode 4 above */
if (SSFAESGCMDecrypt(ct, sizeof(ct), iv, sizeof(iv), auth, sizeof(auth),
                     key, sizeof(key), tag, sizeof(tag), dpt, sizeof(dpt)))
{
    /* Authentication verified; dpt == pt */
}

/* A tampered ciphertext, tag, or AAD causes SSFAESGCMDecrypt() to return false */
uint8_t badTag[16] = { 0 };
if (!SSFAESGCMDecrypt(ct, sizeof(ct), iv, sizeof(iv), auth, sizeof(auth),
                      key, sizeof(key), badTag, sizeof(badTag), dpt, sizeof(dpt)))
{
    /* Authentication failed; treat dpt as invalid */
}

/* Auth-only verification (Mode 2): ct == NULL, pt == NULL */
if (SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), auth, sizeof(auth),
                     key, sizeof(key), tag, sizeof(tag), NULL, 0))
{
    /* AAD authenticated successfully */
}
```
