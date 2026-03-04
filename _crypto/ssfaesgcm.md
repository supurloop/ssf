# ssfaesgcm — AES-GCM Authenticated Encryption

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

AES-GCM authenticated encryption and decryption for arbitrary-length data.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFAESGCMEncrypt(pt, ptLen, iv, ivLen, auth, authLen, key, keyLen, tag, tagSize, ct, ctSize)` | Encrypt and/or authenticate data |
| `SSFAESGCMDecrypt(ct, ctLen, iv, ivLen, auth, authLen, key, keyLen, tag, tagLen, pt, ptSize)` | Decrypt and verify authentication tag |

## Function Reference

### `SSFAESGCMEncrypt`

```c
void SSFAESGCMEncrypt(const uint8_t *pt, size_t ptLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *auth, size_t authLen, const uint8_t *key, size_t keyLen,
                      uint8_t *tag, size_t tagSize, uint8_t *ct, size_t ctSize);
```

Performs AES-GCM authenticated encryption. Encrypts `pt` into `ct` and produces an authentication
tag over both the ciphertext and the additional authenticated data (`auth`). Supports four
operating modes depending on which fields are non-`NULL`:

- **Authentication only** (`pt`/`ct` = `NULL`, `auth` = `NULL`): generates a tag over nothing
- **Auth-data only** (`pt`/`ct` = `NULL`, `auth` non-`NULL`): generates a tag over `auth`
- **Authenticated encryption** (`pt`/`ct` non-`NULL`, `auth` = `NULL`): encrypts and tags `pt`
- **Authenticated encryption with AAD** (all non-`NULL`): encrypts `pt` and tags both

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Plaintext to encrypt. Pass `NULL` when there is no plaintext to encrypt (auth-only modes). |
| `ptLen` | in | `size_t` | Number of plaintext bytes. Must be `0` when `pt` is `NULL`. |
| `iv` | in | `const uint8_t *` | Initialization vector. Must not be `NULL`. A 96-bit (12-byte) IV is recommended. Must be unique for every encryption with the same key. |
| `ivLen` | in | `size_t` | Length of `iv` in bytes. Any length is accepted; 12 bytes is most efficient. |
| `auth` | in | `const uint8_t *` | Additional authenticated data (AAD) to authenticate but not encrypt. Pass `NULL` when there is no AAD. |
| `authLen` | in | `size_t` | Number of AAD bytes. Must be `0` when `auth` is `NULL`. |
| `key` | in | `const uint8_t *` | AES key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Length of `key` in bytes: 16 (AES-128-GCM), 24 (AES-192-GCM), or 32 (AES-256-GCM). |
| `tag` | out | `uint8_t *` | Buffer receiving the authentication tag. Must not be `NULL`. |
| `tagSize` | in | `size_t` | Allocated size of `tag`. Must be at least 16 bytes (full GCM tag). |
| `ct` | out | `uint8_t *` | Buffer receiving the ciphertext. Pass `NULL` when there is no plaintext. When non-`NULL`, must be at least `ptLen` bytes. |
| `ctSize` | in | `size_t` | Allocated size of `ct`. Must be at least `ptLen` when `ct` is non-`NULL`. |

**Returns:** Nothing.

---

### `SSFAESGCMDecrypt`

```c
bool SSFAESGCMDecrypt(const uint8_t *ct, size_t ctLen, const uint8_t *iv, size_t ivLen,
                      const uint8_t *auth, size_t authLen, const uint8_t *key, size_t keyLen,
                      const uint8_t *tag, size_t tagLen, uint8_t *pt, size_t ptSize);
```

Performs AES-GCM authenticated decryption. Verifies the authentication tag before decrypting.
If the tag does not match, the function returns `false` and the output plaintext buffer should be
considered invalid.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ct` | in | `const uint8_t *` | Ciphertext to decrypt. Pass `NULL` when there is no ciphertext. |
| `ctLen` | in | `size_t` | Number of ciphertext bytes. Must be `0` when `ct` is `NULL`. |
| `iv` | in | `const uint8_t *` | Initialization vector used during encryption. Must not be `NULL`. |
| `ivLen` | in | `size_t` | Length of `iv` in bytes. Must match the value used during encryption. |
| `auth` | in | `const uint8_t *` | Additional authenticated data. Pass `NULL` when not used. Must match the value used during encryption. |
| `authLen` | in | `size_t` | Number of AAD bytes. Must be `0` when `auth` is `NULL`. |
| `key` | in | `const uint8_t *` | AES key. Must not be `NULL`. Must match the key used during encryption. |
| `keyLen` | in | `size_t` | Length of `key` in bytes: 16, 24, or 32. |
| `tag` | in | `const uint8_t *` | Authentication tag produced by `SSFAESGCMEncrypt`. Must not be `NULL`. |
| `tagLen` | in | `size_t` | Length of `tag` in bytes. Must match the tag length produced during encryption. |
| `pt` | out | `uint8_t *` | Buffer receiving the decrypted plaintext. Pass `NULL` when there is no ciphertext. When non-`NULL`, must be at least `ctLen` bytes. |
| `ptSize` | in | `size_t` | Allocated size of `pt`. Must be at least `ctLen` when `pt` is non-`NULL`. |

**Returns:** `true` if the authentication tag verified and (when applicable) decryption succeeded; `false` if the tag did not match or an argument error occurred.

## Usage

AES-GCM provides four modes depending on which parameters are supplied: authentication only,
authenticated data only, authenticated encryption, and authenticated encryption with additional
authenticated data. Pass `NULL` and `0` for unused data fields.

A 96-bit IV is recommended and slightly more efficient than other IV lengths. A common embedded
approach is to combine a device EUI-64 with a monotonically increasing frame counter:

```c
#define AES_GCM_MAKE_IV(iv, eui, fc) {      \
    uint32_t befc = htonl(fc);              \
    memcpy(iv, eui, 8);                     \
    memcpy(&iv[8], &befc, 4);               \
    befc = ~befc;                           \
    memcpy(&iv[12], &befc, 4);              \
}

uint8_t pt[100], dpt[100], iv[16], auth[100], key[16], tag[16], ct[100];
uint8_t eui64[8];
uint32_t frameCounter = 0;
size_t ptLen, authLen;

memcpy(eui64, "\x12\x34\x45\x67\x89\xab\xcd\xef", sizeof(eui64));
memcpy(pt,   "1234567890abcdef", 16);  ptLen  = 16;
memcpy(key,  "secretkey1234567", sizeof(key));
memcpy(auth, "unencrypted auth data", 21); authLen = 21;

/* Authenticated encryption with AAD */
AES_GCM_MAKE_IV(iv, eui64, frameCounter++);
SSFAESGCMEncrypt(pt, ptLen, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag, sizeof(tag),
                 ct, sizeof(ct));
if (!SSFAESGCMDecrypt(ct, ptLen, iv, sizeof(iv), auth, authLen, key, sizeof(key), tag, sizeof(tag),
                      dpt, sizeof(dpt)))
    /* Decryption or authentication failed */;
```

## Dependencies

- `ssf/ssfport.h`
- [ssfaes](ssfaes.md) — AES block cipher (used internally)

## Notes

- **This implementation relies on the timing-attack-vulnerable AES block cipher.** Do not use
  in production systems where side-channel security is required.
- Always verify that the frame counter in the IV has increased monotonically to prevent replay
  attacks.
- Supported key sizes: 128, 192, and 256 bits.
- Any IV length is accepted; a 96-bit (12-byte) IV is recommended per the GCM specification.
