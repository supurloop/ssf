# ssfaes — AES Block Cipher

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

AES block cipher supporting 128, 192, and 256-bit keys for 16-byte block encryption/decryption.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, nr, nk)` | Encrypt one 16-byte block (base function) |
| `SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, nr, nk)` | Decrypt one 16-byte block (base function) |
| `SSFAES128BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)` | Encrypt one 16-byte block with a 128-bit key |
| `SSFAES128BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)` | Decrypt one 16-byte block with a 128-bit key |
| `SSFAES192BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)` | Encrypt one 16-byte block with a 192-bit key |
| `SSFAES192BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)` | Decrypt one 16-byte block with a 192-bit key |
| `SSFAES256BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)` | Encrypt one 16-byte block with a 256-bit key |
| `SSFAES256BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)` | Decrypt one 16-byte block with a 256-bit key |
| `SSFAESXXXBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen)` | Encrypt one block; key size inferred from `keyLen` |
| `SSFAESXXXBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen)` | Decrypt one block; key size inferred from `keyLen` |
| `SSF_AES_BLOCK_SIZE` | AES block size constant (16 bytes) |

## Function Reference

### `SSFAESBlockEncrypt`

```c
void SSFAESBlockEncrypt(const uint8_t *pt, size_t ptLen, uint8_t *ct, size_t ctSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk);
```

Encrypts exactly one AES block (16 bytes) of plaintext into ciphertext using the supplied key
and AES round/key-word parameters. Prefer the key-size-specific macros over calling this function
directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pt` | in | `const uint8_t *` | Pointer to the 16-byte plaintext block to encrypt. Must not be `NULL`. |
| `ptLen` | in | `size_t` | Length of `pt`. Must equal `SSF_AES_BLOCK_SIZE` (16). |
| `ct` | out | `uint8_t *` | Buffer receiving the 16-byte ciphertext block. Must not be `NULL`. Must not overlap `pt`. |
| `ctSize` | in | `size_t` | Allocated size of `ct`. Must be at least `SSF_AES_BLOCK_SIZE` (16). |
| `key` | in | `const uint8_t *` | Pointer to the AES key. Must not be `NULL`. |
| `keyLen` | in | `size_t` | Length of `key` in bytes: 16 (AES-128), 24 (AES-192), or 32 (AES-256). |
| `nr` | in | `uint8_t` | Number of AES rounds: 10 (AES-128), 12 (AES-192), or 14 (AES-256). |
| `nk` | in | `uint8_t` | Number of 32-bit key words: 4 (AES-128), 6 (AES-192), or 8 (AES-256). |

**Returns:** Nothing.

---

### `SSFAESBlockDecrypt`

```c
void SSFAESBlockDecrypt(const uint8_t *ct, size_t ctLen, uint8_t *pt, size_t ptSize,
                        const uint8_t *key, size_t keyLen, uint8_t nr, uint8_t nk);
```

Decrypts exactly one AES block (16 bytes) of ciphertext into plaintext. Parameters and return
value are symmetric to `SSFAESBlockEncrypt` with `ct` and `pt` swapped.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ct` | in | `const uint8_t *` | Pointer to the 16-byte ciphertext block. Must not be `NULL`. |
| `ctLen` | in | `size_t` | Length of `ct`. Must equal `SSF_AES_BLOCK_SIZE` (16). |
| `pt` | out | `uint8_t *` | Buffer receiving the 16-byte plaintext block. Must not be `NULL`. Must not overlap `ct`. |
| `ptSize` | in | `size_t` | Allocated size of `pt`. Must be at least `SSF_AES_BLOCK_SIZE` (16). |
| `key` | in | `const uint8_t *` | Pointer to the AES key. Must not be `NULL`. Same key used for encryption. |
| `keyLen` | in | `size_t` | Length of `key` in bytes: 16, 24, or 32. |
| `nr` | in | `uint8_t` | Number of AES rounds: 10, 12, or 14. |
| `nk` | in | `uint8_t` | Number of 32-bit key words: 4, 6, or 8. |

**Returns:** Nothing.

---

### `SSFAES128/192/256 BlockEncrypt/Decrypt`

```c
#define SSFAES128BlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen) \
    SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, 10, 4)
#define SSFAES128BlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen) \
    SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, 10, 4)
/* (similar macros for 192 with nr=12,nk=6 and 256 with nr=14,nk=8) */
```

Key-size-specific convenience macros that supply the correct `nr` and `nk` values automatically.
Use these for the common case when the key size is known at compile time. Parameters are
identical to `SSFAESBlockEncrypt` / `SSFAESBlockDecrypt` without the `nr` and `nk` arguments.

---

### `SSFAESXXXBlockEncrypt` / `SSFAESXXXBlockDecrypt`

```c
#define SSFAESXXXBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen) \
    SSFAESBlockEncrypt(pt, ptLen, ct, ctSize, key, keyLen, \
                       (6 + (((keyLen) & 0xff) >> 2)), (((keyLen) & 0xff) >> 2))
#define SSFAESXXXBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen) \
    SSFAESBlockDecrypt(ct, ctLen, pt, ptSize, key, keyLen, \
                       (6 + (((keyLen) & 0xff) >> 2)), (((keyLen) & 0xff) >> 2))
```

Generic convenience macros that derive `nr` and `nk` from `keyLen` at compile time. Use these
when the key size is determined at runtime or when writing code that handles multiple key sizes.
`keyLen` must be 16, 24, or 32; other values produce undefined behavior.

## Usage

The AES block interface encrypts and decrypts individual 16-byte blocks. Key-size-specific macros
are provided for the common cases; the generic `SSFAESXXX` variants select the correct key
schedule based on `keyLen`.

```c
uint8_t pt[16];
uint8_t ct[16];
uint8_t dpt[16];
uint8_t key[16];

memcpy(pt,  "1234567890abcdef", sizeof(pt));
memcpy(key, "secretkey1234567", sizeof(key));

/* Encrypt */
SSFAES128BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));

/* Decrypt */
SSFAES128BlockDecrypt(ct, sizeof(ct), dpt, sizeof(dpt), key, sizeof(key));
/* dpt == "1234567890abcdef" */

/* Generic interface when key size is variable */
SSFAESXXXBlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));
SSFAESXXXBlockDecrypt(ct, sizeof(ct), dpt, sizeof(dpt), key, sizeof(key));
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- **This implementation is vulnerable to timing attacks.** It SHOULD NOT be used in production
  systems where side-channel security is required. Prefer processor-specific AES hardware
  instructions when available.
- This module is used internally by [ssfaesgcm](ssfaesgcm.md).
- All buffers (`pt`, `ct`, `key`) must be exactly `SSF_AES_BLOCK_SIZE` (16) bytes for block
  operations; the key buffer must match the chosen key length.
