# ssfaes — AES Block Cipher

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

AES block cipher supporting 128, 192, and 256-bit keys for 16-byte block encryption/decryption.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFAES128BlockEncrypt(pt, ptSize, ct, ctSize, key, keySize)` | Encrypt one 16-byte block with a 128-bit key |
| `SSFAES128BlockDecrypt(ct, ctSize, pt, ptSize, key, keySize)` | Decrypt one 16-byte block with a 128-bit key |
| `SSFAES192BlockEncrypt(pt, ptSize, ct, ctSize, key, keySize)` | Encrypt one 16-byte block with a 192-bit key |
| `SSFAES192BlockDecrypt(ct, ctSize, pt, ptSize, key, keySize)` | Decrypt one 16-byte block with a 192-bit key |
| `SSFAES256BlockEncrypt(pt, ptSize, ct, ctSize, key, keySize)` | Encrypt one 16-byte block with a 256-bit key |
| `SSFAES256BlockDecrypt(ct, ctSize, pt, ptSize, key, keySize)` | Decrypt one 16-byte block with a 256-bit key |
| `SSFAESXXXBlockEncrypt(pt, ptSize, ct, ctSize, key, keySize)` | Encrypt one block; key size inferred from `keySize` |
| `SSFAESXXXBlockDecrypt(ct, ctSize, pt, ptSize, key, keySize)` | Decrypt one block; key size inferred from `keySize` |

## Usage

The AES block interface encrypts and decrypts individual 16-byte blocks. Key-size-specific macros
are provided for the common cases; the generic `SSFAESXXX` variants select the correct key
schedule based on `keySize`.

```c
uint8_t pt[16];
uint8_t ct[16];
uint8_t dpt[16];
uint8_t key[16];

memcpy(pt,  "1234567890abcdef", sizeof(pt));
memcpy(key, "secretkey1234567", sizeof(key));

/* Encrypt */
SSFAES128BlockEncrypt(pt, sizeof(pt), ct, sizeof(ct), key, sizeof(key));
/* ct == "\xdc\xc9\x32\xee\xfa\x94\x00\x0d\xfb\x97\x3f\xd4\x3d\x52\x6c\x45" */

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
- Plaintext, ciphertext, and key buffers must each be exactly 16 bytes for block operations.
