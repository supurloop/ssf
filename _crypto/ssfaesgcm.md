# ssfaesgcm — AES-GCM Authenticated Encryption

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

AES-GCM authenticated encryption and decryption for arbitrary-length data.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFAESGCMEncrypt(pt, ptLen, iv, ivSize, aad, aadLen, key, keySize, tag, tagSize, ct, ctSize)` | Encrypt and/or authenticate data |
| `SSFAESGCMDecrypt(ct, ctLen, iv, ivSize, aad, aadLen, key, keySize, tag, tagSize, pt, ptSize)` | Decrypt and verify authentication tag |

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

/* Authentication only */
AES_GCM_MAKE_IV(iv, eui64, frameCounter++);
SSFAESGCMEncrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag), NULL, 0);
if (!SSFAESGCMDecrypt(NULL, 0, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag), NULL, 0))
    /* Authentication failed */;

/* Authenticated encryption */
AES_GCM_MAKE_IV(iv, eui64, frameCounter++);
SSFAESGCMEncrypt(pt, ptLen, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag),
                 ct, sizeof(ct));
if (!SSFAESGCMDecrypt(ct, ptLen, iv, sizeof(iv), NULL, 0, key, sizeof(key), tag, sizeof(tag),
                      dpt, sizeof(dpt)))
    /* Decryption or authentication failed */;

/* Authenticated encryption with authenticated data */
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
