# ssfsha2 — SHA-2 Hash

[Back to Cryptography README](README.md) | [Back to ssf README](../README.md)

SHA-2 hash interface supporting SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFSHA256(in, inLen, out, outSize)` | Compute SHA-256 hash |
| `SSFSHA224(in, inLen, out, outSize)` | Compute SHA-224 hash |
| `SSFSHA512(in, inLen, out, outSize)` | Compute SHA-512 hash |
| `SSFSHA384(in, inLen, out, outSize)` | Compute SHA-384 hash |
| `SSFSHA512_224(in, inLen, out, outSize)` | Compute SHA-512/224 hash |
| `SSFSHA512_256(in, inLen, out, outSize)` | Compute SHA-512/256 hash |
| `SSF_SHA2_256_BYTE_SIZE` | Output size constant for SHA-256 (32 bytes) |
| `SSF_SHA2_224_BYTE_SIZE` | Output size constant for SHA-224 (28 bytes) |
| `SSF_SHA2_512_BYTE_SIZE` | Output size constant for SHA-512 (64 bytes) |
| `SSF_SHA2_384_BYTE_SIZE` | Output size constant for SHA-384 (48 bytes) |
| `SSF_SHA2_512_224_BYTE_SIZE` | Output size constant for SHA-512/224 (28 bytes) |
| `SSF_SHA2_512_256_BYTE_SIZE` | Output size constant for SHA-512/256 (32 bytes) |

## Usage

The macros simplify calling the two base functions that implement all six SHA-2 variants.

```c
uint8_t out[SSF_SHA2_256_BYTE_SIZE];

SSFSHA256("abc", 3, out, sizeof(out));
/* out == "\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23"
          "\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad" */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- The output buffer must be at least as large as the hash output size for the chosen variant.
- The `SSF_SHA2_*_BYTE_SIZE` constants are provided for sizing output buffers.
