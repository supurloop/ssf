# ssfcrc32 — 32-bit CCITT-32 CRC

[Back to EDC README](README.md) | [Back to ssf README](../README.md)

32-bit CRC using the 0x04C11DB7 polynomial (CCITT-32 / ISO 3309 compatible).

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFCRC32(in, inLen, crc)` | Compute or accumulate a 32-bit CRC |
| `SSF_CRC32_INITIAL` | Initial value constant; pass for the first call in a sequence |

## Usage

This 32-bit CRC uses the 0x04C11DB7 polynomial and a 1024-byte lookup table to reduce execution
time. Use it when you need stronger error detection than CRC-16, and/or in conjunction with
Reed-Solomon to detect wrong-solution false positives.

The API supports incremental computation:

```c
uint32_t crc;

crc = SSFCRC32("abcde", 5, SSF_CRC32_INITIAL);
/* crc == 0x8587D865 */

crc = SSFCRC32("a", 1, SSF_CRC32_INITIAL);
crc = SSFCRC32("bcd", 3, crc);
crc = SSFCRC32("e", 1, crc);
/* crc == 0x8587D865 */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Requires 1024 bytes of program memory for the lookup table.
- Use `SSF_CRC32_INITIAL` for the first call; pass the return value to subsequent calls for
  incremental computation over split data.
- Strongly recommended alongside [Reed-Solomon ECC](../_ecc/README.md): Reed-Solomon can
  "successfully" correct to the wrong message, and a CRC-32 check catches this.
