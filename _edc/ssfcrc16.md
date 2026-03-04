# ssfcrc16 — 16-bit XMODEM/CCITT-16 CRC

[Back to EDC README](README.md) | [Back to ssf README](../README.md)

16-bit CRC using the 0x1021 polynomial, compatible with XMODEM and CCITT-16 standards.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFCRC16(in, inLen, crc)` | Compute or accumulate a 16-bit CRC |
| `SSF_CRC16_INITIAL` | Initial value constant; pass for the first call in a sequence |

## Usage

This 16-bit CRC uses the 0x1021 polynomial and a 512-byte lookup table to reduce execution time.
Use it when you need compatibility with the XMODEM CRC and/or can afford the extra program memory
for slightly better error detection than the 16-bit Fletcher checksum.

The API supports incremental computation:

```c
uint16_t crc;

crc = SSFCRC16("abcde", 5, SSF_CRC16_INITIAL);
/* crc == 0x3EE1 */

crc = SSFCRC16("a", 1, SSF_CRC16_INITIAL);
crc = SSFCRC16("bcd", 3, crc);
crc = SSFCRC16("e", 1, crc);
/* crc == 0x3EE1 */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Requires 512 bytes of program memory for the lookup table.
- Compatible with the XMODEM protocol CRC and the CCITT-16 standard.
- Use `SSF_CRC16_INITIAL` for the first call; pass the return value to subsequent calls for
  incremental computation over split data.
- Often used alongside [Reed-Solomon ECC](../_ecc/README.md) to verify that error correction
  converged on the correct solution.
- For stronger error detection see [ssfcrc32](ssfcrc32.md).
