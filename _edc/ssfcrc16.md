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

## Function Reference

### `SSFCRC16`

```c
uint16_t SSFCRC16(const uint8_t *in, uint16_t inLen, uint16_t crc);
```

Computes or accumulates a 16-bit XMODEM/CCITT-16 CRC (polynomial 0x1021) over an input byte
array using a 512-byte lookup table. May be called repeatedly on successive chunks to produce
the same result as a single call over the entire dataset.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the input bytes to process. Must not be `NULL` when `inLen > 0`. |
| `inLen` | in | `uint16_t` | Number of bytes to process from `in`. Range: 0–65535. |
| `crc` | in | `uint16_t` | Starting CRC state. Pass `SSF_CRC16_INITIAL` (0) to begin a new computation; pass the return value of a prior call to accumulate incrementally over split data. |

**Returns:** `uint16_t` — Updated 16-bit CRC. Pass this value as `crc` to the next call when processing data in multiple chunks.

---

### `SSF_CRC16_INITIAL`

```c
#define SSF_CRC16_INITIAL ((uint16_t) 0u)
```

Constant equal to `0`. Pass as `crc` to start a fresh CRC-16 computation.

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
