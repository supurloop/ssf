# ssfcrc16 — 16-bit XMODEM/CCITT-16 CRC

[SSF](../README.md) | [EDC](README.md)

16-bit CRC using the 0x1021 polynomial, compatible with XMODEM and CCITT-16 standards.

The computation uses a 512-byte lookup table for speed. A single call covers a contiguous
buffer; successive calls with the previous return value as `crc` accumulate across non-contiguous
or streaming chunks and produce the same result as one call over the whole dataset.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) Notes

- Always pass [`SSF_CRC16_INITIAL`](#ssf-crc16-initial) as `crc` for the first call in a
  sequence; pass the return value of the previous call for each subsequent chunk.
- Requires 512 bytes of program memory for the lookup table.
- Compatible with the XMODEM protocol CRC and the CCITT-16 standard (polynomial `0x1021`,
  initial value `0x0000`).
- Often used alongside [Reed-Solomon ECC](../_ecc/README.md) to verify that error correction
  converged on the correct solution.
- For stronger error detection see [ssfcrc32](ssfcrc32.md).

<a id="configuration"></a>

## [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-crc16-initial"></a>`SSF_CRC16_INITIAL` | Constant | `0` — initial CRC state; pass as `crc` to begin a fresh computation |

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-crc16) | [`SSFCRC16(in, inLen, crc)`](#ssfcrc16fn) | Compute or accumulate a 16-bit CRC over a byte buffer |

<a id="function-reference"></a>

## [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) Function Reference

<a id="ssfcrc16fn"></a>

### [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) [`SSFCRC16()`](#ex-crc16)

```c
uint16_t SSFCRC16(const uint8_t *in, uint16_t inLen, uint16_t crc);
```

Computes or accumulates a 16-bit XMODEM/CCITT-16 CRC (polynomial `0x1021`) over `inLen` bytes
starting at `in`. May be called repeatedly on successive chunks; passing the return value of
one call as `crc` to the next produces the same result as a single call over all chunks
concatenated.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the input bytes. Must not be `NULL` when `inLen > 0`. |
| `inLen` | in | `uint16_t` | Number of bytes to process. Range: `0`–`65535`. |
| `crc` | in | `uint16_t` | Starting CRC state. Pass [`SSF_CRC16_INITIAL`](#ssf-crc16-initial) to begin a new computation; pass the return value of the previous call to continue an incremental computation. |

**Returns:** Updated 16-bit CRC state. Pass this value as `crc` to the next call when processing data in multiple chunks, or compare it against an expected CRC for verification.

<a id="examples"></a>

## [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) Examples

<a id="ex-crc16"></a>

### [↑](#ssfcrc16--16-bit-xmodemccitt-16-crc) [SSFCRC16()](#ssfcrc16fn)

```c
uint16_t crc;

/* Single-buffer computation */
crc = SSFCRC16((uint8_t *)"abcde", 5, SSF_CRC16_INITIAL);
/* crc == 0x3EE1 */

/* Incremental computation over chunks — same result */
crc = SSFCRC16((uint8_t *)"a",   1, SSF_CRC16_INITIAL);
crc = SSFCRC16((uint8_t *)"bcd", 3, crc);
crc = SSFCRC16((uint8_t *)"e",   1, crc);
/* crc == 0x3EE1 */

/* Verifying received data against a known CRC */
uint8_t  packet[]  = {0x01u, 0x02u, 0x03u, 0x04u};
uint16_t expected  = 0x89C3u;
if (SSFCRC16(packet, sizeof(packet), SSF_CRC16_INITIAL) == expected)
{
    /* Packet integrity confirmed */
}
```
