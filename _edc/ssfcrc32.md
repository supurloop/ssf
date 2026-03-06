# ssfcrc32 — 32-bit CCITT-32 CRC

[SSF](../README.md) | [EDC](README.md)

32-bit CRC using the `0x04C11DB7` polynomial, compatible with CCITT-32 and ISO 3309.

The computation uses a 1024-byte lookup table for speed. A single call covers a contiguous
buffer; successive calls with the previous return value as `crc` accumulate across non-contiguous
or streaming chunks and produce the same result as one call over the whole dataset.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfcrc32--32-bit-ccitt-32-crc) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfcrc32--32-bit-ccitt-32-crc) Notes

- Always pass [`SSF_CRC32_INITIAL`](#ssf-crc32-initial) as `crc` for the first call in a
  sequence; pass the return value of the previous call for each subsequent chunk.
- Requires 1024 bytes of program memory for the lookup table.
- Compatible with CCITT-32 and ISO 3309 (polynomial `0x04C11DB7`, initial value `0x00000000`).
- Strongly recommended alongside [Reed-Solomon ECC](../_ecc/README.md): Reed-Solomon can correct
  to the wrong message without detecting the error; a CRC-32 check catches this false positive.
- For lighter error detection with a smaller table see [ssfcrc16](ssfcrc16.md).

<a id="configuration"></a>

## [↑](#ssfcrc32--32-bit-ccitt-32-crc) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfcrc32--32-bit-ccitt-32-crc) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-crc32-initial"></a>`SSF_CRC32_INITIAL` | Constant | `0` — initial CRC state; pass as `crc` to begin a fresh computation |

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-crc32) | [`SSFCRC32(in, inLen, crc)`](#ssfcrc32fn) | Compute or accumulate a 32-bit CRC over a byte buffer |

<a id="function-reference"></a>

## [↑](#ssfcrc32--32-bit-ccitt-32-crc) Function Reference

<a id="ssfcrc32fn"></a>

### [↑](#ssfcrc32--32-bit-ccitt-32-crc) [`SSFCRC32()`](#ex-crc32)

```c
uint32_t SSFCRC32(const uint8_t *in, uint32_t inLen, uint32_t crc);
```

Computes or accumulates a 32-bit CCITT-32 CRC (polynomial `0x04C11DB7`) over `inLen` bytes
starting at `in`. May be called repeatedly on successive chunks; passing the return value of
one call as `crc` to the next produces the same result as a single call over all chunks
concatenated.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the input bytes. Must not be `NULL` when `inLen > 0`. |
| `inLen` | in | `uint32_t` | Number of bytes to process. |
| `crc` | in | `uint32_t` | Starting CRC state. Pass [`SSF_CRC32_INITIAL`](#ssf-crc32-initial) to begin a new computation; pass the return value of the previous call to continue an incremental computation. |

**Returns:** Updated 32-bit CRC state. Pass this value as `crc` to the next call when processing data in multiple chunks, or compare it against an expected CRC for verification.

<a id="examples"></a>

## [↑](#ssfcrc32--32-bit-ccitt-32-crc) Examples

<a id="ex-crc32"></a>

### [↑](#ssfcrc32--32-bit-ccitt-32-crc) [SSFCRC32()](#ssfcrc32fn)

```c
uint32_t crc;

/* Single-buffer computation */
crc = SSFCRC32((uint8_t *)"abcde", 5, SSF_CRC32_INITIAL);
/* crc == 0x8587D865 */

/* Incremental computation over chunks — same result */
crc = SSFCRC32((uint8_t *)"a",   1, SSF_CRC32_INITIAL);
crc = SSFCRC32((uint8_t *)"bcd", 3, crc);
crc = SSFCRC32((uint8_t *)"e",   1, crc);
/* crc == 0x8587D865 */

/* Verifying received data against a known CRC */
uint8_t  packet[]  = {0x01u, 0x02u, 0x03u, 0x04u};
uint32_t expected  = 0xB63CFBCDu;
if (SSFCRC32(packet, sizeof(packet), SSF_CRC32_INITIAL) == expected)
{
    /* Packet integrity confirmed */
}
```
