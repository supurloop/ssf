# ssffcsum — 16-bit Fletcher Checksum

[SSF](../README.md) | [EDC](README.md)

16-bit Fletcher checksum for lightweight data integrity verification.

The checksum has error-detection capability comparable to a 16-bit CRC at a fraction of the
code size (approximately 88 bytes on MSP430 at -O3) and requires no lookup table. A single call
covers a contiguous buffer; successive calls with the previous return value as `initial`
accumulate across non-contiguous or streaming chunks and produce the same result as one call
over the whole dataset.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssffcsum--16-bit-fletcher-checksum) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssffcsum--16-bit-fletcher-checksum) Notes

- Always pass [`SSF_FCSUM_INITIAL`](#ssf-fcsum-initial) as `initial` for the first call in a
  sequence; pass the return value of the previous call for each subsequent chunk.
- Requires no lookup table; approximately 88 bytes of program memory on MSP430 with -O3.
- Error-detection capability is comparable to a 16-bit CRC but with simpler, smaller code.
- For stronger error detection see [ssfcrc16](ssfcrc16.md) or [ssfcrc32](ssfcrc32.md).

<a id="configuration"></a>

## [↑](#ssffcsum--16-bit-fletcher-checksum) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssffcsum--16-bit-fletcher-checksum) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-fcsum-initial"></a>`SSF_FCSUM_INITIAL` | Constant | `0` — initial checksum state; pass as `initial` to begin a fresh computation |

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-fcsum16) | [`SSFFCSum16(in, inLen, initial)`](#ssffcsum16fn) | Compute or accumulate a 16-bit Fletcher checksum over a byte buffer |

<a id="function-reference"></a>

## [↑](#ssffcsum--16-bit-fletcher-checksum) Function Reference

<a id="ssffcsum16fn"></a>

### [↑](#ssffcsum--16-bit-fletcher-checksum) [`SSFFCSum16()`](#ex-fcsum16)

```c
uint16_t SSFFCSum16(const uint8_t *in, size_t inLen, uint16_t initial);
```

Computes or accumulates a 16-bit Fletcher checksum over `inLen` bytes starting at `in`. May be
called repeatedly on successive chunks; passing the return value of one call as `initial` to
the next produces the same result as a single call over all chunks concatenated. When `inLen`
is `0` the value of `initial` is returned unchanged.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the input bytes. Must not be `NULL` when `inLen > 0`. |
| `inLen` | in | `size_t` | Number of bytes to process. May be `0`, in which case `initial` is returned unchanged. |
| `initial` | in | `uint16_t` | Starting checksum state. Pass [`SSF_FCSUM_INITIAL`](#ssf-fcsum-initial) to begin a new computation; pass the return value of the previous call to continue an incremental computation. |

**Returns:** Updated 16-bit Fletcher checksum state. Pass this value as `initial` to the next call when processing data in multiple chunks, or compare it against an expected checksum for verification.

<a id="examples"></a>

## [↑](#ssffcsum--16-bit-fletcher-checksum) Examples

<a id="ex-fcsum16"></a>

### [↑](#ssffcsum--16-bit-fletcher-checksum) [SSFFCSum16()](#ssffcsum16fn)

```c
uint16_t fc;

/* Single-buffer computation */
fc = SSFFCSum16((uint8_t *)"abcde", 5, SSF_FCSUM_INITIAL);
/* fc == 0xC8F0 */

/* Incremental computation over chunks — same result */
fc = SSFFCSum16((uint8_t *)"a",   1, SSF_FCSUM_INITIAL);
fc = SSFFCSum16((uint8_t *)"bcd", 3, fc);
fc = SSFFCSum16((uint8_t *)"e",   1, fc);
/* fc == 0xC8F0 */

/* Verifying received data against a known checksum */
uint8_t  packet[]  = {0x01u, 0x02u, 0x03u, 0x04u};
uint16_t expected  = 0x140Au;
if (SSFFCSum16(packet, sizeof(packet), SSF_FCSUM_INITIAL) == expected)
{
    /* Packet integrity confirmed */
}
```
