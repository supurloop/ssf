# ssffcsum — 16-bit Fletcher Checksum

[Back to EDC README](README.md) | [Back to ssf README](../README.md)

16-bit Fletcher checksum interface for lightweight data integrity verification.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFFCSum16(in, inLen, initial)` | Compute or accumulate a 16-bit Fletcher checksum |
| `SSF_FCSUM_INITIAL` | Initial value constant; pass for the first call in a sequence |

## Function Reference

### `SSFFCSum16`

```c
uint16_t SSFFCSum16(const uint8_t *in, size_t inLen, uint16_t initial);
```

Computes or accumulates a 16-bit Fletcher checksum over an input byte array. May be called
repeatedly on successive chunks of the same data to produce the same result as a single call
over the entire dataset.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the input bytes to checksum. Must not be `NULL` when `inLen > 0`. |
| `inLen` | in | `size_t` | Number of bytes to process from `in`. May be `0`, in which case `initial` is returned unchanged. |
| `initial` | in | `uint16_t` | Starting checksum state. Pass `SSF_FCSUM_INITIAL` to begin a new computation; pass the return value of a prior call to accumulate incrementally over split data. |

**Returns:** `uint16_t` — Updated 16-bit Fletcher checksum. Pass this value as `initial` to the next call when processing data in multiple chunks.

---

### `SSF_FCSUM_INITIAL`

```c
#define SSF_FCSUM_INITIAL ((uint16_t) 0u)
```

Constant equal to `0`. Pass as `initial` to start a fresh Fletcher checksum computation.

## Usage

Every embedded system needs a checksum somewhere. The 16-bit Fletcher checksum has many of the
error-detecting properties of a 16-bit CRC at the computational cost of a simple arithmetic
checksum. At approximately 88 bytes of program memory on MSP430 with -O3, it is the most
code-efficient integrity check in the framework.

The API supports incremental computation. The first call with `SSF_FCSUM_INITIAL` produces the
same result as chaining multiple calls on sub-slices of the same data:

```c
uint16_t fc;

fc = SSFFCSum16("abcde", 5, SSF_FCSUM_INITIAL);
/* fc == 0xc8f0 */

fc = SSFFCSum16("a", 1, SSF_FCSUM_INITIAL);
fc = SSFFCSum16("bcd", 3, fc);
fc = SSFFCSum16("e", 1, fc);
/* fc == 0xc8f0 */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Use `SSF_FCSUM_INITIAL` for the first call; pass the return value to subsequent calls for
  incremental computation over split data.
- Approximately 88 bytes of program memory on MSP430 with -O3.
- Error detection capability is comparable to a 16-bit CRC but computed with less code.
- For stronger error detection consider [ssfcrc16](ssfcrc16.md) or [ssfcrc32](ssfcrc32.md).
