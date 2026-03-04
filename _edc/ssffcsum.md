# ssffcsum — 16-bit Fletcher Checksum

[Back to EDC README](README.md) | [Back to ssf README](../README.md)

16-bit Fletcher checksum interface for lightweight data integrity verification.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFFCSum16(in, inLen, fcsum)` | Compute or accumulate a 16-bit Fletcher checksum |
| `SSF_FCSUM_INITIAL` | Initial value constant; pass for the first call in a sequence |

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
