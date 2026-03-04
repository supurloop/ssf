# ssfdec — Integer to Decimal String

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Converts signed and unsigned integers to decimal strings, with optional padding.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFDecIntToStr(val, out, outSize)` | Convert integer to decimal string |
| `SSFDecIntToStrPadded(val, out, outSize, width, padChar)` | Convert integer to padded decimal string |

## Usage

This interface converts signed or unsigned integers to padded or unpadded decimal strings. It is
intended to be faster and more strongly typed than `snprintf()`.

```c
size_t len;
char str[32];

len = SSFDecIntToStr(-123456789123ull, str, sizeof(str));
/* len == 13, str == "-123456789123" */

len = SSFDecIntToStrPadded(-123456789123ull, str, sizeof(str), 15, '0');
/* len == 15, str == "-00123456789123" */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Both functions return the length of the resulting string (not including the null terminator).
- The output buffer must be large enough to hold the decimal representation plus a null terminator.
- Functions return `0` if the output buffer is too small.
