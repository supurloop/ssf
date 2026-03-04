# ssfstr — Safe C String Interface

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

True safe replacements for C string functions that always null-terminate output.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFStrCpy(dst, dstSize, dstLen, src, srcSize)` | Safe string copy; always null-terminates |
| `SSFStrCat(dst, dstSize, dstLen, src, srcSize)` | Safe string concatenation; always null-terminates |
| `SSFStrCmp(s1, s1Size, s2, s2Size)` | Safe string comparison |
| `SSFStrNCmp(s1, s1Size, s2, s2Size, n)` | Safe bounded string comparison |
| `SSFStrLen(str, strSize)` | Safe string length (bounded) |
| `SSF_STR_EMPTY` | Empty string constant |

## Usage

This interface provides buffer-size-aware replacements for `strcpy()`, `strcat()`, `strcmp()`,
and related C library functions. Unlike `strncpy()`, these functions always null-terminate the
output on success.

```c
size_t len;
char str[10];

/* Attempt to copy a 10-character string into a 10-byte buffer (no room for null terminator) */
if (SSFStrCpy(str, sizeof(str), &len, "1234567890", 11) == false)
{
    /* Copy failed: str is not large enough to hold the string plus null terminator */
}

/* Copy a 9-character string into a 10-byte buffer */
if (SSFStrCpy(str, sizeof(str), &len, "123456789", 10) == true)
{
    /* Copy succeeded: str == "123456789", len == 9 */
}
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- All functions require the total allocated size of each buffer/string argument.
- Functions return `false` (or 0 for length queries) if the operation cannot complete safely.
- These are true safe replacements: unlike `strncpy()`, a successful `SSFStrCpy()` is always
  null-terminated.
