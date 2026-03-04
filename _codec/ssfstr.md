# ssfstr — Safe C String Interface

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

True safe replacements for C string functions that always null-terminate output.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFStrIsValid(cstr, cstrSize)` | Validate that a null terminator exists within the buffer |
| `SSFStrLen(cstr, cstrSize, cstrLenOut)` | Return the length of a bounded C string |
| `SSFStrCpy(dst, dstSize, dstLenOut, src, srcSize)` | Safe string copy; always null-terminates |
| `SSFStrCat(dst, dstSize, dstLenOut, src, srcSize)` | Safe string concatenation; always null-terminates |
| `SSFStrCmp(cstr1, cstr1Size, cstr2, cstr2Size)` | Safe string equality comparison |
| `SSFStrToCase(cstrOut, cstrOutSize, toCase)` | Convert string to upper or lower case in-place |
| `SSFStrStr(cstr, cstrSize, matchStrOptOut, substr, substrSize)` | Find a substring |
| `SSFStrTok(cstr, cstrSize, tokenOut, tokenSize, tokenLenOut, delims, delimsSize)` | Tokenize a string by delimiters |

## Function Reference

### `SSFStrIsValid`

```c
bool SSFStrIsValid(SSFCStrIn_t cstr, size_t cstrSize);
```

Checks that a null terminator (`\0`) exists somewhere within `cstr[0..cstrSize-1]`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in | `const char *` | Pointer to the string to validate. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of the buffer containing `cstr` in bytes. |

**Returns:** `true` if a null terminator is found within `cstrSize` bytes; `false` otherwise.

---

### `SSFStrLen`

```c
bool SSFStrLen(SSFCStrIn_t cstr, size_t cstrSize, size_t *cstrLenOut);
```

Computes the length of a null-terminated C string bounded by `cstrSize`. Safer than `strlen()`
because it will not read past the declared buffer boundary.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in | `const char *` | Pointer to the null-terminated string. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of the buffer containing `cstr`. |
| `cstrLenOut` | out | `size_t *` | Receives the string length (number of characters excluding null terminator). Must not be `NULL`. |

**Returns:** `true` if a null terminator is found within `cstrSize` bytes and the length was written; `false` if no null terminator exists within the buffer.

---

### `SSFStrCpy`

```c
bool SSFStrCpy(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOut,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize);
```

Copies a null-terminated source string into a destination buffer. Always null-terminates the
destination on success. Unlike `strncpy()`, this function never writes a partial result without a
null terminator.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstrDstOut` | out | `char *` | Destination buffer. Must not be `NULL`. |
| `cstrDstOutSize` | in | `size_t` | Total allocated size of `cstrDstOut` in bytes. Must be at least `strlen(src) + 1`. |
| `cstrDstOutLenOut` | out (opt) | `size_t *` | If not `NULL`, receives the length of the copied string (excluding null terminator). |
| `cstrSrc` | in | `const char *` | Source null-terminated string to copy. Must not be `NULL`. |
| `cstrSrcSize` | in | `size_t` | Total allocated size of `cstrSrc` buffer in bytes. Used for bounds validation of the source. |

**Returns:** `true` if the copy succeeded; `false` if `cstrDstOutSize` is too small to hold the source string and its null terminator.

---

### `SSFStrCat`

```c
bool SSFStrCat(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOut,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize);
```

Appends a null-terminated source string to an existing null-terminated destination string. Always
null-terminates on success.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstrDstOut` | in-out | `char *` | Destination buffer containing an existing null-terminated string to append to. Must not be `NULL`. |
| `cstrDstOutSize` | in | `size_t` | Total allocated size of `cstrDstOut`. Must accommodate both the existing content and the appended content plus null terminator. |
| `cstrDstOutLenOut` | out (opt) | `size_t *` | If not `NULL`, receives the total length of the resulting string (excluding null terminator). |
| `cstrSrc` | in | `const char *` | Source null-terminated string to append. Must not be `NULL`. |
| `cstrSrcSize` | in | `size_t` | Total allocated size of `cstrSrc` buffer. |

**Returns:** `true` if the concatenation succeeded; `false` if the combined result would not fit in `cstrDstOut`.

---

### `SSFStrCmp`

```c
bool SSFStrCmp(SSFCStrIn_t cstr1, size_t cstr1Size, SSFCStrIn_t cstr2, size_t cstr2Size);
```

Compares two bounded null-terminated strings for equality.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr1` | in | `const char *` | First string. Must not be `NULL`. |
| `cstr1Size` | in | `size_t` | Total allocated size of `cstr1` buffer. |
| `cstr2` | in | `const char *` | Second string. Must not be `NULL`. |
| `cstr2Size` | in | `size_t` | Total allocated size of `cstr2` buffer. |

**Returns:** `true` if both strings are valid and identical (byte-for-byte); `false` if they differ or either is invalid.

---

### `SSFStrToCase`

```c
bool SSFStrToCase(SSFCStrOut_t cstrOut, size_t cstrOutSize, SSFSTRCase_t toCase);
```

Converts all alphabetic characters in a null-terminated string to upper or lower case in-place.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstrOut` | in-out | `char *` | The string to convert. Modified in-place. Must not be `NULL`. |
| `cstrOutSize` | in | `size_t` | Total allocated size of `cstrOut` buffer. |
| `toCase` | in | `SSFSTRCase_t` | Conversion direction. `SSF_STR_CASE_LOWER` to lowercase; `SSF_STR_CASE_UPPER` to uppercase. |

**Returns:** `true` if conversion succeeded; `false` if `cstrOut` does not contain a null terminator within `cstrOutSize`.

---

### `SSFStrStr`

```c
bool SSFStrStr(SSFCStrIn_t cstr, size_t cstrSize, SSFCStrIn_t *matchStrOptOut,
               SSFCStrIn_t substr, size_t substrSize);
```

Searches for the first occurrence of `substr` within `cstr`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in | `const char *` | String to search within. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of `cstr` buffer. |
| `matchStrOptOut` | out (opt) | `const char **` | If not `NULL`, receives a pointer to the start of the first match within `cstr` when found. |
| `substr` | in | `const char *` | Substring to search for. Must not be `NULL`. |
| `substrSize` | in | `size_t` | Total allocated size of `substr` buffer. |

**Returns:** `true` if `substr` is found within `cstr`; `false` if not found or either string is invalid.

---

### `SSFStrTok`

```c
bool SSFStrTok(SSFCStrIn_t *cstr, size_t cstrSize, SSFCStrOut_t tokenStrOut,
               size_t tokenStrSize, int32_t *tokenStrLen,
               SSFCStrIn_t delims, size_t delimsSize);
```

Extracts the next token from a string, advancing the string pointer past the delimiter on each
call. Modelled after `strtok_r()` but with bounded buffers.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in-out | `const char **` | Pointer to the current position in the string. On entry, points to the start of the next token search. Updated on exit to point past the consumed token and delimiter. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of the source string buffer. |
| `tokenStrOut` | out | `char *` | Buffer receiving the extracted token as a null-terminated string. Must not be `NULL`. |
| `tokenStrSize` | in | `size_t` | Allocated size of `tokenStrOut`. |
| `tokenStrLen` | out (opt) | `int32_t *` | If not `NULL`, receives the length of the extracted token (excluding null terminator). Set to `-1` if no more tokens remain. |
| `delims` | in | `const char *` | String of delimiter characters. Each character in this string is treated as a delimiter. Must not be `NULL`. |
| `delimsSize` | in | `size_t` | Total allocated size of `delims` buffer. |

**Returns:** `true` if a token was extracted; `false` if no more tokens remain or an error occurred.

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
