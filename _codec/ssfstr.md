# ssfstr — Safe C String Interface

[SSF](../README.md) | [Codecs](README.md)

Safe, buffer-size-aware replacements for the standard C string library.

Every function accepts the allocated size of each buffer argument and always null-terminates output
on success, eliminating the class of bugs caused by `strncpy()`, unbounded `strcpy()`, and similar
functions that can silently truncate or omit the null terminator.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfstr--safe-c-string-interface) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfstr--safe-c-string-interface) Notes

- All functions require the total allocated size of every buffer argument, not the string length.
- All functions return `false` if the operation cannot complete safely; the destination buffer is
  never partially modified when `false` is returned.
- A successful [`SSFStrCpy()`](#ssfstrcpy) or [`SSFStrCat()`](#ssfstrcat) always null-terminates
  the destination, unlike `strncpy()`.
- [`SSFStrTok()`](#ssfstrtok) is re-entrant; it does not use any global state.

<a id="configuration"></a>

## [↑](#ssfstr--safe-c-string-interface) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfstr--safe-c-string-interface) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfcstrin-t"></a>`SSFCStrIn_t` | Typedef | `const char *`; annotates read-only string inputs |
| <a id="type-ssfcstrout-t"></a>`SSFCStrOut_t` | Typedef | `char *`; annotates writable string output buffers |
| `SSF_STR_CASE_LOWER` | Enum value | [`SSFSTRCase_t`](#type-ssfstrcase-t) constant; convert to lowercase |
| `SSF_STR_CASE_UPPER` | Enum value | [`SSFSTRCase_t`](#type-ssfstrcase-t) constant; convert to uppercase |
| <a id="type-ssfstrcase-t"></a>`SSFSTRCase_t` | Enum | Case-conversion direction for [`SSFStrToCase()`](#ssfstrtocase) |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-isvalid) | [`bool SSFStrIsValid(cstr, cstrSize)`](#ssfstrisvalid) | Return true if a null terminator exists within the buffer |
| [e.g.](#ex-len) | [`bool SSFStrLen(cstr, cstrSize, cstrLenOut)`](#ssfstrlen) | Return the length of a bounded C string |
| [e.g.](#ex-cpy) | [`bool SSFStrCpy(dst, dstSize, dstLenOut, src, srcSize)`](#ssfstrcpy) | Safe string copy; always null-terminates on success |
| [e.g.](#ex-cat) | [`bool SSFStrCat(dst, dstSize, dstLenOut, src, srcSize)`](#ssfstrcat) | Safe string concatenation; always null-terminates on success |
| [e.g.](#ex-cmp) | [`bool SSFStrCmp(cstr1, cstr1Size, cstr2, cstr2Size)`](#ssfstrcmp) | Safe string equality comparison |
| [e.g.](#ex-tocase) | [`bool SSFStrToCase(cstrOut, cstrOutSize, toCase)`](#ssfstrtocase) | Convert string to upper or lower case in-place |
| [e.g.](#ex-str) | [`bool SSFStrStr(cstr, cstrSize, matchStrOptOut, substr, substrSize)`](#ssfstrstr) | Find the first occurrence of a substring |
| [e.g.](#ex-tok) | [`bool SSFStrTok(cstr, cstrSize, tokenOut, tokenSize, tokenLenOut, delims, delimsSize)`](#ssfstrtok) | Extract the next token from a string |

<a id="function-reference"></a>

## [↑](#ssfstr--safe-c-string-interface) Function Reference

<a id="ssfstrisvalid"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrIsValid()`](#functions)

```c
bool SSFStrIsValid(SSFCStrIn_t cstr, size_t cstrSize);
```

Checks that a null terminator (`\0`) exists somewhere within `cstr[0..cstrSize-1]`. Use this to
validate externally-sourced buffers before passing them to other `SSFStr` functions.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | Pointer to the buffer to validate. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of the buffer in bytes. |

**Returns:** `true` if a null terminator is found within `cstrSize` bytes; `false` otherwise.

<a id="ex-isvalid"></a>

```c
char buf[8] = {'h', 'i', '\0', 0, 0, 0, 0, 0};

if (SSFStrIsValid(buf, sizeof(buf)))
{
    /* buf contains a valid null-terminated string */
}

char bad[4] = {'a', 'b', 'c', 'd'}; /* no null terminator */
if (SSFStrIsValid(bad, sizeof(bad)) == false)
{
    /* bad has no null terminator within 4 bytes */
}
```

---

<a id="ssfstrlen"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrLen()`](#functions)

```c
bool SSFStrLen(SSFCStrIn_t cstr, size_t cstrSize, size_t *cstrLenOut);
```

Returns the length of a null-terminated C string bounded by `cstrSize`. Safer than `strlen()`
because it will not read past the declared buffer boundary.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | Pointer to the null-terminated string. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of the buffer containing `cstr`. |
| `cstrLenOut` | out | `size_t *` | Receives the string length (number of characters excluding the null terminator). Must not be `NULL`. |

**Returns:** `true` if a null terminator was found within `cstrSize` bytes and `*cstrLenOut` was set; `false` if no null terminator exists within the buffer.

<a id="ex-len"></a>

```c
const char str[] = "hello";
size_t len;

if (SSFStrLen(str, sizeof(str), &len))
{
    /* len == 5 */
}
```

---

<a id="ssfstrcpy"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrCpy()`](#functions)

```c
bool SSFStrCpy(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOut,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize);
```

Copies a null-terminated source string into a destination buffer. Always null-terminates the
destination on success. Unlike `strncpy()`, this function never writes a partial result without a
null terminator, and it returns `false` rather than silently truncating.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstrDstOut` | out | [`SSFCStrOut_t`](#type-ssfcstrout-t) | Destination buffer. Must not be `NULL`. |
| `cstrDstOutSize` | in | `size_t` | Total allocated size of `cstrDstOut` in bytes. Must be at least `strlen(src) + 1`. |
| `cstrDstOutLenOut` | out (opt) | `size_t *` | If not `NULL`, receives the length of the copied string (excluding null terminator). |
| `cstrSrc` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | Source null-terminated string to copy. Must not be `NULL`. |
| `cstrSrcSize` | in | `size_t` | Total allocated size of `cstrSrc` buffer. Used for bounds validation of the source. |

**Returns:** `true` if the copy succeeded and `cstrDstOut` is null-terminated; `false` if `cstrDstOutSize` is too small to hold the source string and its null terminator.

<a id="ex-cpy"></a>

```c
char dst[16];
size_t len;

if (SSFStrCpy(dst, sizeof(dst), &len, "hello", sizeof("hello")))
{
    /* dst == "hello", len == 5 */
}

/* Destination too small — copy fails cleanly */
char small[3];
if (SSFStrCpy(small, sizeof(small), NULL, "hello", sizeof("hello")) == false)
{
    /* small is not modified */
}
```

---

<a id="ssfstrcat"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrCat()`](#functions)

```c
bool SSFStrCat(SSFCStrOut_t cstrDstOut, size_t cstrDstOutSize, size_t *cstrDstOutLenOut,
               SSFCStrIn_t cstrSrc, size_t cstrSrcSize);
```

Appends a null-terminated source string to an existing null-terminated destination string. Always
null-terminates on success. Returns `false` rather than silently truncating.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstrDstOut` | in-out | [`SSFCStrOut_t`](#type-ssfcstrout-t) | Destination buffer containing an existing null-terminated string to append to. Must not be `NULL`. |
| `cstrDstOutSize` | in | `size_t` | Total allocated size of `cstrDstOut`. Must accommodate the existing content plus the appended string plus the null terminator. |
| `cstrDstOutLenOut` | out (opt) | `size_t *` | If not `NULL`, receives the total length of the resulting string (excluding null terminator). |
| `cstrSrc` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | Source null-terminated string to append. Must not be `NULL`. |
| `cstrSrcSize` | in | `size_t` | Total allocated size of `cstrSrc` buffer. |

**Returns:** `true` if the concatenation succeeded and `cstrDstOut` is null-terminated; `false` if the combined result would not fit in `cstrDstOut`.

<a id="ex-cat"></a>

```c
char dst[16];
size_t len;

SSFStrCpy(dst, sizeof(dst), NULL, "hello", sizeof("hello"));

if (SSFStrCat(dst, sizeof(dst), &len, " world", sizeof(" world")))
{
    /* dst == "hello world", len == 11 */
}
```

---

<a id="ssfstrcmp"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrCmp()`](#functions)

```c
bool SSFStrCmp(SSFCStrIn_t cstr1, size_t cstr1Size, SSFCStrIn_t cstr2, size_t cstr2Size);
```

Compares two bounded null-terminated strings for equality.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr1` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | First string. Must not be `NULL`. |
| `cstr1Size` | in | `size_t` | Total allocated size of `cstr1` buffer. |
| `cstr2` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | Second string. Must not be `NULL`. |
| `cstr2Size` | in | `size_t` | Total allocated size of `cstr2` buffer. |

**Returns:** `true` if both strings are valid and identical byte-for-byte; `false` if they differ or either is invalid.

<a id="ex-cmp"></a>

```c
const char a[] = "hello";
const char b[] = "hello";
const char c[] = "world";

SSFStrCmp(a, sizeof(a), b, sizeof(b));   /* returns true */
SSFStrCmp(a, sizeof(a), c, sizeof(c));   /* returns false */
```

---

<a id="ssfstrtocase"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrToCase()`](#functions)

```c
bool SSFStrToCase(SSFCStrOut_t cstrOut, size_t cstrOutSize, SSFSTRCase_t toCase);
```

Converts all alphabetic characters in a null-terminated string to upper or lower case in-place.
Non-alphabetic characters are left unchanged.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstrOut` | in-out | [`SSFCStrOut_t`](#type-ssfcstrout-t) | The string to convert. Modified in-place. Must not be `NULL`. |
| `cstrOutSize` | in | `size_t` | Total allocated size of `cstrOut` buffer. |
| `toCase` | in | [`SSFSTRCase_t`](#type-ssfstrcase-t) | `SSF_STR_CASE_LOWER` to lowercase; `SSF_STR_CASE_UPPER` to uppercase. |

**Returns:** `true` if conversion succeeded; `false` if `cstrOut` does not contain a null terminator within `cstrOutSize`.

<a id="ex-tocase"></a>

```c
char str[16];

SSFStrCpy(str, sizeof(str), NULL, "Hello World", sizeof("Hello World"));

SSFStrToCase(str, sizeof(str), SSF_STR_CASE_UPPER);
/* str == "HELLO WORLD" */

SSFStrToCase(str, sizeof(str), SSF_STR_CASE_LOWER);
/* str == "hello world" */
```

---

<a id="ssfstrstr"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrStr()`](#functions)

```c
bool SSFStrStr(SSFCStrIn_t cstr, size_t cstrSize, SSFCStrIn_t *matchStrOptOut,
               SSFCStrIn_t substr, size_t substrSize);
```

Searches for the first occurrence of `substr` within `cstr`. Bounded equivalent of `strstr()`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | String to search within. Must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of `cstr` buffer. |
| `matchStrOptOut` | out (opt) | `const char **` | If not `NULL`, receives a pointer into `cstr` at the start of the first match when found. |
| `substr` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | Substring to search for. Must not be `NULL`. |
| `substrSize` | in | `size_t` | Total allocated size of `substr` buffer. |

**Returns:** `true` if `substr` is found within `cstr`; `false` if not found or either string is invalid.

<a id="ex-str"></a>

```c
const char haystack[] = "the quick brown fox";
const char needle[]   = "brown";
const char *match;

if (SSFStrStr(haystack, sizeof(haystack), &match, needle, sizeof(needle)))
{
    /* match points to "brown fox" within haystack */
}

if (SSFStrStr(haystack, sizeof(haystack), NULL, "cat", sizeof("cat")) == false)
{
    /* "cat" not found */
}
```

---

<a id="ssfstrtok"></a>

### [↑](#ssfstr--safe-c-string-interface) [`bool SSFStrTok()`](#functions)

```c
bool SSFStrTok(SSFCStrIn_t *cstr, size_t cstrSize, SSFCStrOut_t tokenStrOut,
               size_t tokenStrSize, int32_t *tokenStrLen,
               SSFCStrIn_t delims, size_t delimsSize);
```

Extracts the next token from a string, advancing `*cstr` past the consumed token and its
delimiter on each call. Re-entrant bounded replacement for `strtok_r()`. Call repeatedly until it
returns `false` to consume all tokens.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cstr` | in-out | `const char **` | Pointer to the current position in the source string. Updated on each call to point past the consumed token and delimiter. Must not be `NULL`; `*cstr` must not be `NULL`. |
| `cstrSize` | in | `size_t` | Total allocated size of the source string buffer. |
| `tokenStrOut` | out | [`SSFCStrOut_t`](#type-ssfcstrout-t) | Buffer that receives the extracted token as a null-terminated string. Must not be `NULL`. |
| `tokenStrSize` | in | `size_t` | Allocated size of `tokenStrOut`. |
| `tokenStrLen` | out (opt) | `int32_t *` | If not `NULL`, receives the length of the extracted token (excluding null terminator), or `-1` when no more tokens remain. |
| `delims` | in | [`SSFCStrIn_t`](#type-ssfcstrin-t) | String whose individual characters are treated as delimiters. Must not be `NULL`. |
| `delimsSize` | in | `size_t` | Total allocated size of `delims` buffer. |

**Returns:** `true` if a token was extracted and written to `tokenStrOut`; `false` if no more tokens remain or an error occurred.

<a id="ex-tok"></a>

```c
const char src[]  = "one,two,three";
const char *pos   = src;
char token[16];
int32_t tokLen;

while (SSFStrTok(&pos, sizeof(src), token, sizeof(token), &tokLen, ",", sizeof(",")))
{
    /* Iteration 1: token == "one",   tokLen == 3 */
    /* Iteration 2: token == "two",   tokLen == 3 */
    /* Iteration 3: token == "three", tokLen == 5 */
}
/* Loop exits when no more tokens remain */
```

