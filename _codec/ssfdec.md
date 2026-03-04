# ssfdec — Integer to Decimal String

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Converts signed and unsigned integers to decimal strings, with optional padding.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFDecIntToStr(i, str, strSize)` | Convert signed 64-bit integer to decimal string |
| `SSFDecUIntToStr(i, str, strSize)` | Convert unsigned 64-bit integer to decimal string |
| `SSFDecIntToStrPadded(i, str, strSize, minFieldWidth, padChar)` | Convert signed integer to padded decimal string |
| `SSFDecUIntToStrPadded(i, str, strSize, minFieldWidth, padChar)` | Convert unsigned integer to padded decimal string |
| `SSFDecStrToInt(str, val)` | Parse decimal string to signed 64-bit integer |
| `SSFDecStrToUInt(str, val)` | Parse decimal string to unsigned 64-bit integer |
| `SSF_DEC_MAX_STR_LEN` | Maximum decimal string length (20 characters) |
| `SSF_DEC_MAX_STR_SIZE` | Maximum decimal string buffer size (21 bytes, including null terminator) |

## Function Reference

### `SSFDecIntToStr`

```c
size_t SSFDecIntToStr(int64_t i, SSFCStrOut_t str, size_t strSize);
```

Converts a signed 64-bit integer to a null-terminated decimal string. Faster and more strongly
typed than `snprintf("%lld", ...)`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `int64_t` | Signed integer value to convert. Full range of `int64_t` is supported (−9223372036854775808 to 9223372036854775807). |
| `str` | out | `char *` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str` in bytes. Must be at least `SSF_DEC_MAX_STR_SIZE` (21) to guarantee any value fits. |

**Returns:** `size_t` — Number of characters written (excluding null terminator). Returns `0` if `strSize` is too small.

---

### `SSFDecUIntToStr`

```c
size_t SSFDecUIntToStr(uint64_t i, SSFCStrOut_t str, size_t strSize);
```

Converts an unsigned 64-bit integer to a null-terminated decimal string.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `uint64_t` | Unsigned integer value to convert. Full range of `uint64_t` is supported (0 to 18446744073709551615). |
| `str` | out | `char *` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str`. Must be at least `SSF_DEC_MAX_STR_SIZE` (21) to guarantee any value fits. |

**Returns:** `size_t` — Number of characters written (excluding null terminator). Returns `0` if `strSize` is too small.

---

### `SSFDecIntToStrPadded`

```c
size_t SSFDecIntToStrPadded(int64_t i, SSFCStrOut_t str, size_t strSize,
                             uint8_t minFieldWidth, char padChar);
```

Converts a signed 64-bit integer to a null-terminated decimal string padded to a minimum field
width. A negative sign character is included in the field width count.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `int64_t` | Signed integer value to convert. |
| `str` | out | `char *` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str`. Must be at least `minFieldWidth + 1` bytes. |
| `minFieldWidth` | in | `uint8_t` | Minimum number of characters in the output (excluding null terminator). If the natural representation is shorter, `padChar` is inserted to reach this width. |
| `padChar` | in | `char` | Character used for padding (e.g., `'0'` or `' '`). |

**Returns:** `size_t` — Number of characters written (excluding null terminator). Returns `0` if `strSize` is too small.

---

### `SSFDecUIntToStrPadded`

```c
size_t SSFDecUIntToStrPadded(uint64_t i, SSFCStrOut_t str, size_t strSize,
                              uint8_t minFieldWidth, char padChar);
```

Converts an unsigned 64-bit integer to a null-terminated decimal string padded to a minimum field
width.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `uint64_t` | Unsigned integer value to convert. |
| `str` | out | `char *` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str`. Must be at least `minFieldWidth + 1` bytes. |
| `minFieldWidth` | in | `uint8_t` | Minimum number of characters in the output (excluding null terminator). |
| `padChar` | in | `char` | Character used for padding. |

**Returns:** `size_t` — Number of characters written (excluding null terminator). Returns `0` if `strSize` is too small.

---

### `SSFDecStrToInt` / `SSFDecStrToUInt`

```c
#define SSFDecStrToInt(str, val)  SSFDecStrToXInt(str, val, NULL)
#define SSFDecStrToUInt(str, val) SSFDecStrToXInt(str, NULL, val)

bool SSFDecStrToXInt(SSFCStrIn_t str, int64_t *sval, uint64_t *uval);
```

Parses a null-terminated decimal string to a 64-bit integer. `SSFDecStrToInt` parses a signed
value; `SSFDecStrToUInt` parses an unsigned value. These are convenience macros over the shared
`SSFDecStrToXInt` base function.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `str` | in | `const char *` | Pointer to the null-terminated decimal string to parse. Must not be `NULL`. Must contain only decimal digits (`0-9`), optionally preceded by a `-` sign for `SSFDecStrToInt`. |
| `val` | out | `int64_t *` or `uint64_t *` | Receives the parsed value. Must not be `NULL`. |

**Returns:** `true` if the string represents a valid integer within the range of the target type; `false` if the string is empty, contains invalid characters, or the value is out of range.

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
