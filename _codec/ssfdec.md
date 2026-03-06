# ssfdec — Integer-to-Decimal String Converter

[SSF](../README.md) | [Codecs](README.md)

Converts signed and unsigned 64-bit integers to decimal strings with optional minimum-width
padding, and parses decimal strings back to integers.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfdec--integer-to-decimal-string-converter) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)

<a id="notes"></a>

## [↑](#ssfdec--integer-to-decimal-string-converter) Notes

- `str` must not be `NULL` for all conversion functions; passing `NULL` asserts.
- `minFieldWidth` must be `>= 2` for [`SSFDecIntToStrPadded()`](#ssfdecinttostrpadded) and
  [`SSFDecUIntToStrPadded()`](#ssfdecuinttostrpadded); passing a smaller value asserts.
- For [`SSFDecIntToStrPadded()`](#ssfdecinttostrpadded) the negative sign counts toward
  `minFieldWidth`; e.g. `minFieldWidth = 4` on `-5` with `padChar = '0'` produces `"-005"`.
- All four conversion functions return `0` if `strSize` is too small to hold the result.
- Use `SSF_DEC_MAX_STR_SIZE` (21) as `strSize` to guarantee any `int64_t` or `uint64_t` value fits.
- [`SSFDecStrToInt()`](#ssf-dec-str-to-int) and [`SSFDecStrToUInt()`](#ssf-dec-str-to-uint) skip
  leading whitespace and also accept decimal-fraction and scientific-notation input
  (e.g. `"3.7e2"` → `370`); the fractional part is truncated to zero when no exponent is present.
- `val` must not be `NULL` for both parse macros; passing `NULL` asserts.

<a id="configuration"></a>

## [↑](#ssfdec--integer-to-decimal-string-converter) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfdec--integer-to-decimal-string-converter) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="def-max-str-len"></a>`SSF_DEC_MAX_STR_LEN` | Constant | Maximum decimal string length in characters (`20`); covers the longest `int64_t` or `uint64_t` representation |
| <a id="def-max-str-size"></a>`SSF_DEC_MAX_STR_SIZE` | Constant | Maximum decimal string buffer size in bytes (`21`); equals `SSF_DEC_MAX_STR_LEN + 1` to include the null terminator |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-inttostr) | [`size_t SSFDecIntToStr(i, str, strSize)`](#ssfdecinttostr) | Convert signed 64-bit integer to decimal string |
| [e.g.](#ex-uinttostr) | [`size_t SSFDecUIntToStr(i, str, strSize)`](#ssfdecuinttostr) | Convert unsigned 64-bit integer to decimal string |
| [e.g.](#ex-inttostrpadded) | [`size_t SSFDecIntToStrPadded(i, str, strSize, minFieldWidth, padChar)`](#ssfdecinttostrpadded) | Convert signed integer to padded decimal string |
| [e.g.](#ex-uinttostrpadded) | [`size_t SSFDecUIntToStrPadded(i, str, strSize, minFieldWidth, padChar)`](#ssfdecuinttostrpadded) | Convert unsigned integer to padded decimal string |
| [e.g.](#ex-macro-strtoint) | [`bool SSFDecStrToInt(str, val)`](#ssf-dec-str-to-int) | Macro: parse decimal string to signed 64-bit integer |
| [e.g.](#ex-macro-strtouint) | [`bool SSFDecStrToUInt(str, val)`](#ssf-dec-str-to-uint) | Macro: parse decimal string to unsigned 64-bit integer |

<a id="function-reference"></a>

## [↑](#ssfdec--integer-to-decimal-string-converter) Function Reference

<a id="ssfdecinttostr"></a>

### [↑](#ssfdec--integer-to-decimal-string-converter) [`size_t SSFDecIntToStr()`](#functions)

```c
size_t SSFDecIntToStr(int64_t i, SSFCStrOut_t str, size_t strSize);
```

Converts a signed 64-bit integer to a null-terminated decimal string. Faster and more strongly
typed than `snprintf("%lld", ...)`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `int64_t` | Signed integer value to convert. Full `int64_t` range is supported (−9223372036854775808 to 9223372036854775807). |
| `str` | out | `SSFCStrOut_t` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str` in bytes. Use [`SSF_DEC_MAX_STR_SIZE`](#def-max-str-size) (21) to guarantee any value fits. |

**Returns:** Number of characters written, excluding the null terminator. Returns `0` if `strSize`
is too small.

<a id="ex-inttostr"></a>

```c
char str[SSF_DEC_MAX_STR_SIZE];
size_t len;

len = SSFDecIntToStr(-42, str, sizeof(str));
/* len == 3, str == "-42" */
```

---

<a id="ssfdecuinttostr"></a>

### [↑](#ssfdec--integer-to-decimal-string-converter) [`size_t SSFDecUIntToStr()`](#functions)

```c
size_t SSFDecUIntToStr(uint64_t i, SSFCStrOut_t str, size_t strSize);
```

Converts an unsigned 64-bit integer to a null-terminated decimal string.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `uint64_t` | Unsigned integer value to convert. Full `uint64_t` range is supported (0 to 18446744073709551615). |
| `str` | out | `SSFCStrOut_t` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str` in bytes. Use [`SSF_DEC_MAX_STR_SIZE`](#def-max-str-size) (21) to guarantee any value fits. |

**Returns:** Number of characters written, excluding the null terminator. Returns `0` if `strSize`
is too small.

<a id="ex-uinttostr"></a>

```c
char str[SSF_DEC_MAX_STR_SIZE];
size_t len;

len = SSFDecUIntToStr(12345u, str, sizeof(str));
/* len == 5, str == "12345" */
```

---

<a id="ssfdecinttostrpadded"></a>

### [↑](#ssfdec--integer-to-decimal-string-converter) [`size_t SSFDecIntToStrPadded()`](#functions)

```c
size_t SSFDecIntToStrPadded(int64_t i, SSFCStrOut_t str, size_t strSize,
                             uint8_t minFieldWidth, char padChar);
```

Converts a signed 64-bit integer to a null-terminated decimal string padded to a minimum field
width. The negative sign counts toward `minFieldWidth`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `int64_t` | Signed integer value to convert. |
| `str` | out | `SSFCStrOut_t` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str` in bytes. Must be at least `minFieldWidth + 1`. |
| `minFieldWidth` | in | `uint8_t` | Minimum output width in characters, excluding the null terminator. Must be `>= 2`. If the natural representation is shorter, `padChar` fills the difference. |
| `padChar` | in | `char` | Character used for left-padding (e.g. `'0'` or `' '`). |

**Returns:** Number of characters written, excluding the null terminator. Returns `0` if `strSize`
is too small.

<a id="ex-inttostrpadded"></a>

```c
char str[SSF_DEC_MAX_STR_SIZE];
size_t len;

len = SSFDecIntToStrPadded(-5, str, sizeof(str), 4u, '0');
/* len == 4, str == "-005" */
```

---

<a id="ssfdecuinttostrpadded"></a>

### [↑](#ssfdec--integer-to-decimal-string-converter) [`size_t SSFDecUIntToStrPadded()`](#functions)

```c
size_t SSFDecUIntToStrPadded(uint64_t i, SSFCStrOut_t str, size_t strSize,
                              uint8_t minFieldWidth, char padChar);
```

Converts an unsigned 64-bit integer to a null-terminated decimal string padded to a minimum field
width.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `i` | in | `uint64_t` | Unsigned integer value to convert. |
| `str` | out | `SSFCStrOut_t` | Output buffer receiving the null-terminated decimal string. Must not be `NULL`. |
| `strSize` | in | `size_t` | Allocated size of `str` in bytes. Must be at least `minFieldWidth + 1`. |
| `minFieldWidth` | in | `uint8_t` | Minimum output width in characters, excluding the null terminator. Must be `>= 2`. If the natural representation is shorter, `padChar` fills the difference. |
| `padChar` | in | `char` | Character used for left-padding (e.g. `'0'` or `' '`). |

**Returns:** Number of characters written, excluding the null terminator. Returns `0` if `strSize`
is too small.

<a id="ex-uinttostrpadded"></a>

```c
char str[SSF_DEC_MAX_STR_SIZE];
size_t len;

len = SSFDecUIntToStrPadded(42u, str, sizeof(str), 5u, ' ');
/* len == 5, str == "   42" */
```

---

<a id="convenience-macros"></a>

### [↑](#ssfdec--integer-to-decimal-string-converter) [Convenience Macros](#ex-macro-strtoint)

Thin wrappers over `SSFDecStrToXInt()` that parse a decimal string to either a signed or unsigned
64-bit integer. Both macros skip leading whitespace and accept decimal-fraction and
scientific-notation input in addition to plain integer strings (e.g. `"3.7e2"` → `370`).

---

<a id="ssf-dec-str-to-int"></a>

#### [↑](#ssfdec--integer-to-decimal-string-converter) [`bool SSFDecStrToInt()`](#functions)

```c
#define SSFDecStrToInt(str, val)  SSFDecStrToXInt(str, val, NULL)
```

Parses a null-terminated decimal string to a signed 64-bit integer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `str` | in | `SSFCStrIn_t` | Pointer to the null-terminated string to parse. Must not be `NULL`. |
| `val` | out | `int64_t *` | Receives the parsed signed value. Must not be `NULL`. |

**Returns:** `true` if the string represents a valid value within `int64_t` range; `false` if the
string is empty (after whitespace), contains invalid characters, or the value is out of range.

<a id="ex-macro-strtoint"></a>

```c
int64_t val;

if (SSFDecStrToInt("-42", &val))
{
    /* val == -42 */
}
```

---

<a id="ssf-dec-str-to-uint"></a>

#### [↑](#ssfdec--integer-to-decimal-string-converter) [`bool SSFDecStrToUInt()`](#functions)

```c
#define SSFDecStrToUInt(str, val) SSFDecStrToXInt(str, NULL, val)
```

Parses a null-terminated decimal string to an unsigned 64-bit integer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `str` | in | `SSFCStrIn_t` | Pointer to the null-terminated string to parse. Must not be `NULL`. |
| `val` | out | `uint64_t *` | Receives the parsed unsigned value. Must not be `NULL`. |

**Returns:** `true` if the string represents a valid value within `uint64_t` range; `false` if the
string is empty (after whitespace), contains invalid characters, or the value is out of range.

<a id="ex-macro-strtouint"></a>

```c
uint64_t val;

if (SSFDecStrToUInt("12345", &val))
{
    /* val == 12345 */
}
```

