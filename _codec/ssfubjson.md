# ssfubjson — UBJSON Parser/Generator

[SSF](../README.md) | [Codecs](README.md)

Universal Binary JSON (UBJSON) parser and printer-callback generator.

UBJSON is a binary encoding that is type-compatible with JSON while being more compact. The parser
searches a binary buffer in place using a zero-terminated path array to locate values. The
generator builds a UBJSON binary message into a caller-supplied buffer through a chain of
printer callbacks, one per object or array nesting level.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfubjson--ubjson-parsergenerator) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)

<a id="notes"></a>

## [↑](#ssfubjson--ubjson-parsergenerator) Notes

- Path arrays must be fully zeroed with `memset` before use; set each element to a
  null-terminated key string, a `size_t *` array index, or leave as `NULL` to terminate.
- UBJSON data is binary and not null-terminated; always track message length separately in
  a `size_t` variable (`end` after generation, `jsLen` for parsing).
- Generator functions accept a write offset `start` by value and write the new offset to
  `*end`. Inside a callback advance with `&start`: `SSFUBJsonPrintLabel(..., start, &start, ...)`.
- After the last field in a callback, assign `*end = start` before returning `true`.
- Each nesting level recurses into the parser; keep depth within
  [`SSF_UBJSON_CONFIG_MAX_IN_DEPTH`](#opt-max-in-depth).

<a id="configuration"></a>

## [↑](#ssfubjson--ubjson-parsergenerator) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-max-in-depth"></a>`SSF_UBJSON_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth; each `{` or `[` counts as one level |
| <a id="opt-max-in-len"></a>`SSF_UBJSON_CONFIG_MAX_IN_LEN` | `2047` | Maximum UBJSON message length accepted by the parser |
| <a id="opt-handle-hpn"></a>`SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING` | `1` | `1` to return the high-precision number (HPN) type as a string instead of failing |

<a id="api-summary"></a>

## [↑](#ssfubjson--ubjson-parsergenerator) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfubjsontype-t"></a>`SSFUBJsonType_t` | Enum | Value type returned by [`SSFUBJsonGetType()`](#ssfubjsongettype); also used to specify element types in [`SSFUBJsonPrintArrayOpt()`](#ssfubjsonprintarrayopt) and [`SSFUBJsonPrintInt()`](#ssfubjsonprintint) |
| `SSF_UBJSON_TYPE_ERROR` | Enum value | Path not found or parse error |
| `SSF_UBJSON_TYPE_STRING` | Enum value | UBJSON string (`S`) |
| `SSF_UBJSON_TYPE_NUMBER_INT8` | Enum value | UBJSON int8 (`i`) |
| `SSF_UBJSON_TYPE_NUMBER_UINT8` | Enum value | UBJSON uint8 (`U`) |
| `SSF_UBJSON_TYPE_NUMBER_INT16` | Enum value | UBJSON int16 (`I`) |
| `SSF_UBJSON_TYPE_NUMBER_INT32` | Enum value | UBJSON int32 (`l`) |
| `SSF_UBJSON_TYPE_NUMBER_INT64` | Enum value | UBJSON int64 (`L`) |
| `SSF_UBJSON_TYPE_NUMBER_FLOAT32` | Enum value | UBJSON float32 (`d`) |
| `SSF_UBJSON_TYPE_NUMBER_FLOAT64` | Enum value | UBJSON float64 (`D`) |
| `SSF_UBJSON_TYPE_NUMBER_HPN` | Enum value | UBJSON high-precision number (`H`) |
| `SSF_UBJSON_TYPE_OBJECT` | Enum value | UBJSON object (`{`) |
| `SSF_UBJSON_TYPE_ARRAY` | Enum value | UBJSON array (`[`) |
| `SSF_UBJSON_TYPE_TRUE` | Enum value | UBJSON `true` (`T`) |
| `SSF_UBJSON_TYPE_FALSE` | Enum value | UBJSON `false` (`F`) |
| `SSF_UBJSON_TYPE_NULL` | Enum value | UBJSON `null` (`Z`) |
| <a id="type-ssfubjsonprintfn-t"></a>`SSFUBJsonPrintFn_t` | Typedef | Printer callback: `bool (*)(uint8_t *js, size_t size, size_t start, size_t *end, void *in)`; called by [`SSFUBJsonPrintObject()`](#object-array-print-macros), [`SSFUBJsonPrintArray()`](#object-array-print-macros), and [`SSFUBJsonPrintArrayOpt()`](#ssfubjsonprintarrayopt) to write contents |

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-isvalid) | [`SSFUBJsonIsValid(js, jsLen)`](#ssfubjsonisvalid) | Validate a UBJSON binary message |
| [e.g.](#ex-gettype) | [`SSFUBJsonGetType(js, jsLen, path)`](#ssfubjsongettype) | Return the UBJSON type at a given path |
| [e.g.](#ex-getstring) | [`SSFUBJsonGetString(js, jsLen, path, out, outSize, outLen)`](#ssfubjsongetstring) | Parse a string value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetInt8(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse an int8 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetUInt8(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse a uint8 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetInt16(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse an int16 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetUInt16(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse a uint16 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetInt32(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse an int32 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetUInt32(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse a uint32 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetInt64(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse an int64 value at a path |
| [e.g.](#ex-getint) | [`SSFUBJsonGetUInt64(js, jsLen, path, out)`](#integer-get-macros) | Macro: parse a uint64 value at a path |
| [e.g.](#ex-getfloat) | [`SSFUBJsonGetFloat(js, jsLen, path, out)`](#ssfubjsongetfloat-ssfubjsongetdouble) | Parse a float32 value at a path |
| [e.g.](#ex-getdouble) | [`SSFUBJsonGetDouble(js, jsLen, path, out)`](#ssfubjsongetfloat-ssfubjsongetdouble) | Parse a float64 value at a path |
| [e.g.](#ex-gethex) | [`SSFUBJsonGetHex(js, jsLen, path, out, outSize, outLen, rev)`](#ssfubjsongethex) | Decode a hex-encoded binary string at a path |
| [e.g.](#ex-getbase64) | [`SSFUBJsonGetBase64(js, jsLen, path, out, outSize, outLen)`](#ssfubjsongetbase64) | Decode a Base64-encoded binary string at a path |
| [e.g.](#ex-getbytearrayptr) | [`SSFUBJsonGetByteArrayPtr(js, jsLen, path, out, outLen)`](#ssfubjsongetbytearrayptr) | Return a pointer to a typed byte array at a path |
| [e.g.](#ex-printobject) | [`SSFUBJsonPrintObject(js, size, start, end, fn, in)`](#object-array-print-macros) | Macro: generate a UBJSON object via callback |
| [e.g.](#ex-printarray) | [`SSFUBJsonPrintArray(js, size, start, end, fn, in)`](#object-array-print-macros) | Macro: generate a UBJSON array via callback |
| [e.g.](#ex-printarrayopt) | [`SSFUBJsonPrintArrayOpt(js, size, start, end, fn, in, atype, alen)`](#ssfubjsonprintarrayopt) | Generate an optimized typed UBJSON array |
| [e.g.](#ex-printlabel) | [`SSFUBJsonPrintLabel(js, size, start, end, label)`](#ssfubjsonprintlabel) | Write a UBJSON object key label |
| [e.g.](#ex-printstring) | [`SSFUBJsonPrintString(js, size, start, end, in)`](#ssfubjsonprintstring) | Write a UBJSON string value |
| [e.g.](#ex-printint) | [`SSFUBJsonPrintInt(js, size, start, end, in, opt, optType)`](#ssfubjsonprintint) | Write a UBJSON integer value |
| [e.g.](#ex-printfloat) | [`SSFUBJsonPrintFloat(js, size, start, end, in)`](#ssfubjsonprintfloat-ssfubjsonprintdouble) | Write a UBJSON float32 value |
| [e.g.](#ex-printdouble) | [`SSFUBJsonPrintDouble(js, size, start, end, in)`](#ssfubjsonprintfloat-ssfubjsonprintdouble) | Write a UBJSON float64 value |
| [e.g.](#ex-printtrue) | [`SSFUBJsonPrintTrue(js, size, start, end)`](#booleannull-print-macros) | Macro: write UBJSON `true` |
| [e.g.](#ex-printfalse) | [`SSFUBJsonPrintFalse(js, size, start, end)`](#booleannull-print-macros) | Macro: write UBJSON `false` |
| [e.g.](#ex-printnull) | [`SSFUBJsonPrintNull(js, size, start, end)`](#booleannull-print-macros) | Macro: write UBJSON `null` |
| [e.g.](#ex-printhex) | [`SSFUBJsonPrintHex(js, size, start, end, in, inLen, rev)`](#ssfubjsonprinthex) | Encode binary as a hex string and write as UBJSON string |
| [e.g.](#ex-printbase64) | [`SSFUBJsonPrintBase64(js, size, start, end, in, inLen)`](#ssfubjsonprintbase64) | Encode binary as Base64 and write as UBJSON string |

<a id="function-reference"></a>

## [↑](#ssfubjson--ubjson-parsergenerator) Function Reference

<a id="ssfubjsonisvalid"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonIsValid()`](#ex-isvalid)

```c
bool SSFUBJsonIsValid(uint8_t *js, size_t jsLen);
```

Validates that the binary buffer `js` of length `jsLen` contains a well-formed UBJSON message
within the configured depth and length limits.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | Pointer to the UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. Must not exceed [`SSF_UBJSON_CONFIG_MAX_IN_LEN`](#opt-max-in-len). |

**Returns:** `true` if the message is structurally valid UBJSON; `false` otherwise.

---

<a id="ssfubjsongettype"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonGetType()`](#ex-gettype)

```c
SSFUBJsonType_t SSFUBJsonGetType(uint8_t *js, size_t jsLen, SSFCStrIn_t *path);
```

Returns the UBJSON type of the value located at `path`. Zero the path array with `memset` before
use and set each element to a key string (object field) or a `size_t *` index (array element).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |

**Returns:** A [`SSFUBJsonType_t`](#type-ssfubjsontype-t) enum value indicating the type at `path`, or `SSF_UBJSON_TYPE_ERROR` if the path is not found or the message is malformed.

---

<a id="ssfubjsongetstring"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonGetString()`](#ex-getstring)

```c
bool SSFUBJsonGetString(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, SSFCStrOut_t out,
                        size_t outSize, size_t *outLen);
```

Finds the UBJSON string value at `path` and copies it as a null-terminated C string into `out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |
| `out` | out | `char *` | Buffer receiving the null-terminated string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the string length (excluding null terminator). |

**Returns:** `true` if a string value was found at `path` and copied into `out`; `false` otherwise.

---

<a id="integer-get-macros"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [Integer Get Macros](#ex-getint)

```c
#define SSFUBJsonGetInt8(js, jsLen, path, out)   SSFUBJsonGetInt(js, jsLen, path, out, 1, true)
#define SSFUBJsonGetUInt8(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 1, false)
#define SSFUBJsonGetInt16(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 2, true)
#define SSFUBJsonGetUInt16(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 2, false)
#define SSFUBJsonGetInt32(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 4, true)
#define SSFUBJsonGetUInt32(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 4, false)
#define SSFUBJsonGetInt64(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 8, true)
#define SSFUBJsonGetUInt64(js, jsLen, path, out) SSFUBJsonGetInt(js, jsLen, path, out, 8, false)

bool SSFUBJsonGetInt(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, void *out, uint8_t size,
                     bool isSigned);
```

Convenience macros over `SSFUBJsonGetInt()` for extracting typed integer values at a path. The
UBJSON numeric value is automatically widened or narrowed to fit the requested C type. Call the
appropriately-typed macro rather than `SSFUBJsonGetInt()` directly.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |
| `out` | out | typed pointer | Pointer to the variable receiving the integer. Must not be `NULL`. Type must match the chosen macro (e.g. `int32_t *` for `SSFUBJsonGetInt32`). |

**Returns:** `true` if a numeric value was found at `path` and converted successfully; `false` otherwise.

---

<a id="ssfubjsongetfloat-ssfubjsongetdouble"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonGetFloat()` / `SSFUBJsonGetDouble()`](#ex-getfloat)

```c
bool SSFUBJsonGetFloat(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, float *out);
bool SSFUBJsonGetDouble(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, double *out);
```

Finds a UBJSON float32 (`d`) or float64 (`D`) value at `path` and copies it to `*out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |
| `out` | out | `float *` or `double *` | Receives the floating-point value. Must not be `NULL`. |

**Returns:** `true` if a matching float or double was found at `path`; `false` otherwise.

---

<a id="ssfubjsongethex"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonGetHex()`](#ex-gethex)

```c
bool SSFUBJsonGetHex(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                     size_t *outLen, bool rev);
```

Finds a UBJSON string value at `path`, interprets it as a lowercase hexadecimal-encoded binary
sequence, and decodes it into `out`. Set `rev` to `true` to reverse byte order after decoding
(useful for little-endian integer representations).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |
| `out` | out | `uint8_t *` | Buffer receiving the decoded bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be at least half the hex string length. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of decoded bytes. |
| `rev` | in | `bool` | `true` to reverse the decoded byte order; `false` to keep it as-is. |

**Returns:** `true` if a valid hex string was found at `path` and decoded; `false` otherwise.

---

<a id="ssfubjsongetbase64"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonGetBase64()`](#ex-getbase64)

```c
bool SSFUBJsonGetBase64(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out,
                        size_t outSize, size_t *outLen);
```

Finds a UBJSON string value at `path`, interprets it as a Base64-encoded binary sequence, and
decodes it into `out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |
| `out` | out | `uint8_t *` | Buffer receiving the decoded bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of decoded bytes. |

**Returns:** `true` if a valid Base64 string was found at `path` and decoded; `false` otherwise.

---

<a id="ssfubjsongetbytearrayptr"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonGetByteArrayPtr()`](#ex-getbytearrayptr)

```c
bool SSFUBJsonGetByteArrayPtr(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t **out,
                              size_t *outLen);
```

Finds a typed UBJSON byte array (`[$U#`) at `path` and sets `*out` to point directly into the
UBJSON buffer at the first element byte, avoiding a copy. Do not write through the returned
pointer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. Array must be zeroed before use. |
| `out` | out | `uint8_t **` | Receives a pointer into `js` at the start of the byte array data. Must not be `NULL`. |
| `outLen` | out | `size_t *` | Receives the number of bytes in the array. Must not be `NULL`. |

**Returns:** `true` if a typed byte array was found at `path` and `*out` was set; `false` otherwise.

---

<a id="object-array-print-macros"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [Object / Array Print Macros](#ex-printobject)

```c
#define SSFUBJsonPrintObject(js, size, start, end, fn, in) \
        SSFUBJsonPrint(js, size, start, end, fn, in, "{}")
#define SSFUBJsonPrintArray(js, size, start, end, fn, in) \
        SSFUBJsonPrint(js, size, start, end, fn, in, "[]")
```

Generate a UBJSON object (`{}`) or array (`[]`) by invoking the printer callback `fn`. The
callback receives the same buffer, its allocated size, and the write offset just inside the
opening marker. The callback must write all fields and assign `*end = start` before returning
`true`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Write offset at which to begin the object or array marker. |
| `end` | out | `size_t *` | Receives the write offset after the closing marker. Must not be `NULL`. |
| `fn` | in | [`SSFUBJsonPrintFn_t`](#type-ssfubjsonprintfn-t) | Callback that writes the container contents. Must not be `NULL`. |
| `in` | in | `void *` | Opaque context pointer passed through to `fn`. May be `NULL`. |

**Returns:** `true` if generation succeeded and `*end` was set; `false` if the buffer is too small or `fn` returned `false`.

---

<a id="ssfubjsonprintarrayopt"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintArrayOpt()`](#ex-printarrayopt)

```c
bool SSFUBJsonPrintArrayOpt(uint8_t *js, size_t size, size_t start, size_t *end,
                            SSFUBJsonPrintFn_t fn, void *in, SSFUBJsonType_t atype, size_t alen);
```

Generates a typed UBJSON array using the `[$type#count]` optimized encoding. Per-element type
markers are omitted from the payload, so `fn` must write only the raw value bytes for each
element without any type prefix.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Write offset at which to begin the array. |
| `end` | out | `size_t *` | Receives the write offset after the array is written. Must not be `NULL`. |
| `fn` | in | [`SSFUBJsonPrintFn_t`](#type-ssfubjsonprintfn-t) | Callback writing raw element values (no type markers). Must not be `NULL`. |
| `in` | in | `void *` | Opaque context pointer passed through to `fn`. May be `NULL`. |
| `atype` | in | [`SSFUBJsonType_t`](#type-ssfubjsontype-t) | Element type written in the optimized array header (e.g. `SSF_UBJSON_TYPE_NUMBER_INT32`). |
| `alen` | in | `size_t` | Number of elements `fn` will write. |

**Returns:** `true` if generation succeeded; `false` if the buffer is too small or `fn` returned `false`.

---

<a id="ssfubjsonprintlabel"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintLabel()`](#ex-printlabel)

```c
bool SSFUBJsonPrintLabel(uint8_t *js, size_t size, size_t start, size_t *end,
                         SSFCStrIn_t label);
```

Appends a UBJSON object key label at the current write offset. Must be called inside an object
printer callback immediately before the corresponding value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the label. Must not be `NULL`. |
| `label` | in | `const char *` | Null-terminated key string. Must not be `NULL`. |

**Returns:** `true` if the label was written; `false` if the buffer is too small.

---

<a id="ssfubjsonprintstring"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintString()`](#ex-printstring)

```c
bool SSFUBJsonPrintString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in);
```

Appends a UBJSON string value (`S`) at the current write offset. In an object, call
[`SSFUBJsonPrintLabel()`](#ssfubjsonprintlabel) first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the string. Must not be `NULL`. |
| `in` | in | `const char *` | Null-terminated string value to encode. Must not be `NULL`. |

**Returns:** `true` if the string was written; `false` if the buffer is too small.

---

<a id="ssfubjsonprintint"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintInt()`](#ex-printint)

```c
bool SSFUBJsonPrintInt(uint8_t *js, size_t size, size_t start, size_t *end, int64_t in,
                       bool opt, SSFUBJsonType_t optType);
```

Appends an integer value in UBJSON encoding. When `opt` is `false` the smallest fitting UBJSON
integer type is selected automatically. When `opt` is `true` the caller specifies the type via
`optType`, which is required when writing elements inside a
[`SSFUBJsonPrintArrayOpt()`](#ssfubjsonprintarrayopt) callback where the header already declares
the type.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the integer. Must not be `NULL`. |
| `in` | in | `int64_t` | Integer value to encode. |
| `opt` | in | `bool` | `false` to auto-select the smallest fitting type; `true` to use `optType`. |
| `optType` | in | [`SSFUBJsonType_t`](#type-ssfubjsontype-t) | Explicit type marker used when `opt` is `true`. Ignored when `opt` is `false`. |

**Returns:** `true` if the integer was written; `false` if the buffer is too small.

---

<a id="ssfubjsonprintfloat-ssfubjsonprintdouble"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintFloat()` / `SSFUBJsonPrintDouble()`](#ex-printfloat)

```c
bool SSFUBJsonPrintFloat(uint8_t *js, size_t size, size_t start, size_t *end, float in);
bool SSFUBJsonPrintDouble(uint8_t *js, size_t size, size_t start, size_t *end, double in);
```

Append a 32-bit float (`d`) or 64-bit double (`D`) value in UBJSON encoding. In an object, call
[`SSFUBJsonPrintLabel()`](#ssfubjsonprintlabel) first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the value. Must not be `NULL`. |
| `in` | in | `float` or `double` | Floating-point value to encode. |

**Returns:** `true` if the value was written; `false` if the buffer is too small.

---

<a id="booleannull-print-macros"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [Boolean / Null Print Macros](#ex-printtrue)

```c
#define SSFUBJsonPrintTrue(js, size, start, end)  SSFUBJsonPrintChar(js, size, start, end, 'T')
#define SSFUBJsonPrintFalse(js, size, start, end) SSFUBJsonPrintChar(js, size, start, end, 'F')
#define SSFUBJsonPrintNull(js, size, start, end)  SSFUBJsonPrintChar(js, size, start, end, 'Z')
```

Convenience macros for writing the UBJSON `true` (`T`), `false` (`F`), and `null` (`Z`) type
markers. In an object, call [`SSFUBJsonPrintLabel()`](#ssfubjsonprintlabel) first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the marker. Must not be `NULL`. |

**Returns:** `true` if the marker was written; `false` if the buffer is too small.

---

<a id="ssfubjsonprinthex"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintHex()`](#ex-printhex)

```c
bool SSFUBJsonPrintHex(uint8_t *js, size_t size, size_t start, size_t *end,
                       uint8_t *in, size_t inLen, bool rev);
```

Encodes the binary data at `in` as a lowercase hexadecimal string and appends it as a UBJSON
string value. Set `rev` to `true` to reverse byte order before encoding.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the string. Must not be `NULL`. |
| `in` | in | `uint8_t *` | Binary data to encode. Must not be `NULL`. |
| `inLen` | in | `size_t` | Number of bytes in `in`. |
| `rev` | in | `bool` | `true` to reverse the byte order of `in` before encoding; `false` to encode as-is. |

**Returns:** `true` if the hex string was written; `false` if the buffer is too small.

---

<a id="ssfubjsonprintbase64"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [`SSFUBJsonPrintBase64()`](#ex-printbase64)

```c
bool SSFUBJsonPrintBase64(uint8_t *js, size_t size, size_t start, size_t *end,
                          uint8_t *in, size_t inLen);
```

Encodes the binary data at `in` as a Base64 string and appends it as a UBJSON string value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js` in bytes. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the string. Must not be `NULL`. |
| `in` | in | `uint8_t *` | Binary data to encode. Must not be `NULL`. |
| `inLen` | in | `size_t` | Number of bytes in `in`. |

**Returns:** `true` if the Base64 string was written; `false` if the buffer is too small.

<a id="examples"></a>

## [↑](#ssfubjson--ubjson-parsergenerator) Examples

Parser examples use this hand-crafted UBJSON object `{"name":"Alice","count":42}`:

```c
/* {"name":"Alice","count":42} */
uint8_t ub[] = {
    '{',
    'i', 4, 'n','a','m','e',            /* key "name" (4 bytes) */
    'S', 'i', 5, 'A','l','i','c','e',   /* string "Alice" (5 bytes) */
    'i', 5, 'c','o','u','n','t',        /* key "count" (5 bytes) */
    'i', 42,                             /* int8 value 42 */
    '}'
};
```

Path arrays must be zeroed before each use:

```c
SSFCStrIn_t path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
memset(path, 0, sizeof(path));
```

---

<a id="ex-isvalid"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonIsValid()](#ssfubjsonisvalid)

```c
SSFUBJsonIsValid(ub, sizeof(ub));   /* returns true */

uint8_t bad[] = {'{', 'i', 4, 'n','a','m','e'};  /* truncated — no closing } */
SSFUBJsonIsValid(bad, sizeof(bad)); /* returns false */
```

<a id="ex-gettype"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetType()](#ssfubjsongettype)

```c
memset(path, 0, sizeof(path));
path[0] = "name";
SSFUBJsonGetType(ub, sizeof(ub), path);    /* returns SSF_UBJSON_TYPE_STRING */

memset(path, 0, sizeof(path));
path[0] = "count";
SSFUBJsonGetType(ub, sizeof(ub), path);    /* returns SSF_UBJSON_TYPE_NUMBER_INT8 */

memset(path, 0, sizeof(path));
path[0] = "missing";
SSFUBJsonGetType(ub, sizeof(ub), path);    /* returns SSF_UBJSON_TYPE_ERROR */
```

<a id="ex-getstring"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetString()](#ssfubjsongetstring)

```c
char out[32];
size_t outLen;

memset(path, 0, sizeof(path));
path[0] = "name";
if (SSFUBJsonGetString(ub, sizeof(ub), path, out, sizeof(out), &outLen))
{
    /* out == "Alice", outLen == 5 */
}
```

<a id="ex-getint"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [Integer Get Macros](#integer-get-macros)

```c
int8_t  n8;
int32_t n32;
uint8_t u8;

memset(path, 0, sizeof(path));
path[0] = "count";

SSFUBJsonGetInt8 (ub, sizeof(ub), path, &n8);    /* n8  == 42 */
SSFUBJsonGetInt32(ub, sizeof(ub), path, &n32);   /* n32 == 42 */
SSFUBJsonGetUInt8(ub, sizeof(ub), path, &u8);    /* u8  == 42 */
```

<a id="ex-getfloat"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetFloat()](#ssfubjsongetfloat-ssfubjsongetdouble)

```c
static bool buildFloat(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "temp")) return false;
    if (!SSFUBJsonPrintFloat(js, size, start, &start, 3.14f)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
float   f;

if (SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, buildFloat, NULL))
{
    memset(path, 0, sizeof(path));
    path[0] = "temp";
    if (SSFUBJsonGetFloat(buf, end, path, &f))
    {
        /* f ~= 3.14 */
    }
}
```

<a id="ex-getdouble"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetDouble()](#ssfubjsongetfloat-ssfubjsongetdouble)

```c
static bool buildDouble(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel (js, size, start, &start, "val")) return false;
    if (!SSFUBJsonPrintDouble(js, size, start, &start, 2.718281828)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
double  d;

if (SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, buildDouble, NULL))
{
    memset(path, 0, sizeof(path));
    path[0] = "val";
    if (SSFUBJsonGetDouble(buf, end, path, &d))
    {
        /* d ~= 2.718281828 */
    }
}
```

<a id="ex-gethex"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetHex()](#ssfubjsongethex)

```c
static bool buildHex(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "raw")) return false;
    if (!SSFUBJsonPrintHex  (js, size, start, &start, data, sizeof(data), false)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
uint8_t decoded[8];
size_t  decodedLen;

if (SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, buildHex, NULL))
{
    memset(path, 0, sizeof(path));
    path[0] = "raw";
    if (SSFUBJsonGetHex(buf, end, path, decoded, sizeof(decoded), &decodedLen, false))
    {
        /* decoded[0..3] == {0xDE, 0xAD, 0xBE, 0xEF}, decodedLen == 4 */
    }
}
```

<a id="ex-getbase64"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetBase64()](#ssfubjsongetbase64)

```c
static bool buildB64(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    uint8_t data[] = {'h','e','l','l','o'};
    if (!SSFUBJsonPrintLabel  (js, size, start, &start, "b64")) return false;
    if (!SSFUBJsonPrintBase64 (js, size, start, &start, data, sizeof(data))) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
uint8_t decoded[16];
size_t  decodedLen;

if (SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, buildB64, NULL))
{
    memset(path, 0, sizeof(path));
    path[0] = "b64";
    if (SSFUBJsonGetBase64(buf, end, path, decoded, sizeof(decoded), &decodedLen))
    {
        /* decoded[0..4] == "hello", decodedLen == 5 */
    }
}
```

<a id="ex-getbytearrayptr"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonGetByteArrayPtr()](#ssfubjsongetbytearrayptr)

```c
/* Hand-crafted {"data":[$U#i3, 0x01, 0x02, 0x03]} — typed uint8 array with 3 elements */
uint8_t ubArr[] = {
    '{',
    'i', 4, 'd','a','t','a',   /* key "data" */
    '[','$','U','#','i', 3,    /* typed array: uint8, count 3 */
    0x01, 0x02, 0x03,          /* raw element bytes */
    '}'
};

uint8_t *ptr;
size_t   len;

memset(path, 0, sizeof(path));
path[0] = "data";
if (SSFUBJsonGetByteArrayPtr(ubArr, sizeof(ubArr), path, &ptr, &len))
{
    /* ptr points into ubArr at 0x01, len == 3 — no copy made */
}
```

<a id="ex-printobject"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintObject()](#object-array-print-macros)

```c
static bool objFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel (js, size, start, &start, "msg")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "hello")) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;

if (SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, objFn, NULL))
{
    /* buf[0..end-1] contains {"msg":"hello"} in UBJSON encoding */
}
```

<a id="ex-printarray"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintArray()](#object-array-print-macros)

```c
static bool arrFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintInt(js, size, start, &start, 1, false, SSF_UBJSON_TYPE_ERROR)) return false;
    if (!SSFUBJsonPrintInt(js, size, start, &start, 2, false, SSF_UBJSON_TYPE_ERROR)) return false;
    if (!SSFUBJsonPrintInt(js, size, start, &start, 3, false, SSF_UBJSON_TYPE_ERROR)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;

if (SSFUBJsonPrintArray(buf, sizeof(buf), 0, &end, arrFn, NULL))
{
    /* buf[0..end-1] contains [1,2,3] in UBJSON encoding */
}
```

<a id="ex-printarrayopt"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintArrayOpt()](#ssfubjsonprintarrayopt)

```c
/* Write three int32 raw values — no type markers, because the header declares the type */
static bool optFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintInt(js, size, start, &start, 100, true, SSF_UBJSON_TYPE_NUMBER_INT32)) return false;
    if (!SSFUBJsonPrintInt(js, size, start, &start, 200, true, SSF_UBJSON_TYPE_NUMBER_INT32)) return false;
    if (!SSFUBJsonPrintInt(js, size, start, &start, 300, true, SSF_UBJSON_TYPE_NUMBER_INT32)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;

if (SSFUBJsonPrintArrayOpt(buf, sizeof(buf), 0, &end, optFn, NULL,
                           SSF_UBJSON_TYPE_NUMBER_INT32, 3))
{
    /* buf[0..end-1] contains [$l#i3, ...] — optimized int32 array with 3 elements */
}
```

<a id="ex-printlabel"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintLabel()](#ssfubjsonprintlabel)

```c
static bool labelFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel (js, size, start, &start, "city")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "Denver")) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, labelFn, NULL);
/* buf contains {"city":"Denver"} */
```

<a id="ex-printstring"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintString()](#ssfubjsonprintstring)

```c
static bool strFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel (js, size, start, &start, "status")) return false;
    if (!SSFUBJsonPrintString(js, size, start, &start, "ok")) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, strFn, NULL);
/* buf contains {"status":"ok"} */
```

<a id="ex-printint"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintInt()](#ssfubjsonprintint)

```c
static bool intFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    /* Auto-select smallest type (int8 fits 42) */
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "count")) return false;
    if (!SSFUBJsonPrintInt  (js, size, start, &start, 42, false, SSF_UBJSON_TYPE_ERROR)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, intFn, NULL);
/* buf contains {"count":42} */
```

<a id="ex-printfloat"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintFloat()](#ssfubjsonprintfloat-ssfubjsonprintdouble)

```c
static bool floatFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "ratio")) return false;
    if (!SSFUBJsonPrintFloat(js, size, start, &start, 0.5f)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, floatFn, NULL);
/* buf contains {"ratio":0.5} as float32 */
```

<a id="ex-printdouble"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintDouble()](#ssfubjsonprintfloat-ssfubjsonprintdouble)

```c
static bool dblFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel (js, size, start, &start, "pi")) return false;
    if (!SSFUBJsonPrintDouble(js, size, start, &start, 3.14159265358979)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, dblFn, NULL);
/* buf contains {"pi":3.14159265358979} as float64 */
```

<a id="ex-printtrue"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintTrue()](#booleannull-print-macros)

```c
static bool trueFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "active")) return false;
    if (!SSFUBJsonPrintTrue (js, size, start, &start)) return false;
    *end = start;
    return true;
}

uint8_t buf[32];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, trueFn, NULL);
/* buf contains {"active":true} */
```

<a id="ex-printfalse"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintFalse()](#booleannull-print-macros)

```c
static bool falseFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "enabled")) return false;
    if (!SSFUBJsonPrintFalse(js, size, start, &start)) return false;
    *end = start;
    return true;
}

uint8_t buf[32];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, falseFn, NULL);
/* buf contains {"enabled":false} */
```

<a id="ex-printnull"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintNull()](#booleannull-print-macros)

```c
static bool nullFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "result")) return false;
    if (!SSFUBJsonPrintNull (js, size, start, &start)) return false;
    *end = start;
    return true;
}

uint8_t buf[32];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, nullFn, NULL);
/* buf contains {"result":null} */
```

<a id="ex-printhex"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintHex()](#ssfubjsonprinthex)

```c
static bool hexFn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    uint8_t key[] = {0xA1, 0xB2, 0xC3};
    if (!SSFUBJsonPrintLabel(js, size, start, &start, "key")) return false;
    if (!SSFUBJsonPrintHex  (js, size, start, &start, key, sizeof(key), false)) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, hexFn, NULL);
/* buf contains {"key":"a1b2c3"} */
```

<a id="ex-printbase64"></a>

### [↑](#ssfubjson--ubjson-parsergenerator) [SSFUBJsonPrintBase64()](#ssfubjsonprintbase64)

```c
static bool b64Fn(uint8_t *js, size_t size, size_t start, size_t *end, void *in)
{
    uint8_t data[] = {'h','e','l','l','o'};
    if (!SSFUBJsonPrintLabel  (js, size, start, &start, "b64")) return false;
    if (!SSFUBJsonPrintBase64 (js, size, start, &start, data, sizeof(data))) return false;
    *end = start;
    return true;
}

uint8_t buf[64];
size_t  end;
SSFUBJsonPrintObject(buf, sizeof(buf), 0, &end, b64Fn, NULL);
/* buf contains {"b64":"aGVsbG8="} */
```
