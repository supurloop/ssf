# ssfubjson — UBJSON Parser/Generator

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Universal Binary JSON (UBJSON) parser and printer-callback generator.

## Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_UBJSON_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth; each `{` or `[` counts as one level |
| `SSF_UBJSON_CONFIG_MAX_IN_LEN` | `2047` | Maximum UBJSON message length accepted by the parser |
| `SSF_UBJSON_CONFIG_HANDLE_HPN_AS_STRING` | `1` | `1` to return high-precision number (HPN) type as a string instead of failing |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFUBJsonIsValid(js, jsLen)` | Validate a UBJSON binary message |
| `SSFUBJsonGetType(js, jsLen, path)` | Return the UBJSON type at a given path |
| `SSFUBJsonGetString(js, jsLen, path, out, outSize, outLen)` | Parse a string value at a path |
| `SSFUBJsonGetInt8/16/32/64(js, jsLen, path, out)` | Parse a typed signed integer at a path |
| `SSFUBJsonGetUInt8/16/32/64(js, jsLen, path, out)` | Parse a typed unsigned integer at a path |
| `SSFUBJsonGetFloat(js, jsLen, path, out)` | Parse a 32-bit float at a path |
| `SSFUBJsonGetDouble(js, jsLen, path, out)` | Parse a 64-bit double at a path |
| `SSFUBJsonGetHex(js, jsLen, path, out, outSize, outLen, rev)` | Parse a hex-encoded binary string |
| `SSFUBJsonGetBase64(js, jsLen, path, out, outSize, outLen)` | Parse a Base64-encoded binary string |
| `SSFUBJsonGetByteArrayPtr(js, jsLen, path, out, outLen)` | Get a pointer into the UBJSON buffer at a byte array |
| `SSFUBJsonPrintObject(js, size, start, end, fn, in)` | Generate a UBJSON object |
| `SSFUBJsonPrintArray(js, size, start, end, fn, in)` | Generate a UBJSON array |
| `SSFUBJsonPrintArrayOpt(js, size, start, end, fn, in, atype, alen)` | Generate an optimized typed UBJSON array |
| `SSFUBJsonPrintLabel(js, size, start, end, label)` | Print a UBJSON key label |
| `SSFUBJsonPrintString(js, size, start, end, str)` | Print a UBJSON string value |
| `SSFUBJsonPrintInt(js, size, start, end, in, opt, optType)` | Print an integer value |
| `SSFUBJsonPrintFloat(js, size, start, end, in)` | Print a 32-bit float value |
| `SSFUBJsonPrintDouble(js, size, start, end, in)` | Print a 64-bit double value |
| `SSFUBJsonPrintTrue(js, size, start, end)` | Macro: print UBJSON `true` |
| `SSFUBJsonPrintFalse(js, size, start, end)` | Macro: print UBJSON `false` |
| `SSFUBJsonPrintNull(js, size, start, end)` | Macro: print UBJSON `null` |
| `SSFUBJsonPrintHex(js, size, start, end, in, inLen, rev)` | Print binary as a hex-encoded string |
| `SSFUBJsonPrintBase64(js, size, start, end, in, inLen)` | Print binary as a Base64-encoded string |

## Function Reference

### `SSFUBJsonIsValid`

```c
bool SSFUBJsonIsValid(uint8_t *js, size_t jsLen);
```

Validates that the binary buffer `js` of length `jsLen` contains a well-formed UBJSON message.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | Pointer to the UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js` in bytes. |

**Returns:** `true` if the message is valid UBJSON; `false` otherwise.

---

### `SSFUBJsonGetType`

```c
SSFUBJsonType_t SSFUBJsonGetType(uint8_t *js, size_t jsLen, SSFCStrIn_t *path);
```

Returns the UBJSON type of the value at `path`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js`. |
| `path` | in | `const char **` | Zero-terminated path array (zeroed before use). Must not be `NULL`. |

**Returns:** `SSFUBJsonType_t` enum value indicating the type, or `SSF_UBJSON_TYPE_ERROR` if not found.

---

### `SSFUBJsonGetString`

```c
bool SSFUBJsonGetString(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, SSFCStrOut_t out,
                        size_t outSize, size_t *outLen);
```

Finds the UBJSON string value at `path` and copies it as a null-terminated C string into `out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `char *` | Buffer receiving the null-terminated string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out`. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the string length. |

**Returns:** `true` if a string was found and copied; `false` otherwise.

---

### `SSFUBJsonGetInt8/16/32/64` and `SSFUBJsonGetUInt8/16/32/64`

```c
#define SSFUBJsonGetInt8(js, jsLen, path, out)   SSFUBJsonGetInt(js, jsLen, path, out, 1, true)
#define SSFUBJsonGetInt16(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 2, true)
#define SSFUBJsonGetInt32(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 4, true)
#define SSFUBJsonGetInt64(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 8, true)
#define SSFUBJsonGetUInt8(js, jsLen, path, out)  SSFUBJsonGetInt(js, jsLen, path, out, 1, false)
/* (similar for UInt16, UInt32, UInt64) */

bool SSFUBJsonGetInt(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, void *out, uint8_t size,
                     bool isSigned);
```

Convenience macros over `SSFUBJsonGetInt` for extracting typed integer values. The integer in
the UBJSON message is automatically widened or narrowed to fit the requested type.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `void *` | Buffer of at least `size` bytes receiving the integer value. Must not be `NULL`. |
| `size` | in | `uint8_t` | Byte width of target type: 1, 2, 4, or 8. |
| `isSigned` | in | `bool` | `true` for signed interpretation; `false` for unsigned. |

**Returns:** `true` if a numeric value was found and the conversion succeeded; `false` otherwise.

---

### `SSFUBJsonGetFloat` / `SSFUBJsonGetDouble`

```c
bool SSFUBJsonGetFloat(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, float *out);
bool SSFUBJsonGetDouble(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, double *out);
```

Finds a UBJSON float32 or float64 value at `path`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `float *` or `double *` | Receives the floating-point value. Must not be `NULL`. |

**Returns:** `true` if a matching float/double was found; `false` otherwise.

---

### `SSFUBJsonGetHex`

```c
bool SSFUBJsonGetHex(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                     size_t *outLen, bool rev);
```

Finds a UBJSON string value at `path` and decodes it as a hexadecimal-encoded binary array.
Parameters and return value are analogous to `SSFJsonGetHex`.

---

### `SSFUBJsonGetBase64`

```c
bool SSFUBJsonGetBase64(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                        size_t *outLen);
```

Finds a UBJSON string value at `path` and decodes it as Base64-encoded binary. Parameters and
return value are analogous to `SSFJsonGetBase64`.

---

### `SSFUBJsonGetByteArrayPtr`

```c
bool SSFUBJsonGetByteArrayPtr(uint8_t *js, size_t jsLen, SSFCStrIn_t *path, uint8_t **out,
                              size_t *outLen);
```

Finds a typed UBJSON byte array (`[$U#`) at `path` and returns a pointer directly into the
UBJSON buffer, avoiding a copy.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `uint8_t *` | UBJSON binary data. Must not be `NULL`. |
| `jsLen` | in | `size_t` | Length of `js`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `uint8_t **` | Receives a pointer into `js` at the start of the byte data. Must not be `NULL`. |
| `outLen` | out | `size_t *` | Receives the number of bytes in the array. Must not be `NULL`. |

**Returns:** `true` if a typed byte array was found at `path`; `false` otherwise.

---

### `SSFUBJsonPrintObject` / `SSFUBJsonPrintArray`

```c
#define SSFUBJsonPrintObject(js, size, start, end, fn, in) \
    SSFUBJsonPrint(js, size, start, end, fn, in, "{}")
#define SSFUBJsonPrintArray(js, size, start, end, fn, in) \
    SSFUBJsonPrint(js, size, start, end, fn, in, "[]")
```

Generate a UBJSON object or array by invoking the printer callback `fn`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the closing marker. Must not be `NULL`. |
| `fn` | in | `SSFUBJsonPrintFn_t` | Callback of type `bool (*)(uint8_t *js, size_t size, size_t start, size_t *end, void *in)` that writes the contents. |
| `in` | in | `void *` | Opaque context passed to `fn`. |

**Returns:** `true` if generation succeeded; `false` otherwise.

---

### `SSFUBJsonPrintArrayOpt`

```c
bool SSFUBJsonPrintArrayOpt(uint8_t *js, size_t size, size_t start, size_t *end,
                            SSFUBJsonPrintFn_t fn, void *in, SSFUBJsonType_t atype, size_t alen);
```

Generates a typed UBJSON array using the `[$type#count]` optimized encoding, which omits
per-element type markers for better compactness.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives new write offset. Must not be `NULL`. |
| `fn` | in | `SSFUBJsonPrintFn_t` | Callback writing the array elements (without type markers). |
| `in` | in | `void *` | Opaque context passed to `fn`. |
| `atype` | in | `SSFUBJsonType_t` | Element type for the optimized header. |
| `alen` | in | `size_t` | Number of elements that `fn` will write. |

**Returns:** `true` if generation succeeded; `false` otherwise.

---

### `SSFUBJsonPrintLabel`

```c
bool SSFUBJsonPrintLabel(uint8_t *js, size_t size, size_t start, size_t *end,
                         SSFCStrIn_t label);
```

Appends a UBJSON object key label.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives new write offset. Must not be `NULL`. |
| `label` | in | `const char *` | Null-terminated label string. Must not be `NULL`. |

**Returns:** `true` if appended; `false` if buffer too small.

---

### `SSFUBJsonPrintString`

```c
bool SSFUBJsonPrintString(uint8_t *js, size_t size, size_t start, size_t *end, SSFCStrIn_t in);
```

Appends a UBJSON string value. Parameters are analogous to `SSFUBJsonPrintLabel`.

---

### `SSFUBJsonPrintInt`

```c
bool SSFUBJsonPrintInt(uint8_t *js, size_t size, size_t start, size_t *end, int64_t in,
                       bool opt, SSFUBJsonType_t optType);
```

Appends an integer value in UBJSON encoding.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `uint8_t *` | UBJSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives new write offset. Must not be `NULL`. |
| `in` | in | `int64_t` | Integer value to encode. |
| `opt` | in | `bool` | `true` to use `optType` for the type marker; `false` to select the smallest fitting type automatically. |
| `optType` | in | `SSFUBJsonType_t` | Explicit type marker to use when `opt` is `true` (e.g., for typed arrays where the header already specifies the type). |

**Returns:** `true` if appended; `false` if buffer too small.

---

### `SSFUBJsonPrintFloat` / `SSFUBJsonPrintDouble`

```c
bool SSFUBJsonPrintFloat(uint8_t *js, size_t size, size_t start, size_t *end, float in);
bool SSFUBJsonPrintDouble(uint8_t *js, size_t size, size_t start, size_t *end, double in);
```

Append a 32-bit float or 64-bit double value in UBJSON encoding. Parameters follow the same
pattern as other Print functions (without a `comma` parameter since UBJSON is binary).

**Returns:** `true` if appended; `false` if buffer too small.

---

### `SSFUBJsonPrintTrue` / `SSFUBJsonPrintFalse` / `SSFUBJsonPrintNull`

```c
#define SSFUBJsonPrintTrue(js, size, start, end)  SSFUBJsonPrintChar(js, size, start, end, 'T')
#define SSFUBJsonPrintFalse(js, size, start, end) SSFUBJsonPrintChar(js, size, start, end, 'F')
#define SSFUBJsonPrintNull(js, size, start, end)  SSFUBJsonPrintChar(js, size, start, end, 'Z')
```

Convenience macros for appending the UBJSON `true`, `false`, and `null` type markers.

---

### `SSFUBJsonPrintHex` / `SSFUBJsonPrintBase64`

```c
bool SSFUBJsonPrintHex(uint8_t *js, size_t size, size_t start, size_t *end,
                       uint8_t *in, size_t inLen, bool rev);
bool SSFUBJsonPrintBase64(uint8_t *js, size_t size, size_t start, size_t *end,
                          uint8_t *in, size_t inLen);
```

Encode binary data as a hex or Base64 string and append it as a UBJSON string value.
`rev` in `SSFUBJsonPrintHex` reverses byte order before encoding. Parameters and return values
are analogous to the JSON equivalents.

## Usage

UBJSON is a binary encoding that is 1:1 compatible with JSON data types while being more compact.
The specification can be found at https://ubjson.org/. This parser operates on the UBJSON message
in place and consumes stack proportional to the maximum nesting depth.

### Parsing

```c
uint8_t ubjson1[] = "{i\x04nameSi\x05value}";
size_t ubjson1Len = 16;
char *path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
char strOut[32];

memset(path, 0, sizeof(path));

path[0] = "name";
if (SSFUBJsonGetString(ubjson1, ubjson1Len, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s\r\n", strOut);
    /* Prints "value" */
}
```

### Generating

```c
bool printFn(uint8_t *ub, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(ub, size, start, &start, "label1")) return false;
    if (!SSFUBJsonPrintString(ub, size, start, &start, "value1")) return false;
    *end = start;
    return true;
}

uint8_t ubjson[128];
size_t end;

if (SSFUBJsonPrintObject(ubjson, sizeof(ubjson), 0, &end, printFn, NULL))
{
    /* ubjson contains the encoded message, end is its length */
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Path arrays must be fully zeroed before use.
- For array index access, set a path element to point to a `size_t` index variable.
- Each nesting level consumes stack; keep depth within `SSF_UBJSON_CONFIG_MAX_IN_DEPTH`.
- UBJSON data is binary and not null-terminated; always track its length separately.
