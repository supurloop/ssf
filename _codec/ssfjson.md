# ssfjson — JSON Parser/Generator

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

SAX-style JSON parser and printer-callback generator with optional in-place field update.

## Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_JSON_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth; each `{` or `[` counts as one level |
| `SSF_JSON_CONFIG_MAX_IN_LEN` | `2047` | Maximum JSON string length accepted by the parser |
| `SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE` | `0` | `1` to allow parsing of floating-point numbers |
| `SSF_JSON_CONFIG_ENABLE_FLOAT_GEN` | `1` | `1` to allow generating floating-point numbers |
| `SSF_JSON_CONFIG_ENABLE_UPDATE` | `1` | `1` to enable `SSFJsonUpdate()` for in-place field updates |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFJsonIsValid(js)` | Validate a JSON string |
| `SSFJsonGetType(js, path)` | Return the JSON type at a given path |
| `SSFJsonGetString(js, path, out, outSize, outLen)` | Parse a string value at a path |
| `SSFJsonGetInt(js, path, out)` | Parse a signed integer value at a path |
| `SSFJsonGetUInt(js, path, out)` | Parse an unsigned integer value at a path |
| `SSFJsonGetDouble(js, path, out)` | Parse a float value (requires `ENABLE_FLOAT_PARSE`) |
| `SSFJsonGetHex(js, path, out, outSize, outLen, rev)` | Parse a hex-encoded binary string |
| `SSFJsonGetBase64(js, path, out, outSize, outLen)` | Parse a Base64-encoded binary string |
| `SSFJsonMessage(js, index, start, end, path, depth, jt)` | Low-level message iterator |
| `SSFJsonPrintObject(js, size, start, end, fn, in, comma)` | Generate a JSON object |
| `SSFJsonPrintArray(js, size, start, end, fn, in, comma)` | Generate a JSON array |
| `SSFJsonPrintLabel(js, size, start, end, label, comma)` | Print a JSON key label |
| `SSFJsonPrintString(js, size, start, end, str, comma)` | Print a JSON string value |
| `SSFJsonPrintInt(js, size, start, end, val, comma)` | Print a signed JSON integer value |
| `SSFJsonPrintUInt(js, size, start, end, val, comma)` | Print an unsigned JSON integer value |
| `SSFJsonPrintDouble(js, size, start, end, val, fmt, comma)` | Print a JSON float (requires `ENABLE_FLOAT_GEN`) |
| `SSFJsonPrintTrue(js, size, start, end, comma)` | Macro: print JSON `true` literal |
| `SSFJsonPrintFalse(js, size, start, end, comma)` | Macro: print JSON `false` literal |
| `SSFJsonPrintNull(js, size, start, end, comma)` | Macro: print JSON `null` literal |
| `SSFJsonPrintHex(js, size, start, end, in, inLen, rev, comma)` | Print binary as a hex-encoded string |
| `SSFJsonPrintBase64(js, size, start, end, in, inLen, comma)` | Print binary as a Base64-encoded string |
| `SSFJsonUpdate(js, size, path, fn)` | Update or insert a field (requires `ENABLE_UPDATE`) |

## Function Reference

### `SSFJsonIsValid`

```c
bool SSFJsonIsValid(SSFCStrIn_t js);
```

Validates that `js` is a well-formed JSON string (RFC 8259). Does not check for duplicate keys.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string to validate. Must not be `NULL`. |

**Returns:** `true` if the string is valid JSON; `false` otherwise.

---

### `SSFJsonGetType`

```c
SSFJsonType_t SSFJsonGetType(SSFCStrIn_t js, SSFCStrIn_t *path);
```

Returns the JSON type of the value at `path` within `js`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string to search. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated array of path strings. Each element names an object key; a `size_t *` element indexes into an array. The array must be fully zeroed before use. Must not be `NULL`. |

**Returns:** `SSFJsonType_t` enum value: `SSF_JSON_TYPE_STRING`, `SSF_JSON_TYPE_NUMBER`,
`SSF_JSON_TYPE_OBJECT`, `SSF_JSON_TYPE_ARRAY`, `SSF_JSON_TYPE_TRUE`, `SSF_JSON_TYPE_FALSE`,
`SSF_JSON_TYPE_NULL`, or `SSF_JSON_TYPE_ERROR` if the path was not found.

---

### `SSFJsonGetString`

```c
bool SSFJsonGetString(SSFCStrIn_t js, SSFCStrIn_t *path, SSFCStrOut_t out, size_t outSize,
                      size_t *outLen);
```

Finds the JSON string value at `path` and copies it (unescaped, without surrounding quotes) into
`out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated path array (zeroed before use). Must not be `NULL`. |
| `out` | out | `char *` | Buffer receiving the unescaped string value. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the length of the extracted string. |

**Returns:** `true` if a string value was found at `path` and copied; `false` otherwise.

---

### `SSFJsonGetInt` / `SSFJsonGetUInt`

```c
bool SSFJsonGetInt(SSFCStrIn_t js, SSFCStrIn_t *path, int64_t *out);
bool SSFJsonGetUInt(SSFCStrIn_t js, SSFCStrIn_t *path, uint64_t *out);
```

Finds a JSON number value at `path` and parses it as a signed or unsigned 64-bit integer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated path array (zeroed before use). Must not be `NULL`. |
| `out` | out | `int64_t *` or `uint64_t *` | Receives the parsed integer value. Must not be `NULL`. |

**Returns:** `true` if the value was found and parsed successfully; `false` if not found, not a number, or out of range for the target type.

---

### `SSFJsonGetDouble`

```c
/* Requires SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1 */
bool SSFJsonGetDouble(SSFCStrIn_t js, SSFCStrIn_t *path, double *out);
```

Finds a JSON number value at `path` and parses it as a `double`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `double *` | Receives the parsed floating-point value. Must not be `NULL`. |

**Returns:** `true` if the value was found and parsed; `false` otherwise.

---

### `SSFJsonGetHex`

```c
bool SSFJsonGetHex(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                   size_t *outLen, bool rev);
```

Finds a JSON string value at `path` and decodes it as a hexadecimal-encoded binary array.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the decoded binary bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out`. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of bytes decoded. |
| `rev` | in | `bool` | `true` to reverse the byte order of the decoded output. |

**Returns:** `true` if a valid hex string was found and decoded; `false` otherwise.

---

### `SSFJsonGetBase64`

```c
bool SSFJsonGetBase64(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                      size_t *outLen);
```

Finds a JSON string value at `path` and decodes it as a Base64-encoded binary array.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated path array. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the decoded binary bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out`. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of bytes decoded. |

**Returns:** `true` if a valid Base64 string was found and decoded; `false` otherwise.

---

### `SSFJsonMessage`

```c
bool SSFJsonMessage(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                    SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt);
```

Low-level iterator that walks the JSON string and invokes path matching logic. Used internally
by the `SSFJsonGet*` functions; exposed for advanced use cases where fine-grained control over
parsing is required.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `index` | in-out | `size_t *` | Current byte offset into `js`. Initialize to `0` before the first call. Updated on each call. Must not be `NULL`. |
| `start` | out | `size_t *` | Receives the start offset of the matched value within `js`. Must not be `NULL`. |
| `end` | out | `size_t *` | Receives the end offset (exclusive) of the matched value within `js`. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated path array to match. Must not be `NULL`. |
| `depth` | in | `uint8_t` | Current nesting depth. Pass `0` for a top-level call. |
| `jt` | out | `SSFJsonType_t *` | Receives the JSON type of the matched value. Must not be `NULL`. |

**Returns:** `true` if a matching value was found; `false` if parsing is complete or no match exists.

---

### `SSFJsonPrintString`

```c
bool SSFJsonPrintString(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                        SSFCStrIn_t in, bool *comma);
```

Appends a JSON string value (quoted and escaped) to the output buffer. Optionally prepends a
comma separator.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset into `js`. |
| `end` | out | `size_t *` | Receives the new write offset after appending. Must not be `NULL`. |
| `in` | in | `const char *` | Null-terminated string value to append. Must not be `NULL`. |
| `comma` | in-out | `bool *` | If not `NULL`, a comma is prepended when `*comma` is `true`, then `*comma` is set to `true`. Pass `NULL` to suppress comma handling. |

**Returns:** `true` if the value was appended; `false` if the buffer is too small.

---

### `SSFJsonPrintLabel`

```c
bool SSFJsonPrintLabel(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                       SSFCStrIn_t in, bool *comma);
```

Appends a JSON object key label (quoted, followed by `:`) to the output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `const char *` | Null-terminated label string. Must not be `NULL`. |
| `comma` | in-out | `bool *` | Comma control (same as `SSFJsonPrintString`). |

**Returns:** `true` if the label was appended; `false` if the buffer is too small.

---

### `SSFJsonPrintInt` / `SSFJsonPrintUInt`

```c
bool SSFJsonPrintInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                     int64_t in, bool *comma);
bool SSFJsonPrintUInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                      uint64_t in, bool *comma);
```

Appends a JSON integer number to the output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `int64_t` or `uint64_t` | Integer value to print. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if the value was appended; `false` if the buffer is too small.

---

### `SSFJsonPrintDouble`

```c
/* Requires SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1 */
bool SSFJsonPrintDouble(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                        double in, SSFJsonFltFmt_t fmt, bool *comma);
```

Appends a JSON floating-point number to the output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `double` | Floating-point value to print. |
| `fmt` | in | `SSFJsonFltFmt_t` | Format: `SSF_JSON_FLT_FMT_PREC_0` through `SSF_JSON_FLT_FMT_PREC_9` for fixed decimal places, `SSF_JSON_FLT_FMT_STD` for `%g`, `SSF_JSON_FLT_FMT_SHORT` for shortest representation. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if the value was appended; `false` if the buffer is too small.

---

### `SSFJsonPrintTrue` / `SSFJsonPrintFalse` / `SSFJsonPrintNull`

```c
#define SSFJsonPrintTrue(js, size, start, end, comma)  \
    SSFJsonPrintCString(js, size, start, end, "true", comma)
#define SSFJsonPrintFalse(js, size, start, end, comma) \
    SSFJsonPrintCString(js, size, start, end, "false", comma)
#define SSFJsonPrintNull(js, size, start, end, comma)  \
    SSFJsonPrintCString(js, size, start, end, "null", comma)
```

Convenience macros for appending the JSON literals `true`, `false`, and `null`. Parameters are
identical to `SSFJsonPrintString` (without the `in` argument). Return `true` on success, `false`
if the buffer is too small.

---

### `SSFJsonPrintHex`

```c
bool SSFJsonPrintHex(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                     const uint8_t *in, size_t inLen, bool rev, bool *comma);
```

Encodes `in` as a hexadecimal string and appends it as a quoted JSON string value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives new write offset. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Binary data to encode. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `size_t` | Number of bytes to encode. |
| `rev` | in | `bool` | `true` to encode `in` in reverse byte order. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if appended successfully; `false` if the buffer is too small.

---

### `SSFJsonPrintBase64`

```c
bool SSFJsonPrintBase64(SSFCStrOut_t jstr, size_t size, size_t start, size_t *end,
                        const uint8_t *in, size_t inLen, bool *comma);
```

Encodes `in` as a Base64 string and appends it as a quoted JSON string value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `jstr` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `jstr`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives new write offset. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Binary data to encode. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `size_t` | Number of bytes to encode. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if appended successfully; `false` if the buffer is too small.

---

### `SSFJsonPrintObject` / `SSFJsonPrintArray`

```c
#define SSFJsonPrintObject(js, size, start, end, fn, in, comma) \
    SSFJsonPrint(js, size, start, end, fn, in, "{}", comma)
#define SSFJsonPrintArray(js, size, start, end, fn, in, comma) \
    SSFJsonPrint(js, size, start, end, fn, in, "[]", comma)
```

Generate a JSON object or array by invoking the printer callback `fn`. `fn` receives the
output buffer and writes fields into it, advancing the `start`/`end` cursor.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the write offset after the closing bracket. Must not be `NULL`. |
| `fn` | in | `SSFJsonPrintFn_t` | Callback of type `bool (*)(char *js, size_t size, size_t start, size_t *end, void *in)` that writes the object/array contents. |
| `in` | in | `void *` | Opaque context pointer passed through to `fn`. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if generation succeeded (i.e., `fn` returned `true` and the buffer was large enough); `false` otherwise.

---

### `SSFJsonUpdate`

```c
/* Requires SSF_JSON_CONFIG_ENABLE_UPDATE == 1 */
bool SSFJsonUpdate(SSFCStrOut_t js, size_t size, SSFCStrIn_t *path, SSFJsonPrintFn_t fn);
```

Updates the value at `path` in an existing JSON string in-place. If the path exists, the
existing value is replaced by calling `fn`. If the path does not exist, a new key/value pair is
inserted. The JSON string must have sufficient spare capacity (i.e., `size > strlen(js) + 1`).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON string to modify in-place. Must not be `NULL`. Must have `size > strlen(js) + 1` bytes allocated. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `path` | in | `const char **` | Zero-terminated path array identifying the field to update. Must not be `NULL`. |
| `fn` | in | `SSFJsonPrintFn_t` | Callback that writes the new value. |

**Returns:** `true` if the update succeeded; `false` if the buffer is too small or the callback failed.

## Usage

This is a SAX-like parser that operates on the JSON string in place and consumes stack proportional
to the maximum nesting depth. The JSON string is parsed from the start each time a data element is
accessed, which is computationally inefficient but acceptable since most embedded targets are RAM-
constrained rather than performance-constrained.

### Parsing

```c
char json1Str[] = "{\"name\":\"value\"}";
char json2Str[] = "{\"obj\":{\"name\":\"value\",\"array\":[1,2,3]}}";
char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
char strOut[32];
size_t idx;

/* Must zero out path variable before use */
memset(path, 0, sizeof(path));

/* Get the value of a top-level element */
path[0] = "name";
if (SSFJsonGetString(json1Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "value" (without double quotes) */
}

/* Iterate over a nested array */
path[0] = "obj";
path[1] = "array";
path[2] = (char *)&idx;
for (idx = 0;; idx++)
{
    int64_t si;
    if (SSFJsonGetInt(json2Str, (SSFCStrIn_t *)path, &si))
    {
        if (idx != 0) printf(", ");
        printf("%lld", si);
    }
    else break;
}
/* Prints "1, 2, 3" */
```

### Generating

```c
bool printFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;

    if (!SSFJsonPrintLabel(js, size, start, &start, "label1", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value1", NULL)) return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "label2", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "value2", NULL)) return false;

    *end = start;
    return true;
}

char jsonStr[128];
size_t end;

if (SSFJsonPrintObject(jsonStr, sizeof(jsonStr), 0, &end, printFn, NULL, NULL))
{
    /* jsonStr == "{\"label1\":\"value1\",\"label2\":\"value2\"}" */
}
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Path arrays must be fully zeroed before use (e.g., with `memset(path, 0, sizeof(path))`).
- For array index access, set a path element to point to a `size_t` index variable.
- Top-level arrays are supported; start the path with an index pointer.
- Each `{` or `[` level of nesting consumes stack. Keep nesting within `SSF_JSON_CONFIG_MAX_IN_DEPTH`.
- If unit tests fail unexpectedly on a new port, try increasing the system stack size.
