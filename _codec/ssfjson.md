# ssfjson — JSON Parser/Generator

[SSF](../README.md) | [Codecs](README.md)

SAX-style JSON parser and printer-callback generator.

The parser walks the JSON string on each access without building a DOM; RAM usage scales with
nesting depth, not message size. The generator uses a chained-callback pattern where each
`SSFJsonPrint*` call writes directly into a caller-supplied buffer, advancing an offset cursor.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfjson--json-parsergenerator) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`_opt/ssfjson_opt.h`](../_opt/ssfjson_opt.h) (aggregated through `ssfoptions.h`)
- [`ssfgobj.h`](ssfgobj.h) — only when `SSF_JSON_GOBJ_ENABLE == 1`

<a id="notes"></a>

## [↑](#ssfjson--json-parsergenerator) Notes

- Path arrays must be fully zeroed before use (e.g., `memset(path, 0, sizeof(path))`).
- For array element access, set a path element to point to a `size_t` index variable.
- Top-level arrays are supported; start the path with a `size_t *` index pointer.
- Each `{` or `[` level of nesting consumes one level of stack; keep nesting within
  `SSF_JSON_CONFIG_MAX_IN_DEPTH`.
- The parser considers inputs with duplicate object keys valid and matches only the first
  occurrence.
- Only 8-bit ASCII-encoded strings are accepted; an embedded `\0` terminates input.
- Generator print functions return `false` when the output buffer is too small; no partial output
  is guaranteed.
- The `comma` pointer passed to generator functions may be `NULL` to suppress automatic comma
  insertion.

<a id="configuration"></a>

## [↑](#ssfjson--json-parsergenerator) Configuration

Options live in [`_opt/ssfjson_opt.h`](../_opt/ssfjson_opt.h) (aggregated into the build via `ssfoptions.h`).

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_JSON_CONFIG_MAX_IN_DEPTH` | `4` | Maximum nesting depth for the parser; each `{` or `[` counts as one level |
| `SSF_JSON_CONFIG_MAX_IN_LEN` | `2047` | Maximum JSON string length accepted by the parser in bytes |
| `SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE` | `0` | `1` to compile `SSFJsonGetDouble()`; `0` to omit floating-point parsing |
| `SSF_JSON_CONFIG_ENABLE_FLOAT_GEN` | `1` | `1` to compile `SSFJsonPrintDouble()`; `0` to omit floating-point generation |
| `SSF_JSON_GOBJ_ENABLE` | `1` | `1` to enable `SSFJsonGObjCreate()` and `SSFJsonGObjPrint()` JSON/gobj conversion functions; `0` to exclude them and remove the `ssfgobj` dependency |
| `SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE` | `256` | Maximum length in bytes of any object key or string value during JSON/gobj conversion |

<a id="api-summary"></a>

## [↑](#ssfjson--json-parsergenerator) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssfjsontype-t"></a>`SSFJsonType_t` | Enum | JSON value type returned by [`SSFJsonGetType()`](#ssfjsongettype): `SSF_JSON_TYPE_STRING`, `SSF_JSON_TYPE_NUMBER`, `SSF_JSON_TYPE_OBJECT`, `SSF_JSON_TYPE_ARRAY`, `SSF_JSON_TYPE_TRUE`, `SSF_JSON_TYPE_FALSE`, `SSF_JSON_TYPE_NULL`, `SSF_JSON_TYPE_ERROR` |
| <a id="ssfjsonfltfmt-t"></a>`SSFJsonFltFmt_t` | Enum (requires `SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1`) | Float format for [`SSFJsonPrintDouble()`](#ssfjsonprintdouble): `SSF_JSON_FLT_FMT_PREC_0`–`SSF_JSON_FLT_FMT_PREC_9` for fixed decimal places; `SSF_JSON_FLT_FMT_STD` for `%g`; `SSF_JSON_FLT_FMT_SHORT` for shortest representation |
| <a id="ssfjsonprintfn-t"></a>`SSFJsonPrintFn_t` | Typedef | `bool (*)(char *js, size_t size, size_t start, size_t *end, void *in)` — callback type passed to generator functions |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-isvalid) | [`bool SSFJsonIsValid(js)`](#ssfjsonisvalid) | Validate that `js` is well-formed JSON |
| [e.g.](#ex-gettype) | [`SSFJsonType_t SSFJsonGetType(js, path)`](#ssfjsongettype) | Return the JSON type of the value at `path` |
| [e.g.](#ex-getstring) | [`bool SSFJsonGetString(js, path, out, outSize, outLen)`](#ssfjsongetstring) | Extract and unescape a string value |
| [e.g.](#ex-getint) | [`bool SSFJsonGetInt(js, path, out)` / `bool SSFJsonGetUInt(js, path, out)`](#ssfjsongetint) | Parse a signed or unsigned 64-bit integer value |
| [e.g.](#ex-getdouble) | [`bool SSFJsonGetDouble(js, path, out)`](#ssfjsongetdouble) | Parse a floating-point value (requires `SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1`) |
| [e.g.](#ex-gethex) | [`bool SSFJsonGetHex(js, path, out, outSize, outLen, rev)`](#ssfjsongethex) | Decode a hex-encoded binary string value |
| [e.g.](#ex-getbase64) | [`bool SSFJsonGetBase64(js, path, out, outSize, outLen)`](#ssfjsongetbase64) | Decode a Base64-encoded binary string value |
| [e.g.](#ex-message) | [`bool SSFJsonMessage(js, index, start, end, path, depth, jt)`](#ssfjsonmessage) | Low-level SAX iterator |
| [e.g.](#ex-printobject) | [`bool SSFJsonPrintObject(js, size, start, end, fn, in, comma)` / `bool SSFJsonPrintArray(...)`](#ssfjsonprintobject) | Generate a JSON object or array via callback |
| [e.g.](#ex-printlabel) | [`bool SSFJsonPrintLabel(js, size, start, end, in, comma)`](#ssfjsonprintlabel) | Append a quoted key label followed by `:` |
| [e.g.](#ex-printstring) | [`bool SSFJsonPrintString(js, size, start, end, in, comma)`](#ssfjsonprintstring) | Append a quoted, escaped string value |
| [e.g.](#ex-printint) | [`bool SSFJsonPrintInt(js, size, start, end, in, comma)` / `bool SSFJsonPrintUInt(...)`](#ssfjsonprintint) | Append a signed or unsigned integer value |
| [e.g.](#ex-printdouble) | [`bool SSFJsonPrintDouble(js, size, start, end, in, fmt, comma)`](#ssfjsonprintdouble) | Append a floating-point value (requires `SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1`) |
| [e.g.](#ex-printtrue) | [`bool SSFJsonPrintTrue(js, size, start, end, comma)` / `bool SSFJsonPrintFalse(...)` / `bool SSFJsonPrintNull(...)`](#ssfjsonprinttrue) | Append JSON literal `true`, `false`, or `null` |
| [e.g.](#ex-printhex) | [`bool SSFJsonPrintHex(js, size, start, end, in, inLen, rev, comma)`](#ssfjsonprinthex) | Append binary data as a hex-encoded string value |
| [e.g.](#ex-printbase64) | [`bool SSFJsonPrintBase64(js, size, start, end, in, inLen, comma)`](#ssfjsonprintbase64) | Append binary data as a Base64-encoded string value |
| [e.g.](#ex-gobjcreate) | [`bool SSFJsonGObjCreate(js, gobj, maxChildren)`](#ssfjsongobjcreate) | Convert a JSON string to a gobj tree (`SSF_JSON_GOBJ_ENABLE`) |
| [e.g.](#ex-gobjprint) | [`bool SSFJsonGObjPrint(gobj, js, jsSize, jsLen)`](#ssfjsongobjprint) | Convert a gobj tree to a JSON string (`SSF_JSON_GOBJ_ENABLE`) |

<a id="function-reference"></a>

## [↑](#ssfjson--json-parsergenerator) Function Reference

<a id="ssfjsonisvalid"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonIsValid()`](#functions)

```c
bool SSFJsonIsValid(SSFCStrIn_t js);
```

Validates that `js` is a well-formed JSON string per RFC 8259. Does not check for duplicate
object keys.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string to validate. Must not be `NULL`. |

**Returns:** `true` if `js` is valid JSON; `false` otherwise.

```c
/* JSON string used in parser examples */
const char *js = "{\"name\":\"alice\",\"age\":30,\"active\":true,"
                 "\"scores\":[10,20,30],"
                 "\"data\":\"deadbeef\",\"b64\":\"AQID\"}";

/* Path array — must be zeroed before every use */
const char *path[SSF_JSON_CONFIG_MAX_IN_DEPTH + 1];
```

<a id="ex-isvalid"></a>

```c
if (SSFJsonIsValid(js))
{
    /* js is well-formed JSON */
}
```

---

<a id="ssfjsongettype"></a>

### [↑](#ssfjson--json-parsergenerator) [`SSFJsonType_t SSFJsonGetType()`](#functions)

```c
SSFJsonType_t SSFJsonGetType(SSFCStrIn_t js, SSFCStrIn_t *path);
```

Returns the [`SSFJsonType_t`](#ssfjsontype-t) of the value found at `path` within `js`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated array of path segments. Object keys are `const char *` strings; array indices are `size_t *` pointers. Must be fully zeroed before use. Must not be `NULL`. |

**Returns:** [`SSFJsonType_t`](#ssfjsontype-t) identifying the JSON value type, or
`SSF_JSON_TYPE_ERROR` if the path was not found.

<a id="ex-gettype"></a>

```c
SSFJsonType_t jt;

memset(path, 0, sizeof(path));
path[0] = "name";
jt = SSFJsonGetType(js, (SSFCStrIn_t *)path);
/* jt == SSF_JSON_TYPE_STRING */

memset(path, 0, sizeof(path));
path[0] = "age";
jt = SSFJsonGetType(js, (SSFCStrIn_t *)path);
/* jt == SSF_JSON_TYPE_NUMBER */
```

---

<a id="ssfjsongetstring"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGetString()`](#functions)

```c
bool SSFJsonGetString(SSFCStrIn_t js, SSFCStrIn_t *path, SSFCStrOut_t out, size_t outSize,
                      size_t *outLen);
```

Finds the JSON string value at `path` and copies it unescaped (without surrounding quotes) into
`out`. Null-terminates `out` on success.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated, zeroed path array. Must not be `NULL`. |
| `out` | out | `char *` | Buffer receiving the unescaped string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. |
| `outLen` | out | `size_t *` | If not `NULL`, receives the length of the extracted string (excluding null terminator). |

**Returns:** `true` if a string value was found at `path` and copied into `out`; `false` otherwise.

<a id="ex-getstring"></a>

```c
char   out[32];
size_t outLen;

memset(path, 0, sizeof(path));
path[0] = "name";
if (SSFJsonGetString(js, (SSFCStrIn_t *)path, out, sizeof(out), &outLen))
{
    /* out == "alice", outLen == 5 */
}
```

---

<a id="ssfjsongetint"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGetInt()` / `bool SSFJsonGetUInt()`](#functions)

```c
bool SSFJsonGetInt(SSFCStrIn_t js, SSFCStrIn_t *path, int64_t *out);
bool SSFJsonGetUInt(SSFCStrIn_t js, SSFCStrIn_t *path, uint64_t *out);
```

Finds a JSON number value at `path` and parses it as a signed or unsigned 64-bit integer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated, zeroed path array. Must not be `NULL`. |
| `out` | out | `int64_t *` or `uint64_t *` | Receives the parsed integer value. Must not be `NULL`. |

**Returns:** `true` if the value was found and parsed successfully; `false` if not found, not a
number, or out of range for the target type.

<a id="ex-getint"></a>

```c
int64_t  si;
uint64_t ui;
size_t   idx;

/* Signed integer at a named key */
memset(path, 0, sizeof(path));
path[0] = "age";
if (SSFJsonGetInt(js, (SSFCStrIn_t *)path, &si))
{
    /* si == 30 */
}

/* Unsigned integer — iterate array elements by index */
memset(path, 0, sizeof(path));
path[0] = "scores";
path[1] = (const char *)&idx;
for (idx = 0;; idx++)
{
    if (!SSFJsonGetUInt(js, (SSFCStrIn_t *)path, &ui)) break;
    /* idx==0: ui==10, idx==1: ui==20, idx==2: ui==30 */
}
```

---

<a id="ssfjsongetdouble"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGetDouble()`](#functions)

```c
/* Requires SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1 */
bool SSFJsonGetDouble(SSFCStrIn_t js, SSFCStrIn_t *path, double *out);
```

Finds a JSON number value at `path` and parses it as a `double`. Requires
`SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated, zeroed path array. Must not be `NULL`. |
| `out` | out | `double *` | Receives the parsed floating-point value. Must not be `NULL`. |

**Returns:** `true` if the value was found and parsed; `false` otherwise.

<a id="ex-getdouble"></a>

```c
/* Requires SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1 */
const char *jsf = "{\"pi\":3.14159}";
double d;

memset(path, 0, sizeof(path));
path[0] = "pi";
if (SSFJsonGetDouble(jsf, (SSFCStrIn_t *)path, &d))
{
    /* d == 3.14159 */
}
```

---

<a id="ssfjsongethex"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGetHex()`](#functions)

```c
bool SSFJsonGetHex(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                   size_t *outLen, bool rev);
```

Finds a JSON string value at `path` and decodes it as a hexadecimal-encoded binary array.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated, zeroed path array. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the decoded binary bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. |
| `outLen` | out | `size_t *` | If not `NULL`, receives the number of bytes decoded. |
| `rev` | in | `bool` | `true` to reverse the byte order of the decoded output. |

**Returns:** `true` if a valid hex string was found and decoded; `false` otherwise.

<a id="ex-gethex"></a>

```c
uint8_t bin[8];
size_t  binLen;

memset(path, 0, sizeof(path));
path[0] = "data";
if (SSFJsonGetHex(js, (SSFCStrIn_t *)path, bin, sizeof(bin), &binLen, false))
{
    /* binLen == 4, bin[0..3] == {0xde, 0xad, 0xbe, 0xef} */
}
```

---

<a id="ssfjsongetbase64"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGetBase64()`](#functions)

```c
bool SSFJsonGetBase64(SSFCStrIn_t js, SSFCStrIn_t *path, uint8_t *out, size_t outSize,
                      size_t *outLen);
```

Finds a JSON string value at `path` and decodes it as a Base64-encoded binary array.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated, zeroed path array. Must not be `NULL`. |
| `out` | out | `uint8_t *` | Buffer receiving the decoded binary bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. |
| `outLen` | out | `size_t *` | If not `NULL`, receives the number of bytes decoded. |

**Returns:** `true` if a valid Base64 string was found and decoded; `false` otherwise.

<a id="ex-getbase64"></a>

```c
uint8_t bin[8];
size_t  binLen;

memset(path, 0, sizeof(path));
path[0] = "b64";
if (SSFJsonGetBase64(js, (SSFCStrIn_t *)path, bin, sizeof(bin), &binLen))
{
    /* binLen == 3, bin[0..2] == {0x01, 0x02, 0x03} */
}
```

---

<a id="ssfjsonmessage"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonMessage()`](#functions)

```c
bool SSFJsonMessage(SSFCStrIn_t js, size_t *index, size_t *start, size_t *end,
                    SSFCStrIn_t *path, uint8_t depth, SSFJsonType_t *jt);
```

Low-level SAX iterator used internally by all `SSFJsonGet*` functions. Walks `js` starting at
`*index` and reports the next value that matches `path`. Exposed for advanced use cases requiring
fine-grained control over parsing.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string. Must not be `NULL`. |
| `index` | in-out | `size_t *` | Current byte offset into `js`. Initialize to `0` before the first call; updated on each call. Must not be `NULL`. |
| `start` | out | `size_t *` | Receives the start offset of the matched value within `js`. Must not be `NULL`. |
| `end` | out | `size_t *` | Receives the end offset (exclusive) of the matched value within `js`. Must not be `NULL`. |
| `path` | in | `const char **` | Zero-terminated, zeroed path array to match. Must not be `NULL`. |
| `depth` | in | `uint8_t` | Current nesting depth. Pass `0` for a top-level call. |
| `jt` | out | [`SSFJsonType_t *`](#ssfjsontype-t) | Receives the JSON type of the matched value. Must not be `NULL`. |

**Returns:** `true` if a matching value was found and `*start`, `*end`, and `*jt` were set;
`false` when parsing is complete or no match was found.

<a id="ex-message"></a>

```c
size_t        index = 0;
size_t        start, end;
SSFJsonType_t jt;

memset(path, 0, sizeof(path));
path[0] = "name";
if (SSFJsonMessage(js, &index, &start, &end, (SSFCStrIn_t *)path, 0, &jt))
{
    /* jt == SSF_JSON_TYPE_STRING */
    /* js[start..end-1] == "\"alice\"" (with surrounding quotes) */
}
```

---

<a id="ssfjsonprintobject"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintObject()` / `bool SSFJsonPrintArray()`](#functions)

```c
#define SSFJsonPrintObject(js, size, start, end, fn, in, comma) \
        SSFJsonPrint(js, size, start, end, fn, in, "{}", comma)
#define SSFJsonPrintArray(js, size, start, end, fn, in, comma) \
        SSFJsonPrint(js, size, start, end, fn, in, "[]", comma)
```

Generates a JSON object or array by writing the opening bracket, invoking `fn` to fill the
contents, then writing the closing bracket. `fn` receives the output buffer and advances the
`start`/`end` cursor.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset into `js`. |
| `end` | out | `size_t *` | Receives the write offset after the closing bracket. Must not be `NULL`. |
| `fn` | in | [`SSFJsonPrintFn_t`](#ssfjsonprintfn-t) | Callback that writes the object or array body. Must not be `NULL`. |
| `in` | in | `void *` | Opaque context pointer passed through to `fn`. May be `NULL`. |
| `comma` | in-out | `bool *` | If not `NULL`, a comma is prepended when `*comma` is `true`, then `*comma` is set to `true`. Pass `NULL` to suppress comma handling. |

**Returns:** `true` if generation succeeded (`fn` returned `true` and the buffer was large
enough); `false` otherwise.

<a id="ex-printobject"></a>

```c
bool ObjFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "x", &comma)) return false;
    if (!SSFJsonPrintInt(  js, size, start, &start, 1,   NULL))   return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "y", &comma)) return false;
    if (!SSFJsonPrintInt(  js, size, start, &start, 2,   NULL))   return false;
    *end = start;
    return true;
}

bool ArrFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintInt(js, size, start, &start, 10, &comma)) return false;
    if (!SSFJsonPrintInt(js, size, start, &start, 20, &comma)) return false;
    if (!SSFJsonPrintInt(js, size, start, &start, 30, &comma)) return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, ObjFn, NULL, NULL))
{
    /* out == "{\"x\":1,\"y\":2}" */
}

if (SSFJsonPrintArray(out, sizeof(out), 0, &end, ArrFn, NULL, NULL))
{
    /* out == "[10,20,30]" */
}
```

---

<a id="ssfjsonprintlabel"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintLabel()`](#functions)

```c
bool SSFJsonPrintLabel(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                       SSFCStrIn_t in, bool *comma);
```

Appends a JSON object key label (quoted string followed by `:`) to the output buffer. Optionally
prepends a comma separator.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset after appending. Must not be `NULL`. |
| `in` | in | `const char *` | Null-terminated label string. Must not be `NULL`. |
| `comma` | in-out | `bool *` | Comma control: prepends `,` when `*comma` is `true`, then sets `*comma` to `true`. Pass `NULL` to suppress. |

**Returns:** `true` if the label was appended; `false` if the buffer is too small.

<a id="ex-printlabel"></a>

```c
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "count", &comma)) return false;
    if (!SSFJsonPrintUInt( js, size, start, &start, 42u,     NULL))   return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"count\":42}" */
}
```

---

<a id="ssfjsonprintstring"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintString()`](#functions)

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
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `const char *` | Null-terminated string value to append. Must not be `NULL`. |
| `comma` | in-out | `bool *` | Comma control (same as [`SSFJsonPrintLabel()`](#ssfjsonprintlabel)). |

**Returns:** `true` if the value was appended; `false` if the buffer is too small.

<a id="ex-printstring"></a>

```c
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintLabel( js, size, start, &start, "greeting", &comma)) return false;
    if (!SSFJsonPrintString(js, size, start, &start, "hello",    NULL))   return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"greeting\":\"hello\"}" */
}
```

---

<a id="ssfjsonprintint"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintInt()` / `bool SSFJsonPrintUInt()`](#functions)

```c
bool SSFJsonPrintInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                     int64_t in, bool *comma);
bool SSFJsonPrintUInt(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                      uint64_t in, bool *comma);
```

Appends a JSON integer number (signed or unsigned) to the output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `int64_t` or `uint64_t` | Integer value to print. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if the value was appended; `false` if the buffer is too small.

<a id="ex-printint"></a>

```c
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "signed",   &comma)) return false;
    if (!SSFJsonPrintInt(  js, size, start, &start, -42,        NULL))   return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "unsigned", &comma)) return false;
    if (!SSFJsonPrintUInt( js, size, start, &start, 255u,       NULL))   return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"signed\":-42,\"unsigned\":255}" */
}
```

---

<a id="ssfjsonprintdouble"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintDouble()`](#functions)

```c
/* Requires SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1 */
bool SSFJsonPrintDouble(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                        double in, SSFJsonFltFmt_t fmt, bool *comma);
```

Appends a JSON floating-point number to the output buffer. Requires
`SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `double` | Floating-point value to print. |
| `fmt` | in | [`SSFJsonFltFmt_t`](#ssfjsonfltfmt-t) | Output format: `SSF_JSON_FLT_FMT_PREC_0`–`SSF_JSON_FLT_FMT_PREC_9` for fixed decimal places; `SSF_JSON_FLT_FMT_STD` for `%g`; `SSF_JSON_FLT_FMT_SHORT` for shortest representation. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if the value was appended; `false` if the buffer is too small.

<a id="ex-printdouble"></a>

```c
/* Requires SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1 */
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintLabel( js, size, start, &start, "pi", &comma)) return false;
    if (!SSFJsonPrintDouble(js, size, start, &start, 3.14159,
                            SSF_JSON_FLT_FMT_PREC_2, NULL)) return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"pi\":3.14}" */
}
```

---

<a id="ssfjsonprinttrue"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintTrue()` / `bool SSFJsonPrintFalse()` / `bool SSFJsonPrintNull()`](#functions)

```c
#define SSFJsonPrintTrue(js, size, start, end, comma)  \
        SSFJsonPrintCString(js, size, start, end, "true", comma)
#define SSFJsonPrintFalse(js, size, start, end, comma) \
        SSFJsonPrintCString(js, size, start, end, "false", comma)
#define SSFJsonPrintNull(js, size, start, end, comma)  \
        SSFJsonPrintCString(js, size, start, end, "null", comma)
```

Convenience macros that append the JSON literals `true`, `false`, or `null` to the output
buffer. Parameters and return value are identical to [`SSFJsonPrintString()`](#ssfjsonprintstring)
except there is no `in` argument.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if the literal was appended; `false` if the buffer is too small.

<a id="ex-printtrue"></a>

```c
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool comma = false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "t", &comma)) return false;
    if (!SSFJsonPrintTrue( js, size, start, &start,      NULL))   return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "f", &comma)) return false;
    if (!SSFJsonPrintFalse(js, size, start, &start,      NULL))   return false;
    if (!SSFJsonPrintLabel(js, size, start, &start, "n", &comma)) return false;
    if (!SSFJsonPrintNull( js, size, start, &start,      NULL))   return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"t\":true,\"f\":false,\"n\":null}" */
}
```

---

<a id="ssfjsonprinthex"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintHex()`](#functions)

```c
bool SSFJsonPrintHex(SSFCStrOut_t js, size_t size, size_t start, size_t *end,
                     const uint8_t *in, size_t inLen, bool rev, bool *comma);
```

Encodes `in` as a lowercase hexadecimal string and appends it as a quoted JSON string value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in-out | `char *` | JSON output buffer. Must not be `NULL`. |
| `size` | in | `size_t` | Total allocated size of `js`. |
| `start` | in | `size_t` | Current write offset. |
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Binary data to encode. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `size_t` | Number of bytes to encode. |
| `rev` | in | `bool` | `true` to encode bytes in reverse order. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if appended successfully; `false` if the buffer is too small.

<a id="ex-printhex"></a>

```c
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool          comma = false;
    const uint8_t bin[] = {0xdeu, 0xadu, 0xbeu, 0xefu};
    if (!SSFJsonPrintLabel(js, size, start, &start, "data", &comma)) return false;
    if (!SSFJsonPrintHex(  js, size, start, &start, bin, sizeof(bin), false, NULL)) return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"data\":\"deadbeef\"}" */
}
```

---

<a id="ssfjsonprintbase64"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonPrintBase64()`](#functions)

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
| `end` | out | `size_t *` | Receives the new write offset. Must not be `NULL`. |
| `in` | in | `const uint8_t *` | Binary data to encode. May be `NULL` when `inLen` is `0`. |
| `inLen` | in | `size_t` | Number of bytes to encode. |
| `comma` | in-out | `bool *` | Comma control. |

**Returns:** `true` if appended successfully; `false` if the buffer is too small.

<a id="ex-printbase64"></a>

```c
bool PrintFn(char *js, size_t size, size_t start, size_t *end, void *in)
{
    bool          comma = false;
    const uint8_t bin[] = {0x01u, 0x02u, 0x03u};
    if (!SSFJsonPrintLabel(  js, size, start, &start, "b64", &comma)) return false;
    if (!SSFJsonPrintBase64( js, size, start, &start, bin, sizeof(bin), NULL)) return false;
    *end = start;
    return true;
}

char   out[64];
size_t end;

if (SSFJsonPrintObject(out, sizeof(out), 0, &end, PrintFn, NULL, NULL))
{
    /* out == "{\"b64\":\"AQID\"}" */
}
```

---

<a id="ssfjsongobjcreate"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGObjCreate()`](#functions)

Requires `SSF_JSON_GOBJ_ENABLE == 1`.

```c
bool SSFJsonGObjCreate(SSFCStrIn_t js, SSFGObj_t **gobj, uint16_t maxChildren);
```

Parses a null-terminated JSON string and builds a generic object tree (`SSFGObj_t`)
representing its contents. The JSON is validated with `SSFJsonIsValid()` before parsing.
On success, `*gobj` points to a newly allocated root node that must be freed with
`SSFGObjDeInit()`.

The resulting tree maps JSON types to gobj types as follows:

| JSON type | gobj type |
|-----------|-----------|
| `"string"` | `SSF_OBJ_TYPE_STR` |
| integer number | `SSF_OBJ_TYPE_INT` (signed) or `SSF_OBJ_TYPE_UINT` (unsigned overflow) |
| floating-point number | `SSF_OBJ_TYPE_FLOAT` (requires `SSF_JSON_CONFIG_ENABLE_FLOAT_PARSE == 1`) |
| `true` / `false` | `SSF_OBJ_TYPE_BOOL` |
| `null` | `SSF_OBJ_TYPE_NULL` |
| `{ ... }` | `SSF_OBJ_TYPE_OBJECT` with labeled children |
| `[ ... ]` | `SSF_OBJ_TYPE_ARRAY` with ordered children |

JSON escape sequences in strings (`\"`, `\\`, `\n`, `\t`, `\uXXXX`, etc.) are unescaped into
the stored string value.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `js` | in | `const char *` | Null-terminated JSON string to parse. Must not be `NULL`. |
| `gobj` | out | `SSFGObj_t **` | Receives the root of the newly allocated gobj tree. Must not be `NULL`. |
| `maxChildren` | in | `uint16_t` | Maximum number of children for each container node (objects and arrays). |

**Returns:** `true` if the JSON was successfully converted; `false` if the JSON is invalid, on
allocation failure, or if any object key or string value exceeds
`SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE`.

<a id="ex-gobjcreate"></a>

```c
const char *js = "{\"name\":\"alice\",\"age\":30,\"active\":true}";
SSFGObj_t *gobj = NULL;

if (SSFJsonGObjCreate(js, &gobj, 8))
{
    SSFGObj_t *parent = NULL;
    SSFGObj_t *child = NULL;
    SSFCStrIn_t path[SSF_GOBJ_CONFIG_MAX_IN_DEPTH + 1];
    char name[32];
    int64_t age;
    bool active;

    memset(path, 0, sizeof(path));
    path[0] = "name";
    SSFGObjFindPath(gobj, path, &parent, &child);
    SSFGObjGetString(child, name, sizeof(name));
    /* name == "alice" */

    memset(path, 0, sizeof(path));
    path[0] = "age";
    parent = NULL; child = NULL;
    SSFGObjFindPath(gobj, path, &parent, &child);
    SSFGObjGetInt(child, &age);
    /* age == 30 */

    memset(path, 0, sizeof(path));
    path[0] = "active";
    parent = NULL; child = NULL;
    SSFGObjFindPath(gobj, path, &parent, &child);
    SSFGObjGetBool(child, &active);
    /* active == true */

    SSFGObjDeInit(&gobj);
}
```

---

<a id="ssfjsongobjprint"></a>

### [↑](#ssfjson--json-parsergenerator) [`bool SSFJsonGObjPrint()`](#functions)

Requires `SSF_JSON_GOBJ_ENABLE == 1`.

```c
bool SSFJsonGObjPrint(SSFGObj_t *gobj, SSFCStrOut_t js, size_t jsSize, size_t *jsLen);
```

Serializes a generic object tree into a null-terminated JSON string. The gobj tree may use
any of the supported types:

| gobj type | JSON output |
|-----------|-------------|
| `SSF_OBJ_TYPE_STR` | `"string"` (escaped) |
| `SSF_OBJ_TYPE_INT` | signed integer |
| `SSF_OBJ_TYPE_UINT` | unsigned integer |
| `SSF_OBJ_TYPE_BOOL` | `true` or `false` |
| `SSF_OBJ_TYPE_NULL` | `null` |
| `SSF_OBJ_TYPE_FLOAT` | floating-point (requires `SSF_JSON_CONFIG_ENABLE_FLOAT_GEN == 1`; uses `%g` format) |
| `SSF_OBJ_TYPE_OBJECT` | `{ ... }` with labeled children as `"key":value` pairs |
| `SSF_OBJ_TYPE_ARRAY` | `[ ... ]` with ordered children |

Unsupported types (`SSF_OBJ_TYPE_BIN`, `SSF_OBJ_TYPE_NONE`) cause the function to return
`false`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `gobj` | in | `SSFGObj_t *` | Root of the gobj tree. Must not be `NULL`. |
| `js` | out | `char *` | Output buffer for the JSON string. Must not be `NULL`. |
| `jsSize` | in | `size_t` | Total allocated size of `js` in bytes. Must be > 0. |
| `jsLen` | out | `size_t *` | Receives the length of the JSON string (excluding null terminator). Must not be `NULL`. |

**Returns:** `true` if the entire tree was serialized into the buffer; `false` if the buffer is
too small, a child has an unsupported type, or a string/label exceeds
`SSF_JSON_GOBJ_CONFIG_MAX_STR_SIZE`.

<a id="ex-gobjprint"></a>

```c
/* Build a gobj tree */
SSFGObj_t *root = NULL;
SSFGObj_t *child = NULL;

SSFGObjInit(&root, 8);
SSFGObjSetObject(root);

SSFGObjInit(&child, 0);
SSFGObjSetLabel(child, "name");
SSFGObjSetString(child, "alice");
SSFGObjInsertChild(root, child);

child = NULL;
SSFGObjInit(&child, 0);
SSFGObjSetLabel(child, "age");
SSFGObjSetInt(child, 30);
SSFGObjInsertChild(root, child);

/* Serialize to JSON */
char buf[128];
size_t len;

if (SSFJsonGObjPrint(root, buf, sizeof(buf), &len))
{
    /* buf == "{\"name\":\"alice\",\"age\":30}" */
    /* len == 23 */
}

SSFGObjDeInit(&root);
```


