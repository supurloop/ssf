# ssfmatch — Pattern Matching

[SSF](../README.md) | [Codecs](README.md)

Lightweight string pattern matching for protocol and routing code: case-insensitive ASCII
comparison, a small glob subset (`*` and `?`), URI path templates with `{param}` extraction, and
MQTT topic filter matching. Every function operates on caller-owned, null-terminated strings and
allocates nothing.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfmatch--pattern-matching) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfstr`](ssfstr.md) — `SSFStrCharToLower()` for ASCII case folding

<a id="notes"></a>

## [↑](#ssfmatch--pattern-matching) Notes

- **All string arguments must be non-`NULL`.** Every function asserts on a `NULL` pattern, string,
  filter, or topic.
- **Case folding is ASCII-only.** The `I` variants fold `A–Z` to `a–z` and nothing else; they are
  not Unicode-aware. This is the right behavior for HTTP field names (RFC 7230 §3.2) and DNS
  labels, and the wrong behavior for user-visible text.
- **Glob is a deliberate subset.** [`SSFMatchGlob()`](#ssfmatchglob) and
  [`SSFMatchGlobI()`](#ssfmatchglobi) implement only `*` (any sequence, including empty) and `?`
  (exactly one character) from POSIX.1-2017 §2.13. Bracket expressions `[...]` and `\` escapes are
  **not** supported; every other character matches itself literally.
- **Glob matching is recursive and can backtrack.** Each `*` in the pattern opens a new recursion
  level that tries every remaining suffix of the input. Patterns with several `*` wildcards against
  long inputs degrade toward exponential time. Use glob only with system-owned patterns, or bound
  the input length externally; never hand untrusted patterns to it.
- **Path parameters are zero-copy and not null-terminated.** [`SSFMatchPath()`](#ssfmatchpath)
  fills each [`SSFMatchParam_t`](#type-param) with pointers into the caller's `pattern` (name) and
  `path` (value) strings plus explicit lengths. Use `nameLen` / `valueLen`; do not treat `name` or
  `value` as C strings. Both source strings must stay alive while the parameters are used.
- **Path parameter overflow is reported, not truncated silently.** When the pattern has more
  `{param}` placeholders than `paramsSize`, the extra placeholders are still matched and counted in
  `*numParamsOut` but not stored. A caller can detect the overflow by checking
  `*numParamsOut > paramsSize` after a `true` return.
- **Path matching is byte-literal.** No percent-decoding or normalization is applied. Callers that
  need RFC 3986 §2.1 normalized comparison must percent-decode `path` before matching. A `?` in
  the path ends matching: anything after it is treated as a query string and ignored.
- **`{` always begins a placeholder.** There is no escape for a literal `{` in a path pattern. An
  unterminated `{name` or an empty `{}` placeholder causes `false`.
- **Topic filters are validated first.** [`SSFMatchTopic()`](#ssfmatchtopic) rejects filters that
  violate MQTT v3.1.1 §4.7.1.2 (`+` not occupying a whole level, `#` not last or not preceded by
  `/`) by returning `false`. Per §4.7.2 a filter beginning with `+` or `#` never matches a topic
  beginning with `$`. A trailing `/` on the topic is treated as an optional empty final level, so
  `sport/tennis/+` matches `sport/tennis/ball/`. An empty filter matches only an empty topic; the
  caller is responsible for the §4.7.3 minimum-length rule.

<a id="configuration"></a>

## [↑](#ssfmatch--pattern-matching) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

The unit-test entry point is gated by `SSF_CONFIG_MATCH_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfmatch--pattern-matching) API Summary

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-param"></a>`SSFMatchParam_t` | Struct | One extracted path parameter: `{ SSFCStrIn_t name; uint32_t nameLen; SSFCStrIn_t value; uint32_t valueLen; }`. `name` points into the pattern string, `value` into the path string; neither is null-terminated. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-stri) | [`bool SSFMatchStrI(a, b)`](#ssfmatchstri) | Case-insensitive ASCII string equality |
| [e.g.](#ex-strni) | [`bool SSFMatchStrNI(a, b, len)`](#ssfmatchstrni) | Case-insensitive ASCII equality over at most `len` characters |
| [e.g.](#ex-glob) | [`bool SSFMatchGlob(pattern, str)`](#ssfmatchglob) | Glob match with `*` and `?` |
| [e.g.](#ex-glob) | [`bool SSFMatchGlobI(pattern, str)`](#ssfmatchglobi) | Case-insensitive glob match |
| [e.g.](#ex-path) | [`bool SSFMatchPath(pattern, path, paramsOut, paramsSize, numParamsOut)`](#ssfmatchpath) | URI path template match with `{param}` extraction |
| [e.g.](#ex-topic) | [`bool SSFMatchTopic(filter, topic)`](#ssfmatchtopic) | MQTT v3.1.1 topic filter match |

<a id="function-reference"></a>

## [↑](#ssfmatch--pattern-matching) Function Reference

<a id="ssfmatchstri"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchStrI()`](#functions)

```c
bool SSFMatchStrI(SSFCStrIn_t a, SSFCStrIn_t b);
```

Compares two null-terminated strings for equality, folding ASCII `A–Z` to lower case. Suitable for
HTTP field-name comparison.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `a` | in | `SSFCStrIn_t` | First null-terminated string. Must not be `NULL`. |
| `b` | in | `SSFCStrIn_t` | Second null-terminated string. Must not be `NULL`. |

**Returns:** `true` if the strings have the same length and are equal under ASCII case folding;
otherwise `false`.

<a id="ex-stri"></a>

```c
if (SSFMatchStrI("Content-Type", "content-type"))
{
    /* equal */
}
```

---

<a id="ssfmatchstrni"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchStrNI()`](#functions)

```c
bool SSFMatchStrNI(SSFCStrIn_t a, SSFCStrIn_t b, uint32_t len);
```

Compares at most `len` characters of two strings under ASCII case folding, with POSIX
`strncasecmp()` semantics: comparison stops at the first `'\0'` in either input, so passing a `len`
larger than the actual string length is safe.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `a` | in | `SSFCStrIn_t` | First string. Must not be `NULL`. |
| `b` | in | `SSFCStrIn_t` | Second string. Must not be `NULL`. |
| `len` | in | `uint32_t` | Maximum number of characters to compare. |

**Returns:** `true` if the first `len` characters are equal under ASCII case folding, or both
strings terminate at the same position before `len`; otherwise `false`.

<a id="ex-strni"></a>

```c
/* Prefix test: does the header line start with "Host:"? */
if (SSFMatchStrNI(line, "host:", 5u))
{
    /* header is Host */
}
```

---

<a id="ssfmatchglob"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchGlob()`](#functions)

```c
bool SSFMatchGlob(SSFCStrIn_t pattern, SSFCStrIn_t str);
```

Matches `str` against a glob `pattern` where `*` matches any sequence of characters (including
none) and `?` matches exactly one character. All other characters match literally; there are no
bracket expressions or escapes. Case-sensitive.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pattern` | in | `SSFCStrIn_t` | Null-terminated glob pattern. Must not be `NULL`. |
| `str` | in | `SSFCStrIn_t` | Null-terminated string to test. Must not be `NULL`. |

**Returns:** `true` if the whole of `str` matches `pattern`; otherwise `false`.

See the recursion caveat in [Notes](#notes).

<a id="ex-glob"></a>

```c
SSFMatchGlob("*.cfg", "device.cfg");      /* true  */
SSFMatchGlob("log?.txt", "log1.txt");     /* true  */
SSFMatchGlob("log?.txt", "log10.txt");    /* false */
SSFMatchGlobI("*.CFG", "device.cfg");     /* true  */
```

---

<a id="ssfmatchglobi"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchGlobI()`](#functions)

```c
bool SSFMatchGlobI(SSFCStrIn_t pattern, SSFCStrIn_t str);
```

Same as [`SSFMatchGlob()`](#ssfmatchglob) but literal characters are compared under ASCII case
folding.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pattern` | in | `SSFCStrIn_t` | Null-terminated glob pattern. Must not be `NULL`. |
| `str` | in | `SSFCStrIn_t` | Null-terminated string to test. Must not be `NULL`. |

**Returns:** `true` if the whole of `str` matches `pattern` ignoring ASCII case; otherwise `false`.

---

<a id="ssfmatchpath"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchPath()`](#functions)

```c
bool SSFMatchPath(SSFCStrIn_t pattern, SSFCStrIn_t path, SSFMatchParam_t *paramsOut,
                  uint32_t paramsSize, uint32_t *numParamsOut);
```

Matches a URI `path` against a `pattern` containing literal characters and `{name}` placeholders.
Each placeholder binds one path segment: the bytes up to the next `/`, `?`, or end of string. The
match succeeds when the pattern is fully consumed and the path is exhausted or has reached a `?`
query string. Loosely follows the simple-string-expansion form of RFC 6570 §3.2.2 but is not a
conformant URI Template implementation.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pattern` | in | `SSFCStrIn_t` | Null-terminated path template, e.g. `"/api/v1/devices/{id}/state"`. Must not be `NULL`. |
| `path` | in | `SSFCStrIn_t` | Null-terminated request path. Must not be `NULL`. |
| `paramsOut` | out | `SSFMatchParam_t *` | Array that receives extracted parameters. May be `NULL` only when `paramsSize` is `0`. |
| `paramsSize` | in | `uint32_t` | Number of elements in `paramsOut`. |
| `numParamsOut` | out | `uint32_t *` | Receives the number of placeholders in `pattern` (which may exceed `paramsSize`). Must not be `NULL`. Only written on a `true` return. |

**Returns:** `true` if `path` matches `pattern`; `false` on mismatch, an unterminated `{`, or an
empty `{}` placeholder.

<a id="ex-path"></a>

```c
SSFMatchParam_t params[2];
uint32_t numParams;

if (SSFMatchPath("/devices/{id}/sensors/{sensor}", "/devices/42/sensors/temp?units=c",
                 params, 2u, &numParams))
{
    /* numParams == 2                                              */
    /* params[0].name  -> "id",     nameLen  == 2                  */
    /* params[0].value -> "42",     valueLen == 2                  */
    /* params[1].name  -> "sensor", nameLen  == 6                  */
    /* params[1].value -> "temp",   valueLen == 4 (query ignored)  */
}
```

---

<a id="ssfmatchtopic"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchTopic()`](#functions)

```c
bool SSFMatchTopic(SSFCStrIn_t filter, SSFCStrIn_t topic);
```

Matches an MQTT topic name against a topic filter per MQTT v3.1.1 §4.7. `+` matches exactly one
level; `#` matches the remainder of the topic (zero or more levels) and must be the final
character. The filter is validated against §4.7.1.2 before matching, and the §4.7.2 rule that
wildcard-leading filters never match `$`-prefixed topics is enforced.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `filter` | in | `SSFCStrIn_t` | Null-terminated topic filter, e.g. `"sensors/+/temp"` or `"sensors/#"`. Must not be `NULL`. |
| `topic` | in | `SSFCStrIn_t` | Null-terminated topic name as published. Must not be `NULL`. |

**Returns:** `true` if `topic` matches `filter`; `false` on mismatch or when `filter` is malformed.

<a id="ex-topic"></a>

```c
SSFMatchTopic("sensors/+/temp", "sensors/kitchen/temp");   /* true  */
SSFMatchTopic("sensors/#",      "sensors/kitchen/temp");   /* true  */
SSFMatchTopic("sensors/#",      "sensors");                /* true  (# matches parent level) */
SSFMatchTopic("#",              "$SYS/broker/uptime");     /* false (§4.7.2 $-prefix rule)  */
SSFMatchTopic("sensors/temp#",  "sensors/temp");           /* false (malformed filter)      */
```
