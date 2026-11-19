# ssfmatch — Pattern Matching

[SSF](../README.md) | [Codecs](README.md)

Lightweight string pattern matching for protocol and routing code: case-insensitive ASCII
comparison, a small glob subset (`*` and `?`), and URI path templates with `{param}` extraction.
Every function operates on caller-owned, null-terminated strings and allocates nothing.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfmatch--pattern-matching) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfstr`](ssfstr.md) — `SSFStrCharToLower()` for ASCII case folding

<a id="notes"></a>

## [↑](#ssfmatch--pattern-matching) Notes

- **All string arguments must be non-`NULL`.** Every function asserts on a `NULL` pattern, string,
  or path.
- **Case folding is ASCII-only.** The `I` variants fold `A–Z` to `a–z` and nothing else; they are
  not Unicode-aware. This is the right behavior for HTTP field names (RFC 7230 §3.2) and DNS
  labels, and the wrong behavior for user-visible text.
- **Glob is not certificate wildcard matching.** Glob `*` matches across `.` and matches the empty
  string, so `SSFMatchGlobI("*.example.com", ...)` accepts `a.b.example.com` and `.example.com`.
  RFC 6125 / RFC 9525 wildcards match exactly one non-empty leftmost label; use
  [`ssfx509`](ssfx509.md)'s hostname matching (`SSFX509VerifyChain()`) for that, never glob.
- **Glob is a deliberate subset.** [`SSFMatchGlob()`](#ssfmatchglob) and
  [`SSFMatchGlobI()`](#ssfmatchglobi) implement only `*` (any sequence, including empty) and `?`
  (exactly one character) from POSIX.1-2017 §2.13. Bracket expressions `[...]` and `\` escapes are
  **not** supported; every other character matches itself literally.
- **Glob wildcards are capped.** Each `*` in the pattern opens a recursion level that tries every
  remaining suffix of the input, so cost grows roughly as the input length raised to the number of
  `*` wildcards. To keep that bounded, [`SSFMatchGlob()`](#ssfmatchglob) and
  [`SSFMatchGlobI()`](#ssfmatchglobi) return `false` without matching when the pattern contains
  more than [`SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS`](#cfg-max-glob-wildcards) runs of `*`. A run of
  consecutive `*` counts as one; `?` is not counted because it never backtracks. The cap also
  bounds recursion depth, so stack use is known at compile time.
- **Path parameters are zero-copy and not null-terminated.** [`SSFMatchPath()`](#ssfmatchpath)
  fills each [`SSFMatchParam_t`](#type-param) with pointers into the caller's `patternStr` (name)
  and `pathStr` (value) strings plus explicit lengths. Use `nameLen` / `valueLen`; do not treat
  `name` or `value` as C strings. Both source strings must stay alive while the parameters are
  used.
- **Path parameter overflow is reported, not truncated silently.** When the pattern has more
  `{param}` placeholders than `paramsOutOptSize`, the extra placeholders are still matched and
  counted in `*numParamsOut` but not stored. A caller can detect the overflow by checking
  `*numParamsOut > paramsOutOptSize` after a `true` return.
- **Path matching is byte-literal.** No percent-decoding or normalization is applied. Callers that
  need RFC 3986 §2.1 normalized comparison must percent-decode `pathStr` before matching. A `?` or
  `#` in the path ends matching: anything after it is a query string or fragment (RFC 3986 §3.3,
  neither character can appear unencoded inside a path) and is ignored.
- **Outputs on failure.** Whenever [`SSFMatchPath()`](#ssfmatchpath) returns `false`,
  `*numParamsOut` is `0`. Entries in `paramsOut` may hold values bound before the mismatch was
  found and must not be read.
- **A placeholder binds exactly one non-empty segment.** `{name}` never matches an empty segment,
  whether the emptiness comes from the end of the path (`/a/{id}` vs `/a/`), a doubled slash
  (`/a/{id}/b` vs `/a//b`), or a query string directly after the slash (`/a/{id}` vs `/a/?x=1`).
  All three return `false`.
- **A placeholder binds the whole rest of its segment.** The value runs from the placeholder to the
  next `/`, `?`, `#`, or end of string with no lookahead for the literal that follows in the
  pattern. Literal text *before* a placeholder in the same segment works (`/file{ext}` matches
  `/filetxt` with `ext` = `txt`), but literal text *after* one can never match: `/{name}.json` vs
  `/foo.json` and `/{a}-{b}` vs `/1-2` both return `false` because the first placeholder has
  already consumed `.json` and `-2`. Two adjacent placeholders (`/{a}{b}`) always fail for the same
  reason, the second one binds an empty segment. Put the varying part last in its segment or give it
  its own segment.
- **`{` always begins a placeholder.** There is no escape for a literal `{` in a path pattern. An
  unterminated `{name` or an empty `{}` placeholder causes `false`.

<a id="configuration"></a>

## [↑](#ssfmatch--pattern-matching) Configuration

Options live in [`_opt/ssfmatch_opt.h`](../_opt/ssfmatch_opt.h).

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="cfg-max-glob-wildcards"></a>`SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS` | `4` | Maximum number of `*` runs a glob pattern may contain. Patterns with more are rejected by [`SSFMatchGlob()`](#ssfmatchglob) / [`SSFMatchGlobI()`](#ssfmatchglobi) with `false` before any matching. Worst-case matching time is roughly `inputLen ^ N` character comparisons and recursion depth is `N + 1` frames, so lower it on small targets or where inputs are long. |

The unit-test entry point is gated by `SSF_CONFIG_MATCH_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfmatch--pattern-matching) API Summary

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-param"></a>`SSFMatchParam_t` | Struct | One extracted path parameter: `{ const char *name; uint32_t nameLen; const char *value; uint32_t valueLen; }`. `name` points into the pattern string, `value` into the path string; neither is null-terminated. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-stri) | [`bool SSFMatchStrI(aStr, bStr)`](#ssfmatchstri) | Case-insensitive ASCII string equality |
| [e.g.](#ex-strni) | [`bool SSFMatchStrNI(aStr, bStr, len)`](#ssfmatchstrni) | Case-insensitive ASCII equality over at most `len` characters |
| [e.g.](#ex-glob) | [`bool SSFMatchGlob(patternStr, str)`](#ssfmatchglob) | Glob match with `*` and `?` |
| [e.g.](#ex-glob) | [`bool SSFMatchGlobI(patternStr, str)`](#ssfmatchglobi) | Case-insensitive glob match |
| [e.g.](#ex-path) | [`bool SSFMatchPath(patternStr, pathStr, paramsOutOpt, paramsOutOptSize, numParamsOut)`](#ssfmatchpath) | URI path template match with `{param}` extraction |

<a id="function-reference"></a>

## [↑](#ssfmatch--pattern-matching) Function Reference

<a id="ssfmatchstri"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchStrI()`](#functions)

```c
bool SSFMatchStrI(SSFCStrIn_t aStr, SSFCStrIn_t bStr);
```

Compares two null-terminated strings for equality, folding ASCII `A–Z` to lower case. Suitable for
HTTP field-name comparison.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `aStr` | in | `SSFCStrIn_t` | First null-terminated string. Must not be `NULL`. |
| `bStr` | in | `SSFCStrIn_t` | Second null-terminated string. Must not be `NULL`. |

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
bool SSFMatchStrNI(SSFCStrIn_t aStr, SSFCStrIn_t bStr, uint32_t len);
```

Compares at most `len` characters of two strings under ASCII case folding, with POSIX
`strncasecmp()` semantics: comparison stops at the first `'\0'` in either input, so passing a `len`
larger than the actual string length is safe.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `aStr` | in | `SSFCStrIn_t` | First string. Must not be `NULL`. |
| `bStr` | in | `SSFCStrIn_t` | Second string. Must not be `NULL`. |
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
bool SSFMatchGlob(SSFCStrIn_t patternStr, SSFCStrIn_t str);
```

Matches `str` against a glob `patternStr` where `*` matches any sequence of characters (including
none) and `?` matches exactly one character. All other characters match literally; there are no
bracket expressions or escapes. Case-sensitive.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `patternStr` | in | `SSFCStrIn_t` | Null-terminated glob pattern. Must not be `NULL`. |
| `str` | in | `SSFCStrIn_t` | Null-terminated string to test. Must not be `NULL`. |

**Returns:** `true` if the whole of `str` matches `patternStr`; `false` on mismatch or when
`patternStr` contains more than `SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS` runs of `*` (see
[Notes](#notes)).

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
bool SSFMatchGlobI(SSFCStrIn_t patternStr, SSFCStrIn_t str);
```

Same as [`SSFMatchGlob()`](#ssfmatchglob) but literal characters are compared under ASCII case
folding.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `patternStr` | in | `SSFCStrIn_t` | Null-terminated glob pattern. Must not be `NULL`. |
| `str` | in | `SSFCStrIn_t` | Null-terminated string to test. Must not be `NULL`. |

**Returns:** `true` if the whole of `str` matches `patternStr` ignoring ASCII case; `false` on
mismatch or when `patternStr` exceeds the `SSF_MATCH_CONFIG_MAX_GLOB_WILDCARDS` cap.

---

<a id="ssfmatchpath"></a>

### [↑](#ssfmatch--pattern-matching) [`bool SSFMatchPath()`](#functions)

```c
bool SSFMatchPath(SSFCStrIn_t patternStr, SSFCStrIn_t pathStr, SSFMatchParam_t *paramsOutOpt,
                  uint32_t paramsOutOptSize, uint32_t *numParamsOut);
```

Matches a URI `pathStr` against a `patternStr` containing literal characters and `{name}`
placeholders.
Each placeholder binds one non-empty path segment: the bytes up to the next `/`, `?`, `#`, or end
of string, of which there must be at least one. The placeholder takes everything up to that
boundary, so a literal that follows it within the same segment (as in `/{name}.json`) is never
reachable and the match fails; see [Notes](#notes). The match succeeds when the pattern is fully
consumed and the path is exhausted or has reached a `?` query string or `#` fragment. Loosely
follows the simple-string-expansion form of RFC 6570 §3.2.2 but is not a conformant URI Template
implementation.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `patternStr` | in | `SSFCStrIn_t` | Null-terminated path template, e.g. `"/api/v1/devices/{id}/state"`. Must not be `NULL`. |
| `pathStr` | in | `SSFCStrIn_t` | Null-terminated request path. Must not be `NULL`. |
| `paramsOutOpt` | out (opt) | `SSFMatchParam_t *` | Array that receives extracted parameters. May be `NULL` only when `paramsOutOptSize` is `0`. Contents are undefined after a `false` return. |
| `paramsOutOptSize` | in | `uint32_t` | Number of elements in `paramsOutOpt`. |
| `numParamsOut` | out | `uint32_t *` | Receives the number of placeholders in `patternStr` (which may exceed `paramsOutOptSize`) on `true`, and `0` on `false`. Must not be `NULL`. |

**Returns:** `true` if `pathStr` matches `patternStr`; `false` on mismatch, a placeholder that
would bind an empty segment, an unterminated `{`, or an empty `{}` placeholder.

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
    /* params[1].value -> "temp",   valueLen == 4 (query ignored; a #fragment would be too) */
}
```
