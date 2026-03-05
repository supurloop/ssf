# ssfini — INI File Parser/Generator

[SSF](../README.md) | [Codecs](README.md)

INI file parser and generator supporting string, boolean, and integer value types.

The parser searches a null-terminated INI string in memory for sections, names, and values.
The generator appends INI text (comments, section headers, and name=value lines) to a
caller-supplied buffer. Both sides use bounded buffers and return `false` rather than
truncating or overflowing.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference) | [Examples](#examples)

<a id="dependencies"></a>

## [↑](#ssfini--ini-file-parsergenerator) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfini--ini-file-parsergenerator) Notes

- Section and name comparisons are case-sensitive.
- Multiple entries with the same name within a section are allowed; use the `index` parameter
  (0-based) to select among them.
- Values cannot contain whitespace; quoted strings are not supported.
- Pass `NULL` for the `section` parameter to operate in the global (no-section) scope.
- Generator functions require `*iniLen` to be initialized to `0` before the first call and
  updated by each successive call; the buffer is always null-terminated on success.

<a id="configuration"></a>

## [↑](#ssfini--ini-file-parsergenerator) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfini--ini-file-parsergenerator) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfiniliend-t"></a>`SSFINILineEnd_t` | Enum | Line-ending style for generator functions |
| `SSF_INI_LF` | Enum value | [`SSFINILineEnd_t`](#type-ssfiniliend-t) — Unix `\n` line ending |
| `SSF_INI_CRLF` | Enum value | [`SSFINILineEnd_t`](#type-ssfiniliend-t) — Windows `\r\n` line ending |
| <a id="type-ssfinibool-t"></a>`SSFINIBool_t` | Enum | Boolean text format for [`SSFINIPrintNameBoolValue()`](#ssfiniprintnameboolvalue) |
| `SSF_INI_BOOL_1_0` | Enum value | [`SSFINIBool_t`](#type-ssfinibool-t) — writes `1` / `0` |
| `SSF_INI_BOOL_YES_NO` | Enum value | [`SSFINIBool_t`](#type-ssfinibool-t) — writes `yes` / `no` |
| `SSF_INI_BOOL_ON_OFF` | Enum value | [`SSFINIBool_t`](#type-ssfinibool-t) — writes `on` / `off` |
| `SSF_INI_BOOL_TRUE_FALSE` | Enum value | [`SSFINIBool_t`](#type-ssfinibool-t) — writes `true` / `false` |
| <a id="type-ssfinicomment-t"></a>`SSFINIComment_t` | Enum | Comment prefix character for [`SSFINIPrintComment()`](#ssfiniprintcomment) |
| `SSF_INI_COMMENT_SEMI` | Enum value | [`SSFINIComment_t`](#type-ssfinicomment-t) — `;` prefix |
| `SSF_INI_COMMENT_HASH` | Enum value | [`SSFINIComment_t`](#type-ssfinicomment-t) — `#` prefix |
| `SSF_INI_COMMENT_NONE` | Enum value | [`SSFINIComment_t`](#type-ssfinicomment-t) — no prefix |

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-issectionpresent) | [`SSFINIIsSectionPresent(ini, section)`](#ssfiniissectionpresent) | Check whether a named section exists |
| [e.g.](#ex-isnamepresent) | [`SSFINIIsNameValuePresent(ini, section, name, index)`](#ssfiniisnamevaluepresent) | Check whether a name/value pair exists |
| [e.g.](#ex-getstr) | [`SSFINIGetStrValue(ini, section, name, index, out, outSize, outLen)`](#ssfinigetstrvalue) | Get a value as a string |
| [e.g.](#ex-getbool) | [`SSFINIGetBoolValue(ini, section, name, index, out)`](#ssfinigetboolvalue) | Get a value as a boolean |
| [e.g.](#ex-getint) | [`SSFINIGetIntValue(ini, section, name, index, out)`](#ssfinigetintvalue) | Get a value as a signed 64-bit integer |
| [e.g.](#ex-printcomment) | [`SSFINIPrintComment(ini, iniSize, iniLen, text, commentType, lineEnding)`](#ssfiniprintcomment) | Append a comment line to an INI output buffer |
| [e.g.](#ex-printsection) | [`SSFINIPrintSection(ini, iniSize, iniLen, section, lineEnding)`](#ssfiniprintsection) | Append a section header line to an INI output buffer |
| [e.g.](#ex-printstrvalue) | [`SSFINIPrintNameStrValue(ini, iniSize, iniLen, name, value, lineEnding)`](#ssfiniprintnamestrvalue) | Append a string name=value line |
| [e.g.](#ex-printboolvalue) | [`SSFINIPrintNameBoolValue(ini, iniSize, iniLen, name, value, boolType, lineEnding)`](#ssfiniprintnameboolvalue) | Append a boolean name=value line |
| [e.g.](#ex-printintvalue) | [`SSFINIPrintNameIntValue(ini, iniSize, iniLen, name, value, lineEnding)`](#ssfiniprintnameintvalue) | Append an integer name=value line |

<a id="function-reference"></a>

## [↑](#ssfini--ini-file-parsergenerator) Function Reference

<a id="ssfiniissectionpresent"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIIsSectionPresent()`](#ex-issectionpresent)

```c
bool SSFINIIsSectionPresent(SSFCStrIn_t ini, SSFCStrIn_t section);
```

Searches a null-terminated INI string for a section header whose name exactly matches
`section`. The comparison is case-sensitive.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string to search. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name to find (without brackets). Must not be `NULL`. |

**Returns:** `true` if a matching `[section]` header is found; `false` otherwise.

---

<a id="ssfiniisnamevaluepresent"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIIsNameValuePresent()`](#ex-isnamepresent)

```c
bool SSFINIIsNameValuePresent(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name,
                               uint8_t index);
```

Checks whether a name/value entry with the given `name` exists within the specified `section`.
The `index` parameter selects among multiple entries with the same name (0-based).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name to search within. Pass `NULL` to search the global (no-section) scope. |
| `name` | in | `const char *` | Null-terminated name to find. Must not be `NULL`. |
| `index` | in | `uint8_t` | 0-based occurrence index among entries with the same name within the section. |

**Returns:** `true` if the `index`-th occurrence of `name` exists in the specified section; `false` otherwise.

---

<a id="ssfinigetstrvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIGetStrValue()`](#ex-getstr)

```c
bool SSFINIGetStrValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                       SSFCStrOut_t out, size_t outSize, size_t *outLen);
```

Retrieves the string value of the `index`-th occurrence of `name` within `section`, copying
it as a null-terminated string into `out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name. Pass `NULL` for the global scope. |
| `name` | in | `const char *` | Null-terminated name to look up. Must not be `NULL`. |
| `index` | in | `uint8_t` | 0-based occurrence index. |
| `out` | out | `char *` | Buffer receiving the null-terminated value string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be large enough for the value plus null terminator. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the length of the value string (excluding null terminator). |

**Returns:** `true` if the entry was found and the value copied into `out`; `false` if not found or `outSize` is too small.

---

<a id="ssfinigetboolvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIGetBoolValue()`](#ex-getbool)

```c
bool SSFINIGetBoolValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                        bool *out);
```

Retrieves the boolean value of the `index`-th occurrence of `name` within `section`. Recognized
true values: `1`, `yes`, `on`, `true` (case-insensitive). Recognized false values: `0`, `no`,
`off`, `false` (case-insensitive).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name. Pass `NULL` for the global scope. |
| `name` | in | `const char *` | Null-terminated name to look up. Must not be `NULL`. |
| `index` | in | `uint8_t` | 0-based occurrence index. |
| `out` | out | `bool *` | Receives the parsed boolean value. Must not be `NULL`. |

**Returns:** `true` if the entry was found and the value is a recognized boolean string; `false` otherwise.

---

<a id="ssfinigetintvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIGetIntValue()`](#ex-getint)

```c
bool SSFINIGetIntValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                       int64_t *out);
```

Retrieves the integer value of the `index`-th occurrence of `name` within `section`, parsing
it as a signed 64-bit decimal integer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name. Pass `NULL` for the global scope. |
| `name` | in | `const char *` | Null-terminated name to look up. Must not be `NULL`. |
| `index` | in | `uint8_t` | 0-based occurrence index. |
| `out` | out | `int64_t *` | Receives the parsed integer value. Must not be `NULL`. |

**Returns:** `true` if the entry was found and parsed as a valid integer; `false` otherwise.

---

<a id="ssfiniprintcomment"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIPrintComment()`](#ex-printcomment)

```c
bool SSFINIPrintComment(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t text,
                        SSFINIComment_t commentType, SSFINILineEnd_t lineEnding);
```

Appends a comment line to the INI output buffer. The comment character is selected by
`commentType`. `*iniLen` must be initialized to `0` before the first generator call and is
updated by each successive call.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. Must be null-terminated. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini` (excluding null terminator). Updated on success. Must not be `NULL`. |
| `text` | in | `const char *` | Null-terminated comment text (without the comment character). Must not be `NULL`. |
| `commentType` | in | [`SSFINIComment_t`](#type-ssfinicomment-t) | Comment prefix: `SSF_INI_COMMENT_SEMI` for `;`, `SSF_INI_COMMENT_HASH` for `#`, `SSF_INI_COMMENT_NONE` for no prefix. |
| `lineEnding` | in | [`SSFINILineEnd_t`](#type-ssfiniliend-t) | Line ending style: `SSF_INI_LF` for `\n`, `SSF_INI_CRLF` for `\r\n`. |

**Returns:** `true` if the comment line was appended; `false` if the buffer is too small.

---

<a id="ssfiniprintsection"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIPrintSection()`](#ex-printsection)

```c
bool SSFINIPrintSection(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t section,
                        SSFINILineEnd_t lineEnding);
```

Appends a section header line (`[section]`) to the INI output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. Must be null-terminated. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name (without brackets). Must not be `NULL`. |
| `lineEnding` | in | [`SSFINILineEnd_t`](#type-ssfiniliend-t) | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the section header was appended; `false` if the buffer is too small.

---

<a id="ssfiniprintnamestrvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIPrintNameStrValue()`](#ex-printstrvalue)

```c
bool SSFINIPrintNameStrValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                             SSFCStrIn_t value, SSFINILineEnd_t lineEnding);
```

Appends a `name=value` line with a string value to the INI output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. Must be null-terminated. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `name` | in | `const char *` | Null-terminated name string. Must not be `NULL`. |
| `value` | in | `const char *` | Null-terminated value string. Must not be `NULL`. |
| `lineEnding` | in | [`SSFINILineEnd_t`](#type-ssfiniliend-t) | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the line was appended; `false` if the buffer is too small.

---

<a id="ssfiniprintnameboolvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIPrintNameBoolValue()`](#ex-printboolvalue)

```c
bool SSFINIPrintNameBoolValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                              bool value, SSFINIBool_t boolType, SSFINILineEnd_t lineEnding);
```

Appends a `name=value` line with a boolean value to the INI output buffer. The text
representation is selected by `boolType`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. Must be null-terminated. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `name` | in | `const char *` | Null-terminated name string. Must not be `NULL`. |
| `value` | in | `bool` | Boolean value to write. |
| `boolType` | in | [`SSFINIBool_t`](#type-ssfinibool-t) | Text format: `SSF_INI_BOOL_1_0`, `SSF_INI_BOOL_YES_NO`, `SSF_INI_BOOL_ON_OFF`, or `SSF_INI_BOOL_TRUE_FALSE`. |
| `lineEnding` | in | [`SSFINILineEnd_t`](#type-ssfiniliend-t) | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the line was appended; `false` if the buffer is too small.

---

<a id="ssfiniprintnameintvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [`SSFINIPrintNameIntValue()`](#ex-printintvalue)

```c
bool SSFINIPrintNameIntValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                             int64_t value, SSFINILineEnd_t lineEnding);
```

Appends a `name=value` line with a signed 64-bit integer value to the INI output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. Must be null-terminated. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `name` | in | `const char *` | Null-terminated name string. Must not be `NULL`. |
| `value` | in | `int64_t` | Signed integer value to write. |
| `lineEnding` | in | [`SSFINILineEnd_t`](#type-ssfiniliend-t) | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the line was appended; `false` if the buffer is too small.

<a id="examples"></a>

## [↑](#ssfini--ini-file-parsergenerator) Examples

The parser examples all use this INI source string:

```c
const char ini[] = "global=42\r\n"
                   "[section]\r\n"
                   "name=yes\r\n"
                   "name=0\r\n"
                   "host=localhost\r\n";
```

<a id="ex-issectionpresent"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIIsSectionPresent()](#ssfiniissectionpresent)

```c
SSFINIIsSectionPresent(ini, "section");   /* returns true  */
SSFINIIsSectionPresent(ini, "Section");   /* returns false — case-sensitive */
SSFINIIsSectionPresent(ini, "other");     /* returns false */
```

<a id="ex-isnamepresent"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIIsNameValuePresent()](#ssfiniisnamevaluepresent)

```c
/* Global scope (NULL section) */
SSFINIIsNameValuePresent(ini, NULL,      "global", 0);   /* returns true  */
SSFINIIsNameValuePresent(ini, NULL,      "global", 1);   /* returns false — only one occurrence */

/* Named section — "name" appears twice, index 0 and 1 */
SSFINIIsNameValuePresent(ini, "section", "name", 0);     /* returns true  */
SSFINIIsNameValuePresent(ini, "section", "name", 1);     /* returns true  */
SSFINIIsNameValuePresent(ini, "section", "name", 2);     /* returns false */
```

<a id="ex-getstr"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIGetStrValue()](#ssfinigetstrvalue)

```c
char val[32];
size_t valLen;

/* First occurrence of "name" in [section] → "yes" */
if (SSFINIGetStrValue(ini, "section", "name", 0, val, sizeof(val), &valLen))
{
    /* val == "yes", valLen == 3 */
}

/* Second occurrence of "name" in [section] → "0" */
if (SSFINIGetStrValue(ini, "section", "name", 1, val, sizeof(val), NULL))
{
    /* val == "0" */
}
```

<a id="ex-getbool"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIGetBoolValue()](#ssfinigetboolvalue)

```c
bool b;

/* "name=yes" at index 0 */
if (SSFINIGetBoolValue(ini, "section", "name", 0, &b))
{
    /* b == true */
}

/* "name=0" at index 1 */
if (SSFINIGetBoolValue(ini, "section", "name", 1, &b))
{
    /* b == false */
}
```

<a id="ex-getint"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIGetIntValue()](#ssfinigetintvalue)

```c
int64_t n;

/* "global=42" in global scope */
if (SSFINIGetIntValue(ini, NULL, "global", 0, &n))
{
    /* n == 42 */
}

/* "name=0" at index 1 in [section] */
if (SSFINIGetIntValue(ini, "section", "name", 1, &n))
{
    /* n == 0 */
}
```

<a id="ex-printcomment"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIPrintComment()](#ssfiniprintcomment)

```c
char buf[128];
size_t len = 0;

SSFINIPrintComment(buf, sizeof(buf), &len, " generated config", SSF_INI_COMMENT_SEMI, SSF_INI_CRLF);
/* buf == "; generated config\r\n" */

SSFINIPrintComment(buf, sizeof(buf), &len, " also a comment",   SSF_INI_COMMENT_HASH, SSF_INI_CRLF);
/* buf == "; generated config\r\n# also a comment\r\n" */
```

<a id="ex-printsection"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIPrintSection()](#ssfiniprintsection)

```c
char buf[128];
size_t len = 0;

SSFINIPrintSection(buf, sizeof(buf), &len, "network", SSF_INI_CRLF);
/* buf == "[network]\r\n" */
```

<a id="ex-printstrvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIPrintNameStrValue()](#ssfiniprintnamestrvalue)

```c
char buf[128];
size_t len = 0;

SSFINIPrintSection     (buf, sizeof(buf), &len, "network",   SSF_INI_CRLF);
SSFINIPrintNameStrValue(buf, sizeof(buf), &len, "host", "localhost", SSF_INI_CRLF);
/* buf == "[network]\r\nhost=localhost\r\n" */
```

<a id="ex-printboolvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIPrintNameBoolValue()](#ssfiniprintnameboolvalue)

```c
char buf[128];
size_t len = 0;

SSFINIPrintSection      (buf, sizeof(buf), &len, "network",             SSF_INI_CRLF);
SSFINIPrintNameBoolValue(buf, sizeof(buf), &len, "enabled", true,  SSF_INI_BOOL_YES_NO,    SSF_INI_CRLF);
SSFINIPrintNameBoolValue(buf, sizeof(buf), &len, "debug",   false, SSF_INI_BOOL_TRUE_FALSE, SSF_INI_CRLF);
/* buf == "[network]\r\nenabled=yes\r\ndebug=false\r\n" */
```

<a id="ex-printintvalue"></a>

### [↑](#ssfini--ini-file-parsergenerator) [SSFINIPrintNameIntValue()](#ssfiniprintnameintvalue)

```c
char buf[128];
size_t len = 0;

SSFINIPrintSection     (buf, sizeof(buf), &len, "network",          SSF_INI_CRLF);
SSFINIPrintNameIntValue(buf, sizeof(buf), &len, "port",    8080,    SSF_INI_CRLF);
SSFINIPrintNameIntValue(buf, sizeof(buf), &len, "timeout", -1,      SSF_INI_CRLF);
/* buf == "[network]\r\nport=8080\r\ntimeout=-1\r\n" */
```
