# ssfini — INI File Parser/Generator

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

INI file parser and generator supporting string, boolean, and integer value types.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFINIIsSectionPresent(ini, section)` | Check whether a named section exists |
| `SSFINIIsNameValuePresent(ini, section, name, index)` | Check whether a name/value pair exists |
| `SSFINIGetStrValue(ini, section, name, index, out, outSize, outLen)` | Get a value as a string |
| `SSFINIGetBoolValue(ini, section, name, index, out)` | Get a value as a boolean |
| `SSFINIGetIntValue(ini, section, name, index, out)` | Get a value as a signed 64-bit integer |
| `SSFINIPrintComment(ini, iniSize, iniLen, text, commentType, lineEnding)` | Generate an INI comment line |
| `SSFINIPrintSection(ini, iniSize, iniLen, section, lineEnding)` | Generate a section header |
| `SSFINIPrintNameStrValue(ini, iniSize, iniLen, name, value, lineEnding)` | Generate a string name=value pair |
| `SSFINIPrintNameBoolValue(ini, iniSize, iniLen, name, value, boolType, lineEnding)` | Generate a boolean name=value pair |
| `SSFINIPrintNameIntValue(ini, iniSize, iniLen, name, value, lineEnding)` | Generate an integer name=value pair |

## Function Reference

### `SSFINIIsSectionPresent`

```c
bool SSFINIIsSectionPresent(SSFCStrIn_t ini, SSFCStrIn_t section);
```

Searches a null-terminated INI string for a section header whose name exactly matches `section`.
The comparison is case-sensitive.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string to search. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name to find (without brackets). Must not be `NULL`. |

**Returns:** `true` if a matching `[section]` header is found; `false` otherwise.

---

### `SSFINIIsNameValuePresent`

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

### `SSFINIGetStrValue`

```c
bool SSFINIGetStrValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                       SSFCStrOut_t out, size_t outSize, size_t *outLen);
```

Retrieves the string value associated with the `index`-th occurrence of `name` within `section`,
copying it as a null-terminated string into `out`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name. Pass `NULL` for the global scope. |
| `name` | in | `const char *` | Null-terminated name to look up. Must not be `NULL`. |
| `index` | in | `uint8_t` | 0-based occurrence index. |
| `out` | out | `char *` | Buffer receiving the null-terminated value string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be large enough for the value plus null terminator. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the length of the value string (excluding null terminator). |

**Returns:** `true` if the entry was found and the value copied; `false` if not found or `outSize` is too small.

---

### `SSFINIGetBoolValue`

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

### `SSFINIGetIntValue`

```c
bool SSFINIGetIntValue(SSFCStrIn_t ini, SSFCStrIn_t section, SSFCStrIn_t name, uint8_t index,
                       int64_t *out);
```

Retrieves the integer value of the `index`-th occurrence of `name` within `section`, parsing it
as a signed 64-bit decimal integer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in | `const char *` | Pointer to the null-terminated INI string. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name. Pass `NULL` for the global scope. |
| `name` | in | `const char *` | Null-terminated name to look up. Must not be `NULL`. |
| `index` | in | `uint8_t` | 0-based occurrence index. |
| `out` | out | `int64_t *` | Receives the parsed integer value. Must not be `NULL`. |

**Returns:** `true` if the entry was found and parsed as a valid integer; `false` otherwise.

---

### `SSFINIPrintComment`

```c
bool SSFINIPrintComment(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t text,
                        SSFINIComment_t commentType, SSFINILineEnd_t lineEnding);
```

Appends a comment line to the INI output buffer. The comment character is selected by
`commentType`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini` (excluding null terminator). Updated on success. Must not be `NULL`. |
| `text` | in | `const char *` | Null-terminated comment text (without the comment character). Must not be `NULL`. |
| `commentType` | in | `SSFINIComment_t` | Comment character: `SSF_INI_COMMENT_SEMI` for `;`, `SSF_INI_COMMENT_HASH` for `#`, `SSF_INI_COMMENT_NONE` for no prefix. |
| `lineEnding` | in | `SSFINILineEnd_t` | Line ending style: `SSF_INI_LF` for `\n`, `SSF_INI_CRLF` for `\r\n`. |

**Returns:** `true` if the comment was appended; `false` if the buffer is too small.

---

### `SSFINIPrintSection`

```c
bool SSFINIPrintSection(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t section,
                        SSFINILineEnd_t lineEnding);
```

Appends a section header line (`[section]`) to the INI output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. |
| `iniSize` | in | `size_t` | Total allocated size of `ini` in bytes. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `section` | in | `const char *` | Null-terminated section name (without brackets). Must not be `NULL`. |
| `lineEnding` | in | `SSFINILineEnd_t` | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the section header was appended; `false` if the buffer is too small.

---

### `SSFINIPrintNameStrValue`

```c
bool SSFINIPrintNameStrValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                             SSFCStrIn_t value, SSFINILineEnd_t lineEnding);
```

Appends a `name=value` line with a string value to the INI output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. |
| `iniSize` | in | `size_t` | Total allocated size of `ini`. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `name` | in | `const char *` | Null-terminated name string. Must not be `NULL`. |
| `value` | in | `const char *` | Null-terminated value string. Must not be `NULL`. |
| `lineEnding` | in | `SSFINILineEnd_t` | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the line was appended; `false` if the buffer is too small.

---

### `SSFINIPrintNameBoolValue`

```c
bool SSFINIPrintNameBoolValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                              bool value, SSFINIBool_t boolType, SSFINILineEnd_t lineEnding);
```

Appends a `name=value` line with a boolean value to the INI output buffer. The text
representation of the boolean is selected by `boolType`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. |
| `iniSize` | in | `size_t` | Total allocated size of `ini`. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `name` | in | `const char *` | Null-terminated name string. Must not be `NULL`. |
| `value` | in | `bool` | Boolean value to write. |
| `boolType` | in | `SSFINIBool_t` | Text format: `SSF_INI_BOOL_1_0`, `SSF_INI_BOOL_YES_NO`, `SSF_INI_BOOL_ON_OFF`, or `SSF_INI_BOOL_TRUE_FALSE`. |
| `lineEnding` | in | `SSFINILineEnd_t` | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the line was appended; `false` if the buffer is too small.

---

### `SSFINIPrintNameIntValue`

```c
bool SSFINIPrintNameIntValue(SSFCStrOut_t ini, size_t iniSize, size_t *iniLen, SSFCStrIn_t name,
                             int64_t value, SSFINILineEnd_t lineEnding);
```

Appends a `name=value` line with a signed 64-bit integer value to the INI output buffer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `ini` | in-out | `char *` | INI output buffer. Must not be `NULL`. |
| `iniSize` | in | `size_t` | Total allocated size of `ini`. |
| `iniLen` | in-out | `size_t *` | Current length of text in `ini`. Updated on success. Must not be `NULL`. |
| `name` | in | `const char *` | Null-terminated name string. Must not be `NULL`. |
| `value` | in | `int64_t` | Signed integer value to write. |
| `lineEnding` | in | `SSFINILineEnd_t` | Line ending style: `SSF_INI_LF` or `SSF_INI_CRLF`. |

**Returns:** `true` if the line was appended; `false` if the buffer is too small.

## Usage

The parser is forgiving of whitespace and supports `;` and `#` comment styles. The main limitation
is that values cannot contain whitespace (quoted strings are not supported).

```c
char iniParse[] = "; comment\r\nname=value1\r\n[section]\r\nname=yes\r\nname=0\r\nfoo=bar\r\nX=\r\n";
char outStr[16];
bool outBool;
int64_t outInt;
char iniGen[256];
size_t iniGenLen;

/* Parse */
SSFINIIsSectionPresent(iniParse, "section"); /* Returns true */
SSFINIIsSectionPresent(iniParse, "Section"); /* Returns false (case-sensitive) */

SSFINIIsNameValuePresent(iniParse, NULL,      "name", 0); /* Returns true */
SSFINIIsNameValuePresent(iniParse, NULL,      "name", 1); /* Returns false */
SSFINIIsNameValuePresent(iniParse, "section", "name", 0); /* Returns true */
SSFINIIsNameValuePresent(iniParse, "section", "name", 1); /* Returns true (duplicate) */
SSFINIIsNameValuePresent(iniParse, "section", "name", 2); /* Returns false */

SSFINIGetStrValue (iniParse, "section", "name", 1, outStr, sizeof(outStr), NULL); /* outStr = "0" */
SSFINIGetBoolValue(iniParse, "section", "name", 1, &outBool);                    /* outBool = false */
SSFINIGetIntValue (iniParse, "section", "name", 1, &outInt);                     /* outInt = 0 */

/* Generate */
iniGenLen = 0;
SSFINIPrintComment     (iniGen, sizeof(iniGen), &iniGenLen, " comment",  SSF_INI_COMMENT_HASH, SSF_INI_CRLF);
SSFINIPrintSection     (iniGen, sizeof(iniGen), &iniGenLen, "section",   SSF_INI_CRLF);
SSFINIPrintNameStrValue(iniGen, sizeof(iniGen), &iniGenLen, "strName",   "value",     SSF_INI_CRLF);
SSFINIPrintNameBoolValue(iniGen, sizeof(iniGen), &iniGenLen, "boolName", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF);
SSFINIPrintNameIntValue(iniGen, sizeof(iniGen), &iniGenLen, "intName",   -1234567890ll, SSF_INI_CRLF);

/* iniGen = "# comment\r\n[section]\r\nstrName=value\r\nboolName=yes\r\nintName=-1234567890\r\n" */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Section and name comparisons are case-sensitive.
- Multiple occurrences of the same name within a section are allowed; use the `index` parameter
  (0-based) to iterate over them.
- Values cannot contain whitespace; quoted strings are not supported.
- Passing `NULL` for the `section` parameter searches the global (no-section) scope.
