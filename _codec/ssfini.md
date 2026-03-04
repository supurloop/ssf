# ssfini — INI File Parser/Generator

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

INI file parser and generator supporting string, boolean, and integer value types.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFINIIsSectionPresent(ini, section)` | Check whether a named section exists |
| `SSFIsNameValuePresent(ini, section, name, index)` | Check whether a name/value pair exists |
| `SSFINIGetStrValue(ini, section, name, index, out, outSize, outLen)` | Get a value as a string |
| `SSFINIGetBoolValue(ini, section, name, index, out)` | Get a value as a boolean |
| `SSFINIGetLongValue(ini, section, name, index, out)` | Get a value as a long integer |
| `SSFINIPrintComment(buf, bufSize, bufLen, text, style, eol)` | Generate an INI comment |
| `SSFINIPrintSection(buf, bufSize, bufLen, section, eol)` | Generate a section header |
| `SSFINIPrintNameStrValue(buf, bufSize, bufLen, name, value, eol)` | Generate a string name=value pair |
| `SSFINIPrintNameBoolValue(buf, bufSize, bufLen, name, value, style, eol)` | Generate a boolean name=value pair |
| `SSFINIPrintNameLongValue(buf, bufSize, bufLen, name, value, eol)` | Generate an integer name=value pair |

## Usage

The parser is forgiving of whitespace and supports `;` and `#` comment styles. The main limitation
is that values cannot contain whitespace (quoted strings are not supported).

```c
char iniParse[] = "; comment\r\nname=value1\r\n[section]\r\nname=yes\r\nname=0\r\nfoo=bar\r\nX=\r\n";
char outStr[16];
bool outBool;
long int outLong;
char iniGen[256];
size_t iniGenLen;

/* Parse */
SSFINIIsSectionPresent(iniParse, "section"); /* Returns true */
SSFINIIsSectionPresent(iniParse, "Section"); /* Returns false (case-sensitive) */

SSFIsNameValuePresent(iniParse, NULL,      "name", 0); /* Returns true */
SSFIsNameValuePresent(iniParse, NULL,      "name", 1); /* Returns false */
SSFIsNameValuePresent(iniParse, "section", "name", 0); /* Returns true */
SSFIsNameValuePresent(iniParse, "section", "name", 1); /* Returns true (duplicate) */
SSFIsNameValuePresent(iniParse, "section", "name", 2); /* Returns false */

SSFINIGetStrValue (iniParse, "section", "name", 1, outStr, sizeof(outStr), NULL); /* outStr = "0" */
SSFINIGetBoolValue(iniParse, "section", "name", 1, &outBool);                    /* outBool = false */
SSFINIGetLongValue(iniParse, "section", "name", 1, &outLong);                    /* outLong = 0 */

/* Generate */
iniGenLen = 0;
SSFINIPrintComment     (iniGen, sizeof(iniGen), &iniGenLen, " comment",  SSF_INI_COMMENT_HASH, SSF_INI_CRLF);
SSFINIPrintSection     (iniGen, sizeof(iniGen), &iniGenLen, "section",   SSF_INI_CRLF);
SSFINIPrintNameStrValue(iniGen, sizeof(iniGen), &iniGenLen, "strName",   "value",     SSF_INI_CRLF);
SSFINIPrintNameBoolValue(iniGen, sizeof(iniGen), &iniGenLen, "boolName", true, SSF_INI_BOOL_YES_NO, SSF_INI_CRLF);
SSFINIPrintNameLongValue(iniGen, sizeof(iniGen), &iniGenLen, "longName", -1234567890l, SSF_INI_CRLF);

/* iniGen = "# comment\r\n[section]\r\nstrName=value\r\nboolName=yes\r\nlongName=-1234567890\r\n" */
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Section and name comparisons are case-sensitive.
- Multiple occurrences of the same name within a section are allowed; use the `index` parameter
  (0-based) to iterate over them.
- Values cannot contain whitespace; quoted strings are not supported.
- Passing `NULL` for the `section` parameter searches the global (no-section) scope.
