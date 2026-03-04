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
| `SSFUBJsonGetString(ub, ubLen, path, out, outSize, outLen)` | Parse a string value at a path |
| `SSFUBJsonGetInt8/16/32/64(ub, ubLen, path, out)` | Parse a typed integer value at a path |
| `SSFUBJsonGetUInt8/16/32/64(ub, ubLen, path, out)` | Parse a typed unsigned integer value at a path |
| `SSFUBJsonGetFloat/Double(ub, ubLen, path, out)` | Parse a floating-point value at a path |
| `SSFUBJsonGetBool(ub, ubLen, path, out)` | Parse a boolean value at a path |
| `SSFUBJsonGetType(ub, ubLen, path, type)` | Return the UBJSON type at a given path |
| `SSFUBJsonPrintObject(ub, size, start, end, fn, in)` | Generate a UBJSON object |
| `SSFUBJsonPrintArray(ub, size, start, end, fn, in)` | Generate a UBJSON array |
| `SSFUBJsonPrintLabel(ub, size, start, end, label)` | Print a UBJSON key label |
| `SSFUBJsonPrintString(ub, size, start, end, str)` | Print a UBJSON string value |
| `SSFUBJsonPrintInt8/16/32/64(ub, size, start, end, val)` | Print a typed integer value |
| `SSFUBJsonPrintUInt8/16/32/64(ub, size, start, end, val)` | Print a typed unsigned integer value |
| `SSFUBJsonPrintFloat/Double(ub, size, start, end, val)` | Print a floating-point value |
| `SSFUBJsonPrintBool(ub, size, start, end, val)` | Print a boolean value |
| `SSFUBJsonPrintNull(ub, size, start, end)` | Print a null value |

## Usage

UBJSON is a binary encoding that is 1:1 compatible with JSON data types while being more compact.
The specification can be found at https://ubjson.org/. This parser operates on the UBJSON message
in place and consumes stack proportional to the maximum nesting depth.

### Parsing

```c
uint8_t ubjson1[] = "{i\x04nameSi\x05value}";
size_t ubjson1Len = 16;
uint8_t ubjson2[] = "{i\x03obj{i\x04nameSi\x05valuei\x05" "array[$i#i\x03" "123}}";
size_t ubjson2Len = 39;
char *path[SSF_UBJSON_CONFIG_MAX_IN_DEPTH + 1];
char strOut[32];
size_t idx;

memset(path, 0, sizeof(path));

/* Get the value of a top-level element */
path[0] = "name";
if (SSFUBJsonGetString(ubjson1, ubjson1Len, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s\r\n", strOut);
    /* Prints "value" */
}

/* Iterate over a nested array */
path[0] = "obj";
path[1] = "array";
path[2] = (char *)&idx;
for (idx = 0;; idx++)
{
    int8_t si;
    if (SSFUBJsonGetInt8(ubjson2, ubjson2Len, (SSFCStrIn_t *)path, &si))
    {
        if (idx != 0) printf(", ");
        printf("%d", si);
    }
    else break;
}
/* Prints "1, 2, 3" */
```

### Generating

```c
bool printFn(uint8_t *ub, size_t size, size_t start, size_t *end, void *in)
{
    if (!SSFUBJsonPrintLabel(ub, size, start, &start, "label1")) return false;
    if (!SSFUBJsonPrintString(ub, size, start, &start, "value1")) return false;
    if (!SSFUBJsonPrintLabel(ub, size, start, &start, "label2")) return false;
    if (!SSFUBJsonPrintString(ub, size, start, &start, "value2")) return false;
    *end = start;
    return true;
}

uint8_t ubjson[128];
size_t end;

if (SSFUBJsonPrintObject(ubjson, sizeof(ubjson), 0, &end, printFn, NULL))
{
    /* ubjson == "{U\x06label1SU\x06value1U\x06label2SU\x06value2}", end == 36 */
}
```

Object and array nesting is achieved by calling `SSFUBJsonPrintObject()` or
`SSFUBJsonPrintArray()` from within a printer function. Optimized typed integer arrays are also
supported.

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Path arrays must be fully zeroed before use.
- For array index access, set a path element to point to a `size_t` index variable.
- Each nesting level consumes stack; keep depth within `SSF_UBJSON_CONFIG_MAX_IN_DEPTH`.
- UBJSON data is binary and not null-terminated; always track its length separately.
