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
| `SSFJsonGetString(js, path, out, outSize, outLen)` | Parse a string value at a path |
| `SSFJsonGetInt(js, path, out)` | Parse an integer value at a path |
| `SSFJsonGetDouble(js, path, out)` | Parse a float value (requires `ENABLE_FLOAT_PARSE`) |
| `SSFJsonGetBool(js, path, out)` | Parse a boolean value at a path |
| `SSFJsonGetHex(js, path, out, outSize, outLen)` | Parse a hex-encoded binary string |
| `SSFJsonGetType(js, path, type)` | Return the JSON type at a given path |
| `SSFJsonIsValid(js)` | Validate a JSON string |
| `SSFJsonPrintObject(js, size, start, end, fn, in, comma)` | Generate a JSON object |
| `SSFJsonPrintArray(js, size, start, end, fn, in, comma)` | Generate a JSON array |
| `SSFJsonPrintLabel(js, size, start, end, label, comma)` | Print a JSON key label |
| `SSFJsonPrintString(js, size, start, end, str, comma)` | Print a JSON string value |
| `SSFJsonPrintInt(js, size, start, end, val, comma)` | Print a JSON integer value |
| `SSFJsonPrintDouble(js, size, start, end, val, comma)` | Print a JSON float value (requires `ENABLE_FLOAT_GEN`) |
| `SSFJsonPrintBool(js, size, start, end, val, comma)` | Print a JSON boolean value |
| `SSFJsonPrintNull(js, size, start, end, comma)` | Print a JSON null value |
| `SSFJsonPrintHex(js, size, start, end, in, inLen, comma)` | Print binary data as a hex-encoded string |
| `SSFJsonUpdate(js, size, path, fn, in)` | Update or insert a field in an existing JSON string |

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

/* Get the value of a nested element */
path[0] = "obj";
path[1] = "name";
if (SSFJsonGetString(json2Str, (SSFCStrIn_t *)path, strOut, sizeof(strOut), NULL))
{
    printf("%s", strOut);
    /* Prints "value" */
}

/* Iterate over a nested array */
path[0] = "obj";
path[1] = "array";
path[2] = (char *)&idx;
for (idx = 0;; idx++)
{
    long si;
    if (SSFJsonGetInt(json2Str, (SSFCStrIn_t *)path, &si))
    {
        if (idx != 0) printf(", ");
        printf("%ld", si);
    }
    else break;
}
/* Prints "1, 2, 3" */
```

### Generating

The generator uses a printer-callback pattern. Each call to `SSFJsonPrintObject()` or
`SSFJsonPrintArray()` invokes a user-supplied callback that writes fields into the buffer.

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

Object and array nesting is achieved by calling `SSFJsonPrintObject()` or `SSFJsonPrintArray()`
from within a printer function.

### Updating (requires `SSF_JSON_CONFIG_ENABLE_UPDATE == 1`)

`SSFJsonUpdate()` updates an existing field in a JSON string or inserts a new field if the
specified path does not exist. The replacement value is written by a printer callback using the
same signature as the generation callbacks above.

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- Path arrays must be fully zeroed before use (e.g., with `memset(path, 0, sizeof(path))`).
- For array index access, set a path element to point to a `size_t` index variable.
- Top-level arrays are supported; start the path with an index pointer.
- Each `{` or `[` level of nesting consumes stack. Keep nesting within `SSF_JSON_CONFIG_MAX_IN_DEPTH`.
- If unit tests fail unexpectedly on a new port, try increasing the system stack size.
