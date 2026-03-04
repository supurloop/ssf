# ssfbase64 — Base64 Encoder/Decoder

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Base64 encoding and decoding interface.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFBase64Encode(in, inLen, out, outSize, outLen)` | Encode binary data to a Base64 string |
| `SSFBase64Decode(in, inLen, out, outSize, outLen)` | Decode a Base64 string to binary data |

## Usage

This interface allows you to encode a binary data stream into a Base64 string, or decode one back
to binary. Both functions return `true` on success and `false` if the output buffer is too small.

```c
char encodedStr[16];
char decodedBin[16];
uint8_t binOut[2];
size_t binLen;

/* Encode arbitrary binary data */
if (SSFBase64Encode("a", 1, encodedStr, sizeof(encodedStr), NULL))
{
    /* Encode successful */
    printf("%s", encodedStr);
    /* output is "YQ==" */
}

/* Decode Base64 string into binary data */
if (SSFBase64Decode(encodedStr, strlen(encodedStr), decodedBin, sizeof(decodedBin), &binLen))
{
    /* Decode successful */
    /* binLen == 1 */
    /* decodedBin[0] == 'a' */
}
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Passing `NULL` for `outLen` is valid when the output length is not needed.
- Output strings are always null-terminated on successful encode.
