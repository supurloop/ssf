# ssfhex — Binary to Hex ASCII Encoder/Decoder

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Binary to hexadecimal ASCII string encoder/decoder with optional byte-order reversal.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFHexBytesToBin(in, inLen, out, outSize, outLen, reversed)` | Decode hex ASCII string to binary |
| `SSFHexBinToBytes(in, inLen, out, outSize, outLen, reversed, caseMode)` | Encode binary to hex ASCII string |
| `SSF_HEX_CASE_LOWER` | Constant: emit lowercase hex digits |
| `SSF_HEX_CASE_UPPER` | Constant: emit uppercase hex digits |

## Usage

This interface encodes a binary data stream into an ASCII hexadecimal string, or decodes one back
to binary. Setting `reversed` to `true` reverses the byte order during the operation, which is
useful when working with little-endian multi-byte values.

```c
uint8_t binOut[2];
char strOut[5];
size_t binLen;

if (SSFHexBytesToBin("A1F5", 4, binOut, sizeof(binOut), &binLen, false))
{
    /* binLen == 2 */
    /* binOut[0] = '\xA1' */
    /* binOut[1] = '\xF5' */
}

if (SSFHexBinToBytes(binOut, binLen, strOut, sizeof(strOut), NULL, false, SSF_HEX_CASE_LOWER))
{
    printf("%s", strOut);
    /* prints "a1f5" */
}
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Both functions return `false` if the output buffer is too small.
- Passing `NULL` for `outLen` is valid when the encoded length is not needed.
- Decoding is case-insensitive; both `A1F5` and `a1f5` are accepted.
