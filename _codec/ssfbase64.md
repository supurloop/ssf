# ssfbase64 — Base64 Encoder/Decoder

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Base64 encoding and decoding interface.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFBase64Encode(in, inLen, out, outSize, outLen)` | Encode binary data to a Base64 string |
| `SSFBase64Decode(in, inLenLim, out, outSize, outLen)` | Decode a Base64 string to binary data |

## Function Reference

### `SSFBase64Encode`

```c
bool SSFBase64Encode(const uint8_t *in, size_t inLen,
                     SSFCStrOut_t out, size_t outSize, size_t *outLen);
```

Encodes a binary byte array as a null-terminated Base64 string. The output length is always a
multiple of 4 characters (padded with `=`).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the binary data to encode. May be `NULL` only when `inLen` is `0`. |
| `inLen` | in | `size_t` | Number of bytes to encode from `in`. |
| `out` | out | `char *` | Output buffer that receives the null-terminated Base64 string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `out` in bytes, including space for the null terminator. Must be at least `((inLen + 2) / 3) * 4 + 1`. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of Base64 characters written (excluding null terminator). |

**Returns:** `true` if encoding succeeded; `false` if `outSize` is too small to hold the result.

---

### `SSFBase64Decode`

```c
bool SSFBase64Decode(SSFCStrIn_t in, size_t inLenLim,
                     uint8_t *out, size_t outSize, size_t *outLen);
```

Decodes a Base64-encoded string to binary bytes. The input is processed up to `inLenLim`
characters or the first null terminator, whichever comes first.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const char *` | Pointer to the null-terminated Base64 string to decode. Must not be `NULL`. Must contain only valid Base64 characters (`A-Z`, `a-z`, `0-9`, `+`, `/`, `=`). |
| `inLenLim` | in | `size_t` | Maximum number of input characters to read. Processing stops at this limit or the first null terminator, whichever is reached first. |
| `out` | out | `uint8_t *` | Output buffer that receives the decoded binary data. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `out` in bytes. Must be at least `(inLen / 4) * 3` bytes (before padding adjustment). |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of decoded binary bytes written to `out`. |

**Returns:** `true` if decoding succeeded; `false` if the input is not valid Base64 or `outSize` is too small.

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
