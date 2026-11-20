# ssfbase64 — Base64 Encoder/Decoder

[SSF](../README.md) | [Codecs](README.md)

Encodes binary data as printable ASCII and decodes it back to binary using the standard Base64
alphabet (`A–Z`, `a–z`, `0–9`, `+`, `/`) with `=` padding.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfbase64--base64-encoderdecoder) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfbase64--base64-encoderdecoder) Notes

- `in` must not be `NULL` for [`SSFBase64Encode()`](#ssfbase64encode); passing `NULL` asserts even
  when `inLen` is `0`.
- `outLen` must not be `NULL` for [`SSFBase64Decode()`](#ssfbase64decode); passing `NULL` asserts.
- `inLenLim` passed to [`SSFBase64Decode()`](#ssfbase64decode) must be a multiple of `4`; any
  other value returns `false` immediately.
- [`SSFBase64Decode()`](#ssfbase64decode) rejects non-canonical encodings (RFC 4648 Sec. 3.5):
  when the final quantum decodes to fewer than 3 bytes, the unused low bits of the last non-pad
  character must be zero. This guarantees that decode(encode(x)) == x for every x.
- On successful encode the output buffer is always null-terminated and padded to a multiple of 4
  characters with `=`.
- `outLenOpt` may be `NULL` for [`SSFBase64Encode()`](#ssfbase64encode) when the encoded length
  is not needed.

<a id="configuration"></a>

## [↑](#ssfbase64--base64-encoderdecoder) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfbase64--base64-encoderdecoder) API Summary

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-encode) | [`bool SSFBase64Encode(in, inLen, outStr, outSize, outLenOpt)`](#ssfbase64encode) | Encode binary data to a Base64 string |
| [e.g.](#ex-decode) | [`bool SSFBase64Decode(inStr, inLenLim, out, outSize, outLen)`](#ssfbase64decode) | Decode a Base64 string to binary data |

<a id="function-reference"></a>

## [↑](#ssfbase64--base64-encoderdecoder) Function Reference

<a id="ssfbase64encode"></a>

### [↑](#ssfbase64--base64-encoderdecoder) [`bool SSFBase64Encode()`](#functions)

```c
bool SSFBase64Encode(const uint8_t *in, size_t inLen,
                     SSFCStrOut_t outStr, size_t outSize, size_t *outLenOpt);
```

Encodes a binary byte array as a null-terminated Base64 string. Output length is always a
multiple of 4 characters padded with `=`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the binary data to encode. Must not be `NULL`. |
| `inLen` | in | `size_t` | Number of bytes to encode from `in`. |
| `outStr` | out | `SSFCStrOut_t` | Output buffer that receives the null-terminated Base64 string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `outStr` in bytes, including the null terminator. Must be at least `((inLen + 2) / 3) * 4 + 1`. |
| `outLenOpt` | out (opt) | `size_t *` | If not `NULL`, receives the number of Base64 characters written, excluding the null terminator. |

**Returns:** `true` if encoding succeeded; `false` if `outSize` is too small to hold the result.

<a id="ex-encode"></a>

```c
uint8_t bin[] = {0x01u, 0x02u, 0x03u};
char out[9];
size_t outLen;

if (SSFBase64Encode(bin, sizeof(bin), out, sizeof(out), &outLen))
{
    /* out == "AQID", outLen == 4 */
}
```

---

<a id="ssfbase64decode"></a>

### [↑](#ssfbase64--base64-encoderdecoder) [`bool SSFBase64Decode()`](#functions)

```c
bool SSFBase64Decode(SSFCStrIn_t inStr, size_t inLenLim,
                     uint8_t *out, size_t outSize, size_t *outLen);
```

Decodes a Base64-encoded string to binary bytes. `inLenLim` must be a multiple of `4`; any other
value returns `false` immediately.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `inStr` | in | `SSFCStrIn_t` | Pointer to the Base64 string to decode. Must not be `NULL`. |
| `inLenLim` | in | `size_t` | Number of input characters to decode. Must be a multiple of `4`. |
| `out` | out | `uint8_t *` | Output buffer that receives the decoded binary data. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `out` in bytes. Must be sufficient to hold all decoded output. |
| `outLen` | out | `size_t *` | Receives the number of decoded bytes written to `out`. Must not be `NULL`. |

**Returns:** `true` if decoding succeeded; `false` if `inLenLim` is not a multiple of `4`, the
input contains invalid Base64 characters, or `outSize` is too small.

<a id="ex-decode"></a>

```c
uint8_t out[3];
size_t outLen;

if (SSFBase64Decode("AQID", 4u, out, sizeof(out), &outLen))
{
    /* outLen == 3, out[0..2] == {0x01, 0x02, 0x03} */
}
```
