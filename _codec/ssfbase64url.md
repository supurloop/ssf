# ssfbase64url — Base64URL Encoder/Decoder

[SSF](../README.md) | [Codecs](README.md)

Encodes binary data as a URL- and filename-safe Base64 string per RFC 4648 §5 (alphabet `A–Z`,
`a–z`, `0–9`, `-`, `_`) with `=` padding stripped, and strictly decodes it back to binary. This is
the encoding used by JWS / JWT (RFC 7515) and other web token formats.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfbase64`](ssfbase64.md) — the standard Base64 codec this module wraps

<a id="notes"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) Notes

- `in`, `out`, and `outLen` must all be non-`NULL` for both functions; passing `NULL` asserts.
  Unlike [`SSFBase64Encode()`](ssfbase64.md#ssfbase64encode), `outLen` is **required** on encode.
- **Encode output is unpadded.** [`SSFBase64URLEncode()`](#ssfbase64urlencode) produces the
  standard Base64 encoding, then substitutes `+` → `-`, `/` → `_`, and removes trailing `=`. The
  result is always null-terminated. Because the padded form is produced first, `outSize` must still
  be large enough for the padded encoding: `((inLen + 2) / 3) * 4 + 1` bytes.
- **Decode is strict.** [`SSFBase64URLDecode()`](#ssfbase64urldecode) accepts both padded and
  unpadded input (RFC 4648 §3.2), but returns `false` for: any character outside the §5 alphabet
  (including `+` and `/`, §3.3); non-canonical encodings whose final-quantum low bits are not zero
  (§3.5); and inputs whose length after re-padding is not a multiple of 4.
- **Decode input length is bounded.** The decoder re-pads into an on-stack buffer of
  [`SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN`](#cfg-max-encoded-len) bytes. Inputs with
  `inLen >= SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 4` are rejected with `false` before any
  processing. Size the option for the longest token segment the application must decode.
- Decoded output never exceeds `(inLen * 3) / 4` bytes; `outSize` smaller than the decoded length
  returns `false`.

<a id="configuration"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) Configuration

Options live in [`_opt/ssfbase64url_opt.h`](../_opt/ssfbase64url_opt.h).

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="cfg-max-encoded-len"></a>`SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN` | `1024` | Size in bytes of the stack scratch buffer [`SSFBase64URLDecode()`](#ssfbase64urldecode) uses to re-pad its input. Bounds the longest decodable Base64URL string to `SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 5` characters. Must be at least `8`; smaller values fail at compile time. Directly sets the decoder's peak stack usage. |

The unit-test entry point is gated by `SSF_CONFIG_BASE64URL_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) API Summary

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-encode) | [`bool SSFBase64URLEncode(in, inLen, out, outSize, outLen)`](#ssfbase64urlencode) | Encode binary data to an unpadded Base64URL string |
| [e.g.](#ex-decode) | [`bool SSFBase64URLDecode(in, inLen, out, outSize, outLen)`](#ssfbase64urldecode) | Strictly decode a padded or unpadded Base64URL string to binary |

<a id="function-reference"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) Function Reference

<a id="ssfbase64urlencode"></a>

### [↑](#ssfbase64url--base64url-encoderdecoder) [`bool SSFBase64URLEncode()`](#functions)

```c
bool SSFBase64URLEncode(const uint8_t *in, size_t inLen,
                        SSFCStrOut_t out, size_t outSize, size_t *outLen);
```

Encodes a binary byte array as a null-terminated Base64URL string using the RFC 4648 §5 alphabet
with `=` padding removed (the RFC 7515 JWT convention).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the binary data to encode. Must not be `NULL`. |
| `inLen` | in | `size_t` | Number of bytes to encode from `in`. |
| `out` | out | `SSFCStrOut_t` | Output buffer that receives the null-terminated Base64URL string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `out` in bytes. Must be at least `((inLen + 2) / 3) * 4 + 1` because the padded form is produced before padding is stripped. |
| `outLen` | out | `size_t *` | Receives the number of characters written, excluding the null terminator. Must not be `NULL`. |

**Returns:** `true` if encoding succeeded; `false` if `outSize` is too small to hold the padded
intermediate result.

<a id="ex-encode"></a>

```c
uint8_t bin[] = {0xfbu, 0xffu};
char out[5];
size_t outLen;

if (SSFBase64URLEncode(bin, sizeof(bin), out, sizeof(out), &outLen))
{
    /* out == "-_8", outLen == 3  (standard Base64 would be "+/8=") */
}
```

---

<a id="ssfbase64urldecode"></a>

### [↑](#ssfbase64url--base64url-encoderdecoder) [`bool SSFBase64URLDecode()`](#functions)

```c
bool SSFBase64URLDecode(SSFCStrIn_t in, size_t inLen,
                        uint8_t *out, size_t outSize, size_t *outLen);
```

Decodes a Base64URL string to binary bytes. Padding is optional on input: the function re-pads to
a multiple of 4 internally, maps `-` → `+` and `_` → `/`, then runs the strict standard
[`SSFBase64Decode()`](ssfbase64.md#ssfbase64decode).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `SSFCStrIn_t` | Pointer to the Base64URL string to decode. Must not be `NULL`. Need not be null-terminated. |
| `inLen` | in | `size_t` | Number of input characters to decode. Must be less than `SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 4`. |
| `out` | out | `uint8_t *` | Output buffer that receives the decoded binary data. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `out` in bytes. Must be sufficient to hold all decoded output. |
| `outLen` | out | `size_t *` | Receives the number of decoded bytes written to `out`. Must not be `NULL`. |

**Returns:** `true` if decoding succeeded; `false` if `inLen` exceeds the configured bound, the
input contains `+`, `/`, or any other character outside the §5 alphabet, the encoding is
non-canonical, the re-padded length is not a multiple of 4, or `outSize` is too small.

<a id="ex-decode"></a>

```c
uint8_t out[2];
size_t outLen;

if (SSFBase64URLDecode("-_8", 3u, out, sizeof(out), &outLen))
{
    /* outLen == 2, out[0..1] == {0xfb, 0xff} */
}

/* Padded input is accepted too: */
if (SSFBase64URLDecode("-_8=", 4u, out, sizeof(out), &outLen)) { /* same result */ }

/* Standard-alphabet input is rejected: */
if (!SSFBase64URLDecode("+/8", 3u, out, sizeof(out), &outLen)) { /* false */ }
```
