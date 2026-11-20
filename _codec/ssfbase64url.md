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
- [`ssfcrypt`](../_crypto/ssfcrypt.md) — `SSFCryptSecureZero()` to scrub the decoder's stack
  scratch buffer

<a id="notes"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) Notes

- The input, output, and length pointers must all be non-`NULL` for both functions; passing
  `NULL` asserts. Unlike [`SSFBase64Encode()`](ssfbase64.md#ssfbase64encode), `outStrLen` is
  **required** on encode.
- `outStrSize` must be at least `1` for [`SSFBase64URLEncode()`](#ssfbase64urlencode) so the null
  terminator always has a home; `0` asserts rather than returning `false`.
- **Encode output is unpadded.** [`SSFBase64URLEncode()`](#ssfbase64urlencode) produces the
  standard Base64 encoding, then substitutes `+` → `-`, `/` → `_`, and removes trailing `=`. The
  result is always null-terminated. Because the padded form is produced first, `outStrSize` must
  still be large enough for the padded encoding: `((inLen + 2) / 3) * 4 + 1` bytes.
- **Encode failure leaves nothing behind.** When [`SSFBase64URLEncode()`](#ssfbase64urlencode)
  returns `false`, `*outStrLen` is `0` and all `outStrSize` bytes of `outStr` have been zeroed, so
  `outStr` is the empty string. Without this a caller that ignored the return value could pick up
  the partially written *standard* Base64 intermediate, complete with `+`, `/`, and `=`.
- **Decode is strict.** [`SSFBase64URLDecode()`](#ssfbase64urldecode) accepts either fully
  padded or fully unpadded input (RFC 4648 §3.2), but returns `false` for: any character outside
  the §5 alphabet (including `+` and `/`, §3.3); `=` anywhere other than the final block
  (§3.3 / §4); partially padded input, i.e. any `=` present when `inStrLen` is not already a
  multiple of 4; non-canonical encodings whose final-quantum low bits are not zero (§3.5); and
  inputs whose length after re-padding is not a multiple of 4.
- **Decode input length is bounded.** The decoder re-pads into an on-stack buffer of
  [`SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN`](#cfg-max-encoded-len) bytes. Inputs with
  `inStrLen >= SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 4` are rejected with `false` before any
  processing. Size the option for the longest token segment the application must decode.
- Decoded output never exceeds `(inStrLen * 3) / 4` bytes; `outSize` smaller than the decoded
  length returns `false`.
- **Failure leaves nothing behind.** Whenever [`SSFBase64URLDecode()`](#ssfbase64urldecode)
  returns `false`, `*outLen` is `0` and any bytes already written to `out` have been zeroed, so a
  caller that reads `*outLen` without checking the return value cannot consume a partial result.
- **Stack scratch is scrubbed.** Base64URL is the encoding of JWK private keys and JWS / HMAC
  secrets, so the re-padded stack copy is cleared with `SSFCryptSecureZero()` before return on
  every path that writes it, and a failed encode clears its output buffer the same way. Note that the underlying [`ssfbase64`](ssfbase64.md) alphabet lookup
  is not constant-time; decode timing can depend on the character values being processed.

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
| [e.g.](#ex-encode) | [`bool SSFBase64URLEncode(in, inLen, outStr, outStrSize, outStrLen)`](#ssfbase64urlencode) | Encode binary data to an unpadded Base64URL string |
| [e.g.](#ex-decode) | [`bool SSFBase64URLDecode(inStr, inStrLen, out, outSize, outLen)`](#ssfbase64urldecode) | Strictly decode a padded or unpadded Base64URL string to binary |

<a id="function-reference"></a>

## [↑](#ssfbase64url--base64url-encoderdecoder) Function Reference

<a id="ssfbase64urlencode"></a>

### [↑](#ssfbase64url--base64url-encoderdecoder) [`bool SSFBase64URLEncode()`](#functions)

```c
bool SSFBase64URLEncode(const uint8_t *in, size_t inLen,
                        SSFCStrOut_t outStr, size_t outStrSize, size_t *outStrLen);
```

Encodes a binary byte array as a null-terminated Base64URL string using the RFC 4648 §5 alphabet
with `=` padding removed (the RFC 7515 JWT convention).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the binary data to encode. Must not be `NULL`. |
| `inLen` | in | `size_t` | Number of bytes to encode from `in`. |
| `outStr` | out | `SSFCStrOut_t` | Output buffer that receives the null-terminated Base64URL string. Must not be `NULL`. |
| `outStrSize` | in | `size_t` | Total allocated size of `outStr` in bytes. Must be greater than `0` (asserts otherwise) and at least `((inLen + 2) / 3) * 4 + 1` for the encode to succeed, because the padded form is produced before padding is stripped. |
| `outStrLen` | out | `size_t *` | Receives the number of characters written, excluding the null terminator, or `0` on failure. Must not be `NULL`. |

**Returns:** `true` if encoding succeeded; `false` if `outStrSize` is too small to hold the padded
intermediate result. On `false`, `*outStrLen` is `0` and `outStr` has been zeroed over its full
`outStrSize`, leaving an empty string.

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
bool SSFBase64URLDecode(SSFCStrIn_t inStr, size_t inStrLen,
                        uint8_t *out, size_t outSize, size_t *outLen);
```

Decodes a Base64URL string to binary bytes. Padding is optional on input: the function re-pads to
a multiple of 4 internally, maps `-` → `+` and `_` → `/`, then runs the strict standard
[`SSFBase64Decode()`](ssfbase64.md#ssfbase64decode).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `inStr` | in | `SSFCStrIn_t` | Pointer to the Base64URL string to decode. Must not be `NULL`. Need not be null-terminated. |
| `inStrLen` | in | `size_t` | Number of input characters to decode. Must be less than `SSF_BASE64URL_CONFIG_MAX_ENCODED_LEN - 4`. |
| `out` | out | `uint8_t *` | Output buffer that receives the decoded binary data. Must not be `NULL`. |
| `outSize` | in | `size_t` | Total allocated size of `out` in bytes. Must be sufficient to hold all decoded output. |
| `outLen` | out | `size_t *` | Receives the number of decoded bytes written to `out`. Must not be `NULL`. |

**Returns:** `true` if decoding succeeded; `false` if `inStrLen` exceeds the configured bound, the
input contains `+`, `/`, or any other character outside the §5 alphabet, padding is present but
incomplete, the encoding is non-canonical, the re-padded length is not a multiple of 4, or
`outSize` is too small. On `false`, `*outLen` is `0` and any partially decoded bytes in `out` have
been zeroed.

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
