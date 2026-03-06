# ssfhex — Binary-to-Hex ASCII Encoder/Decoder

[SSF](../README.md) | [Codecs](README.md)

Encodes binary bytes to hexadecimal ASCII strings and decodes them back, with optional
byte-order reversal for little-endian multi-byte values.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)

<a id="notes"></a>

## [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) Notes

- `out` must not be `NULL` for all functions; passing `NULL` asserts.
- [`SSFHexBinToByte()`](#ssfhexbintobyte) returns `false` if `outSize < 2`. With `outSize == 2`
  it writes 2 hex characters but **no null terminator**; pass `outSize >= 3` for a
  null-terminated C string.
- `hex` and `out` must not be `NULL` for [`SSFHexByteToBin()`](#ssfhexbytetobin); both assert.
- `in` and `out` must not be `NULL` for [`SSFHexBytesToBin()`](#ssfhexbytestobin); both assert.
- `outLen` is **required** (not optional) for [`SSFHexBytesToBin()`](#ssfhexbytestobin); passing
  `NULL` asserts.
- `inLenLim` must be even for [`SSFHexBytesToBin()`](#ssfhexbytestobin); returns `false`
  immediately if odd.
- `in` must not be `NULL` for [`SSFHexBinToBytes()`](#ssfhexbintobytes); passing `NULL` asserts.
- `outSize >= 1` is required for [`SSFHexBinToBytes()`](#ssfhexbintobytes); asserts otherwise.
- `outLen` is optional (may be `NULL`) for [`SSFHexBinToBytes()`](#ssfhexbintobytes) when the
  encoded length is not needed.
- Decoding ([`SSFHexBytesToBin()`](#ssfhexbytestobin), [`SSFHexByteToBin()`](#ssfhexbytetobin))
  is case-insensitive; both `A1F5` and `a1f5` are accepted.

<a id="configuration"></a>

## [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

<a id="api-summary"></a>

## [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssfhexcase-t"></a>`SSFHexCase_t` | Enum | Output digit case: `SSF_HEX_CASE_LOWER` emits `a–f`; `SSF_HEX_CASE_UPPER` emits `A–F` |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-bintobyte) | [`bool SSFHexBinToByte(in, out, outSize, hcase)`](#ssfhexbintobyte) | Encode one byte to a 2-character hex string |
| [e.g.](#ex-bytetobin) | [`bool SSFHexByteToBin(hex, out)`](#ssfhexbytetobin) | Decode 2 hex characters to one byte |
| [e.g.](#ex-bytestobin) | [`bool SSFHexBytesToBin(in, inLenLim, out, outSize, outLen, rev)`](#ssfhexbytestobin) | Decode hex ASCII string to binary |
| [e.g.](#ex-bintobytes) | [`bool SSFHexBinToBytes(in, inLen, out, outSize, outLen, rev, hcase)`](#ssfhexbintobytes) | Encode binary to hex ASCII string |
| [e.g.](#ex-macro-ishex) | [`bool SSFIsHex(h)`](#ssf-is-hex) | Macro: true if `h` is a valid hex digit |

<a id="function-reference"></a>

## [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) Function Reference

<a id="ssfhexbintobyte"></a>

### [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) [`bool SSFHexBinToByte()`](#functions)

```c
bool SSFHexBinToByte(uint8_t in, char *out, size_t outSize, SSFHexCase_t hcase);
```

Converts one binary byte to a 2-character hexadecimal string. If `outSize >= 3`, also writes a
null terminator; with `outSize == 2` the output is not null-terminated.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `uint8_t` | Binary byte to convert (0–255). |
| `out` | out | `char *` | Output buffer. Must not be `NULL`. Pass `outSize >= 3` for a null-terminated result. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be at least `2`. |
| `hcase` | in | [`SSFHexCase_t`](#type-ssfhexcase-t) | `SSF_HEX_CASE_LOWER` for `a–f`; `SSF_HEX_CASE_UPPER` for `A–F`. |

**Returns:** `true` if conversion succeeded; `false` if `outSize < 2`.

<a id="ex-bintobyte"></a>

```c
char out[3];

if (SSFHexBinToByte(0xA5u, out, sizeof(out), SSF_HEX_CASE_UPPER))
{
    /* out == "A5" */
}
```

---

<a id="ssfhexbytetobin"></a>

### [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) [`bool SSFHexByteToBin()`](#functions)

```c
bool SSFHexByteToBin(const char *hex, uint8_t *out);
```

Converts exactly 2 consecutive hex ASCII characters to one binary byte. Case-insensitive.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hex` | in | `const char *` | Pointer to exactly 2 hex characters (`0–9`, `a–f`, `A–F`). Must not be `NULL`. |
| `out` | out | `uint8_t *` | Receives the decoded byte. Must not be `NULL`. |

**Returns:** `true` if both characters are valid hex digits; `false` otherwise.

<a id="ex-bytetobin"></a>

```c
uint8_t out;

if (SSFHexByteToBin("A5", &out))
{
    /* out == 0xA5 */
}
```

---

<a id="ssfhexbytestobin"></a>

### [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) [`bool SSFHexBytesToBin()`](#functions)

```c
bool SSFHexBytesToBin(SSFCStrIn_t in, size_t inLenLim,
                      uint8_t *out, size_t outSize, size_t *outLen, bool rev);
```

Decodes a hexadecimal ASCII string into binary bytes. `inLenLim` must be even; an odd value
returns `false` immediately. Optionally reverses the byte order of the output.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `SSFCStrIn_t` | Pointer to the hex ASCII string. Must not be `NULL`. Must contain only valid hex characters. |
| `inLenLim` | in | `size_t` | Number of input hex characters to decode. Must be even. Must be `<= strlen(in)`. |
| `out` | out | `uint8_t *` | Output buffer receiving decoded bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be at least `inLenLim / 2`. |
| `outLen` | out | `size_t *` | Receives the number of bytes written to `out`. Must not be `NULL`. |
| `rev` | in | `bool` | `true` to decode the hex string in reverse byte order; `false` to preserve order. |

**Returns:** `true` if decoding succeeded; `false` if `inLenLim` is odd, any input character is
not a valid hex digit, or `outSize` is too small.

<a id="ex-bytestobin"></a>

```c
uint8_t out[2];
size_t outLen;

if (SSFHexBytesToBin("A5F0", 4u, out, sizeof(out), &outLen, false))
{
    /* outLen == 2, out[0] == 0xA5, out[1] == 0xF0 */
}
```

---

<a id="ssfhexbintobytes"></a>

### [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) [`bool SSFHexBinToBytes()`](#functions)

```c
bool SSFHexBinToBytes(const uint8_t *in, size_t inLen,
                      SSFCStrOut_t out, size_t outSize, size_t *outLen,
                      bool rev, SSFHexCase_t hcase);
```

Encodes binary bytes as a null-terminated hexadecimal ASCII string. Optionally reverses the
byte order of the input before encoding.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the bytes to encode. Must not be `NULL`. |
| `inLen` | in | `size_t` | Number of bytes to encode from `in`. |
| `out` | out | `SSFCStrOut_t` | Output buffer receiving the null-terminated hex string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be `>= 1`. Must be at least `(inLen * 2) + 1` to hold the full result. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of hex characters written, excluding the null terminator. |
| `rev` | in | `bool` | `true` to encode bytes in reverse order; `false` to preserve order. |
| `hcase` | in | [`SSFHexCase_t`](#type-ssfhexcase-t) | `SSF_HEX_CASE_LOWER` for `a–f`; `SSF_HEX_CASE_UPPER` for `A–F`. |

**Returns:** `true` if encoding succeeded; `false` if `outSize` is too small to hold the result.

<a id="ex-bintobytes"></a>

```c
uint8_t bin[] = {0xA5u, 0xF0u};
char out[5];
size_t outLen;

if (SSFHexBinToBytes(bin, sizeof(bin), out, sizeof(out), &outLen, false, SSF_HEX_CASE_LOWER))
{
    /* outLen == 4, out == "a5f0" */
}
```

---

<a id="convenience-macros"></a>

### [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) [Convenience Macros](#ex-macro-ishex)

---

<a id="ssf-is-hex"></a>

#### [↑](#ssfhex--binary-to-hex-ascii-encoderdecoder) [`bool SSFIsHex()`](#functions)

```c
#define SSFIsHex(h)
```

Evaluates to `true` if character `h` is a valid hexadecimal digit (`0–9`, `a–f`, or `A–F`).
`h` is evaluated exactly once.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `h` | in | `char` | Character to test. |

**Returns:** Non-zero (true) if `h` is a hex digit; zero (false) otherwise.

<a id="ex-macro-ishex"></a>

```c
SSFIsHex('A');    /* returns true  */
SSFIsHex('f');    /* returns true  */
SSFIsHex('3');    /* returns true  */
SSFIsHex('g');    /* returns false */
SSFIsHex(' ');    /* returns false */
```

