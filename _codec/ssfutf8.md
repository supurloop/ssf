# ssfutf8 — UTF-8 Codec

[SSF](../README.md) | [Codecs](README.md)

Strict UTF-8 (RFC 3629) validation, decoding and encoding over caller buffers, with no tables
and no state. Used by [`ssfx509`](ssfx509.md) to refuse Name values that are not UTF-8; also
the building block for checking MQTT strings (MQTT 3.1.1 section 1.5.3), WebSocket text
(RFC 6455 section 8.1) and decoding JSON `\uXXXX` escapes into UTF-8.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfutf8--utf-8-codec) Dependencies

- [`ssfport.h`](../ssfport.h)

<a id="notes"></a>

## [↑](#ssfutf8--utf-8-codec) Notes

- **Strict.** Only the well-formed byte sequences of RFC 3629 section 4 (Unicode Table 3-7) are
  accepted. Refused: a continuation byte (80..BF) where a character should start; the overlong
  leads C0 and C1; an overlong 3- or 4-byte form (E0 80..9F, F0 80..8F); a surrogate
  (ED A0..BF, U+D800..U+DFFF); a value above U+10FFFF (F4 90..BF, and F5..FF anywhere); a
  continuation byte outside 80..BF; a sequence cut off by the end of the input. CESU-8 and
  "modified UTF-8" (C0 80 for NUL) are refused too.
- **Lengths, not terminators.** Every function takes a pointer and a byte count and reads
  nothing past it. A NUL byte is data: [`SSFUTF8IsValid()`](#ssfutf8isvalid) refuses U+0000
  unless `allowNul` is `true`, which callers whose protocol forbids it (MQTT, X.509 Names
  stored as C strings) use to catch an embedded NUL.
- **Outputs are written only on success.** Every function returns `false` on failure and then
  leaves `*cpOut`, `*seqLenOut`, `*outLenOut`, `*countOut` and `out` as they were.
- **The encoder writes the shortest form only**, and refuses surrogates and values above
  U+10FFFF, so its output always passes [`SSFUTF8IsValid()`](#ssfutf8isvalid) and decodes back to
  the same code point.
- **UTF-16 pairs.** [`SSFUTF8FromUTF16Pair()`](#ssfutf8fromutf16pair) joins a high and a low
  surrogate (as in JSON `😀`) into one code point for
  [`SSFUTF8EncodeCP()`](#ssfutf8encodecp). A lone or reversed surrogate is refused; a JSON
  decoder should then treat the escape as an error.
- **Not constant-time.** Decoding branches on the bytes. The data this module handles (names,
  topics, text) is not secret.
- **Size.** About 550 to 620 bytes on Cortex-M (`-Os`, 553 B M4, 617 B M0+, including the
  17-byte file name the assertions use) and about 1 KB on PIC32 (XC32); no RAM or tables. Stack is at
  most 64 B (`SSFUTF8Count()` or `SSFUTF8IsValid()` calling `SSFUTF8DecodeNext()`). With
  `-ffunction-sections` and `--gc-sections`, a validator-only build
  ([`SSFUTF8DecodeNext()`](#ssfutf8decodenext) + [`SSFUTF8IsValid()`](#ssfutf8isvalid)) links
  about 285 B (M4) / 317 B (M0+).

<a id="configuration"></a>

## [↑](#ssfutf8--utf-8-codec) Configuration

No options file. The unit-test entry point is gated by `SSF_CONFIG_UTF8_UNIT_TEST` in
`ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfutf8--utf-8-codec) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-utf8-max-cp"></a>`SSF_UTF8_MAX_CP` | Constant | Largest Unicode code point, `0x10FFFF`. |
| <a id="ssf-utf8-max-seq-len"></a>`SSF_UTF8_MAX_SEQ_LEN` | Constant | Longest UTF-8 sequence, `4` bytes; enough output for any [`SSFUTF8EncodeCP()`](#ssfutf8encodecp) call. |

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-decodenext) | [`bool SSFUTF8DecodeNext(str, strLen, cpOut, seqLenOut)`](#ssfutf8decodenext) | Decode one code point |
| [e.g.](#ex-isvalid) | [`bool SSFUTF8IsValid(str, strLen, allowNul)`](#ssfutf8isvalid) | Check a whole string |
| [e.g.](#ex-encodecp) | [`bool SSFUTF8EncodeCP(cp, out, outSize, outLenOut)`](#ssfutf8encodecp) | Encode one code point |
| [e.g.](#ex-encodecp) | [`bool SSFUTF8FromUTF16Pair(hi, lo, cpOut)`](#ssfutf8fromutf16pair) | Join a UTF-16 surrogate pair |
| | [`bool SSFUTF8Count(str, strLen, countOut)`](#ssfutf8count) | Count the code points in a string |

<a id="function-reference"></a>

## [↑](#ssfutf8--utf-8-codec) Function Reference

<a id="ssfutf8decodenext"></a>

### [↑](#ssfutf8--utf-8-codec) [`bool SSFUTF8DecodeNext()`](#functions)

```c
bool SSFUTF8DecodeNext(const uint8_t *str, size_t strLen, uint32_t *cpOut, size_t *seqLenOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `str` | in | `const uint8_t *` | Input bytes. Must not be `NULL`. |
| `strLen` | in | `size_t` | Number of input bytes; nothing past it is read. |
| `cpOut` | out | `uint32_t *` | On success, the code point. Must not be `NULL`. |
| `seqLenOut` | out | `size_t *` | On success, the sequence length, 1..4. Must not be `NULL`. |

**Returns:** `true` if a well-formed sequence starts at `str`; `false` if `strLen` is `0` or the
sequence is ill formed or cut off, in which case `*cpOut` and `*seqLenOut` are not written.

<a id="ex-decodenext"></a>

```c
const uint8_t *p = text;
size_t left = textLen;
uint32_t cp;
size_t n;

while ((left > 0u) && SSFUTF8DecodeNext(p, left, &cp, &n))
{
    /* cp is the next character */
    p += n;
    left -= n;
}
if (left != 0u) { /* ill-formed UTF-8 at p */ }
```

---

<a id="ssfutf8isvalid"></a>

### [↑](#ssfutf8--utf-8-codec) [`bool SSFUTF8IsValid()`](#functions)

```c
bool SSFUTF8IsValid(const uint8_t *str, size_t strLen, bool allowNul);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `str` | in | `const uint8_t *` | Input bytes. Must not be `NULL`, even when `strLen` is `0`. |
| `strLen` | in | `size_t` | Number of input bytes. |
| `allowNul` | in | `bool` | `false` refuses any U+0000 (a `0x00` byte). |

**Returns:** `true` if all `strLen` bytes are well-formed UTF-8 (and, unless `allowNul`, contain
no NUL); `true` for `strLen == 0`.

<a id="ex-isvalid"></a>

```c
size_t idLen;

if (SSFStrLen(thingName, 129u, &idLen) &&
    SSFUTF8IsValid((const uint8_t *)thingName, idLen, false))
{
    /* thingName is valid text for an MQTT client id or an X.509 CN */
}
```

---

<a id="ssfutf8encodecp"></a>

### [↑](#ssfutf8--utf-8-codec) [`bool SSFUTF8EncodeCP()`](#functions)

```c
bool SSFUTF8EncodeCP(uint32_t cp, uint8_t *out, size_t outSize, size_t *outLenOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `cp` | in | `uint32_t` | Code point, 0..0x10FFFF excluding U+D800..U+DFFF. |
| `out` | out | `uint8_t *` | Receives the encoded bytes (no NUL). Must not be `NULL`. |
| `outSize` | in | `size_t` | Size of `out`; `SSF_UTF8_MAX_SEQ_LEN` is always enough. |
| `outLenOut` | out | `size_t *` | On success, the number of bytes written, 1..4. Must not be `NULL`. |

**Returns:** `true` if the shortest form of `cp` was written; `false` if `cp` is a surrogate or
above U+10FFFF, or `outSize` is too small, and then nothing is written.

---

<a id="ssfutf8fromutf16pair"></a>

### [↑](#ssfutf8--utf-8-codec) [`bool SSFUTF8FromUTF16Pair()`](#functions)

```c
bool SSFUTF8FromUTF16Pair(uint16_t hi, uint16_t lo, uint32_t *cpOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hi` | in | `uint16_t` | High (leading) surrogate, 0xD800..0xDBFF. |
| `lo` | in | `uint16_t` | Low (trailing) surrogate, 0xDC00..0xDFFF. |
| `cpOut` | out | `uint32_t *` | On success, the code point, 0x10000..0x10FFFF. Must not be `NULL`. |

**Returns:** `true` if `hi` and `lo` are a high then a low surrogate; else `false` and `*cpOut`
is not written.

<a id="ex-encodecp"></a>

```c
/* JSON "😀" after the two hex escapes are parsed */
uint32_t cp;
uint8_t utf8[SSF_UTF8_MAX_SEQ_LEN];
size_t n;

if (SSFUTF8FromUTF16Pair(0xD83Du, 0xDE00u, &cp) &&
    SSFUTF8EncodeCP(cp, utf8, sizeof(utf8), &n))
{
    /* utf8[0..n) is F0 9F 98 80, n == 4 */
}
```

---

<a id="ssfutf8count"></a>

### [↑](#ssfutf8--utf-8-codec) [`bool SSFUTF8Count()`](#functions)

```c
bool SSFUTF8Count(const uint8_t *str, size_t strLen, size_t *countOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `str` | in | `const uint8_t *` | Input bytes. Must not be `NULL`. |
| `strLen` | in | `size_t` | Number of input bytes. |
| `countOut` | out | `size_t *` | On success, the number of code points (a NUL counts as one). Must not be `NULL`. |

**Returns:** `true` if `str` is well-formed UTF-8; else `false` and `*countOut` is not written.
