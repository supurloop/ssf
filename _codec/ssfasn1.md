# ssfasn1 — ASN.1 DER Encoder/Decoder

[SSF](../README.md) | [Codecs](README.md)

ASN.1 DER (Distinguished Encoding Rules) encoder and decoder. Provides the primitives used
by [`ssfrsa`](../_crypto/ssfrsa.md) and [`ssfecdsa`](../_crypto/ssfecdsa.md) to read and
write PKCS#1 / SEC 1 / DER-formatted keys and signatures, plus standalone tag-class
constants and helpers for X.509 OPTIONAL / IMPLICIT / EXPLICIT context tagging.

The decoder is **zero-copy** — every Get function returns pointers directly into the input
buffer rather than allocating or memcpying. The encoder uses a **two-pass measure-then-write**
pattern: call with `buf == NULL` to compute the byte count needed, then again with a
correctly sized buffer to write.

[Dependencies](#dependencies) | [Limitations](#limitations) | [Tag Representation](#tag-representation) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfdtime`](../_time/ssfdtime.md) — date/time conversion used by the time encoders /
  decoders (`SSFASN1*Time`, `SSFASN1*Date`, `SSFASN1*DateTime`).

<a id="limitations"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) Limitations

- **Tag numbers 0–127 only.** Single-byte tag form covers numbers 0–30; the two-byte
  high-tag-number form (first byte's low five bits = `0x1F`, extension byte holds the
  number) covers 31–127. Tags requiring multi-byte extension (≥ 128) are not supported.
- **Definite-length only.** Indefinite-length encoding (BER) is not accepted by the
  decoder and never emitted by the encoder. DER is a strict subset and always uses
  definite length.
- **Maximum content length is `2^32 − 1` bytes.** Length fields use 1–5 bytes (short form
  + long form encodings 1–4); a 5-byte long form is the largest emitted.
- **OID arc decoding caps at [`SSF_ASN1_CONFIG_MAX_OID_ARCS`](#cfg-max-oid-arcs).** OIDs
  with more arcs are rejected by [`SSFASN1DecGetOID()`](#ssfasn1decgetoid). Use
  [`SSFASN1DecGetOIDRaw()`](#ssfasn1decgetoidraw) to read the raw DER bytes for any OID
  the consumer compares byte-for-byte against a known constant.

<a id="tag-representation"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) Tag Representation

ASN.1 tags are stored as `uint16_t`:

- **Bits 0–7** hold the first DER tag byte: class (top 2 bits) + primitive/constructed bit
  (bit 5) + tag number (low 5 bits, or `0x1F` to signal the two-byte high-tag form).
- **Bits 8–15** hold the extension byte for tag numbers 31–127. Single-byte tags carry `0`
  in this half.

So `SSF_ASN1_TAG_SEQUENCE == 0x0030` (single-byte: class universal `00` + constructed `1` +
number `0x10` = `0x30`). And `SSF_ASN1_TAG_DATE == 0x1F1F` (low byte `0x1F` = "high-tag
form follows"; high byte `0x1F` = the actual tag number 31).

Context-class tagged fields use the [`SSF_ASN1_CONTEXT_EXPLICIT(n)`](#api-summary) /
[`SSF_ASN1_CONTEXT_IMPLICIT(n)`](#api-summary) helper macros for `n` in `[0, 30]`. Numbers
≥ 31 require the caller to construct the two-byte form by hand (`(n << 8) | 0x9F` for
context-implicit constructed, etc.).

<a id="notes"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) Notes

- **Decoder is zero-copy.** Every Get function returns pointers directly into the caller's
  DER buffer; the caller must keep the input buffer alive for as long as the returned
  pointers are used. No internal allocation, no copy.
- **Cursors are immutable per-call inputs.** [`SSFASN1Cursor_t`](#type-cursor) holds
  `(buf, bufLen)`. Each decode call takes a `const SSFASN1Cursor_t *cursor` and writes a
  fresh advanced cursor to `*next`. The caller chains these together to walk a SEQUENCE
  or SET. Holding two cursors simultaneously (e.g., one inside an opened SEQUENCE and one
  for the parent) is the normal pattern.
- **All decoders return `bool`.** `false` is returned on any DER malformation: tag
  mismatch, length out-of-range, truncated buffer, invalid encoding (e.g., an INTEGER
  with non-minimal sign byte). On `false`, all output parameters are left undefined and
  `*next` is not advanced — the caller must treat the decode as having consumed nothing.
- **Encoders use the two-pass measure-then-write pattern.** Call any encoder with
  `buf == NULL` and `bufSize == 0` to compute the required byte count into `*bytesWritten`
  without writing. Then allocate / size a buffer and call again with `buf` non-`NULL`.
  When `buf == NULL`, no read of `buf` happens. The pattern allows precise sizing of
  multi-element constructions:

  ```c
  uint32_t inner1Len, inner2Len, total;
  SSFASN1EncIntU64(NULL, 0, 1234, &inner1Len);     /* measure */
  SSFASN1EncIntU64(NULL, 0, 5678, &inner2Len);     /* measure */
  SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE,
                   inner1Len + inner2Len, &total); /* sequence header */
  ```

- **`bytesWritten` is required.** Every encoder asserts that `bytesWritten != NULL`. On
  success it holds the number of bytes written (or, for the measure pass, the number of
  bytes that would be written). On failure it is set to `0`.
- **OID storage is caller-owned.** The arc decoder writes into a caller-supplied
  `uint32_t[]`, and the raw decoder returns a pointer into the source buffer. The encoder
  takes a raw DER OID body — there is no arc-array encoder. To encode an OID from arcs,
  build the raw bytes externally (the multi-arc base-128 encoding is standard) and pass
  to [`SSFASN1EncOIDRaw()`](#ssfasn1encoidraw).
- **Strings: any of six tag types are accepted on decode.**
  [`SSFASN1DecGetString()`](#ssfasn1decgetstring) accepts UTF-8, Printable, IA5, BMP, T61
  (TeletexString — legacy), and UniversalString tags per RFC 5280 §4.1.2.4 DirectoryString.
  The actual tag is returned via the optional `strTagOut` parameter so callers can
  re-encode in the same string type if needed. Encoders take an explicit tag.
- **Time / Date / DateTime decoders return Unix seconds.** UTCTime requires the X.509
  profile's exact `YYMMDDHHMMSSZ` form (13 bytes). GeneralizedTime accepts the X.509
  profile's `YYYYMMDDHHMMSSZ` form (15 bytes). DATE and DATE-TIME are the universal-31
  and universal-33 (newer) tags using `YYYY-MM-DD` and `YYYY-MM-DDTHH:MM:SS`. Pre-1970
  dates produce `false` — Unix epoch is the floor.
- **Constructed types use `OpenConstructed`.** [`SSFASN1DecOpenConstructed()`](#ssfasn1decopenconstructed)
  verifies the tag, returns an inner cursor scoped to the SEQUENCE / SET / context-tagged
  body, and a next-cursor scoped past the whole element. Use the inner cursor to walk the
  contents; use the next cursor to continue with the parent's siblings.
- **Tag class helpers compose by OR.** `SSF_ASN1_CLASS_CONTEXT | SSF_ASN1_CONSTRUCTED |
  n` is the standard form for an EXPLICIT context-tagged field with number `n`; the
  [`SSF_ASN1_CONTEXT_EXPLICIT(n)`](#api-summary) macro packages this. IMPLICIT context
  tagging drops the `CONSTRUCTED` bit when the underlying type is primitive — use
  [`SSF_ASN1_CONTEXT_IMPLICIT(n)`](#api-summary) and OR `SSF_ASN1_CONSTRUCTED` back in if
  the underlying type is itself constructed.

<a id="configuration"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) Configuration

Options live in [`_opt/ssfasn1_opt.h`](../_opt/ssfasn1_opt.h).

| Macro | Default | Description |
|-------|---------|-------------|
| <a id="cfg-max-oid-arcs"></a>`SSF_ASN1_CONFIG_MAX_OID_ARCS` | `12` | Maximum number of arcs the [`SSFASN1DecGetOID()`](#ssfasn1decgetoid) decoder will produce. The caller passes its own arc array; the function returns `false` if the OID would require more arcs than `oidArcsSize`. The macro is the upper bound the rest of the framework assumes when sizing intermediate buffers. |

The unit-test entry point is gated by `SSF_CONFIG_ASN1_UNIT_TEST` in `ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) API Summary

### Tag Constants

**Universal class, single-byte form (tag numbers 0–30):**

| Symbol | Value | Tag |
|--------|------:|-----|
| `SSF_ASN1_TAG_BOOLEAN` | `0x0001` | BOOLEAN |
| `SSF_ASN1_TAG_INTEGER` | `0x0002` | INTEGER |
| `SSF_ASN1_TAG_BIT_STRING` | `0x0003` | BIT STRING |
| `SSF_ASN1_TAG_OCTET_STRING` | `0x0004` | OCTET STRING |
| `SSF_ASN1_TAG_NULL` | `0x0005` | NULL |
| `SSF_ASN1_TAG_OID` | `0x0006` | OBJECT IDENTIFIER |
| `SSF_ASN1_TAG_UTF8_STRING` | `0x000C` | UTF8String |
| `SSF_ASN1_TAG_PRINTABLE_STRING` | `0x0013` | PrintableString |
| `SSF_ASN1_TAG_T61_STRING` | `0x0014` | TeletexString (legacy) |
| `SSF_ASN1_TAG_IA5_STRING` | `0x0016` | IA5String |
| `SSF_ASN1_TAG_UTC_TIME` | `0x0017` | UTCTime |
| `SSF_ASN1_TAG_GENERALIZED_TIME` | `0x0018` | GeneralizedTime |
| `SSF_ASN1_TAG_UNIVERSAL_STRING` | `0x001C` | UniversalString |
| `SSF_ASN1_TAG_BMP_STRING` | `0x001E` | BMPString |
| `SSF_ASN1_TAG_SEQUENCE` | `0x0030` | SEQUENCE / SEQUENCE OF (constructed) |
| `SSF_ASN1_TAG_SET` | `0x0031` | SET / SET OF (constructed) |

**Universal class, two-byte high-tag form (tag numbers ≥ 31):**

| Symbol | Value | Tag |
|--------|------:|-----|
| `SSF_ASN1_TAG_DATE` | `0x1F1F` | DATE (universal 31) |
| `SSF_ASN1_TAG_DATE_TIME` | `0x211F` | DATE-TIME (universal 33) |

**Class bits (apply to the first DER tag byte):**

| Symbol | Value | Class |
|--------|------:|-------|
| `SSF_ASN1_CLASS_UNIVERSAL` | `0x00` | Universal |
| `SSF_ASN1_CLASS_APPLICATION` | `0x40` | Application |
| `SSF_ASN1_CLASS_CONTEXT` | `0x80` | Context-specific |
| `SSF_ASN1_CLASS_PRIVATE` | `0xC0` | Private |
| `SSF_ASN1_CONSTRUCTED` | `0x20` | Constructed (vs. primitive) |

**Context-tag helper macros** (single-byte form; `n` in `[0, 30]`):

| Macro | Expansion | Use |
|-------|-----------|-----|
| `SSF_ASN1_CONTEXT_EXPLICIT(n)` | `0x80 \| 0x20 \| n` | EXPLICIT context-tagged field — wraps the underlying TLV. |
| `SSF_ASN1_CONTEXT_IMPLICIT(n)` | `0x80 \| n` | IMPLICIT context-tagged field — replaces the underlying primitive tag. OR `SSF_ASN1_CONSTRUCTED` when the underlying type is itself constructed. |

### Types

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-cursor"></a>`SSFASN1Cursor_t` | Struct | Zero-copy parse cursor: `{ const uint8_t *buf; uint32_t bufLen; }`. Pass by const pointer to every decode function. The function writes a freshly advanced cursor to its `*next` argument; the caller chains these to walk the buffer. |

<a id="functions-cursor"></a>

### Decoder — Cursor Operations

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-walk) | [`bool SSFASN1DecGetTLV(cursor, tagOut, valueOut, valueLenOut, next)`](#ssfasn1decgettlv) | Read tag + value pointer + value length; advance cursor past the whole TLV |
| [e.g.](#ex-walk) | [`bool SSFASN1DecOpenConstructed(cursor, expectedTag, inner, next)`](#ssfasn1decopenconstructed) | Verify tag and descend into a SEQUENCE / SET / context-tagged element |
| [e.g.](#ex-peek) | [`bool SSFASN1DecPeekTag(cursor, tagOut)`](#ssfasn1decpeektag) | Read the tag without advancing |
| [e.g.](#ex-skip) | [`bool SSFASN1DecSkip(cursor, next)`](#ssfasn1decskip) | Advance past one TLV without decoding its value |
| [e.g.](#ex-skip) | [`bool SSFASN1DecIsEmpty(cursor)`](#ssfasn1decisempty) | Returns true if the cursor has no remaining bytes |

<a id="functions-decode-prim"></a>

### Decoder — Primitive Types

| | Function | Description |
|---|----------|-------------|
| | [`bool SSFASN1DecGetBool(cursor, valOut, next)`](#ssfasn1decgetbool) | Decode BOOLEAN |
| | [`bool SSFASN1DecGetInt(cursor, intBufOut, intLenOut, next)`](#ssfasn1decgetint) | Decode INTEGER as a pointer into the source bytes |
| | [`bool SSFASN1DecGetIntU64(cursor, valOut, next)`](#ssfasn1decgetintu64) | Decode INTEGER as a `uint64_t` |
| | [`bool SSFASN1DecGetBitString(cursor, bitsOut, bitsLenOut, unusedBitsOut, next)`](#ssfasn1decgetbitstring) | Decode BIT STRING — pointer + length + unused-bit count |
| | [`bool SSFASN1DecGetOctetString(cursor, octetsOut, octetsLenOut, next)`](#ssfasn1decgetoctetstring) | Decode OCTET STRING |
| | [`bool SSFASN1DecGetNull(cursor, next)`](#ssfasn1decgetnull) | Decode NULL |
| [e.g.](#ex-oid) | [`bool SSFASN1DecGetOID(cursor, oidArcsOut, oidArcsSize, oidArcsLenOut, next)`](#ssfasn1decgetoid) | Decode OID into an arc array |
| | [`bool SSFASN1DecGetOIDRaw(cursor, oidRawOut, oidRawLenOut, next)`](#ssfasn1decgetoidraw) | Get OID body bytes for byte-level comparison |
| [e.g.](#ex-string) | [`bool SSFASN1DecGetString(cursor, strOut, strLenOut, strTagOut, next)`](#ssfasn1decgetstring) | Decode any of the six DirectoryString variants |
| [e.g.](#ex-time) | [`bool SSFASN1DecGetTime(cursor, unixSecOut, next)`](#ssfasn1decgettime) | Decode UTCTime or GeneralizedTime → Unix seconds |
| | [`bool SSFASN1DecGetDate(cursor, unixSecOut, next)`](#ssfasn1decgetdate) | Decode DATE (universal 31) → Unix seconds at midnight UTC |
| | [`bool SSFASN1DecGetDateTime(cursor, unixSecOut, next)`](#ssfasn1decgetdatetime) | Decode DATE-TIME (universal 33) → Unix seconds |

<a id="functions-encode"></a>

### Encoder

All encoders return `true` on success and write the byte count to `*bytesWritten`. Pass
`buf == NULL`, `bufSize == 0` to measure without writing.

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-encode) | [`bool SSFASN1EncTagLen(buf, bufSize, tag, contentLen, bytesWritten)`](#ssfasn1enctaglen) | Emit just the T+L bytes; caller writes the V separately |
| | [`bool SSFASN1EncBool(buf, bufSize, val, bytesWritten)`](#ssfasn1encbool) | Encode BOOLEAN |
| | [`bool SSFASN1EncInt(buf, bufSize, intBuf, intLen, bytesWritten)`](#ssfasn1encint) | Encode INTEGER from raw bytes |
| | [`bool SSFASN1EncIntU64(buf, bufSize, val, bytesWritten)`](#ssfasn1encintu64) | Encode INTEGER from a `uint64_t` |
| | [`bool SSFASN1EncBitString(buf, bufSize, bits, bitsLen, unusedBits, bytesWritten)`](#ssfasn1encbitstring) | Encode BIT STRING |
| | [`bool SSFASN1EncOctetString(buf, bufSize, octets, octetsLen, bytesWritten)`](#ssfasn1encoctetstring) | Encode OCTET STRING |
| | [`bool SSFASN1EncNull(buf, bufSize, bytesWritten)`](#ssfasn1encnull) | Encode NULL |
| | [`bool SSFASN1EncOIDRaw(buf, bufSize, oidRaw, oidRawLen, bytesWritten)`](#ssfasn1encoidraw) | Encode OID from raw DER body bytes |
| | [`bool SSFASN1EncString(buf, bufSize, strTag, str, strLen, bytesWritten)`](#ssfasn1encstring) | Encode any of the six string variants |
| | [`bool SSFASN1EncUTCTime(buf, bufSize, unixSec, bytesWritten)`](#ssfasn1encutctime) | Encode UTCTime from Unix seconds |
| | [`bool SSFASN1EncGeneralizedTime(buf, bufSize, unixSec, bytesWritten)`](#ssfasn1encgeneralizedtime) | Encode GeneralizedTime from Unix seconds |
| | [`bool SSFASN1EncDate(buf, bufSize, unixSec, bytesWritten)`](#ssfasn1encdate) | Encode DATE (universal 31) — sub-day truncated to midnight UTC |
| | [`bool SSFASN1EncDateTime(buf, bufSize, unixSec, bytesWritten)`](#ssfasn1encdatetime) | Encode DATE-TIME (universal 33) UTC |
| [e.g.](#ex-encode) | [`bool SSFASN1EncWrap(buf, bufSize, tag, content, contentLen, bytesWritten)`](#ssfasn1encwrap) | Wrap an already-encoded inner blob with a constructed-type T+L header |

<a id="function-reference"></a>

## [↑](#ssfasn1--asn1-der-encoderdecoder) Function Reference

<a id="cursor-operations"></a>

### [↑](#functions-cursor) Cursor Operations

<a id="ssfasn1decgettlv"></a>
```c
bool SSFASN1DecGetTLV(const SSFASN1Cursor_t *cursor, uint16_t *tagOut,
                      const uint8_t **valueOut, uint32_t *valueLenOut,
                      SSFASN1Cursor_t *next);
```
Reads the tag, value pointer, and value length of the TLV at `cursor`. Writes a fresh
cursor pointing past the entire TLV to `*next`. Returns `false` on malformed DER (truncated
buffer, length out of range). The returned `*valueOut` points into the source buffer; do
not write through it and keep the buffer alive while it is used.

<a id="ssfasn1decopenconstructed"></a>
```c
bool SSFASN1DecOpenConstructed(const SSFASN1Cursor_t *cursor, uint16_t expectedTag,
                               SSFASN1Cursor_t *inner, SSFASN1Cursor_t *next);
```
Verifies the cursor's current TLV has tag `expectedTag` (typically `SSF_ASN1_TAG_SEQUENCE`,
`SSF_ASN1_TAG_SET`, or a context-tagged constructed value) and writes two cursors:

- `*inner` is scoped to the body of the constructed element (use this to walk its
  children).
- `*next` is scoped past the entire element (use this to continue with the constructed
  element's siblings).

Returns `false` if the tag doesn't match, the encoded length runs off the end, or the
element is primitive instead of constructed.

<a id="ssfasn1decpeektag"></a>
```c
bool SSFASN1DecPeekTag(const SSFASN1Cursor_t *cursor, uint16_t *tagOut);
```
Reads the tag at the cursor's current position without advancing. Useful for
OPTIONAL-field branching: peek the tag, decide which decoder to call. Returns `false` if
the cursor is empty.

<a id="ex-peek"></a>

**Example (peek for OPTIONAL field):**

```c
uint16_t tag;
SSFASN1Cursor_t next;

if (SSFASN1DecPeekTag(&inner, &tag) && tag == SSF_ASN1_CONTEXT_EXPLICIT(0))
{
    /* OPTIONAL [0] field present — decode it */
}
else
{
    /* skip; field was omitted */
}
```

<a id="ssfasn1decskip"></a>
```c
bool SSFASN1DecSkip(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next);
```
Advances `cursor` past one entire TLV without decoding its value. Equivalent to
[`SSFASN1DecGetTLV()`](#ssfasn1decgettlv) discarding the outputs, but cheaper. Returns
`false` on malformed DER.

<a id="ssfasn1decisempty"></a>
```c
bool SSFASN1DecIsEmpty(const SSFASN1Cursor_t *cursor);
```
Returns `true` when `cursor->bufLen == 0` — i.e., the cursor has no remaining bytes to
parse. Use this to terminate a SEQUENCE-walking loop.

<a id="ex-walk"></a>

**Example (walk a SEQUENCE):**

```c
SSFASN1Cursor_t doc = { derBuf, derLen };
SSFASN1Cursor_t inner, next;

/* Open the outer SEQUENCE */
if (!SSFASN1DecOpenConstructed(&doc, SSF_ASN1_TAG_SEQUENCE, &inner, &next)) return false;

/* Walk its children */
while (!SSFASN1DecIsEmpty(&inner))
{
    uint16_t tag;
    if (!SSFASN1DecPeekTag(&inner, &tag)) return false;

    switch (tag)
    {
        case SSF_ASN1_TAG_INTEGER:
        {
            uint64_t v;
            if (!SSFASN1DecGetIntU64(&inner, &v, &next)) return false;
            inner = next;
            break;
        }
        case SSF_ASN1_TAG_OCTET_STRING:
        {
            const uint8_t *p; uint32_t n;
            if (!SSFASN1DecGetOctetString(&inner, &p, &n, &next)) return false;
            inner = next;
            break;
        }
        default:
            if (!SSFASN1DecSkip(&inner, &next)) return false;
            inner = next;
            break;
    }
}
```

<a id="ex-skip"></a>

The same example shows the `Skip` and `IsEmpty` patterns.

---

<a id="primitive-decoders"></a>

### [↑](#functions-decode-prim) Primitive Decoders

Each function fails with `false` (and leaves `*next` unchanged) on tag mismatch, length
violation, or any DER non-conformance.

<a id="ssfasn1decgetbool"></a>
```c
bool SSFASN1DecGetBool(const SSFASN1Cursor_t *cursor, bool *valOut, SSFASN1Cursor_t *next);
```
Decode BOOLEAN. DER requires the value byte to be `0xFF` for `true` or `0x00` for `false`;
any other value is rejected.

<a id="ssfasn1decgetint"></a>
```c
bool SSFASN1DecGetInt(const SSFASN1Cursor_t *cursor, const uint8_t **intBufOut,
                      uint32_t *intLenOut, SSFASN1Cursor_t *next);
```
Decode INTEGER as a pointer + length into the DER buffer. `*intBufOut` points at the
INTEGER body bytes (the DER encoding — two's-complement big-endian, with the high bit of
the first byte being the sign). The caller is responsible for any conversion (e.g., to a
`SSFBN_t` for arbitrary-precision use).

<a id="ssfasn1decgetintu64"></a>
```c
bool SSFASN1DecGetIntU64(const SSFASN1Cursor_t *cursor, uint64_t *valOut,
                         SSFASN1Cursor_t *next);
```
Decode INTEGER into a `uint64_t`. Returns `false` if the INTEGER is negative or its
unsigned value would exceed `UINT64_MAX`.

<a id="ssfasn1decgetbitstring"></a>
```c
bool SSFASN1DecGetBitString(const SSFASN1Cursor_t *cursor, const uint8_t **bitsOut,
                            uint32_t *bitsLenOut, uint8_t *unusedBitsOut,
                            SSFASN1Cursor_t *next);
```
Decode BIT STRING. `*bitsOut` points at the bit-payload bytes (DER stores them
big-endian-byte-order, MSB of byte 0 is bit 0 of the string). `*bitsLenOut` is the byte
length; `*unusedBitsOut` is the count of bits at the end of the last byte that should be
ignored (`0..7`).

<a id="ssfasn1decgetoctetstring"></a>
```c
bool SSFASN1DecGetOctetString(const SSFASN1Cursor_t *cursor, const uint8_t **octetsOut,
                              uint32_t *octetsLenOut, SSFASN1Cursor_t *next);
```
Decode OCTET STRING. Returns a pointer + length into the DER buffer.

<a id="ssfasn1decgetnull"></a>
```c
bool SSFASN1DecGetNull(const SSFASN1Cursor_t *cursor, SSFASN1Cursor_t *next);
```
Decode NULL. DER requires zero-length content; non-zero content is rejected.

<a id="ssfasn1decgetoid"></a>
```c
bool SSFASN1DecGetOID(const SSFASN1Cursor_t *cursor, uint32_t *oidArcsOut,
                      uint8_t oidArcsSize, uint8_t *oidArcsLenOut, SSFASN1Cursor_t *next);
```
Decode OID into a caller-supplied `uint32_t[]` array. Writes the actual arc count to
`*oidArcsLenOut`. Returns `false` if the OID requires more than `oidArcsSize` arcs (the
caller should retry with a larger buffer or fall back to
[`SSFASN1DecGetOIDRaw()`](#ssfasn1decgetoidraw)).

The first two arcs of any OID are jointly encoded in the first DER byte per X.690; the
function unpacks them into the first two slots of the output array.

<a id="ssfasn1decgetoidraw"></a>
```c
bool SSFASN1DecGetOIDRaw(const SSFASN1Cursor_t *cursor, const uint8_t **oidRawOut,
                         uint32_t *oidRawLenOut, SSFASN1Cursor_t *next);
```
Returns a pointer + length to the OID body (the DER bytes after the T and L). Use this
when comparing against a known OID (e.g., `id-rsaEncryption`) byte-for-byte without
allocating arc storage.

<a id="ex-oid"></a>

**Example (OID compare):**

```c
/* DER body bytes for 1.2.840.113549.1.1.1 (rsaEncryption) */
static const uint8_t OID_RSA_ENC[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};

const uint8_t *oid; uint32_t oidLen;
if (SSFASN1DecGetOIDRaw(&cur, &oid, &oidLen, &next) &&
    oidLen == sizeof(OID_RSA_ENC) &&
    memcmp(oid, OID_RSA_ENC, oidLen) == 0)
{
    /* matched */
}
```

<a id="ssfasn1decgetstring"></a>
```c
bool SSFASN1DecGetString(const SSFASN1Cursor_t *cursor, const uint8_t **strOut,
                         uint32_t *strLenOut, uint16_t *strTagOut,
                         SSFASN1Cursor_t *next);
```
Decode any of the six string variants permitted by RFC 5280 §4.1.2.4 DirectoryString:
UTF-8, Printable, IA5, BMP, T61 (TeletexString — legacy), or UniversalString. Returns
pointer + length into the DER buffer; if `strTagOut != NULL`, also writes which of the
six tag types matched, so the caller can re-encode in the same type.

<a id="ex-string"></a>

**Example:**

```c
const uint8_t *s; uint32_t n; uint16_t tag;
if (SSFASN1DecGetString(&cur, &s, &n, &tag, &next))
{
    /* s[0..n-1] is the string body in its native encoding (UTF-8, BMP, ...). */
    /* tag identifies which variant was used. */
}
```

<a id="ssfasn1decgettime"></a>
```c
bool SSFASN1DecGetTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                       SSFASN1Cursor_t *next);
```
Decode UTCTime or GeneralizedTime into Unix seconds (UTC). Accepts the X.509 profile's
strict forms only:

- UTCTime: exactly `YYMMDDHHMMSSZ` (13 bytes). Years `00..49` are interpreted as
  `2000..2049`; years `50..99` as `1950..1999`.
- GeneralizedTime: exactly `YYYYMMDDHHMMSSZ` (15 bytes).

Pre-1970 dates and any non-conforming format produce `false`.

<a id="ex-time"></a>

**Example:**

```c
uint64_t notBefore;
if (SSFASN1DecGetTime(&inner, &notBefore, &next))
{
    /* notBefore is Unix seconds. */
}
```

<a id="ssfasn1decgetdate"></a>
```c
bool SSFASN1DecGetDate(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                       SSFASN1Cursor_t *next);
```
Decode the universal-31 DATE tag, which carries `YYYY-MM-DD`. Returns Unix seconds for
00:00:00 UTC on the decoded date. Pre-1970 dates produce `false`.

<a id="ssfasn1decgetdatetime"></a>
```c
bool SSFASN1DecGetDateTime(const SSFASN1Cursor_t *cursor, uint64_t *unixSecOut,
                           SSFASN1Cursor_t *next);
```
Decode the universal-33 DATE-TIME tag, which carries `YYYY-MM-DDTHH:MM:SS` (UTC). Returns
Unix seconds.

---

<a id="encoders"></a>

### [↑](#functions-encode) Encoders

Every encoder shares the contract: pass `buf == NULL, bufSize == 0` to measure (the
required byte count is written to `*bytesWritten`); pass a non-`NULL` `buf` with
`bufSize` ≥ the measured count to write. On any failure (invalid input, buffer too small,
overflow) the encoder returns `false` and sets `*bytesWritten = 0`. `bytesWritten` must
not be `NULL` — that is enforced by `SSF_REQUIRE`.

<a id="ssfasn1enctaglen"></a>
```c
bool SSFASN1EncTagLen(uint8_t *buf, uint32_t bufSize, uint16_t tag, uint32_t contentLen,
                      uint32_t *bytesWritten);
```
Emit just the tag and length bytes for a TLV whose value the caller will write
separately. Useful for streaming a long OCTET STRING or BIT STRING out of a stable
location without first materialising it in `buf`.

<a id="ssfasn1encbool"></a>
```c
bool SSFASN1EncBool(uint8_t *buf, uint32_t bufSize, bool val, uint32_t *bytesWritten);
```
Encode BOOLEAN. Writes 3 bytes: tag `0x01`, length `0x01`, value `0xFF` (true) or `0x00`
(false).

<a id="ssfasn1encint"></a>
```c
bool SSFASN1EncInt(uint8_t *buf, uint32_t bufSize, const uint8_t *intBuf, uint32_t intLen,
                   uint32_t *bytesWritten);
```
Encode INTEGER from a caller-supplied two's-complement big-endian byte buffer. The
encoder strips redundant leading sign bytes per DER's minimal-encoding rule and adds a
leading `0x00` when the unsigned value's high bit is set.

<a id="ssfasn1encintu64"></a>
```c
bool SSFASN1EncIntU64(uint8_t *buf, uint32_t bufSize, uint64_t val,
                      uint32_t *bytesWritten);
```
Encode an unsigned 64-bit value as INTEGER. Output is between 3 bytes (for `val == 0`)
and 11 bytes (for `val > INT64_MAX`, which forces a leading `0x00`).

<a id="ssfasn1encbitstring"></a>
```c
bool SSFASN1EncBitString(uint8_t *buf, uint32_t bufSize, const uint8_t *bits,
                         uint32_t bitsLen, uint8_t unusedBits, uint32_t *bytesWritten);
```
Encode BIT STRING. `bits` / `bitsLen` is the byte payload; `unusedBits` is the trailing-
bit-ignore count (`0..7`). Returns `false` if `unusedBits > 7`.

<a id="ssfasn1encoctetstring"></a>
```c
bool SSFASN1EncOctetString(uint8_t *buf, uint32_t bufSize, const uint8_t *octets,
                           uint32_t octetsLen, uint32_t *bytesWritten);
```
Encode OCTET STRING. The body is `octets[0..octetsLen-1]` verbatim.

<a id="ssfasn1encnull"></a>
```c
bool SSFASN1EncNull(uint8_t *buf, uint32_t bufSize, uint32_t *bytesWritten);
```
Encode NULL. Writes 2 bytes: tag `0x05`, length `0x00`.

<a id="ssfasn1encoidraw"></a>
```c
bool SSFASN1EncOIDRaw(uint8_t *buf, uint32_t bufSize, const uint8_t *oidRaw,
                      uint32_t oidRawLen, uint32_t *bytesWritten);
```
Encode OBJECT IDENTIFIER from raw DER body bytes. The caller is responsible for the
arc-to-base-128 multi-byte encoding; this function just wraps the bytes in the OID
T + L.

<a id="ssfasn1encstring"></a>
```c
bool SSFASN1EncString(uint8_t *buf, uint32_t bufSize, uint16_t strTag, const uint8_t *str,
                      uint32_t strLen, uint32_t *bytesWritten);
```
Encode a string under one of the six DirectoryString tag types. `strTag` must be one of
`SSF_ASN1_TAG_UTF8_STRING`, `_PRINTABLE_STRING`, `_T61_STRING`, `_IA5_STRING`,
`_UNIVERSAL_STRING`, `_BMP_STRING`. Body bytes are not validated against the tag's
character class — caller is responsible for that.

<a id="ssfasn1encutctime"></a>
```c
bool SSFASN1EncUTCTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                       uint32_t *bytesWritten);
```
Encode UTCTime as `YYMMDDHHMMSSZ`. Years are formatted in two-digit form per X.509 (years
1950–2049 only); a `unixSec` outside that range returns `false`.

<a id="ssfasn1encgeneralizedtime"></a>
```c
bool SSFASN1EncGeneralizedTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                               uint32_t *bytesWritten);
```
Encode GeneralizedTime as `YYYYMMDDHHMMSSZ`. No date-range restriction beyond Unix epoch
(1970-01-01).

<a id="ssfasn1encdate"></a>
```c
bool SSFASN1EncDate(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                    uint32_t *bytesWritten);
```
Encode the universal-31 DATE tag with body `YYYY-MM-DD`. Sub-day resolution in `unixSec`
is truncated (rounded down) to midnight UTC.

<a id="ssfasn1encdatetime"></a>
```c
bool SSFASN1EncDateTime(uint8_t *buf, uint32_t bufSize, uint64_t unixSec,
                        uint32_t *bytesWritten);
```
Encode the universal-33 DATE-TIME tag with body `YYYY-MM-DDTHH:MM:SS` (UTC).

<a id="ssfasn1encwrap"></a>
```c
bool SSFASN1EncWrap(uint8_t *buf, uint32_t bufSize, uint16_t tag, const uint8_t *content,
                    uint32_t contentLen, uint32_t *bytesWritten);
```
Wrap an already-encoded inner blob with a SEQUENCE / SET / context-tagged constructed
header. Useful as the final step of building a SEQUENCE: encode each child into a
contiguous buffer, then call `EncWrap` to prepend the sequence T + L.

<a id="ex-encode"></a>

**Example (build a SEQUENCE { INTEGER, OCTET STRING }):**

```c
uint32_t intLen, octLen, totalLen;
uint8_t  buf[64];
uint8_t  *p = buf;
uint32_t inner;

/* Pass 1: measure each child */
SSFASN1EncIntU64(NULL, 0, 1234, &intLen);
SSFASN1EncOctetString(NULL, 0, payload, payloadLen, &octLen);

/* Pass 2: write the children into a temporary inner buffer */
uint8_t inner_buf[60];
uint32_t off = 0;

SSFASN1EncIntU64(inner_buf + off, sizeof(inner_buf) - off, 1234, &inner);
off += inner;

SSFASN1EncOctetString(inner_buf + off, sizeof(inner_buf) - off, payload, payloadLen,
                      &inner);
off += inner;

/* Wrap with a SEQUENCE header */
if (!SSFASN1EncWrap(buf, sizeof(buf), SSF_ASN1_TAG_SEQUENCE,
                    inner_buf, off, &totalLen))
{
    /* Buffer too small */
}
/* buf[0..totalLen-1] is the encoded SEQUENCE. */
```
