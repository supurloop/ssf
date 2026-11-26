# ssfpem — PEM Block Codec

[SSF](../README.md) | [Codecs](README.md)

Decodes and encodes the textual encoding of RFC 7468 ("PEM"): `-----BEGIN <label>-----` /
Base64 / `-----END <label>-----` blocks, one at a time, in caller-supplied buffers. Used by
[`ssfpkey`](ssfpkey.md) for private keys; certificate bundles use the same blocks. The encoder
turns DER (a certificate signing request, a certificate) into the text that services such as
AWS IoT fleet provisioning expect. No filesystem access: the input is a byte buffer from flash,
a file the application read, or provisioning.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfpem--pem-block-codec) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfbase64`](ssfbase64.md) — decodes each four-character group (strict, canonical padding)
  and encodes each 48-byte line
- [`ssfcrypt`](../_crypto/ssfcrypt.md) — `SSFCryptSecureZero()` to wipe output on failure

<a id="notes"></a>

## [↑](#ssfpem--pem-block-codec) Notes

- **One block per call.** [`SSFPEMDecodeNext()`](#ssfpemdecodenext) finds the next BEGIN line
  at or after `*pos`, decodes up to the matching END line and advances `*pos` past it. Call it
  until it returns `SSF_PEM_END` to walk a buffer holding several blocks (a CA bundle, or
  `openssl ecparam -genkey` output with an `EC PARAMETERS` block before the key).
- **What is accepted.** Text before, between and after blocks is ignored (RFC 7468 §2
  explanatory text). Lines may end in LF, CR or CRLF. The `-----BEGIN ` and `-----END ` lines
  must each start a line, as every PEM writer produces and OpenSSL's reader requires: a BEGIN
  elsewhere in a line, or indented, is explanatory text, not a block. Inside the Base64, spaces,
  tabs and line breaks are skipped anywhere, so any line length works. The label is 1 to
  [`SSF_PEM_MAX_LABEL_LEN`](#ssf-pem-max-label-len) printable ASCII characters and the END
  line must repeat it exactly. Spaces or tabs may trail the BEGIN and END lines.
- **What is refused (`SSF_PEM_ERR`).** A BEGIN line without closing dashes, or with other text
  after them; a missing, misspelled or different END label; an END line that does not start a
  line (after Base64 on the same line, or indented); text after the END line's dashes;
  any character outside the Base64 alphabet, including RFC 1421 encapsulated headers such as
  `Proc-Type: 4,ENCRYPTED` (legacy encrypted keys); an incomplete final group; data after a
  padded group; non-canonical padding bits; an empty or over-long label, or one with control
  characters; a block cut off by `pemLen`.
- **Failure leaves nothing behind.** On `SSF_PEM_ERR` or `SSF_PEM_ERR_SIZE`, all `derSize`
  bytes of the output are zeroed, since a block may hold a private key, and `*pos` is unchanged.
  The decoder's four-character and three-byte scratch buffers, which hold key bytes in Base64
  and decoded form, are wiped on every return, success included.
- **`derOpt` must not overlap `pem`.** Decoding in place would overwrite text not yet read.
- **Measure first, if needed.** With `derOpt == NULL` the block is fully checked and
  `*derLenOut` set without writing anything, so a caller can size a buffer, or skip blocks it
  does not want without room for them.
- The label pointer points into the input buffer; it is not null-terminated. Compare it with
  [`SSFPEMLabelIs()`](#ssfpemlabelis).
- Base64 decoding is constant-time per character (see [`ssfbase64`](ssfbase64.md)). The body
  loop still branches on whitespace and line breaks, so timing reflects the layout of the text
  and its length, not the key bytes.
- **Encoding.** [`SSFPEMEncode()`](#ssfpemencode) writes `-----BEGIN <label>-----`, the
  Base64 in lines of 64 characters (48 input bytes), and `-----END <label>-----`, every line
  ending in LF, then a NUL. This is the layout OpenSSL writes; the unit tests reproduce
  OpenSSL output byte for byte. Zero input bytes give the two lines only.
- **Encoder labels match the decoder.** The label is 1 to
  [`SSF_PEM_MAX_LABEL_LEN`](#ssf-pem-max-label-len) characters 0x20..0x7E, with no `-----` in
  it and not ending in `-` (that dash would run into the closing dashes). These are exactly the
  labels [`SSFPEMDecodeNext()`](#ssfpemdecodenext) accepts, so a decoded label always
  re-encodes and an encoded block always decodes back. RFC 7468 is stricter (no leading,
  trailing or doubled spaces or hyphens): conforming output is a matter of the label the caller
  passes. Labels are constants in practice, so an invalid one is a programming error
  (`SSF_REQUIRE`), not a `false` return.
- **Sizing.** [`SSF_PEM_ENCODE_SIZE(labelLen, derLen)`](#ssf-pem-encode-size) is the buffer size
  needed, NUL included, and is a constant expression for constant arguments, so it can size a
  static array. `*pemLenOut` is always set to the length the block needs (NUL not counted),
  even when the call fails, and `pemOpt == NULL` only measures.
- **Encoder failure leaves nothing behind.** If `pemSize` is too small for the block and its
  NUL, `SSFPEMEncode()` returns `false` and zeroes all `pemSize` bytes; nothing past them is
  written. The size is checked before anything is written.
- **Encode public data.** The encoder is meant for certificates and certificate signing
  requests. It is not constant-time: [`ssfbase64`](ssfbase64.md) encodes by indexing its
  alphabet table with the data, and leaves the last three input bytes in a stack copy. Do not
  use it on a private key where timing or stack residue matter.
- **`pemOpt` must not overlap `derOpt` or `labelStr`** (`SSF_REQUIRE`), even when `pemSize` is too
  small. The label is copied into both the BEGIN and END lines, so re-encoding a decoded block
  into the text it was decoded from (where the label lives) is refused rather than producing
  a corrupt END line. `derLen` may be at most `SIZE_MAX / 2`, which keeps the size computation
  from overflowing.
- **DBC exemptions.** The per-character helpers `_SSFPEMAt()` and `_SSFPEMIsEol()` carry no
  assertions; [`SSFPEMDecodeNext()`](#ssfpemdecodenext) validates their inputs.

<a id="configuration"></a>

## [↑](#ssfpem--pem-block-codec) Configuration

No options file. The unit-test entry point is gated by `SSF_CONFIG_PEM_UNIT_TEST` in
`ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfpem--pem-block-codec) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-pem-max-label-len"></a>`SSF_PEM_MAX_LABEL_LEN` | Constant | Longest label accepted: `40` characters. |
| <a id="ssf-pem-encode-size"></a>`SSF_PEM_ENCODE_SIZE(labelLen, derLen)` | Macro | Bytes `SSFPEMEncode()` writes, NUL included: `2 * labelLen + 33 + 4 * ceil(derLen / 3) + ceil(derLen / 48)`. A constant expression for constant arguments. |
| `SSFPEMResult_t` | Enum | `SSF_PEM_BLOCK` (decoded), `SSF_PEM_END` (no further BEGIN line), `SSF_PEM_ERR` (malformed), `SSF_PEM_ERR_SIZE` (output too small). |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-decodenext) | [`SSFPEMResult_t SSFPEMDecodeNext(pem, pemLen, pos, labelOut, labelLenOut, derOpt, derSize, derLenOut)`](#ssfpemdecodenext) | Decode the next block |
| | [`bool SSFPEMLabelIs(label, labelLen, cmpStr)`](#ssfpemlabelis) | Compare a block's label with a C string |
| [e.g.](#ex-encode) | [`bool SSFPEMEncode(labelStr, derOpt, derLen, pemOpt, pemSize, pemLenOut)`](#ssfpemencode) | Encode one block |

<a id="function-reference"></a>

## [↑](#ssfpem--pem-block-codec) Function Reference

<a id="ssfpemdecodenext"></a>

### [↑](#ssfpem--pem-block-codec) [`SSFPEMResult_t SSFPEMDecodeNext()`](#functions)

```c
SSFPEMResult_t SSFPEMDecodeNext(const char *pem, size_t pemLen, size_t *pos,
                                const char **labelOut, size_t *labelLenOut,
                                uint8_t *derOpt, size_t derSize, size_t *derLenOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `pem` | in | `const char *` | Input text. Need not be null-terminated. Must not be `NULL`. |
| `pemLen` | in | `size_t` | Number of input bytes; nothing past it is read. |
| `pos` | in-out | `size_t *` | Offset to search from (start at `0`); on `SSF_PEM_BLOCK`, advanced past the END line. Must not be `NULL` and must not exceed `pemLen`. |
| `labelOut` | out | `const char **` | On `SSF_PEM_BLOCK`, points at the label inside `pem`. Must not be `NULL`. |
| `labelLenOut` | out | `size_t *` | On `SSF_PEM_BLOCK`, the label length. Must not be `NULL`. |
| `derOpt` | out | `uint8_t *` | Receives the decoded bytes, or `NULL` to only check and measure. |
| `derSize` | in | `size_t` | Size of `derOpt`. |
| `derLenOut` | out | `size_t *` | On `SSF_PEM_BLOCK`, the decoded length. Must not be `NULL`. |

**Returns:** `SSF_PEM_BLOCK`, `SSF_PEM_END`, `SSF_PEM_ERR` or `SSF_PEM_ERR_SIZE` (see
[Definitions](#definitions)).

<a id="ex-decodenext"></a>

```c
size_t pos = 0;
const char *label;
size_t labelLen;
uint8_t der[2048];
size_t derLen;
SSFPEMResult_t r;

while ((r = SSFPEMDecodeNext(text, textLen, &pos, &label, &labelLen, der, sizeof(der),
                             &derLen)) == SSF_PEM_BLOCK)
{
    if (SSFPEMLabelIs(label, labelLen, "CERTIFICATE")) { /* der[0..derLen) is one certificate */ }
}
if (r != SSF_PEM_END) { /* malformed block or too large: do not use a partial result */ }
```

---

<a id="ssfpemlabelis"></a>

### [↑](#ssfpem--pem-block-codec) [`bool SSFPEMLabelIs()`](#functions)

```c
bool SSFPEMLabelIs(const char *label, size_t labelLen, const char *cmpStr);
```

Returns `true` if `label[0..labelLen)` equals the null-terminated `cmpStr` exactly (same length,
same bytes). `label` and `cmpStr` must not be `NULL`.

---

<a id="ssfpemencode"></a>

### [↑](#ssfpem--pem-block-codec) [`bool SSFPEMEncode()`](#functions)

```c
bool SSFPEMEncode(const char *labelStr, const uint8_t *derOpt, size_t derLen, char *pemOpt,
                  size_t pemSize, size_t *pemLenOut);
```

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `labelStr` | in | `const char *` | Null-terminated label, e.g. `"CERTIFICATE REQUEST"`. 1 to `SSF_PEM_MAX_LABEL_LEN` characters 0x20..0x7E, no `-----`, not ending in `-`. Must not be `NULL`. |
| `derOpt` | in | `const uint8_t *` | Bytes to encode. May be `NULL` only when `derLen` is `0`. |
| `derLen` | in | `size_t` | Number of bytes to encode; at most `SIZE_MAX / 2`. |
| `pemOpt` | out | `char *` | Receives the block and a NUL, or `NULL` to only measure. Must not overlap `derOpt` or `labelStr`. |
| `pemSize` | in | `size_t` | Size of `pemOpt`; `SSF_PEM_ENCODE_SIZE(strlen(labelStr), derLen)` is enough. |
| `pemLenOut` | out | `size_t *` | Always set to the block's length, NUL not counted. Must not be `NULL`. |

**Returns:** `true` if the block was written (or only measured); `false` if `pemSize` is too
small, in which case all `pemSize` bytes of `pemOpt` are zeroed.

<a id="ex-encode"></a>

```c
uint8_t csrDer[256];                 /* e.g. a CSR from ssfx509 */
size_t csrDerLen;
char csrPem[SSF_PEM_ENCODE_SIZE(19u, sizeof(csrDer))];  /* 19 = strlen("CERTIFICATE REQUEST") */
size_t csrPemLen;

if (SSFPEMEncode("CERTIFICATE REQUEST", csrDer, csrDerLen, csrPem, sizeof(csrPem), &csrPemLen))
{
    /* csrPem[0..csrPemLen) is the block; csrPem[csrPemLen] is its NUL */
}
```
