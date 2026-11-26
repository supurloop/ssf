# ssfpem — PEM Block Decoder

[SSF](../README.md) | [Codecs](README.md)

Decodes the textual encoding of RFC 7468 ("PEM"): `-----BEGIN <label>-----` / Base64 /
`-----END <label>-----` blocks, one at a time, from a caller-supplied buffer. Used by
[`ssfpkey`](ssfpkey.md) for private keys; certificate bundles use the same blocks. No
filesystem access: the input is a byte buffer from flash, a file the application read, or
provisioning.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfpem--pem-block-decoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfbase64`](ssfbase64.md) — decodes each four-character group (strict, canonical padding)
- [`ssfcrypt`](../_crypto/ssfcrypt.md) — `SSFCryptSecureZero()` to wipe output on failure

<a id="notes"></a>

## [↑](#ssfpem--pem-block-decoder) Notes

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

<a id="configuration"></a>

## [↑](#ssfpem--pem-block-decoder) Configuration

No options file. The unit-test entry point is gated by `SSF_CONFIG_PEM_UNIT_TEST` in
`ssfport.h`.

<a id="api-summary"></a>

## [↑](#ssfpem--pem-block-decoder) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="ssf-pem-max-label-len"></a>`SSF_PEM_MAX_LABEL_LEN` | Constant | Longest label accepted: `40` characters. |
| `SSFPEMResult_t` | Enum | `SSF_PEM_BLOCK` (decoded), `SSF_PEM_END` (no further BEGIN line), `SSF_PEM_ERR` (malformed), `SSF_PEM_ERR_SIZE` (output too small). |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-decodenext) | [`SSFPEMResult_t SSFPEMDecodeNext(pem, pemLen, pos, labelOut, labelLenOut, derOpt, derSize, derLenOut)`](#ssfpemdecodenext) | Decode the next block |
| | [`bool SSFPEMLabelIs(label, labelLen, str)`](#ssfpemlabelis) | Compare a block's label with a C string |

<a id="function-reference"></a>

## [↑](#ssfpem--pem-block-decoder) Function Reference

<a id="ssfpemdecodenext"></a>

### [↑](#ssfpem--pem-block-decoder) [`SSFPEMResult_t SSFPEMDecodeNext()`](#functions)

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

### [↑](#ssfpem--pem-block-decoder) [`bool SSFPEMLabelIs()`](#functions)

```c
bool SSFPEMLabelIs(const char *label, size_t labelLen, const char *str);
```

Returns `true` if `label[0..labelLen)` equals the null-terminated `str` exactly (same length,
same bytes). `label` and `str` must not be `NULL`.
