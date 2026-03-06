# ssftlv — TLV Encoder/Decoder

[SSF](../README.md) | [Codecs](README.md)

Tag-Length-Value encoder and decoder for compact binary data serialization.

The same context and buffer serve both roles: initialize with `bufLen == 0` to encode, or with
`bufLen` equal to the number of received bytes to decode. The same tag may appear multiple times;
use the `instance` parameter (0-based) to iterate over duplicates.

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssftlv--tlv-encoderdecoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`ssfoptions.h`](../ssfoptions.h)

<a id="notes"></a>

## [↑](#ssftlv--tlv-encoderdecoder) Notes

- Initialize with `bufLen == 0` for an encode session; with `bufLen == receivedBytes` for a
  decode session.
- After encoding, `tlv.bufLen` holds the total number of bytes written and is the length to
  transmit.
- The same tag may appear more than once in a TLV buffer; use the `instance` parameter (0-based)
  to select among duplicates.
- [`SSFTLVFind()`](#ssftlvfind) returns a pointer directly into the TLV buffer, avoiding a copy;
  do not write through that pointer.
- In variable mode (default), TAG and LEN fields are 1–4 bytes each, sized automatically by the
  value being encoded. This is transparent to the caller.
- Fixed mode (`SSF_TLV_ENABLE_FIXED_MODE == 1`) reduces per-field overhead but limits to 256
  distinct tags and values up to 255 bytes each.

<a id="configuration"></a>

## [↑](#ssftlv--tlv-encoderdecoder) Configuration

All options are set in `ssfoptions.h`.

| Option | Default | Description |
|--------|---------|-------------|
| <a id="opt-fixed-mode"></a>`SSF_TLV_ENABLE_FIXED_MODE` | `0` | `1` for 1-byte TAG and LEN fields (max 256 tags, max 255-byte values); `0` for variable 1–4 byte fields (max 2^30 tags, max 2^30-byte values) |

<a id="api-summary"></a>

## [↑](#ssftlv--tlv-encoderdecoder) API Summary

### Definitions

| Symbol | Kind | Description |
|--------|------|-------------|
| <a id="type-ssftlvvar-t"></a>`SSFTLVVar_t` | Typedef | `uint8_t` when [`SSF_TLV_ENABLE_FIXED_MODE`](#opt-fixed-mode) is `1`; `uint32_t` otherwise. Used for tag and value-length fields |
| <a id="type-ssftlv-t"></a>`SSFTLV_t` | Struct | TLV context; pass by pointer to all API functions. After encoding, read `tlv.bufLen` for the number of bytes to transmit. Do not access other fields directly |

<a id="functions"></a>

### Functions

| | Function / Macro | Description |
|---|-----------------|-------------|
| [e.g.](#ex-init) | [`void SSFTLVInit(tlv, buf, bufSize, bufLen)`](#ssftlvinit) | Initialize a TLV context for encoding or decoding |
| [e.g.](#ex-deinit) | [`void SSFTLVDeInit(tlv)`](#ssftlvdeinit) | De-initialize a TLV context |
| [e.g.](#ex-put) | [`bool SSFTLVPut(tlv, tag, val, valLen)`](#ssftlvput) | Encode a tag/value pair into the TLV buffer |
| [e.g.](#ex-read) | [`bool SSFTLVRead(tlv, tag, instance, val, valSize, valPtr, valLen)`](#ssftlvread) | Find a tag/instance and copy or point to its value |
| [e.g.](#ex-get) | [`bool SSFTLVGet(tlv, tag, instance, val, valSize, valLen)`](#ssftlvget) | Macro: decode a value by tag into a caller-supplied buffer |
| [e.g.](#ex-find) | [`bool SSFTLVFind(tlv, tag, instance, valPtr, valLen)`](#ssftlvfind) | Macro: locate a value by tag as a pointer into the TLV buffer |

<a id="function-reference"></a>

## [↑](#ssftlv--tlv-encoderdecoder) Function Reference

<a id="ssftlvinit"></a>

### [↑](#ssftlv--tlv-encoderdecoder) [`void SSFTLVInit()`](#functions)

```c
void SSFTLVInit(SSFTLV_t *tlv, uint8_t *buf, uint32_t bufSize, uint32_t bufLen);
```

Initializes a TLV context over a caller-supplied buffer. Pass `bufLen == 0` to start an encode
session; pass `bufLen` equal to the number of received bytes to start a decode session.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | out | [`SSFTLV_t *`](#type-ssftlv-t) | Pointer to the TLV context to initialize. Must not be `NULL`. |
| `buf` | in | `uint8_t *` | Buffer that holds or will hold TLV-encoded data. Must not be `NULL`. |
| `bufSize` | in | `uint32_t` | Total allocated size of `buf` in bytes. |
| `bufLen` | in | `uint32_t` | Number of valid TLV bytes already present in `buf`. Set to `0` for a new encode session; set to the received data length for a decode session. Must not exceed `bufSize`. |

**Returns:** Nothing.

<a id="ex-init"></a>

```c
#define TAG_ID   1u
#define TAG_NAME 2u

SSFTLV_t tlv;
uint8_t buf[64];

/* Encode session: bufLen == 0 */
SSFTLVInit(&tlv, buf, sizeof(buf), 0);
/* tlv is ready; tlv.bufLen == 0 */

/* Decode session: bufLen == number of received bytes */
uint32_t rxLen = 7u; /* bytes received into buf from transport */
SSFTLVInit(&tlv, buf, sizeof(buf), rxLen);
/* tlv is ready for decoding rxLen bytes */
```

---

<a id="ssftlvdeinit"></a>

### [↑](#ssftlv--tlv-encoderdecoder) [`void SSFTLVDeInit()`](#functions)

```c
void SSFTLVDeInit(SSFTLV_t *tlv);
```

De-initializes a TLV context, clearing its internal magic marker.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in-out | [`SSFTLV_t *`](#type-ssftlv-t) | Pointer to the TLV context to de-initialize. Must not be `NULL`. |

**Returns:** Nothing.

<a id="ex-deinit"></a>

```c
SSFTLV_t tlv;
uint8_t buf[64];

SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVDeInit(&tlv);
/* tlv is no longer valid */
```

---

<a id="ssftlvput"></a>

### [↑](#ssftlv--tlv-encoderdecoder) [`bool SSFTLVPut()`](#functions)

```c
bool SSFTLVPut(SSFTLV_t *tlv, SSFTLVVar_t tag, const uint8_t *val, SSFTLVVar_t valLen);
```

Encodes one tag/value pair into the TLV buffer, appending it after any previously encoded pairs.
On success `tlv.bufLen` is updated to reflect the new total encoded length.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in-out | [`SSFTLV_t *`](#type-ssftlv-t) | Pointer to an initialized TLV context. Must not be `NULL`. |
| `tag` | in | [`SSFTLVVar_t`](#type-ssftlvvar-t) | Tag identifier. Variable mode: 0–2^30−1. Fixed mode: 0–255. |
| `val` | in | `const uint8_t *` | Pointer to the value bytes to encode. May be `NULL` only when `valLen` is `0`. |
| `valLen` | in | [`SSFTLVVar_t`](#type-ssftlvvar-t) | Number of bytes in `val`. Variable mode: 0–2^30−1. Fixed mode: 0–255. |

**Returns:** `true` if encoding succeeded and `tlv.bufLen` was updated; `false` if the buffer does not have enough remaining space for the tag, length, and value fields.

<a id="ex-put"></a>

```c
#define TAG_ID   1u
#define TAG_NAME 2u

SSFTLV_t tlv;
uint8_t buf[64];
uint8_t id = 42u;

SSFTLVInit(&tlv, buf, sizeof(buf), 0);

if (SSFTLVPut(&tlv, TAG_ID,   &id,              1) &&
    SSFTLVPut(&tlv, TAG_NAME, (uint8_t *)"Alice", 5))
{
    /* tlv.bufLen bytes of buf are ready to transmit */
}
```

---

<a id="ssftlvread"></a>

### [↑](#ssftlv--tlv-encoderdecoder) [`bool SSFTLVRead()`](#functions)

```c
bool SSFTLVRead(const SSFTLV_t *tlv, SSFTLVVar_t tag, uint16_t instance,
                uint8_t *val, uint32_t valSize, uint8_t **valPtr, SSFTLVVar_t *valLen);
```

Searches the TLV buffer for the `instance`-th occurrence (0-based) of `tag`. When found,
optionally copies the value into `val` and/or sets `*valPtr` to point directly into the TLV
buffer at the start of the value. [`SSFTLVGet()`](#ssftlvget) and [`SSFTLVFind()`](#ssftlvfind)
are convenience macros over this function.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in | [`const SSFTLV_t *`](#type-ssftlv-t) | Pointer to an initialized TLV context. Must not be `NULL`. |
| `tag` | in | [`SSFTLVVar_t`](#type-ssftlvvar-t) | Tag identifier to search for. |
| `instance` | in | `uint16_t` | 0-based occurrence index; `0` finds the first match, `1` the second, and so on. |
| `val` | out (opt) | `uint8_t *` | If not `NULL`, receives a copy of the found value. Pass `NULL` when only a pointer is needed. |
| `valSize` | in | `uint32_t` | Allocated size of `val` in bytes. Ignored when `val` is `NULL`. Must be large enough to hold the found value. |
| `valPtr` | out (opt) | `uint8_t **` | If not `NULL`, receives a pointer into the TLV buffer at the start of the found value. Pass `NULL` when only a copy is needed. |
| `valLen` | out (opt) | [`SSFTLVVar_t *`](#type-ssftlvvar-t) | If not `NULL`, receives the length of the found value in bytes. |

**Returns:** `true` if the tag/instance was found and all requested outputs were written; `false` if the tag/instance was not found or `valSize` is too small to hold the value.

<a id="ex-read"></a>

```c
#define TAG_ID   1u
#define TAG_NAME 2u

SSFTLV_t tlv;
uint8_t buf[64];
uint8_t id = 42u;
uint8_t val[32];
SSFTLVVar_t valLen;
uint8_t *valPtr;

/* Build a TLV buffer to decode */
SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVPut(&tlv, TAG_ID,   &id,               1);
SSFTLVPut(&tlv, TAG_NAME, (uint8_t *)"Alice", 5);

/* Re-initialize for decoding */
SSFTLVInit(&tlv, buf, sizeof(buf), tlv.bufLen);

/* Copy value into a local buffer */
if (SSFTLVRead(&tlv, TAG_NAME, 0, val, sizeof(val), NULL, &valLen))
{
    /* val[0..4] == "Alice", valLen == 5 */
}

/* Obtain a pointer directly into the TLV buffer */
if (SSFTLVRead(&tlv, TAG_NAME, 0, NULL, 0, &valPtr, &valLen))
{
    /* valPtr points into buf at "Alice", valLen == 5 */
}
```

---

<a id="convenience-macros"></a>

### [↑](#ssftlv--tlv-encoderdecoder) [Convenience Macros](#ex-get)

Thin wrappers over [`SSFTLVRead()`](#ssftlvread) that fix the unused output arguments to `NULL`
and `0`. Use [`SSFTLVGet()`](#ssftlvget) when a copy into a local buffer is needed; use
[`SSFTLVFind()`](#ssftlvfind) when a zero-copy pointer into the TLV buffer is sufficient.

---

<a id="ssftlvget"></a>

#### [↑](#ssftlv--tlv-encoderdecoder) [`bool SSFTLVGet()`](#functions)

```c
#define SSFTLVGet(tlv, tag, instance, val, valSize, valLen) \
    SSFTLVRead(tlv, tag, instance, val, valSize, NULL, valLen)
```

Finds the `instance`-th occurrence of `tag` and copies its value into `val`. Equivalent to
calling `SSFTLVRead()` with `valPtr` set to `NULL`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in | [`const SSFTLV_t *`](#type-ssftlv-t) | Pointer to an initialized TLV context. Must not be `NULL`. |
| `tag` | in | [`SSFTLVVar_t`](#type-ssftlvvar-t) | Tag identifier to search for. |
| `instance` | in | `uint16_t` | 0-based occurrence index. |
| `val` | out | `uint8_t *` | Buffer receiving a copy of the found value. Must not be `NULL`. |
| `valSize` | in | `uint32_t` | Allocated size of `val`. Must be large enough to hold the found value. |
| `valLen` | out (opt) | [`SSFTLVVar_t *`](#type-ssftlvvar-t) | If not `NULL`, receives the length of the found value. |

**Returns:** `true` if the tag/instance was found and copied; `false` otherwise.

<a id="ex-get"></a>

```c
#define TAG_ID   1u
#define TAG_NAME 2u

SSFTLV_t tlv;
uint8_t buf[64];
uint8_t id = 42u;
uint8_t val[32];
SSFTLVVar_t valLen;

SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVPut(&tlv, TAG_ID,   &id,               1);
SSFTLVPut(&tlv, TAG_NAME, (uint8_t *)"Alice", 5);
SSFTLVInit(&tlv, buf, sizeof(buf), tlv.bufLen);

if (SSFTLVGet(&tlv, TAG_NAME, 0, val, sizeof(val), &valLen))
{
    /* val[0..4] == "Alice", valLen == 5 */
}
```

---

<a id="ssftlvfind"></a>

#### [↑](#ssftlv--tlv-encoderdecoder) [`bool SSFTLVFind()`](#functions)

```c
#define SSFTLVFind(tlv, tag, instance, valPtr, valLen) \
    SSFTLVRead(tlv, tag, instance, NULL, 0, valPtr, valLen)
```

Finds the `instance`-th occurrence of `tag` and sets `*valPtr` to point directly into the TLV
buffer at the start of the value, avoiding a copy. Equivalent to calling `SSFTLVRead()` with
`val` set to `NULL` and `valSize` set to `0`. Do not write through the returned pointer.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in | [`const SSFTLV_t *`](#type-ssftlv-t) | Pointer to an initialized TLV context. Must not be `NULL`. |
| `tag` | in | [`SSFTLVVar_t`](#type-ssftlvvar-t) | Tag identifier to search for. |
| `instance` | in | `uint16_t` | 0-based occurrence index. |
| `valPtr` | out | `uint8_t **` | Receives a pointer into the TLV buffer at the start of the found value. Must not be `NULL`. |
| `valLen` | out (opt) | [`SSFTLVVar_t *`](#type-ssftlvvar-t) | If not `NULL`, receives the length of the found value. |

**Returns:** `true` if the tag/instance was found and `*valPtr` was set; `false` otherwise.

<a id="ex-find"></a>

```c
#define TAG_ID   1u
#define TAG_NAME 2u

SSFTLV_t tlv;
uint8_t buf[64];
uint8_t id = 42u;
uint8_t *valPtr;
SSFTLVVar_t valLen;

SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVPut(&tlv, TAG_ID,   &id,               1);
SSFTLVPut(&tlv, TAG_NAME, (uint8_t *)"Alice", 5);
SSFTLVInit(&tlv, buf, sizeof(buf), tlv.bufLen);

if (SSFTLVFind(&tlv, TAG_NAME, 0, &valPtr, &valLen))
{
    /* valPtr points into buf at "Alice", valLen == 5 — no copy made */
}
```

