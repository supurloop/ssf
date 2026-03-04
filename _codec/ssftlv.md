# ssftlv — TLV Encoder/Decoder

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Tag-Length-Value encoder/decoder for compact binary data serialization.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_TLV_ENABLE_FIXED_MODE` | `0` | `1` for 1-byte TAG and LEN fields (max 256 tags, max 255-byte values); `0` for variable 1–4 byte fields (max 2^30 tags, max 2^30-byte values) |

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFTLVInit(tlv, buf, bufSize, bufLen)` | Initialize a TLV context over a buffer |
| `SSFTLVDeInit(tlv)` | De-initialize a TLV context |
| `SSFTLVPut(tlv, tag, val, valLen)` | Encode a tag/value pair into the TLV buffer |
| `SSFTLVRead(tlv, tag, instance, val, valSize, valPtr, valLen)` | Find a tag/instance and copy or point to its value |
| `SSFTLVGet(tlv, tag, instance, val, valSize, valLen)` | Macro: decode a value by tag (copies to caller buffer) |
| `SSFTLVFind(tlv, tag, instance, valPtr, valLen)` | Macro: locate a value by tag (returns pointer into TLV buffer) |

## Function Reference

### `SSFTLVInit`

```c
void SSFTLVInit(SSFTLV_t *tlv, uint8_t *buf, uint32_t bufSize, uint32_t bufLen);
```

Initializes a TLV context. The same buffer can be used for encoding new TLV data (pass `bufLen`
as `0`) or for decoding received TLV data (pass `bufLen` as the number of valid bytes in `buf`).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | out | `SSFTLV_t *` | Pointer to the TLV context to initialize. Must not be `NULL`. |
| `buf` | in | `uint8_t *` | Buffer that holds or will hold TLV-encoded data. Must not be `NULL`. |
| `bufSize` | in | `uint32_t` | Total allocated size of `buf` in bytes. |
| `bufLen` | in | `uint32_t` | Number of valid TLV bytes already present in `buf`. Set to `0` for a new encode session; set to the received data length for a decode session. Must not exceed `bufSize`. |

**Returns:** Nothing.

---

### `SSFTLVDeInit`

```c
void SSFTLVDeInit(SSFTLV_t *tlv);
```

De-initializes a TLV context, clearing its internal magic marker. Primarily used in unit test
teardown scenarios.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in-out | `SSFTLV_t *` | Pointer to the TLV context to de-initialize. Must not be `NULL`. |

**Returns:** Nothing.

---

### `SSFTLVPut`

```c
bool SSFTLVPut(SSFTLV_t *tlv, SSFTLVVar_t tag, const uint8_t *val, SSFTLVVar_t valLen);
```

Encodes one tag/value pair into the TLV buffer, appending it after any previously encoded pairs.
On success, `tlv->bufLen` is increased by the encoded field size.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in-out | `SSFTLV_t *` | Pointer to an initialized TLV context. Must not be `NULL`. |
| `tag` | in | `SSFTLVVar_t` | Tag identifier. In fixed mode (`uint8_t`): 0–255. In variable mode (`uint32_t`): 0–2^30−1. |
| `val` | in | `const uint8_t *` | Pointer to the value data to encode. May be `NULL` only when `valLen` is `0`. |
| `valLen` | in | `SSFTLVVar_t` | Number of bytes in `val`. In fixed mode: 0–255. In variable mode: 0–2^30−1. |

**Returns:** `true` if encoding succeeded; `false` if the buffer does not have enough space for the tag, length, and value.

---

### `SSFTLVRead`

```c
bool SSFTLVRead(const SSFTLV_t *tlv, SSFTLVVar_t tag, uint16_t instance,
                uint8_t *val, uint32_t valSize, uint8_t **valPtr, SSFTLVVar_t *valLen);
```

Searches the TLV buffer for the `instance`-th occurrence (0-based) of `tag`. When found,
optionally copies the value into `val` and/or sets `valPtr` to point directly into the TLV
buffer at the value data. `SSFTLVGet` and `SSFTLVFind` are convenience macros over this function.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `tlv` | in | `const SSFTLV_t *` | Pointer to an initialized TLV context. Must not be `NULL`. |
| `tag` | in | `SSFTLVVar_t` | Tag identifier to search for. |
| `instance` | in | `uint16_t` | 0-based occurrence index. `0` finds the first match, `1` the second, and so on. |
| `val` | out (opt) | `uint8_t *` | If not `NULL`, receives a copy of the value. Must be at least `valSize` bytes. Pass `NULL` when only a pointer is needed (as `SSFTLVFind` does). |
| `valSize` | in | `uint32_t` | Allocated size of `val`. Ignored when `val` is `NULL`. Must be large enough for the found value. |
| `valPtr` | out (opt) | `uint8_t **` | If not `NULL`, receives a pointer directly into the TLV buffer at the start of the found value. Pass `NULL` when only a copy is needed (as `SSFTLVGet` does). |
| `valLen` | out (opt) | `SSFTLVVar_t *` | If not `NULL`, receives the length of the found value in bytes. |

**Returns:** `true` if the tag/instance was found and the output was written; `false` if the tag/instance was not found or `valSize` is too small to hold the value.

---

### `SSFTLVGet`

```c
#define SSFTLVGet(tlv, tag, instance, val, valSize, valLen) \
    SSFTLVRead(tlv, tag, instance, val, valSize, NULL, valLen)
```

Convenience macro over `SSFTLVRead` that copies the found value into a caller-supplied buffer.
Equivalent to calling `SSFTLVRead` with `valPtr` set to `NULL`.

---

### `SSFTLVFind`

```c
#define SSFTLVFind(tlv, tag, instance, valPtr, valLen) \
    SSFTLVRead(tlv, tag, instance, NULL, 0, valPtr, valLen)
```

Convenience macro over `SSFTLVRead` that returns a pointer directly into the TLV buffer at the
found value, avoiding a copy. Equivalent to calling `SSFTLVRead` with `val` set to `NULL` and
`valSize` set to `0`.

## Usage

TLV is a compact alternative to JSON when data size matters, such as on metered connections or
bandwidth-constrained wireless links. The same tag may appear multiple times; `SSFTLVGet()` and
`SSFTLVFind()` accept an index to iterate over duplicate tags.

```c
#define TAG_NAME  1
#define TAG_HOBBY 2

SSFTLV_t tlv;
uint8_t buf[100];

/* Encode */
SSFTLVInit(&tlv, buf, sizeof(buf), 0);
SSFTLVPut(&tlv, TAG_NAME,  "Jimmy",  5);
SSFTLVPut(&tlv, TAG_HOBBY, "Coding", 6);
/* tlv.bufLen is the total length of TLV data encoded */

/* ... Transmit tlv.bufLen bytes of tlv.buf to another system ... */

/* Decode */
SSFTLV_t tlvRx;
uint8_t rxbuf[100];
uint8_t val[100];
SSFTLVVar_t valLen;
uint8_t *valPtr;

/* rxbuf contains rxlen bytes of received data */
SSFTLVInit(&tlvRx, rxbuf, sizeof(rxbuf), rxlen);

SSFTLVGet(&tlvRx, TAG_NAME,  0, val, sizeof(val), &valLen);
/* val == "Jimmy", valLen == 5 */

SSFTLVGet(&tlvRx, TAG_HOBBY, 0, val, sizeof(val), &valLen);
/* val == "Coding", valLen == 6 */

SSFTLVFind(&tlvRx, TAG_NAME, 0, &valPtr, &valLen);
/* valPtr points into rxbuf at "Jimmy", valLen == 5 */
```

## Dependencies

- `ssf/ssfport.h`
- `ssf/ssfoptions.h`

## Notes

- In variable mode (default), TAG and LEN fields are 1–4 bytes each, determined automatically
  by the value being encoded. This is transparent to the caller.
- Fixed mode (`SSF_TLV_ENABLE_FIXED_MODE == 1`) reduces overhead but limits to 256 tags and
  values up to 255 bytes.
- The decode interface can return a pointer directly into the TLV buffer (`SSFTLVFind`) to avoid
  a copy when the application only needs to read the value in-place.
