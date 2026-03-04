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
| `SSFTLVInit(tlv, buf, bufSize, tlvLen)` | Initialize a TLV context over a buffer |
| `SSFTLVPut(tlv, tag, val, valLen)` | Encode a tag/value pair into the TLV buffer |
| `SSFTLVGet(tlv, tag, index, out, outSize, outLen)` | Decode a value by tag (copies to caller buffer) |
| `SSFTLVFind(tlv, tag, index, valPtr, outLen)` | Locate a value by tag (returns pointer into TLV buffer) |

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
