# ssfrs — Reed-Solomon FEC Encoder/Decoder

[SSF](../README.md)

Reed-Solomon forward error correction for embedded systems: memory-efficient encode and
in-place decode with configurable chunk size and ECC symbol count.

`SSFRSEncode()` takes a message and produces a compact block of ECC bytes. Transmit the
original message followed by the ECC bytes. `SSFRSDecode()` receives the concatenated
message-plus-ECC buffer and corrects up to `eccNumBytes / 2` byte errors per chunk in place,
returning the recovered message length. Large messages are processed in fixed-size chunks,
allowing RAM usage to be traded against ECC overhead and throughput.

**Important:** Always verify message integrity with a CRC after decoding. Reed-Solomon can
converge on a plausible but incorrect solution without detecting the failure. See
[`ssfcrc16`](../_edc/ssfcrc16.md) or [`ssfcrc32`](../_edc/ssfcrc32.md).

[Dependencies](#dependencies) | [Notes](#notes) | [Configuration](#configuration) | [API Summary](#api-summary) | [Function Reference](#function-reference)

<a id="dependencies"></a>

## [↑](#ssfrs--reed-solomon-fec-encoderdecoder) Dependencies

- [`ssfport.h`](../ssfport.h)
- [`_opt/ssfrs_opt.h`](../_opt/ssfrs_opt.h) (aggregated through `ssfoptions.h`)

<a id="notes"></a>

## [↑](#ssfrs--reed-solomon-fec-encoderdecoder) Notes

- Always run a CRC over the decoded message to detect false corrections; Reed-Solomon can
  silently produce a wrong result when the error count exceeds the correction capacity.
- The `SSFRSDecode()` input buffer must contain the original message bytes followed immediately
  by the ECC bytes produced by `SSFRSEncode()`, with no gap or header between them.
- `SSFRSDecode()` corrects up to `chunkSyms / 2` byte errors per chunk. More errors than this
  in any single chunk cause `SSFRSDecode()` to return `false`; the buffer contents are
  undefined on failure.
- Erasure corrections (errors at known locations) are not supported; only error corrections
  (errors at unknown locations) are performed.
- Smaller `chunkSize` values reduce peak RAM usage but increase ECC overhead and processing
  time; larger values are more efficient but require more RAM.
- `eccNumBytes` / `chunkSyms` must be even, between 2 and 254 inclusive, and must satisfy
  `chunkSize + eccNumBytes <= 254`.
- `SSFRSEncode()` always succeeds and has no error return.
- The ECC buffer passed to `SSFRSEncode()` must be at least
  `SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS` bytes.
- The combined receive buffer passed to `SSFRSDecode()` must be at least
  `SSF_RS_MAX_MESSAGE_SIZE + (SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS)` bytes.

<a id="configuration"></a>

## [↑](#ssfrs--reed-solomon-fec-encoderdecoder) Configuration

Options live in [`_opt/ssfrs_opt.h`](../_opt/ssfrs_opt.h) (aggregated into the build via
`ssfoptions.h`).

| Option | Default | Description |
|--------|---------|-------------|
| `SSF_RS_ENABLE_ENCODING` | `1` | `1` to compile `SSFRSEncode()`; `0` to omit (decode-only builds) |
| `SSF_RS_ENABLE_DECODING` | `1` | `1` to compile `SSFRSDecode()`; `0` to omit (encode-only builds) |
| `SSF_RS_MAX_MESSAGE_SIZE` | `1024` | Maximum message length in bytes that the encoder or decoder will handle; must be `<= 2048` |
| `SSF_RS_MAX_CHUNK_SIZE` | `127` | Maximum bytes per chunk passed to the encode/decode functions; must be `<= 253` and satisfy `SSF_RS_MAX_CHUNK_SIZE + SSF_RS_MAX_SYMBOLS <= 254` |
| `SSF_RS_MAX_SYMBOLS` | `8` | Maximum ECC bytes per chunk; must be even and in the range 2–254; corrects up to `SSF_RS_MAX_SYMBOLS / 2` byte errors per chunk |
| `SSF_RS_ENABLE_GF_MUL_OPT` | `1` | `1` to use an optimized Galois Field multiply (faster, slightly more ROM); `0` for the compact loop version |

`SSF_RS_MAX_CHUNKS` is derived automatically:

```c
#if SSF_RS_MAX_MESSAGE_SIZE % SSF_RS_MAX_CHUNK_SIZE == 0
#define SSF_RS_MAX_CHUNKS (SSF_RS_MAX_MESSAGE_SIZE / SSF_RS_MAX_CHUNK_SIZE)
#else
#define SSF_RS_MAX_CHUNKS ((SSF_RS_MAX_MESSAGE_SIZE / SSF_RS_MAX_CHUNK_SIZE) + 1)
#endif
```

Use `SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS` to size the ECC buffer and
`SSF_RS_MAX_MESSAGE_SIZE + (SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS)` to size the receive
buffer.

<a id="api-summary"></a>

## [↑](#ssfrs--reed-solomon-fec-encoderdecoder) API Summary

<a id="functions"></a>

### Functions

| | Function | Description |
|---|----------|-------------|
| [e.g.](#ex-encode) | [`void SSFRSEncode(msg, msgLen, eccBuf, eccBufSize, eccBufLen, eccNumBytes, chunkSize)`](#ssfrsencode) | Encode a message and write ECC bytes to a separate buffer |
| [e.g.](#ex-decode) | [`bool SSFRSDecode(msg, msgSize, msgLen, chunkSyms, chunkSize)`](#ssfrsdecode) | Correct errors in a received message-plus-ECC buffer in place |

<a id="function-reference"></a>

## [↑](#ssfrs--reed-solomon-fec-encoderdecoder) Function Reference

<a id="ssfrsencode"></a>

### [↑](#functions) [`void SSFRSEncode()`](#functions)

```c
void SSFRSEncode(const uint8_t *msg, uint16_t msgLen, uint8_t *eccBuf, uint16_t eccBufSize,
                 uint16_t *eccBufLen, uint8_t eccNumBytes, uint8_t chunkSize);
```

Encodes `msgLen` bytes from `msg` using Reed-Solomon and writes the ECC bytes into `eccBuf`.
The message is split into chunks of `chunkSize` bytes; each chunk produces `eccNumBytes` ECC
bytes. The actual number of ECC bytes written is stored in `*eccBufLen`. Always succeeds.
Transmit `msg` followed by `eccBuf[0..*eccBufLen-1]` to the receiver.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `msg` | in | `const uint8_t *` | Pointer to the message to encode. Must not be `NULL`. |
| `msgLen` | in | `uint16_t` | Number of message bytes. Must be `> 0` and `<= SSF_RS_MAX_MESSAGE_SIZE`. |
| `eccBuf` | out | `uint8_t *` | Buffer to receive the ECC bytes. Must not be `NULL`. |
| `eccBufSize` | in | `uint16_t` | Size of `eccBuf`. Must be at least `SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS`. |
| `eccBufLen` | out | `uint16_t *` | Receives the number of ECC bytes written to `eccBuf`. Must not be `NULL`. |
| `eccNumBytes` | in | `uint8_t` | ECC bytes per chunk; must be even, 2–254, and `<= SSF_RS_MAX_SYMBOLS`. Corrects `eccNumBytes / 2` byte errors per chunk. |
| `chunkSize` | in | `uint8_t` | Message bytes per chunk; must be `> 0`, `<= SSF_RS_MAX_CHUNK_SIZE`, and `chunkSize + eccNumBytes <= 254`. |

**Returns:** Nothing (always succeeds).

<a id="ex-encode"></a>

**Example:**

```c
uint8_t  msg[SSF_RS_MAX_MESSAGE_SIZE];
uint8_t  ecc[SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS];
uint16_t eccLen;

/* Fill message with data to protect */
memset(msg, 0xaau, sizeof(msg));

/* Encode: produces ECC bytes for each chunk of the message */
SSFRSEncode(msg, (uint16_t)sizeof(msg), ecc, (uint16_t)sizeof(ecc), &eccLen,
            SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE);
/* eccLen == actual ECC bytes written; always <= SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS */

/* Transmit: send msg[0..sizeof(msg)-1] followed by ecc[0..eccLen-1] */
```

---

<a id="ssfrsdecode"></a>

### [↑](#functions) [`bool SSFRSDecode()`](#functions)

```c
bool SSFRSDecode(uint8_t *msg, uint16_t msgSize, uint16_t *msgLen, uint8_t chunkSyms,
                 uint8_t chunkSize);
```

Decodes and error-corrects the received buffer `msg` in place. `msg` must contain the original
message bytes followed immediately by the ECC bytes produced by `SSFRSEncode()`, with
`msgSize` equal to the sum of the message length and the ECC length. On success, `*msgLen` is
set to the recovered message length and the corrected bytes are written back into `msg[0..*msgLen-1]`.
On failure the buffer contents are undefined. `chunkSyms` and `chunkSize` must match the
values used during encoding.

**Always verify message integrity with a CRC after a successful decode**; Reed-Solomon can
converge on an incorrect solution without returning `false`.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `msg` | in-out | `uint8_t *` | Buffer containing message bytes followed by ECC bytes. Corrected message is written back in place on success. Must not be `NULL`. |
| `msgSize` | in | `uint16_t` | Total size of `msg`: message bytes plus ECC bytes. Must equal the transmitted message length plus `*eccBufLen` from `SSFRSEncode()`. |
| `msgLen` | out | `uint16_t *` | Receives the recovered message length (message bytes only, excluding ECC). Must not be `NULL`. Valid only when the function returns `true`. |
| `chunkSyms` | in | `uint8_t` | ECC bytes per chunk; must equal the `eccNumBytes` value used during encoding. |
| `chunkSize` | in | `uint8_t` | Message bytes per chunk; must equal the `chunkSize` value used during encoding. |

**Returns:** `true` if error correction succeeded and `msg[0..*msgLen-1]` contains the
recovered message; `false` if any chunk had more errors than `chunkSyms / 2`, in which case
the buffer contents are undefined. Always follow a `true` return with a CRC integrity check.

<a id="ex-decode"></a>

**Example:**

```c
uint8_t  msg[SSF_RS_MAX_MESSAGE_SIZE];
uint8_t  ecc[SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS];
uint16_t eccLen;

/* Encode first to have ECC data for decoding */
memset(msg, 0xaau, sizeof(msg));
SSFRSEncode(msg, (uint16_t)sizeof(msg), ecc, (uint16_t)sizeof(ecc), &eccLen,
            SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE);

/* Receive buffer: message bytes followed immediately by ECC bytes — no gap */
uint8_t  rx[SSF_RS_MAX_MESSAGE_SIZE + (SSF_RS_MAX_SYMBOLS * SSF_RS_MAX_CHUNKS)];
uint16_t rxMsgLen;

/* Assemble received buffer (simulating reception of msg then ecc) */
memcpy(rx, msg, sizeof(msg));
memcpy(&rx[sizeof(msg)], ecc, eccLen);

/* Simulate two byte errors anywhere in the message */
rx[0]   ^= 0xffu;
rx[100] ^= 0x55u;

/* Decode and correct in place; chunkSyms and chunkSize must match the encode call */
if (SSFRSDecode(rx, (uint16_t)(sizeof(msg) + eccLen), &rxMsgLen,
                SSF_RS_MAX_SYMBOLS, SSF_RS_MAX_CHUNK_SIZE))
{
    /* rx[0..rxMsgLen-1] contains the corrected message */
    /* rxMsgLen == sizeof(msg) */

    /* Always verify integrity after decoding — RS can correct to a wrong result */
    /* uint32_t crc = SSFCRC32(rx, rxMsgLen, SSF_CRC32_INITIAL); */
}
else
{
    /* More than SSF_RS_MAX_SYMBOLS/2 errors in some chunk — correction failed */
}
```
