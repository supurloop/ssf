# ssfhex — Binary to Hex ASCII Encoder/Decoder

[Back to Codecs README](README.md) | [Back to ssf README](../README.md)

Binary to hexadecimal ASCII string encoder/decoder with optional byte-order reversal.

## Configuration

This module has no compile-time configuration options in `ssfoptions.h`.

## API Summary

| Function / Macro | Description |
|-----------------|-------------|
| `SSFHexBinToByte(in, out, outSize, hcase)` | Convert one binary byte to a 2-character hex string |
| `SSFHexByteToBin(hex, out)` | Convert a 2-character hex string to one binary byte |
| `SSFHexBytesToBin(in, inLenLim, out, outSize, outLen, rev)` | Decode hex ASCII string to binary |
| `SSFHexBinToBytes(in, inLen, out, outSize, outLen, rev, hcase)` | Encode binary to hex ASCII string |
| `SSFIsHex(h)` | Macro: returns true if character `h` is a valid hex digit |
| `SSF_HEX_CASE_LOWER` | Constant: emit lowercase hex digits (`a-f`) |
| `SSF_HEX_CASE_UPPER` | Constant: emit uppercase hex digits (`A-F`) |

## Function Reference

### `SSFHexBinToByte`

```c
bool SSFHexBinToByte(uint8_t in, char *out, size_t outSize, SSFHexCase_t hcase);
```

Converts a single binary byte to a 2-character null-terminated hexadecimal string.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `uint8_t` | Binary byte value to convert (0–255). |
| `out` | out | `char *` | Output buffer receiving the 2-character hex string plus null terminator. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be at least 3 (2 hex chars + null). |
| `hcase` | in | `SSFHexCase_t` | Case of output hex digits. `SSF_HEX_CASE_LOWER` for `a-f`; `SSF_HEX_CASE_UPPER` for `A-F`. |

**Returns:** `true` if conversion succeeded; `false` if `outSize < 3`.

---

### `SSFHexByteToBin`

```c
bool SSFHexByteToBin(const char *hex, uint8_t *out);
```

Converts exactly 2 consecutive hex ASCII characters to a single binary byte.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `hex` | in | `const char *` | Pointer to exactly 2 hex characters (`0-9`, `a-f`, `A-F`). Must not be `NULL`. |
| `out` | out | `uint8_t *` | Receives the decoded binary byte. Must not be `NULL`. |

**Returns:** `true` if both characters are valid hex digits and conversion succeeded; `false` otherwise.

---

### `SSFHexBytesToBin`

```c
bool SSFHexBytesToBin(SSFCStrIn_t in, size_t inLenLim,
                      uint8_t *out, size_t outSize, size_t *outLen, bool rev);
```

Decodes a hexadecimal ASCII string into binary bytes. Optionally reverses the byte order of the
output (useful for little-endian multi-byte values).

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const char *` | Pointer to the null-terminated hex ASCII string. Must contain only valid hex characters (`0-9`, `a-f`, `A-F`) and must have an even number of characters. Must not be `NULL`. |
| `inLenLim` | in | `size_t` | Maximum number of input characters to read. Processing also stops at the first null terminator. |
| `out` | out | `uint8_t *` | Output buffer receiving the decoded binary bytes. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out` in bytes. Must be at least `inLenLim / 2`. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of binary bytes written to `out`. |
| `rev` | in | `bool` | `true` to reverse the byte order of the output; `false` to preserve order. |

**Returns:** `true` if decoding succeeded; `false` if the input contains invalid hex characters, has an odd character count, or `outSize` is too small.

---

### `SSFHexBinToBytes`

```c
bool SSFHexBinToBytes(const uint8_t *in, size_t inLen,
                      SSFCStrOut_t out, size_t outSize, size_t *outLen,
                      bool rev, SSFHexCase_t hcase);
```

Encodes binary bytes as a null-terminated hexadecimal ASCII string. Optionally reverses the byte
order of the input before encoding.

| Parameter | Direction | Type | Description |
|-----------|-----------|------|-------------|
| `in` | in | `const uint8_t *` | Pointer to the binary bytes to encode. May be `NULL` only when `inLen` is `0`. |
| `inLen` | in | `size_t` | Number of bytes to encode from `in`. |
| `out` | out | `char *` | Output buffer receiving the null-terminated hex string. Must not be `NULL`. |
| `outSize` | in | `size_t` | Allocated size of `out`. Must be at least `(inLen * 2) + 1`. |
| `outLen` | out (opt) | `size_t *` | If not `NULL`, receives the number of hex characters written (excluding null terminator). |
| `rev` | in | `bool` | `true` to read `in` in reverse byte order before encoding; `false` to preserve order. |
| `hcase` | in | `SSFHexCase_t` | `SSF_HEX_CASE_LOWER` to emit `a-f`; `SSF_HEX_CASE_UPPER` to emit `A-F`. |

**Returns:** `true` if encoding succeeded; `false` if `outSize` is too small.

---

### `SSFIsHex`

```c
#define SSFIsHex(h)  /* evaluates to bool */
```

Evaluates to `true` if the character `h` is a valid hexadecimal digit (`0-9`, `a-f`, or `A-F`);
`false` otherwise. `h` is evaluated only once.

## Usage

This interface encodes a binary data stream into an ASCII hexadecimal string, or decodes one back
to binary. Setting `rev` to `true` reverses the byte order during the operation, which is
useful when working with little-endian multi-byte values.

```c
uint8_t binOut[2];
char strOut[5];
size_t binLen;

if (SSFHexBytesToBin("A1F5", 4, binOut, sizeof(binOut), &binLen, false))
{
    /* binLen == 2 */
    /* binOut[0] = '\xA1' */
    /* binOut[1] = '\xF5' */
}

if (SSFHexBinToBytes(binOut, binLen, strOut, sizeof(strOut), NULL, false, SSF_HEX_CASE_LOWER))
{
    printf("%s", strOut);
    /* prints "a1f5" */
}
```

## Dependencies

- `ssf/ssfport.h`

## Notes

- Both functions return `false` if the output buffer is too small.
- Passing `NULL` for `outLen` is valid when the encoded length is not needed.
- Decoding is case-insensitive; both `A1F5` and `a1f5` are accepted.
